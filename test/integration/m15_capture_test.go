//go:build integration

package integration

import (
	"context"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/PanPakaPancake/daemonica/internal/capture"
)

// TestCaptureOnHost runs tcpdump as the real sandboxed transient unit (SPEC
// §7.6 M1.5d acceptance): the process is not root, has only CAP_NET_RAW and
// the unit carries the sandbox; the pcap stream passes through systemd's fd
// passing, the helper writes a file tcpdump -r can read, and the unit is gone
// afterwards.
func TestCaptureOnHost(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		t.Skip("needs systemd")
	}
	if _, err := os.Stat(capture.Tcpdump); err != nil {
		t.Skip("tcpdump not installed")
	}
	st, err := capture.ConnectSystemd()
	if err != nil {
		t.Fatal(err)
	}
	m := &capture.Manager{Dir: t.TempDir(), Starter: st}
	ctx := context.Background()
	if err := m.Init(ctx); err != nil {
		t.Fatal(err)
	}
	spec, err := capture.Spec{Iface: "lo", AcceptWarning: true, Builder: capture.Builder{Proto: "icmp"}, DurationSec: 20, Packets: 6}.Normalize()
	if err != nil {
		t.Fatal(err)
	}
	meta, err := m.Start(ctx, spec, "it")
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	unit := capture.UnitPrefix + meta.ID + ".service"
	t.Cleanup(func() { _ = exec.Command("systemctl", "stop", unit).Run() })

	// Wait until tcpdump runs, then check the sandbox of the live process.
	var pid string
	for i := 0; i < 50 && (pid == "" || pid == "0"); i++ {
		time.Sleep(100 * time.Millisecond)
		out, _ := exec.Command("systemctl", "show", "-p", "MainPID", "--value", unit).Output()
		pid = strings.TrimSpace(string(out))
	}
	if pid == "" || pid == "0" {
		t.Fatalf("unit %s did not start", unit)
	}
	props, _ := exec.Command("systemctl", "show", unit, "-p",
		"DynamicUser,NoNewPrivileges,ProtectSystem,ProtectHome,PrivateTmp,PrivateDevices,RestrictAddressFamilies,CapabilityBoundingSet,AmbientCapabilities,MemoryMax,TasksMax,RuntimeMaxUSec").Output()
	t.Logf("unit properties:\n%s", props)
	for _, want := range []string{"DynamicUser=yes", "NoNewPrivileges=yes", "ProtectSystem=strict", "PrivateTmp=yes", "CapabilityBoundingSet=cap_net_raw\n"} {
		if !strings.Contains(string(props), want) {
			t.Errorf("unit lacks %q", strings.TrimSpace(want))
		}
	}
	if !strings.Contains(string(props), "RestrictAddressFamilies=AF_UNIX AF_PACKET") && !strings.Contains(string(props), "RestrictAddressFamilies=AF_PACKET AF_UNIX") {
		t.Errorf("address families not restricted")
	}
	status, err := os.ReadFile("/proc/" + pid + "/status")
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range strings.Split(string(status), "\n") {
		f := strings.Fields(l)
		switch {
		case len(f) > 1 && f[0] == "Uid:":
			if f[1] == "0" {
				t.Errorf("tcpdump runs as root: %s", l)
			}
		case len(f) > 1 && f[0] == "CapEff:":
			v, _ := strconv.ParseUint(f[1], 16, 64)
			if v&^(1<<13) != 0 {
				t.Errorf("tcpdump has more than CAP_NET_RAW: %s", l)
			}
		case len(f) > 1 && f[0] == "NoNewPrivs:" && f[1] != "1":
			t.Errorf("no_new_privs not set: %s", l)
		}
	}

	// Traffic: the capture ends at its packet limit.
	if out, err := exec.Command("ping", "-c", "4", "-i", "0.2", "127.0.0.1").CombinedOutput(); err != nil {
		t.Fatalf("ping: %v %s", err, out)
	}
	deadline := time.Now().Add(15 * time.Second)
	for {
		got, err := m.Get(meta.ID)
		if err != nil {
			t.Fatal(err)
		}
		if got.State != "running" {
			meta = got
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("capture still running: %+v", got)
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Logf("capture ended: %+v", meta)
	if meta.State != "done" || meta.Captured < 6 || (meta.Reason != "packets" && meta.Reason != "ended") {
		t.Fatalf("capture result: %+v", meta)
	}
	lines, err := m.Lines(meta.ID, "", 10)
	if err != nil || len(lines.Entries) < 6 || lines.Entries[0].Proto != "icmp" {
		t.Fatalf("lines: %+v %v", lines, err)
	}
	f, _, err := m.Open(meta.ID)
	if err != nil {
		t.Fatal(err)
	}
	path := f.Name()
	_ = f.Close()
	out, err := exec.Command(capture.Tcpdump, "-n", "-r", path).CombinedOutput()
	if err != nil || strings.Count(string(out), "ICMP") < 6 {
		t.Fatalf("tcpdump -r: %v\n%s", err, out)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("pcap mode: %v %v", fi.Mode(), err)
	}
	time.Sleep(time.Second)
	if out, _ := exec.Command("systemctl", "list-units", "--all", "--no-legend", unit).Output(); strings.TrimSpace(string(out)) != "" {
		t.Fatalf("unit left behind: %s", out)
	}
}
