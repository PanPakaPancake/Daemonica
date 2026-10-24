//go:build integration

// Integration tests for M1.1 against the real host (run on the test VM as root):
//
//	go test -tags integration ./test/integration/
package integration

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/PanPakaPancake/daemonica/internal/journal"
	"github.com/PanPakaPancake/daemonica/internal/services"
	"github.com/PanPakaPancake/daemonica/internal/sysinfo"
)

func TestCollectorOnHost(t *testing.T) {
	c := &sysinfo.Collector{FS: sysinfo.FS{Root: "/"}}
	ctx := context.Background()
	c.Sample(ctx)
	time.Sleep(1100 * time.Millisecond)
	c.Sample(ctx)
	s := c.Snapshot()
	if s.Hostname == "" || s.Kernel == "" || s.CPUs < 1 || s.Memory.Total == 0 || s.Processes < 10 {
		t.Fatalf("implausible snapshot: %+v", s)
	}
	root := false
	for _, m := range s.Mounts {
		if m.Mountpoint == "/" && m.Total > 0 {
			root = true
		}
	}
	if !root {
		t.Fatal("root filesystem missing")
	}
	t.Logf("host=%s os=%q cpu=%.1f%% load=%v mem=%d/%d procs=%d mounts=%d ifaces=%d",
		s.Hostname, s.OS, s.CPUPct, s.Load, s.Memory.Used, s.Memory.Total, s.Processes, len(s.Mounts), len(s.Interfaces))
	found := false
	for _, p := range c.Processes() {
		if p.PID == os.Getpid() {
			found = true
		}
	}
	if !found {
		t.Fatal("own process not in table")
	}
}

func TestSystemdOverDBus(t *testing.T) {
	sd, err := services.Connect()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sd.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	units, err := sd.List(ctx)
	if err != nil || len(units) < 10 {
		t.Fatalf("list: %v (%d units)", err, len(units))
	}
	var ssh bool
	for _, u := range units {
		if strings.HasPrefix(u.Name, "ssh.") && u.Protected {
			ssh = true
		}
	}
	if !ssh {
		t.Error("ssh unit missing or not protected")
	}
	d, err := sd.Get(ctx, "daemonica-web.service")
	if err != nil || d.Active != "active" || !strings.Contains(d.UnitFile, "ProtectSystem") {
		t.Fatalf("detail: %v %+v", err, d.Unit)
	}
	n, err := sd.FailedCount(ctx)
	t.Logf("units=%d failed=%d err=%v", len(units), n, err)

	// Start/stop roundtrip on a harmless transient-free unit shipped with Ubuntu.
	const unit = "apt-daily.timer"
	if _, err := sd.Get(ctx, unit); err == nil {
		before, _ := sd.Get(ctx, unit)
		if err := sd.Do(ctx, unit, services.ActRestart); err != nil {
			t.Fatalf("restart %s: %v", unit, err)
		}
		after, _ := sd.Get(ctx, unit)
		t.Logf("%s: %s → %s", unit, before.Active, after.Active)
	}
	if err := sd.Do(ctx, "x.service\n[Service]", services.ActStart); err == nil {
		t.Fatal("injected unit name accepted")
	}
}

func TestJournalOnHost(t *testing.T) {
	ctx := context.Background()
	r, err := journal.Run(ctx, journal.Query{Lines: 20})
	if err != nil || len(r.Entries) == 0 || r.Cursor == "" {
		t.Fatalf("journal: %v %d", err, len(r.Entries))
	}
	r2, err := journal.Run(ctx, journal.Query{After: r.Cursor})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("tail=%d after-cursor=%d", len(r.Entries), len(r2.Entries))
	u, err := journal.Run(ctx, journal.Query{Unit: "daemonica-helper.service", Lines: 5, Grep: "started"})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range u.Entries {
		if !strings.Contains(strings.ToLower(e.Message), "started") {
			t.Fatalf("grep filter not applied: %q", e.Message)
		}
	}
}
