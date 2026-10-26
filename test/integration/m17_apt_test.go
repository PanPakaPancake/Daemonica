//go:build integration

package integration

import (
	"context"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/PanPakaPancake/daemonica/internal/apt"
	"github.com/godbus/dbus/v5"
)

// TestAptOnHost (M1.7a, DEC-031): the read side parses the real host
// (simulation, installed list, sources, unattended-upgrades), and the two
// harmless jobs (apt-get update, unattended-upgrade dry run) run as
// transient units with the helper's umask, end with a result line and
// leave no unit behind. Installing updates is part of the manual acceptance.
func TestAptOnHost(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	if _, err := os.Stat(apt.AptGet); err != nil {
		t.Skip("needs apt")
	}
	old := syscall.Umask(0o077)
	defer syscall.Umask(old)
	ctx := context.Background()
	sys := apt.System{Run: apt.ExecRun}

	sim, err := sys.Simulate(ctx, apt.KindUpgrade, nil)
	if err != nil {
		t.Fatalf("simulate: %v", err)
	}
	t.Logf("upgradable: %d (kept back %d)", len(sim.Install), len(sim.Kept))
	for _, p := range sim.Install {
		if p.Name == "" || p.New == "" || len(p.Origins) == 0 {
			t.Errorf("unparsed simulation line: %+v", p)
		}
	}
	inst, err := sys.Installed(ctx)
	if err != nil || len(inst) < 50 {
		t.Fatalf("installed: %d %v", len(inst), err)
	}
	var sawApt bool
	for _, p := range inst {
		sawApt = sawApt || (p.Name == "apt" && p.Status == "ii")
	}
	if !sawApt {
		t.Error("apt not listed as installed")
	}
	src := apt.ReadSources("/")
	if len(src.Entries) == 0 {
		t.Fatalf("no sources: %+v", src.Files)
	}
	for _, e := range src.Entries {
		t.Logf("source %s:%d %s %v official=%v https=%v", e.File, e.Line, e.Format, e.URIs, e.Official, e.HTTPS)
	}
	ua, err := sys.Unattended(ctx)
	if err != nil {
		t.Fatalf("unattended: %v", err)
	}
	t.Logf("unattended: installed=%v update_lists=%v upgrade=%v security_only=%v origins=%v patterns=%v",
		ua.Installed, ua.UpdateLists, ua.Upgrade, ua.SecurityOnly, ua.Origins, ua.Patterns)
	if _, err := os.Stat(apt.NeedRestartBin); err == nil {
		nr, err := sys.NeedRestart(ctx)
		if err != nil || !nr.Available || nr.Kernel == 0 {
			t.Errorf("needrestart: %+v %v", nr, err)
		}
	}
	if h := apt.LockHolder(); h != nil {
		t.Logf("package lock held by %+v", *h)
	}

	conn, err := dbus.ConnectSystemBus()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	units := apt.SystemdUnits{Conn: conn}
	r := &apt.Runner{Dir: t.TempDir(), Units: units}
	if err := r.Init(); err != nil {
		t.Fatal(err)
	}
	kinds := []apt.Kind{apt.KindUpdate}
	if ua.Installed {
		kinds = append(kinds, apt.KindDryRun)
	}
	for _, k := range kinds {
		j, err := r.Start(ctx, k, nil, nil, "ittest")
		if err != nil {
			t.Fatalf("%s: start: %v", k, err)
		}
		deadline := time.Now().Add(10 * time.Minute)
		for j.State == apt.StateRunning && time.Now().Before(deadline) {
			time.Sleep(time.Second)
			if j, err = r.Get(ctx, j.ID); err != nil {
				t.Fatal(err)
			}
		}
		text, _, _ := r.Log(j.ID, 0)
		t.Logf("%s: state=%s result=%s exit=%d issues=%v\n%s", k, j.State, j.Result, j.Exit, j.Issues, tail(text, 1500))
		if j.State != apt.StateSucceeded {
			t.Errorf("%s did not succeed: %+v", k, j)
		}
		if strings.Contains(text, apt.ResultMarker) || strings.Contains(text, "dlstatus:") {
			t.Errorf("%s: status lines in the shown log", k)
		}
		if units.Exists(ctx, apt.UnitPrefix+j.ID+".service") {
			t.Errorf("%s: unit left behind", k)
		}
		if k == apt.KindDryRun && !strings.Contains(text, "dry-run") && !strings.Contains(text, "Allowed origins") {
			t.Errorf("dry run output unexpected")
		}
	}
	if _, err := r.Start(ctx, apt.KindUpdate, nil, nil, "ittest"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Start(ctx, apt.KindUpdate, nil, nil, "ittest"); err != apt.ErrBusy {
		t.Errorf("second job while one runs: %v", err)
	}
	for _, j := range r.List(ctx) {
		for j.State == apt.StateRunning {
			time.Sleep(time.Second)
			j, _ = r.Get(ctx, j.ID)
		}
	}
}

func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return "…" + s[len(s)-n:]
}
