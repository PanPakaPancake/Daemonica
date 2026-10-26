package helper

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/PanPakaPancake/daemonica/internal/apt"
	"github.com/PanPakaPancake/daemonica/internal/execx"
	"github.com/PanPakaPancake/daemonica/internal/policy"
	"github.com/PanPakaPancake/daemonica/internal/rpc"
)

type aptFakeUnits struct{ started []apt.Unit }

func (f *aptFakeUnits) Start(_ context.Context, u apt.Unit) error {
	f.started = append(f.started, u)
	return nil
}

func (f *aptFakeUnits) Exists(context.Context, string) bool { return true }

func TestAptOpsRoles(t *testing.T) {
	root := t.TempDir()
	_ = os.MkdirAll(filepath.Join(root, "etc/apt/apt.conf.d"), 0o755)
	_ = os.WriteFile(filepath.Join(root, "etc/os-release"), []byte("ID=ubuntu\nVERSION_ID=\"26.04\"\nVERSION_CODENAME=resolute\n"), 0o644)
	removes := "Remv vim [2:9.1]\n"
	var calls [][]string
	run := func(_ context.Context, _ time.Duration, path string, args ...string) (execx.Result, error) {
		calls = append(calls, append([]string{path}, args...))
		a := strings.Join(args, " ")
		switch {
		case path == apt.AptGet && strings.HasSuffix(a, "--with-new-pkgs upgrade"):
			return execx.Result{Stdout: []byte("Inst openssl [3.5.0-1] (3.5.0-1.1 Ubuntu:26.04/resolute-security [amd64])\nInst tzdata [1] (2 Ubuntu:26.04/resolute-updates [all])\n")}, nil
		case path == apt.AptGet && strings.Contains(a, " remove "):
			if strings.Contains(a, "daemonica") {
				return execx.Result{Stdout: []byte("Remv daemonica [0.7]\n")}, nil
			}
			return execx.Result{Stdout: []byte(removes)}, nil
		case path == apt.AptGet && strings.Contains(a, " install "):
			if strings.Contains(a, "nosuch") {
				return execx.Result{ExitCode: 100, Stdout: []byte("Reading package lists...\nE: Unable to locate package nosuch\n")}, nil
			}
			return execx.Result{Stdout: []byte("Inst openssl [3.5.0-1] (3.5.0-1.1 Ubuntu:26.04/resolute-security [amd64])\n")}, nil
		case path == apt.AptMark:
			return execx.Result{Stdout: []byte("openssl\nlibfoo\n")}, nil
		case path == apt.DpkgQ && strings.HasSuffix(a, "${db:Status-Abbrev}\t${Package}\n"):
			return execx.Result{Stdout: []byte("ii \tvim\niF \tdracut\n")}, nil
		case path == apt.DpkgQ:
			return execx.Result{Stdout: []byte("ii \t2.12\n")}, nil
		case path == apt.AptCfg:
			return execx.Result{Stdout: []byte(`APT::Periodic::Unattended-Upgrade "1";` + "\n")}, nil
		}
		return execx.Result{}, nil
	}
	fu := &aptFakeUnits{}
	runner := &apt.Runner{Dir: t.TempDir(), Units: fu}
	if err := runner.Init(); err != nil {
		t.Fatal(err)
	}
	e := newAuthEnv(t)
	g, sa, _ := setupAdmin(t, e)
	uaPath := filepath.Join(root, apt.UnattendedFile)
	(&AptOps{Sys: apt.System{Run: run, Root: root}, Jobs: runner, UnattendedPath: uaPath, Root: root, Kernel: func() string { return "7.0.0-38-generic" }}).Register(e.web.Ops)
	const ip = "198.51.100.7"

	ro, _ := e.web.Grants.Issue(policy.Subject{AccountID: "ro", Role: policy.RoleReadOnly, LinuxUser: "carol", LinuxUID: 1002}, time.Now())
	r := e.callFrom(ip, "packages.overview", ro, nil)
	mustOK(t, r, "overview")
	var ov AptOverview
	_ = json.Unmarshal(r.Result, &ov)
	if ov.Distro.ID != "ubuntu" || len(ov.Upgrade.Install) != 2 || ov.Security != 1 || ov.Reboot || ov.Running != nil || !slices.Equal(ov.Broken, []string{"dracut"}) {
		t.Fatalf("overview: %s", r.Result)
	}

	// Finishing interrupted installs is simulated like any other job.
	r = e.callFrom(ip, "packages.simulate", ro, map[string]any{"kind": "repair"})
	mustOK(t, r, "simulate repair")
	if c := code(e.callFrom(ip, "packages.simulate", ro, map[string]any{"kind": "repair", "packages": []string{"vim"}})); c != rpc.CodeValidation {
		t.Fatalf("repair with packages: %s", c)
	}

	// Simulation is open to all roles; bad names never reach apt.
	r = e.callFrom(ip, "packages.simulate", ro, map[string]any{"kind": "remove", "packages": []string{"vim"}})
	mustOK(t, r, "simulate")
	var pl AptPlan
	_ = json.Unmarshal(r.Result, &pl)
	if len(pl.Sim.Remove) != 1 || len(pl.Critical) != 0 || pl.Protected {
		t.Fatalf("plan: %s", r.Result)
	}
	n := len(calls)
	for _, bad := range []map[string]any{
		{"kind": "remove", "packages": []string{"-y"}},
		{"kind": "remove", "packages": []string{"vim;reboot"}},
		{"kind": "remove"},
		{"kind": "update", "packages": []string{"vim"}},
		{"kind": "rm-rf"},
	} {
		if c := code(e.callFrom(ip, "packages.simulate", ro, bad)); c != rpc.CodeValidation {
			t.Fatalf("%v: %s", bad, c)
		}
	}
	if len(calls) != n {
		t.Fatalf("invalid input ran apt: %v", calls[n:])
	}
	r = e.callFrom(ip, "packages.simulate", ro, map[string]any{"kind": "install", "packages": []string{"nosuch"}})
	pl = AptPlan{}
	_ = json.Unmarshal(r.Result, &pl)
	if !strings.Contains(pl.Error, "Unable to locate package nosuch") {
		t.Fatalf("sim error: %s", r.Result)
	}

	// Starting needs admin + step-up and the confirmed removals.
	rm := map[string]any{"kind": "remove", "packages": []string{"vim"}, "expect_remove": []string{"vim"}}
	if c := code(e.callFrom(ip, "packages.start", ro, rm)); c != rpc.CodeForbidden {
		t.Fatalf("start by read-only: %s", c)
	}
	if c := code(e.callFrom(ip, "packages.start", g, rm)); c != rpc.CodeStepUpNeeded {
		t.Fatalf("start without step-up: %s", c)
	}
	gs := stepUp(t, e, sa, g)
	if c := code(e.callFrom(ip, "packages.start", gs, map[string]any{"kind": "remove", "packages": []string{"vim"}})); c != CodeAptPlanChanged {
		t.Fatalf("unconfirmed removal: %s", c)
	}
	if c := code(e.callFrom(ip, "packages.start", gs, map[string]any{"kind": "remove", "packages": []string{"daemonica"}, "expect_remove": []string{"daemonica"}})); c != CodeAptProtected {
		t.Fatalf("removing daemonica: %s", c)
	}
	removes = "Remv vim [2:9.1]\nRemv openssh-server [1:10.0]\n"
	both := map[string]any{"kind": "remove", "packages": []string{"vim"}, "expect_remove": []string{"openssh-server", "vim"}}
	if c := code(e.callFrom(ip, "packages.start", gs, both)); c != CodeAptCritical {
		t.Fatalf("critical without ack: %s", c)
	}
	both["ack_critical"] = true
	r = e.callFrom(ip, "packages.start", gs, both)
	mustOK(t, r, "start remove")
	var j apt.Job
	_ = json.Unmarshal(r.Result, &j)
	if j.Kind != apt.KindRemove || len(fu.started) != 1 || !slices.Contains(fu.started[0].Exec[0], "vim") {
		t.Fatalf("job: %s %+v", r.Result, fu.started)
	}
	if c := code(e.callFrom(ip, "packages.start", gs, map[string]any{"kind": "update"})); c != CodeAptBusy {
		t.Fatalf("second job: %s", c)
	}
	r = e.callFrom(ip, "packages.job", ro, map[string]any{"id": j.ID})
	mustOK(t, r, "job")
	if c := code(e.callFrom(ip, "packages.job", ro, map[string]any{"id": "../../etc/passwd"})); c != rpc.CodeNotFound {
		t.Fatalf("job traversal: %s", c)
	}

	// Security updates restore the automatic marks.
	_ = os.WriteFile(filepath.Join(runner.Dir, j.ID+".log"), []byte(apt.ResultMarker+" success exited 0\n"), 0o600)
	r = e.callFrom(ip, "packages.start", gs, map[string]any{"kind": "selected", "packages": []string{"openssl"}})
	mustOK(t, r, "start selected")
	if last := fu.started[len(fu.started)-1]; len(last.Exec) != 2 || !slices.Equal(last.Exec[1], []string{apt.AptMark, "auto", "openssl"}) {
		t.Fatalf("restore auto: %q", last.Exec)
	}

	// unattended-upgrades: managed file, security only.
	if c := code(e.callFrom(ip, "packages.unattended.set", gs, map[string]any{"enabled": true, "auto_reboot": true, "reboot_time": "3:30"})); c != rpc.CodeValidation {
		t.Fatalf("bad time: %s", c)
	}
	r = e.callFrom(ip, "packages.unattended.set", gs, map[string]any{"enabled": true, "auto_reboot": true, "reboot_time": "03:30"})
	mustOK(t, r, "unattended set")
	b, err := os.ReadFile(uaPath)
	if err != nil || !strings.Contains(string(b), "origin=Ubuntu,archive=${distro_codename}-security") {
		t.Fatalf("file: %v %s", err, b)
	}
	if st, _ := os.Stat(uaPath); st.Mode().Perm() != 0o644 {
		t.Fatalf("mode %v", st.Mode())
	}
	var ua AptUnattended
	_ = json.Unmarshal(r.Result, &ua)
	if !ua.Managed || ua.Wanted == nil || ua.Wanted.RebootTime != "03:30" || !ua.Installed || !ua.Supported {
		t.Fatalf("unattended: %s", r.Result)
	}
	if c := code(e.callFrom(ip, "packages.unattended.set", ro, map[string]any{"enabled": false})); c != rpc.CodeForbidden {
		t.Fatalf("set by read-only: %s", c)
	}
	if c := code(e.callFrom(ip, "packages.search", ro, map[string]any{"q": "-o"})); c != rpc.CodeValidation {
		t.Fatalf("search flag: %s", c)
	}
}
