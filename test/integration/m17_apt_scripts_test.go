//go:build integration

package integration

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"

	"github.com/PanPakaPancake/daemonica/internal/apt"
)

// TestAptMaintainerScripts (M1.7a, DEC-031): maintainer scripts of a package
// job can write to stdout and stderr (on the VM they failed with EIO/EBADF
// when apt's status fd was stdout), an interrupted configuration shows up as
// broken, and the repair job finishes it.
func TestAptMaintainerScripts(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	const pkg = "daemonica-ittest-scripts"
	const gate = "/run/daemonica-ittest-postinst-ok"
	dir := t.TempDir()
	_ = os.Chmod(dir, 0o755)
	_ = os.MkdirAll(filepath.Join(dir, "p/DEBIAN"), 0o755)
	_ = os.WriteFile(filepath.Join(dir, "p/DEBIAN/control"), []byte("Package: "+pkg+"\nVersion: 1.0\nArchitecture: all\nMaintainer: Daemonica <noreply@example.org>\nDescription: Daemonica integration test\n"), 0o644)
	postinst := "#!/bin/sh\nset -e\necho \"postinst stdout ok\"\necho \"postinst stderr ok\" >&2\n[ -e " + gate + " ] || { echo \"gate missing\"; exit 1; }\n"
	_ = os.WriteFile(filepath.Join(dir, "p/DEBIAN/postinst"), []byte(postinst), 0o755)
	deb := filepath.Join(dir, pkg+".deb")
	if out, err := exec.Command("dpkg-deb", "-b", filepath.Join(dir, "p"), deb).CombinedOutput(); err != nil {
		t.Fatalf("dpkg-deb: %v %s", err, out)
	}
	_ = os.Chmod(deb, 0o644)
	_ = os.Remove(gate)
	t.Cleanup(func() {
		_ = os.Remove(gate)
		_ = exec.Command("dpkg", "--purge", pkg).Run()
	})

	conn, err := dbus.ConnectSystemBus()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	ctx := context.Background()
	r := &apt.Runner{Dir: t.TempDir(), Units: apt.SystemdUnits{Conn: conn}}
	if err := r.Init(); err != nil {
		t.Fatal(err)
	}
	sys := apt.System{Run: apt.ExecRun}
	run := func(k apt.Kind, pkgs []string) (apt.Job, string) {
		j, err := r.Start(ctx, k, pkgs, nil, "ittest")
		if err != nil {
			t.Fatalf("%s: start: %v", k, err)
		}
		for deadline := time.Now().Add(10 * time.Minute); j.State == apt.StateRunning && time.Now().Before(deadline); {
			time.Sleep(time.Second)
			if j, err = r.Get(ctx, j.ID); err != nil {
				t.Fatal(err)
			}
		}
		text, _, _ := r.Log(j.ID, 0)
		t.Logf("%s: state=%s exit=%d issues=%v\n%s", k, j.State, j.Exit, j.Issues, tail(text, 1500))
		return j, text
	}

	// First install: the scripts' output arrives, the gate makes postinst fail.
	j, text := run(apt.KindInstall, []string{deb})
	if j.State != apt.StateFailed || !strings.Contains(text, "postinst stdout ok") || !strings.Contains(text, "postinst stderr ok") || !strings.Contains(text, "gate missing") {
		t.Fatalf("install with failing postinst: %+v", j)
	}
	if strings.Contains(text, "I/O error") || strings.Contains(text, "Bad file descriptor") {
		t.Fatal("maintainer script could not write its output")
	}
	if b, err := sys.Broken(ctx); err != nil || !slices.Contains(b, pkg) {
		t.Fatalf("broken after failed postinst: %v %v", b, err)
	}

	// Repair finishes the configuration once the cause is gone.
	if err := os.WriteFile(gate, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if j, text = run(apt.KindRepair, nil); j.State != apt.StateSucceeded || !strings.Contains(text, "postinst stdout ok") {
		t.Fatalf("repair: %+v", j)
	}
	if b, _ := sys.Broken(ctx); slices.Contains(b, pkg) {
		t.Fatalf("still broken after repair: %v", b)
	}
	if j, _ = run(apt.KindPurge, []string{pkg}); j.State != apt.StateSucceeded {
		t.Fatalf("purge: %+v", j)
	}
}
