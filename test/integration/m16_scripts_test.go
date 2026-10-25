//go:build integration

package integration

import (
	"context"
	"errors"
	"os"
	"slices"
	"syscall"
	"testing"
	"time"

	"github.com/PanPakaPancake/daemonica/internal/helper"
	"github.com/PanPakaPancake/daemonica/internal/jobs"
	"github.com/PanPakaPancake/daemonica/internal/netcfg"
	"github.com/PanPakaPancake/daemonica/internal/scripts"
	"github.com/PanPakaPancake/daemonica/internal/services"
)

// TestScriptLibraryOnHost (DEC-030): with the helper's umask 0077 the
// library stays readable for other users, root jobs accept its files as
// trusted, a job running as nobody executes a library script, and a GitHub
// collection is installed at a pinned commit with its executable bits.
func TestScriptLibraryOnHost(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		t.Skip("needs systemd")
	}
	old := syscall.Umask(0o077)
	defer syscall.Umask(old)
	root := "/var/lib/daemonica-scripts-ittest"
	_ = os.RemoveAll(root)
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	lib := &scripts.Library{Root: root, StateFile: t.TempDir() + "/scripts.json", GitHub: scripts.NewGitHub()}
	if err := lib.Init(); err != nil {
		t.Fatal(err)
	}
	if _, err := lib.SaveLocal("it.sh", []byte("#!/bin/sh\necho \"it-$(id -un)\"\n"), true, ""); err != nil {
		t.Fatal(err)
	}
	abs := lib.Abs(scripts.LocalID, "it.sh")
	if err := jobs.Trusted(abs, 0); err != nil {
		t.Fatalf("library file not trusted for root jobs: %v", err)
	}

	sd, err := services.Connect()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sd.Close() }()
	m := &jobs.Manager{Dir: t.TempDir(), UnitDir: "/etc/systemd/system", Systemd: helper.JobSystemd{C: sd},
		Run: netcfg.ExecRunner, LookupUser: helper.LookupLinuxUser}
	ctx := context.Background()
	j := jobs.Job{ID: "itscript", Mode: jobs.ModeScript, Script: abs, User: "nobody",
		Schedule: jobs.Schedule{Kind: jobs.KindDaily, Time: "03:00"}, Enabled: false}
	_ = m.Delete(ctx, j.ID)
	t.Cleanup(func() { _ = m.Delete(context.Background(), "itscript") })
	if _, err := m.Save(ctx, j, true, "it"); err != nil {
		t.Fatalf("save: %v", err)
	}
	if err := m.RunNow(ctx, j.ID); err != nil {
		t.Fatal(err)
	}
	var runs []jobs.Run
	for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); time.Sleep(time.Second) {
		if runs, _ = jobs.History(ctx, j.Service(), true); len(runs) > 0 && runs[0].Result != "running" {
			break
		}
	}
	if len(runs) == 0 || runs[0].Result != "success" || !slices.Equal(runs[0].Excerpt, []string{"it-nobody"}) {
		t.Fatalf("run as nobody: %+v", runs)
	}

	// A public collection from GitHub, pinned to the commit it resolved to.
	gctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	spec, _ := scripts.Spec{ID: "daemonica", Repo: "PanPakaPancake/Daemonica", Subdir: "packaging/maintainer-scripts"}.Normalize()
	c, err := lib.GitHub.Resolve(gctx, spec.Repo, "", "")
	var fe *scripts.FetchError
	if errors.As(err, &fe) && (fe.Code == scripts.FetchNetwork || fe.Code == scripts.FetchRateLimited) {
		t.Skipf("GitHub not reachable from this host: %v", err)
	}
	if err != nil {
		t.Fatal(err)
	}
	tree, skipped, err := lib.GitHub.Tree(gctx, spec.Repo, c.SHA, spec.Subdir, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("commit %s %q: %d files, skipped %v", c.SHA, c.Message, len(tree), skipped)
	src, err := lib.Add(spec, c, tree, "it")
	if err != nil || src.Commit.SHA != c.SHA {
		t.Fatalf("add: %+v %v", src, err)
	}
	fi, err := os.Stat(lib.Abs("daemonica", "postinst"))
	if err != nil || fi.Mode().Perm() != 0o755 {
		t.Fatalf("postinst: %v %v", fi, err)
	}
	if err := jobs.Trusted(lib.Abs("daemonica", "postinst"), 0); err != nil {
		t.Fatalf("collection file not trusted: %v", err)
	}
}
