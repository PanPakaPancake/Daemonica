package helper

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/PanPakaPancake/daemonica/internal/disks"
	"github.com/PanPakaPancake/daemonica/internal/execx"
	"github.com/PanPakaPancake/daemonica/internal/planner"
	"github.com/PanPakaPancake/daemonica/internal/policy"
	"github.com/PanPakaPancake/daemonica/internal/rpc"
	"github.com/PanPakaPancake/daemonica/internal/sysinfo"
)

type fakeMounter struct {
	units   []string
	reloads int
	onStart func()
}

func (f *fakeMounter) Reload(context.Context) error { f.reloads++; return nil }

func (f *fakeMounter) Unit(_ context.Context, unit string, start bool) error {
	f.units = append(f.units, map[bool]string{true: "start ", false: "stop "}[start]+unit)
	if start && f.onStart != nil {
		f.onStart()
	}
	return nil
}

func TestDiskOpsRoles(t *testing.T) {
	dir := t.TempDir()
	fstab := filepath.Join(dir, "fstab")
	orig := "# test\nUUID=1111\t/\text4\tdefaults\t0\t1\n/dev/sdb1 /srv/data xfs defaults,nofail 0 2\n"
	_ = os.WriteFile(fstab, []byte(orig), 0o644)
	proc := filepath.Join(dir, "proc")
	_ = os.MkdirAll(filepath.Join(proc, "self"), 0o755)
	mountinfo := "36 1 8:1 / / rw - ext4 /dev/vda1 rw\n40 36 8:17 / /srv/data rw - xfs /dev/sdb1 rw\n"
	_ = os.WriteFile(filepath.Join(proc, "self/mountinfo"), []byte(mountinfo), 0o644)
	_ = os.WriteFile(filepath.Join(proc, "swaps"), []byte("Filename Type Size Used Priority\n/swap.img file 2097148 1024 -2\n"), 0o644)
	verifyOut := ""
	run := func(_ context.Context, _ time.Duration, path string, args ...string) (execx.Result, error) {
		switch path {
		case disks.Lsblk:
			return execx.Result{Stdout: []byte(`{"blockdevices":[{"name":"sdb","path":"/dev/sdb","type":"disk","size":100,"mountpoints":[null]}]}`)}, nil
		case disks.Findmnt:
			if b, _ := os.ReadFile(args[len(args)-1]); strings.Contains(string(b), "/missing") {
				return execx.Result{ExitCode: 1, Stdout: []byte("/missing\n   [E] unreachable on boot required source: UUID=9999\n")}, nil
			}
			return execx.Result{Stdout: []byte(verifyOut)}, nil
		}
		return execx.Result{}, nil
	}
	pm, err := planner.New(filepath.Join(dir, "journal"), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	reloads := 0
	pm.Register(&FstabHandler{Path: fstab, Reload: func(context.Context) error { reloads++; return nil }})
	fm := &fakeMounter{}
	e := newAuthEnv(t)
	g, sa, _ := setupAdmin(t, e)
	stat := func(string, *syscall.Statfs_t) error { return nil }
	(&DiskOps{Run: run, FstabPath: fstab, ProcRoot: proc, FS: sysinfo.FS{Root: dir}, Statfs: stat, Mounter: fm, Planner: pm,
		Now: func() time.Time { return time.Date(2026, 10, 26, 1, 2, 3, 0, time.UTC) }}).Register(e.web.Ops)
	const ip = "198.51.100.7"
	ro, _ := e.web.Grants.Issue(policy.Subject{AccountID: "ro", Role: policy.RoleReadOnly, LinuxUser: "carol", LinuxUID: 1002}, time.Now())

	r := e.callFrom(ip, "disks.overview", ro, nil)
	mustOK(t, r, "overview")
	var ov DiskOverview
	_ = json.Unmarshal(r.Result, &ov)
	if len(ov.Blocks) != 1 || len(ov.Fstab.Entries) != 2 || len(ov.Swaps) != 1 || ov.Swaps[0].Size != 2097148<<10 {
		t.Fatalf("overview: %s", r.Result)
	}

	entries := ov.Fstab.Entries
	entries[1].Options = "defaults,nofail,noexec"
	add := append(entries, disks.Entry{Spec: "UUID=9999", File: "/missing", Type: "ext4", Options: "nofail"})
	// A broken fstab is rejected before anything is planned.
	r = e.callFrom(ip, "disks.fstab_check", ro, map[string]any{"entries": add})
	mustOK(t, r, "check")
	var ck FstabCheck
	_ = json.Unmarshal(r.Result, &ck)
	if !ck.Blocking || ck.Problems[len(ck.Problems)-1].Code != "verify" || !strings.Contains(ck.Diff, "+UUID=9999") {
		t.Fatalf("check: %s", r.Result)
	}
	if c := code(e.callFrom(ip, "disks.fstab_plan", ro, map[string]any{"entries": entries})); c != rpc.CodeForbidden {
		t.Fatalf("plan by read-only: %s", c)
	}
	if c := code(e.callFrom(ip, "disks.fstab_plan", g, map[string]any{"entries": entries})); c != rpc.CodeStepUpNeeded {
		t.Fatalf("plan without step-up: %s", c)
	}
	gs := stepUp(t, e, sa, g)
	r = e.callFrom(ip, "disks.fstab_plan", gs, map[string]any{"entries": add})
	ck = FstabCheck{}
	_ = json.Unmarshal(r.Result, &ck)
	if ck.Change != nil || !ck.Blocking {
		t.Fatalf("broken fstab planned: %s", r.Result)
	}
	noRoot := []disks.Entry{entries[1]}
	r = e.callFrom(ip, "disks.fstab_plan", gs, map[string]any{"entries": noRoot})
	ck = FstabCheck{}
	_ = json.Unmarshal(r.Result, &ck)
	if ck.Change != nil || !slices.ContainsFunc(ck.Problems, func(p disks.Problem) bool { return p.Code == "root_missing" }) {
		t.Fatalf("root removal planned: %s", r.Result)
	}
	if b, _ := os.ReadFile(fstab); string(b) != orig {
		t.Fatal("fstab changed by a rejected plan")
	}

	verifyOut = "/\n   [W] cannot detect on-disk filesystem type (Operation not permitted)\n"
	r = e.callFrom(ip, "disks.fstab_plan", gs, map[string]any{"entries": entries})
	mustOK(t, r, "plan")
	ck = FstabCheck{}
	_ = json.Unmarshal(r.Result, &ck)
	if ck.Change == nil || ck.Blocking || strings.Contains(string(r.Result), `"old"`) || len(ck.Problems) == 0 {
		t.Fatalf("plan: %s", r.Result)
	}
	if _, err := pm.Apply(context.Background(), ck.Change.ID, "admin-1"); err != nil {
		if _, err2 := pm.Apply(context.Background(), ck.Change.ID, ck.Change.Owner); err2 != nil {
			t.Fatalf("apply: %v / %v", err, err2)
		}
	}
	b, _ := os.ReadFile(fstab)
	backup := fstab + ".daemonica-20261026-010203"
	bk, _ := os.ReadFile(backup)
	if !strings.Contains(string(b), "/dev/sdb1\t/srv/data\txfs\tdefaults,nofail,noexec\t0\t2") || !strings.HasPrefix(string(b), "# test\nUUID=1111\t/") ||
		string(bk) != orig || reloads != 1 {
		t.Fatalf("applied: %q backup %q reloads %d", b, bk, reloads)
	}
	if st, _ := os.Stat(fstab); st.Mode().Perm() != 0o644 {
		t.Fatalf("mode %v", st.Mode())
	}
	if _, err := pm.Rollback(ck.Change.ID, ck.Change.Owner); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(fstab); string(b) != orig || reloads != 2 {
		t.Fatalf("rolled back: %q", b)
	}

	// Unmount: critical mounts are refused, busy ones report the users.
	if c := code(e.callFrom(ip, "disks.unmount", gs, map[string]any{"target": "/"})); c != CodeProtectedMount {
		t.Fatalf("unmount /: %s", c)
	}
	if c := code(e.callFrom(ip, "disks.unmount", gs, map[string]any{"target": "/srv/../etc"})); c != rpc.CodeValidation {
		t.Fatalf("unclean target: %s", c)
	}
	pd := filepath.Join(proc, "4242")
	_ = os.MkdirAll(filepath.Join(pd, "fd"), 0o755)
	_ = os.WriteFile(filepath.Join(pd, "comm"), []byte("rsync\n"), 0o644)
	_ = os.Symlink("/srv/data/x", filepath.Join(pd, "cwd"))
	r = e.callFrom(ip, "disks.unmount", gs, map[string]any{"target": "/srv/data"})
	mustOK(t, r, "unmount busy")
	var mr MountResult
	_ = json.Unmarshal(r.Result, &mr)
	if mr.OK || len(mr.Users) != 1 || mr.Users[0].Comm != "rsync" || len(fm.units) != 0 {
		t.Fatalf("busy: %s %v", r.Result, fm.units)
	}
	_ = os.RemoveAll(pd)
	_ = os.WriteFile(filepath.Join(proc, "self/mountinfo"), []byte("36 1 8:1 / / rw - ext4 /dev/vda1 rw\n"), 0o644)
	if c := code(e.callFrom(ip, "disks.unmount", gs, map[string]any{"target": "/srv/data"})); c != rpc.CodeNotFound {
		t.Fatalf("not mounted: %s", c)
	}
	// Mount only what fstab lists.
	if c := code(e.callFrom(ip, "disks.mount", gs, map[string]any{"target": "/etc"})); c != rpc.CodeNotFound {
		t.Fatalf("mount outside fstab: %s", c)
	}
	fm.onStart = func() { _ = os.WriteFile(filepath.Join(proc, "self/mountinfo"), []byte(mountinfo), 0o644) }
	r = e.callFrom(ip, "disks.mount", gs, map[string]any{"target": "/srv/data"})
	mustOK(t, r, "mount")
	mr = MountResult{}
	_ = json.Unmarshal(r.Result, &mr)
	if !mr.OK || fm.reloads != 1 || fm.units[0] != "start srv-data.mount" {
		t.Fatalf("mount: %s %v", r.Result, fm.units)
	}
	if c := code(e.callFrom(ip, "disks.mount", ro, map[string]any{"target": "/srv/data"})); c != rpc.CodeForbidden {
		t.Fatalf("mount by read-only: %s", c)
	}
}
