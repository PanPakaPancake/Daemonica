package helper

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PanPakaPancake/daemonica/internal/files"
	"github.com/PanPakaPancake/daemonica/internal/policy"
	"github.com/PanPakaPancake/daemonica/internal/rpc"
	"github.com/PanPakaPancake/daemonica/internal/worker"
)

// inProcWorker runs the fs.* worker operations in the test process (as the
// test user) instead of a re-exec'd worker.
type inProcWorker struct{}

func (inProcWorker) Run(_ context.Context, _ worker.Identity, _ bool, op string, args, out any) error {
	raw, _ := json.Marshal(args)
	h, ok := files.WorkerHandlers()[op]
	if !ok || strings.HasPrefix(op, "fs.read") || op == "fs.write" {
		return errors.New("unsupported op " + op)
	}
	res, err := h(raw)
	if err != nil {
		return err
	}
	b, _ := json.Marshal(res)
	return json.Unmarshal(b, out)
}

func (inProcWorker) RunStream(_ context.Context, _ worker.Identity, _ bool, op string, args, out any, data *os.File) error {
	defer func() { _ = data.Close() }()
	raw, _ := json.Marshal(args)
	var res any
	var err error
	switch op {
	case "fs.read":
		var a files.ReadArgs
		_ = json.Unmarshal(raw, &a)
		res, err = files.Read(a, data)
	case "fs.write":
		var a files.WriteArgs
		_ = json.Unmarshal(raw, &a)
		res, err = files.Write(a, &rpc.ChunkReader{R: data})
	default:
		return errors.New("unsupported op " + op)
	}
	if err != nil {
		return err
	}
	b, _ := json.Marshal(res)
	return json.Unmarshal(b, out)
}

// shValidator fails when the checked file contains "BAD".
func shValidator(pre bool) *Validator {
	return &Validator{Tool: "test-check", Pre: pre, Blocking: pre, bin: "/bin/sh",
		args: func(f string) []string {
			return []string{"-c", `if grep -q BAD "$0"; then echo "error in $0"; exit 1; fi`, f}
		}}
}

type saveEnv struct {
	f    *FileOps
	dir  string
	call Call
}

func newSaveEnv(t *testing.T, v *Validator) *saveEnv {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	state := t.TempDir()
	f := &FileOps{Worker: inProcWorker{}, StateDir: state,
		Versions: &VersionStore{Dir: filepath.Join(state, "versions"), Prefix: dir + "/"},
		Validate: func(string) *Validator { return v }}
	return &saveEnv{f: f, dir: dir, call: Call{Subject: &policy.Subject{AccountID: "acc1", Role: policy.RoleAdmin}, AuditKV: map[string]string{}}}
}

func (e *saveEnv) put(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(e.dir, name)
	if err := os.WriteFile(p, []byte(content), 0o640); err != nil {
		t.Fatal(err)
	}
	return sha256Hex([]byte(content))
}

func (e *saveEnv) save(t *testing.T, name, hash, content string, create, force bool) SaveResult {
	t.Helper()
	a := files.WriteArgs{Target: files.Target{Dir: e.dir, Name: name}, ExpectedHash: hash, Create: create}
	res, err := e.f.save(context.Background(), e.call, worker.Identity{}, false, a, force, []byte(content))
	if err != nil {
		t.Fatalf("save: %v", err)
	}
	return res
}

func (e *saveEnv) content(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(e.dir, name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestSaveKeepsPreviousVersion(t *testing.T) {
	e := newSaveEnv(t, nil)
	h := e.put(t, "app.conf", "one\n")
	res := e.save(t, "app.conf", h, "two\n", false, false)
	if !res.Saved || res.Version == "" || res.Validation != nil {
		t.Fatalf("result %+v", res)
	}
	p := filepath.Join(e.dir, "app.conf")
	vs, err := e.f.Versions.List(p)
	if err != nil || len(vs) != 1 || vs[0].ID != res.Version || vs[0].Account != "acc1" {
		t.Fatalf("versions %+v %v", vs, err)
	}
	_, data, err := e.f.Versions.Read(p, res.Version)
	if err != nil || string(data) != "one\n" {
		t.Fatalf("version content %q %v", data, err)
	}
	// Saving identical content stores no new version.
	if res2 := e.save(t, "app.conf", res.Hash, "two\n", false, false); res2.Version != "" {
		t.Fatalf("no-op save stored a version: %+v", res2)
	}
	// A failed save (stale hash) leaves no version behind.
	a := files.WriteArgs{Target: files.Target{Dir: e.dir, Name: "app.conf"}, ExpectedHash: h}
	if _, err := e.f.save(context.Background(), e.call, worker.Identity{}, false, a, false, []byte("three\n")); err == nil {
		t.Fatal("stale hash accepted")
	}
	if vs, _ := e.f.Versions.List(p); len(vs) != 1 {
		t.Fatalf("versions after conflict: %d", len(vs))
	}
}

func TestSavePostValidationRollsBack(t *testing.T) {
	e := newSaveEnv(t, shValidator(false))
	h := e.put(t, "nginx.conf", "good\n")
	res := e.save(t, "nginx.conf", h, "BAD\n", false, false)
	if res.Saved || res.Validation == nil || res.Validation.OK || !res.Validation.RolledBack {
		t.Fatalf("result %+v %+v", res, res.Validation)
	}
	if !strings.Contains(res.Validation.Output, "error in "+filepath.Join(e.dir, "nginx.conf")) {
		t.Fatalf("output %q", res.Validation.Output)
	}
	if got := e.content(t, "nginx.conf"); got != "good\n" {
		t.Fatalf("not rolled back: %q", got)
	}
	if res.Hash != h {
		t.Fatalf("hash after rollback %s, want %s", res.Hash, h)
	}
	if vs, _ := e.f.Versions.List(filepath.Join(e.dir, "nginx.conf")); len(vs) != 0 {
		t.Fatalf("rolled-back save kept a version: %+v", vs)
	}
	if e.call.AuditKV["rolled_back"] != "true" || e.call.AuditKV["saved"] != "false" {
		t.Fatalf("audit %v", e.call.AuditKV)
	}

	// "Save anyway" keeps the content.
	res = e.save(t, "nginx.conf", h, "BAD\n", false, true)
	if !res.Saved || res.Validation == nil || res.Validation.OK || res.Validation.RolledBack {
		t.Fatalf("forced result %+v %+v", res, res.Validation)
	}
	if got := e.content(t, "nginx.conf"); got != "BAD\n" {
		t.Fatalf("forced save lost: %q", got)
	}

	// A valid save passes.
	res = e.save(t, "nginx.conf", res.Hash, "fine\n", false, false)
	if !res.Saved || res.Validation == nil || !res.Validation.OK {
		t.Fatalf("valid result %+v", res)
	}
}

func TestSavePostValidationRemovesNewFile(t *testing.T) {
	e := newSaveEnv(t, shValidator(false))
	res := e.save(t, "new.conf", "", "BAD\n", true, false)
	if res.Saved || res.Validation == nil || !res.Validation.RolledBack {
		t.Fatalf("result %+v %+v", res, res.Validation)
	}
	if _, err := os.Stat(filepath.Join(e.dir, "new.conf")); !os.IsNotExist(err) {
		t.Fatalf("new file kept: %v", err)
	}
}

func TestSavePreValidationBlocks(t *testing.T) {
	e := newSaveEnv(t, shValidator(true))
	h := e.put(t, "sudoers", "ok\n")
	for _, force := range []bool{false, true} {
		res := e.save(t, "sudoers", h, "BAD\n", false, force)
		if res.Saved || res.Validation == nil || res.Validation.OK || !res.Validation.Blocking {
			t.Fatalf("force=%v result %+v", force, res)
		}
		// The private copy's path never shows up in the output.
		if strings.Contains(res.Validation.Output, "validate-") {
			t.Fatalf("output leaks temp path: %q", res.Validation.Output)
		}
		if got := e.content(t, "sudoers"); got != "ok\n" {
			t.Fatalf("blocked save written: %q", got)
		}
	}
	if ents, _ := os.ReadDir(filepath.Join(e.f.StateDir, "tmp")); len(ents) != 0 {
		t.Fatalf("temp copies left: %d", len(ents))
	}
	if res := e.save(t, "sudoers", h, "fine\n", false, false); !res.Saved {
		t.Fatalf("valid save refused: %+v", res)
	}
}

func TestSaveSkipsMissingValidator(t *testing.T) {
	v := shValidator(false)
	v.bin = "/nonexistent/check"
	e := newSaveEnv(t, v)
	h := e.put(t, "x.conf", "a\n")
	if res := e.save(t, "x.conf", h, "BAD\n", false, false); !res.Saved || res.Validation != nil {
		t.Fatalf("result %+v", res)
	}
}

func TestVersionStoreRetention(t *testing.T) {
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	s := &VersionStore{Dir: t.TempDir(), Now: func() time.Time { return now }}
	for i := range 25 {
		now = now.Add(time.Minute)
		if _, err := s.Save("/etc/x", []byte{byte('a' + i)}, ""); err != nil {
			t.Fatal(err)
		}
	}
	vs, err := s.List("/etc/x")
	if err != nil || len(vs) != VersionsKeep {
		t.Fatalf("kept %d %v", len(vs), err)
	}
	if _, data, _ := s.Read("/etc/x", vs[0].ID); string(data) != "y" {
		t.Fatalf("newest first: %q", data)
	}
	now = now.Add(VersionsMaxAge + time.Hour)
	if _, _, err := s.Read("/etc/x", vs[0].ID); err == nil {
		t.Fatal("expired version readable")
	}
	if vs, _ := s.List("/etc/x"); len(vs) != 0 {
		t.Fatalf("expired versions listed: %d", len(vs))
	}
	if _, _, err := s.Read("/etc/x", "../../etc/shadow"); err == nil {
		t.Fatal("invalid id accepted")
	}
}

func TestVersionStoreCovers(t *testing.T) {
	s := &VersionStore{}
	for p, want := range map[string]bool{
		"/etc/nginx/nginx.conf":             true,
		"/etc/fstab":                        true,
		"/etc/shadow":                       false,
		"/etc/ssh/ssh_host_ed25519_key":     false,
		"/home/pancake/notes.txt":           false,
		"/etcetera/x":                       false,
		"/etc/ssh/ssh_host_ed25519_key.pub": true,
	} {
		if got := s.Covers(p); got != want {
			t.Errorf("Covers(%s) = %v", p, got)
		}
	}
	if (*VersionStore)(nil).Covers("/etc/fstab") {
		t.Error("nil store covers")
	}
}

func TestValidatorFor(t *testing.T) {
	for p, want := range map[string]string{
		"/etc/ssh/sshd_config":                                    "sshd -t",
		"/etc/ssh/sshd_config.d/50-cloud-init.conf":               "sshd -t",
		"/etc/ssh/sshd_config.d/README":                           "",
		"/etc/ssh/ssh_config":                                     "",
		"/etc/sudoers":                                            "visudo -c",
		"/etc/sudoers.d/pancake":                                  "visudo -c",
		"/etc/nginx/nginx.conf":                                   "nginx -t",
		"/etc/nginx/sites-available/default":                      "nginx -t",
		"/etc/fstab":                                              "findmnt --verify",
		"/etc/systemd/system/app.service":                         "systemd-analyze verify",
		"/etc/systemd/system/backup.timer":                        "systemd-analyze verify",
		"/etc/systemd/system/app.service.d/x.conf":                "",
		"/etc/systemd/system/multi-user.target.wants/app.service": "systemd-analyze verify",
		"/home/pancake/sshd_config":                               "",
	} {
		v := ValidatorFor(p)
		got := ""
		if v != nil {
			got = v.Tool
		}
		if got != want {
			t.Errorf("ValidatorFor(%s) = %q, want %q", p, got, want)
		}
	}
	if v := ValidatorFor("/etc/sudoers"); !v.Pre || !v.Blocking {
		t.Error("sudoers must be checked before writing, without override")
	}
}

func TestCleanOutput(t *testing.T) {
	got := cleanOutput("line1\x1b[31m red\x07\n\tline2\xff\n")
	if got != "line1[31m red\n\tline2?" {
		t.Fatalf("got %q", got)
	}
	if long := cleanOutput(strings.Repeat("x", 10000)); len(long) > validateOutMax+4 {
		t.Fatalf("not capped: %d", len(long))
	}
}
