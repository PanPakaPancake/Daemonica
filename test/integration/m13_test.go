//go:build integration

package integration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/PanPakaPancake/daemonica/internal/helper"
	"github.com/PanPakaPancake/daemonica/internal/policy"
	"github.com/PanPakaPancake/daemonica/internal/rpc"
	"github.com/PanPakaPancake/daemonica/internal/worker"
)

const fsUser = "dmn-it13"

type fsEnv struct {
	t      *testing.T
	c      *rpc.Client
	grants *helper.GrantStore
	home   string
	uid    uint32
}

// grant issues a session for a subject (operator by default) mapped to fsUser.
func (e *fsEnv) grant(role policy.Role, stepUp bool) string {
	g, err := e.grants.Issue(policy.Subject{AccountID: string(role) + strconv.FormatBool(stepUp), Role: role,
		LinuxUser: fsUser, LinuxUID: e.uid}, time.Now())
	if err != nil {
		e.t.Fatal(err)
	}
	if stepUp {
		_ = e.grants.MarkStepUp(g, time.Now())
	}
	return g
}

func (e *fsEnv) call(grant, op string, p map[string]any, out any) string {
	return rpc.ErrorCode(e.c.Call(context.Background(), op, grant, "127.0.0.1", p, out))
}

func (e *fsEnv) upload(grant, dir, name string, body io.Reader, size int64, extra map[string]any) (map[string]any, string) {
	p := map[string]any{"dir": dir, "name": name, "size": size}
	for k, v := range extra {
		p[k] = v
	}
	var out map[string]any
	err := e.c.Upload(context.Background(), "fs.upload", grant, "127.0.0.1", p, body, nil, &out)
	return out, rpc.ErrorCode(err)
}

func (e *fsEnv) download(grant string, p map[string]any) ([]byte, string) {
	var b bytes.Buffer
	_, code := e.downloadTo(grant, p, &b)
	return b.Bytes(), code
}

func (e *fsEnv) downloadTo(grant string, p map[string]any, w io.Writer) (int64, string) {
	var tok struct {
		Token string `json:"token"`
	}
	if code := e.call(grant, "fs.download_token", p, &tok); code != "" {
		return 0, code
	}
	ds, err := e.c.Download(context.Background(), "fs.download", grant, "127.0.0.1", map[string]any{"token": tok.Token}, nil)
	if err != nil {
		return 0, rpc.ErrorCode(err)
	}
	defer func() { _ = ds.Close() }()
	n, err := io.Copy(w, ds)
	if err != nil {
		return n, "read"
	}
	return n, rpc.ErrorCode(ds.Finish(nil))
}

func newFSEnv(t *testing.T, uploadMiB int) *fsEnv {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	_ = exec.Command("/usr/sbin/userdel", "--remove", "--", fsUser).Run()
	if out, err := exec.Command("/usr/sbin/useradd", "--create-home", "--user-group", "--", fsUser).CombinedOutput(); err != nil {
		t.Fatalf("useradd: %v %s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("/usr/sbin/userdel", "--remove", "--", fsUser).Run() })
	id, err := worker.Lookup(fsUser)
	if err != nil {
		t.Fatal(err)
	}
	ops := map[string]*helper.Op{}
	state := t.TempDir()
	(&helper.FileOps{Worker: &worker.Runner{Timeout: 5 * time.Minute}, Lookup: worker.Lookup,
		UploadMiB: func() int { return uploadMiB },
		Versions:  &helper.VersionStore{Dir: filepath.Join(state, "versions")}, StateDir: state}).Register(ops)
	gs := helper.NewGrantStore(30*time.Minute, 12*time.Hour)
	sock := filepath.Join(t.TempDir(), "h.sock")
	l, err := helper.ListenUnix(sock, 0o600, -1)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	srv := &helper.Server{Channel: helper.ChannelWeb, AllowedUID: 0, Ops: ops, Grants: gs,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	go func() { _ = srv.Serve(ctx, l) }()
	return &fsEnv{t: t, c: &rpc.Client{Socket: sock, Timeout: time.Minute}, grants: gs, home: id.Home, uid: id.UID}
}

func TestFileManagerEndToEnd(t *testing.T) {
	e := newFSEnv(t, 1)
	op := e.grant(policy.RoleOperator, false)

	// Upload within the limit, as the mapped user; over the limit is refused.
	data := bytes.Repeat([]byte("daemonica\n"), 60_000)
	res, code := e.upload(op, e.home, "up.txt", bytes.NewReader(data), int64(len(data)), nil)
	if code != "" {
		t.Fatalf("upload: %s", code)
	}
	sum := sha256.Sum256(data)
	if res["sha256"] != hex.EncodeToString(sum[:]) {
		t.Fatalf("upload result %v", res)
	}
	fi, err := os.Stat(filepath.Join(e.home, "up.txt"))
	if err != nil || fi.Mode().Perm() != 0o640 {
		t.Fatalf("stored: %v %v", fi, err)
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); !ok || st.Uid != e.uid {
		t.Fatalf("upload not owned by the mapped user: %+v", fi.Sys())
	}
	big := bytes.Repeat([]byte("x"), 3<<20)
	if _, code := e.upload(op, e.home, "big", bytes.NewReader(big), int64(len(big)), nil); code != "too_large" {
		t.Fatalf("declared too large: %s", code)
	}
	if _, code := e.upload(op, e.home, "big", bytes.NewReader(big), 10, nil); code != "too_large" {
		t.Fatalf("lying about size: %s", code)
	}
	if _, err := os.Stat(filepath.Join(e.home, "big")); !os.IsNotExist(err) {
		t.Fatal("oversized upload left a file")
	}
	if _, code := e.upload(op, e.home, "up.txt", bytes.NewReader(data), int64(len(data)), nil); code != "already_exists" {
		t.Fatalf("overwrite without confirmation: %s", code)
	}

	// Download (full) and one-time token.
	got, code := e.download(op, map[string]any{"dir": e.home, "name": "up.txt"})
	if code != "" || !bytes.Equal(got, data) {
		t.Fatalf("download: %s (%d bytes)", code, len(got))
	}
	var tok struct {
		Token string `json:"token"`
	}
	e.call(op, "fs.download_token", map[string]any{"dir": e.home, "name": "up.txt"}, &tok)
	other := e.grant(policy.RoleAdmin, false)
	if _, err := e.c.Download(context.Background(), "fs.download", other, "", map[string]any{"token": tok.Token}, nil); rpc.ErrorCode(err) != "token_invalid" {
		t.Fatalf("token from another session: %v", err)
	}
	if _, err := e.c.Download(context.Background(), "fs.download", op, "", map[string]any{"token": tok.Token}, nil); rpc.ErrorCode(err) != "token_invalid" {
		t.Fatalf("token reuse: %v", err)
	}

	// Editor round trip with conflict detection.
	var rd map[string]any
	ds, err := e.c.Download(context.Background(), "fs.read", op, "", map[string]any{"dir": e.home, "name": "up.txt"}, &rd)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, ds)
	_ = ds.Finish(nil)
	_ = ds.Close()
	hash, _ := rd["hash"].(string)
	var wr map[string]any
	if err := e.c.Upload(context.Background(), "fs.write", op, "", map[string]any{"dir": e.home, "name": "up.txt", "expected_hash": hash},
		bytes.NewReader([]byte("edited\n")), nil, &wr); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := e.c.Upload(context.Background(), "fs.write", op, "", map[string]any{"dir": e.home, "name": "up.txt", "expected_hash": hash},
		bytes.NewReader([]byte("again\n")), nil, nil); rpc.ErrorCode(err) != "conflict" {
		t.Fatalf("stale write: %v", err)
	}

	// Linux permissions are the boundary for the mapped user.
	if code := e.call(op, "fs.create", map[string]any{"dir": "/etc", "name": "dmn-it13", "kind": "file"}, nil); code != "permission_denied" {
		t.Fatalf("create in /etc: %s", code)
	}
	opSU := e.grant(policy.RoleOperator, true)
	if code := e.call(opSU, "fs.download_token", map[string]any{"dir": "/etc", "name": "shadow", "confirm_sensitive": true}, nil); code != "permission_denied" {
		t.Fatalf("shadow as user: %s", code)
	}
	// The browser cannot smuggle the worker permit.
	if code := e.call(op, "fs.download_token", map[string]any{"dir": "/etc", "name": "shadow", "sensitive_ok": true}, nil); code != "bad_request" && code != "sensitive_path" {
		t.Fatalf("smuggled permit: %s", code)
	}

	// Root mode: operators never; admins only after enabling it (step-up).
	if code := e.call(op, "fs.list", map[string]any{"path": "/root", "as_root": true}, nil); code != "forbidden" {
		t.Fatalf("operator as root: %s", code)
	}
	adm := e.grant(policy.RoleAdmin, false)
	if code := e.call(adm, "fs.list", map[string]any{"path": "/root", "as_root": true}, nil); code != "root_mode_required" {
		t.Fatalf("admin without root mode: %s", code)
	}
	if code := e.call(adm, "fs.root_enable", nil, nil); code != "" {
		// Policy (step-up) is enforced by the server's authorize step.
		if code != "step_up_required" {
			t.Fatalf("root_enable without step-up: %s", code)
		}
	}
	admSU := e.grant(policy.RoleAdmin, true)
	if code := e.call(admSU, "fs.root_enable", nil, nil); code != "" {
		t.Fatalf("root_enable: %s", code)
	}
	if code := e.call(admSU, "fs.list", map[string]any{"path": "/root", "as_root": true}, nil); code != "" {
		t.Fatalf("list /root as root: %s", code)
	}
	// Sensitive paths need the confirmation (and the step-up of this session).
	if code := e.call(admSU, "fs.download_token", map[string]any{"dir": "/etc", "name": "shadow", "as_root": true}, nil); code != "sensitive_path" {
		t.Fatalf("shadow unconfirmed: %s", code)
	}
	if code := e.call(admSU, "fs.download_token", map[string]any{"dir": "/etc", "name": "shadow", "as_root": true, "confirm_sensitive": true}, nil); code != "" {
		t.Fatalf("shadow confirmed as root: %s", code)
	}
	if code := e.call(admSU, "fs.list", map[string]any{"path": "/var/lib/daemonica-helper", "as_root": true}, nil); code != "path_blocked" && code != "not_found" {
		t.Fatalf("blocked path as root: %s", code)
	}
	if code := e.call(admSU, "fs.delete", map[string]any{"dir": "/", "name": "home", "recursive": true, "confirm": "home", "as_root": true}, nil); code != "protected_path" {
		t.Fatalf("delete /home: %s", code)
	}
	if code := e.call(admSU, "fs.chown", map[string]any{"dir": e.home, "name": "up.txt", "user": "root"}, nil); code != "root_mode_required" {
		t.Fatalf("chown outside root mode: %s", code)
	}
	if code := e.call(admSU, "fs.chown", map[string]any{"dir": e.home, "name": "up.txt", "user": "root", "as_root": true}, nil); code != "" {
		t.Fatalf("chown as root: %s", code)
	}
	if code := e.call(admSU, "fs.delete", map[string]any{"dir": e.home, "name": ".cache", "recursive": true, "confirm": "wrong"}, nil); code != "validation_failed" {
		t.Fatalf("recursive delete without typed confirmation: %s", code)
	}
}

// TestSymlinkRaceRootMode swaps a directory for a symlink to /etc while the
// admin writes into it in root mode: nothing may ever land in /etc.
func TestSymlinkRaceRootMode(t *testing.T) {
	e := newFSEnv(t, 1)
	adm := e.grant(policy.RoleAdmin, true)
	if code := e.call(adm, "fs.root_enable", nil, nil); code != "" {
		t.Fatal(code)
	}
	d := filepath.Join(e.home, "d")
	_ = os.Mkdir(d, 0o755)
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
			}
			_ = os.Rename(d, d+".real")
			_ = os.Symlink("/etc", d)
			_ = os.Remove(d)
			_ = os.Rename(d+".real", d)
		}
	}()
	for i := range 150 {
		name := fmt.Sprintf("dmn-race-%d", i)
		e.call(adm, "fs.create", map[string]any{"dir": d, "name": name, "kind": "file", "as_root": true}, nil)
		_, _ = e.upload(adm, d, name+".u", bytes.NewReader([]byte("x")), 1, map[string]any{"as_root": true})
	}
	close(stop)
	<-done
	matches, _ := filepath.Glob("/etc/dmn-race-*")
	if len(matches) > 0 {
		for _, m := range matches {
			_ = os.Remove(m)
		}
		t.Fatalf("symlink race wrote into /etc: %v", matches)
	}
}

// TestLargeUploadStreams checks that a large upload is streamed (no RAM spike).
func TestLargeUploadStreams(t *testing.T) {
	e := newFSEnv(t, 1024)
	op := e.grant(policy.RoleOperator, false)
	const size = 512 << 20
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	src := io.LimitReader(zeroReader{}, size)
	res, code := e.upload(op, e.home, "large.bin", src, size, nil)
	runtime.ReadMemStats(&after)
	if code != "" {
		t.Fatalf("large upload: %s", code)
	}
	if n, _ := res["size"].(float64); int64(n) != size {
		t.Fatalf("size %v", res["size"])
	}
	if grow := int64(after.HeapSys) - int64(before.HeapSys); grow > 64<<20 {
		t.Fatalf("heap grew by %d MiB during a %d MiB upload", grow>>20, size>>20)
	}
	n, code := e.downloadTo(op, map[string]any{"dir": e.home, "name": "large.bin"}, io.Discard)
	if code != "" || n != size {
		t.Fatalf("large download: %s %d", code, n)
	}
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}
