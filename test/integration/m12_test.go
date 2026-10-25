//go:build integration

package integration

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/PanPakaPancake/daemonica/internal/execx"
	"github.com/PanPakaPancake/daemonica/internal/files"
	"github.com/PanPakaPancake/daemonica/internal/helper"
	"github.com/PanPakaPancake/daemonica/internal/policy"
	"github.com/PanPakaPancake/daemonica/internal/sshkeys"
	"github.com/PanPakaPancake/daemonica/internal/users"
	"github.com/PanPakaPancake/daemonica/internal/worker"
)

// The test binary doubles as the worker (like daemonica-helper does).
func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == execx.UmaskArg {
		execx.LauncherMain(os.Args[2:])
	}
	if len(os.Args) > 1 && os.Args[1] == worker.Arg {
		h := sshkeys.WorkerHandlers()
		for k, v := range files.WorkerHandlers() {
			h[k] = v
		}
		worker.Main(h)
	}
	os.Exit(m.Run())
}

const testUser = "dmn-ittest"

func edLine(c string) string {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	w := func(b []byte) []byte {
		var l [4]byte
		binary.BigEndian.PutUint32(l[:], uint32(len(b)))
		return append(l[:], b...)
	}
	return "ssh-ed25519 " + base64.StdEncoding.EncodeToString(append(w([]byte("ssh-ed25519")), w(pub)...)) + " " + c
}

func TestUsersAndKeysOnHost(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	_ = exec.Command("/usr/sbin/userdel", "--remove", "--", testUser).Run()
	ops := map[string]*helper.Op{}
	uo := &helper.UserOps{DB: users.DB{Root: "/"}}
	uo.Register(ops)
	ko := &helper.SSHKeyOps{Worker: &worker.Runner{Timeout: 20 * time.Second}, Lookup: worker.Lookup, Config: sshkeys.EffectiveConfig, HostKeyDir: "/etc/ssh"}
	ko.Register(ops)
	admin := policy.Subject{AccountID: "it", Role: policy.RoleAdmin, LinuxUID: 999999, StepUp: true}
	run := func(op string, p map[string]any) (any, error) {
		return ops[op].Handle(context.Background(), helper.Call{Subject: &admin, Params: mustJSON(p)})
	}

	if _, err := run("users.create", map[string]any{"name": testUser, "create_home": true}); err != nil {
		t.Fatalf("create: %v", err)
	}
	defer func() {
		_, _ = run("users.delete", map[string]any{"name": testUser, "confirm_name": testUser, "remove_home": true})
	}()

	l1, err := run("sshkeys.list", map[string]any{"user": testUser})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if kl := l1.(helper.KeyListing); kl.WritePath != ".ssh/authorized_keys" || len(kl.Keys) != 0 {
		t.Fatalf("listing %+v", kl)
	}
	line := edLine("it@test")
	res, err := run("sshkeys.add", map[string]any{"user": testUser, "key": line, "options": []string{"restrict", `from="10.0.0.0/8"`}})
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	kl := res.(helper.KeyListing)
	if len(kl.Keys) != 1 || len(kl.Problems) != 0 {
		t.Fatalf("after add %+v", kl)
	}
	home := "/home/" + testUser
	fi, _ := os.Stat(filepath.Join(home, ".ssh/authorized_keys"))
	st := fi.Sys().(*syscall.Stat_t)
	di, _ := os.Stat(filepath.Join(home, ".ssh"))
	if fi.Mode().Perm() != 0o600 || di.Mode().Perm() != 0o700 || st.Uid == 0 {
		t.Fatalf("file mode %v dir %v uid %d", fi.Mode().Perm(), di.Mode().Perm(), st.Uid)
	}
	b, _ := os.ReadFile(filepath.Join(home, ".ssh/authorized_keys"))
	if !strings.HasPrefix(string(b), `restrict,from="10.0.0.0/8" ssh-ed25519 `) {
		t.Fatalf("content %q", b)
	}

	// Break permissions and owner, then repair.
	_ = os.Chmod(filepath.Join(home, ".ssh/authorized_keys"), 0o644)
	_ = os.Chown(filepath.Join(home, ".ssh"), 0, 0)
	_ = os.Chmod(filepath.Join(home, ".ssh"), 0o755)
	l2, _ := run("sshkeys.list", map[string]any{"user": testUser})
	if len(l2.(helper.KeyListing).Problems) == 0 {
		t.Fatal("broken permissions not reported")
	}
	if _, err := run("sshkeys.fix_permissions", map[string]any{"user": testUser}); err != nil {
		t.Fatalf("fix: %v", err)
	}
	l3, _ := run("sshkeys.list", map[string]any{"user": testUser})
	if p := l3.(helper.KeyListing).Problems; len(p) != 0 {
		t.Fatalf("problems after fix: %v", p)
	}

	// Symlink attack: authorized_keys → /etc/shadow must not be followed by writes.
	ak := filepath.Join(home, ".ssh/authorized_keys")
	_ = os.Remove(ak)
	_ = os.Symlink("/etc/shadow", ak)
	before, _ := os.ReadFile("/etc/shadow")
	if _, err := run("sshkeys.add", map[string]any{"user": testUser, "key": edLine("evil")}); err == nil {
		t.Fatal("write through symlink accepted")
	}
	if _, err := run("sshkeys.fix_permissions", map[string]any{"user": testUser}); err != nil {
		t.Logf("fix with symlink: %v (expected refusal or skip)", err)
	}
	after, _ := os.ReadFile("/etc/shadow")
	sfi, _ := os.Stat("/etc/shadow")
	if string(before) != string(after) || sfi.Mode().Perm() != 0o640 {
		t.Fatalf("/etc/shadow touched! mode=%v", sfi.Mode().Perm())
	}
	_ = os.Remove(ak)

	// Lock and sudo.
	tr := true
	if _, err := run("users.set_locked", map[string]any{"name": testUser, "locked": tr}); err != nil {
		t.Fatalf("lock: %v", err)
	}
	us, _, _ := users.DB{Root: "/"}.List(time.Now())
	for _, u := range us {
		if u.Name == testUser && (!u.Locked || !u.Expired) {
			t.Fatalf("lock not effective: %+v", u)
		}
	}
	if _, err := run("users.set_password", map[string]any{"name": testUser, "password": "a-very-long-test-passphrase", "force_change": true}); err != nil {
		t.Fatalf("password: %v", err)
	}
	srv, err := run("sshkeys.server", map[string]any{})
	if err != nil || len(srv.(map[string]any)["host_keys"].([]sshkeys.HostKey)) == 0 {
		t.Fatalf("server info: %v", err)
	}
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}
