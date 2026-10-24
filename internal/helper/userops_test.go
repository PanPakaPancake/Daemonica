package helper

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PanPakaPancake/daemonica/internal/policy"
	"github.com/PanPakaPancake/daemonica/internal/rpc"
	"github.com/PanPakaPancake/daemonica/internal/users"
)

type call struct {
	stdin string
	argv  string
}

func userEnv(t *testing.T) (*UserOps, map[string]*Op, *[]call) {
	t.Helper()
	root := t.TempDir()
	for p, c := range map[string]string{
		"etc/passwd":     "root:x:0:0:root:/root:/bin/bash\nsshd:x:105:65534::/run/sshd:/usr/sbin/nologin\npancake:x:1000:1000::/home/pancake:/bin/bash\nbob:x:1001:1001::/home/bob:/bin/bash\n",
		"etc/group":      "root:x:0:\nsudo:x:27:pancake\npancake:x:1000:\nbob:x:1001:\ndev:x:1002:bob\n",
		"etc/shadow":     "pancake:!:20000:0:99999:7:::\nbob:$y$x:20000:0:99999:7:::\n",
		"etc/login.defs": "UID_MIN 1000\nUID_MAX 60000\n",
		"etc/shells":     "/bin/bash\n",
	} {
		full := filepath.Join(root, p)
		_ = os.MkdirAll(filepath.Dir(full), 0o755)
		_ = os.WriteFile(full, []byte(c), 0o644)
	}
	db, err := OpenDB(context.Background(), filepath.Join(t.TempDir(), "a.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.CreateAccount(context.Background(), "Pancake", policy.RoleAdmin, "pancake", 1000, nil, nowFn()); err != nil {
		t.Fatal(err)
	}
	var calls []call
	u := &UserOps{DB: users.DB{Root: root}, Accts: db, Run: func(_ context.Context, stdin []byte, path string, args ...string) error {
		calls = append(calls, call{string(stdin), filepath.Base(path) + " " + strings.Join(args, " ")})
		return nil
	}}
	ops := map[string]*Op{}
	u.Register(ops)
	return u, ops, &calls
}

func runOp(ops map[string]*Op, name string, params any) error {
	s := policy.Subject{AccountID: "x", Role: policy.RoleAdmin, LinuxUID: 1000, StepUp: true}
	_, err := ops[name].Handle(context.Background(), Call{Subject: &s, Params: mustJSON(params)})
	return err
}

func TestUserOpsProtections(t *testing.T) {
	_, ops, calls := userEnv(t)
	tr, fa := true, false
	cases := []struct {
		op     string
		params map[string]any
		want   string
	}{
		{"users.delete", map[string]any{"name": "root", "confirm_name": "root", "confirm_mapped": true}, rpc.CodeLockout},
		{"users.set_locked", map[string]any{"name": "root", "locked": tr}, rpc.CodeLockout},
		{"users.delete", map[string]any{"name": "bob", "confirm_name": "bobx"}, rpc.CodeValidation},
		{"users.delete", map[string]any{"name": "pancake", "confirm_name": "pancake"}, rpc.CodeLockout},
		{"users.set_sudo", map[string]any{"name": "pancake", "sudo": fa}, rpc.CodeLockout},
		{"users.update", map[string]any{"name": "sshd", "shell": "/bin/bash"}, rpc.CodeValidation},
		{"users.update", map[string]any{"name": "bob", "set_groups": true, "groups": []string{"sudo"}}, rpc.CodeValidation},
		{"users.update", map[string]any{"name": "bob", "shell": "/bin/zsh"}, rpc.CodeValidation},
		{"users.set_password", map[string]any{"name": "bob", "password": "short"}, rpc.CodeValidation},
		{"users.set_password", map[string]any{"name": "bob", "password": "longenough123\nroot:x"}, rpc.CodeValidation},
		{"groups.set_members", map[string]any{"name": "sudo", "members": []string{"bob"}}, rpc.CodeValidation},
		{"groups.delete", map[string]any{"name": "sudo", "confirm_name": "sudo"}, rpc.CodeLockout},
		{"users.create", map[string]any{"name": "--help"}, rpc.CodeValidation},
	}
	for _, c := range cases {
		if got := errCode(runOp(ops, c.op, c.params)); got != c.want {
			t.Errorf("%s %v: got %q want %q", c.op, c.params, got, c.want)
		}
	}
	if len(*calls) != 0 {
		t.Fatalf("refused operations executed tools: %v", *calls)
	}
}

func TestUserOpsCommands(t *testing.T) {
	_, ops, calls := userEnv(t)
	tr, fa := true, false
	steps := []struct {
		op     string
		params map[string]any
		argv   string
	}{
		{"users.create", map[string]any{"name": "alice", "create_home": true}, "useradd --user-group --create-home --shell /bin/bash -- alice"},
		{"users.set_locked", map[string]any{"name": "bob", "locked": tr}, "usermod --lock --expiredate 1 -- bob"},
		{"users.set_sudo", map[string]any{"name": "bob", "sudo": tr}, "gpasswd --add bob sudo"},
		{"users.set_sudo", map[string]any{"name": "pancake", "sudo": fa, "confirm_mapped": true}, "gpasswd --delete pancake sudo"},
		{"users.update", map[string]any{"name": "bob", "set_groups": true, "groups": []string{"dev"}, "expires": "2027-01-31"}, "usermod --groups dev --expiredate 2027-01-31 -- bob"},
		{"users.delete", map[string]any{"name": "bob", "confirm_name": "bob", "remove_home": true}, "userdel --remove -- bob"},
		{"groups.set_members", map[string]any{"name": "dev", "members": []string{"bob", "pancake"}}, "gpasswd --members bob,pancake dev"},
	}
	for _, s := range steps {
		*calls = nil
		if err := runOp(ops, s.op, s.params); err != nil {
			t.Fatalf("%s: %v", s.op, err)
		}
		if len(*calls) == 0 || (*calls)[0].argv != s.argv {
			t.Fatalf("%s: argv %v want %q", s.op, *calls, s.argv)
		}
	}
	*calls = nil
	if err := runOp(ops, "users.set_password", map[string]any{"name": "bob", "password": "correct horse battery", "force_change": true}); err != nil {
		t.Fatal(err)
	}
	if (*calls)[0].argv != "chpasswd " || (*calls)[0].stdin != "bob:correct horse battery\n" || (*calls)[1].argv != "chage --lastday 0 -- bob" {
		t.Fatalf("password calls %v", *calls)
	}
}
