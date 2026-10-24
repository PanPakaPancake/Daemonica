package helper

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/PanPakaPancake/daemonica/internal/journal"
	"github.com/PanPakaPancake/daemonica/internal/policy"
	"github.com/PanPakaPancake/daemonica/internal/rpc"
	"github.com/PanPakaPancake/daemonica/internal/services"
	"github.com/PanPakaPancake/daemonica/internal/sysinfo"
)

func errCode(err error) string {
	var oe *OpError
	if errors.As(err, &oe) {
		return oe.Code
	}
	return ""
}

func TestServiceDecisionMatrix(t *testing.T) {
	admin := policy.Subject{AccountID: "a", Role: policy.RoleAdmin, LinuxUID: 1000}
	adminSU := admin
	adminSU.StepUp = true
	op := policy.Subject{AccountID: "o", Role: policy.RoleOperator, LinuxUID: 1001, StepUp: true}
	ro := policy.Subject{AccountID: "r", Role: policy.RoleReadOnly, LinuxUID: 1002, StepUp: true}
	cases := []struct {
		s            policy.Subject
		unit, action string
		confirm      bool
		want         string
	}{
		{admin, "nginx.service", "restart", false, ""},
		{op, "nginx.service", "stop", false, ""},
		{ro, "nginx.service", "start", false, rpc.CodeForbidden},
		{op, "nginx.service", "enable", false, rpc.CodeForbidden},
		{admin, "nginx.service", "disable", false, rpc.CodeStepUpNeeded},
		{adminSU, "nginx.service", "mask", false, ""},
		{op, "ssh.service", "restart", false, rpc.CodeForbidden},
		{admin, "ssh.service", "restart", false, rpc.CodeStepUpNeeded},
		{adminSU, "systemd-resolved.service", "restart", false, ""},
		{adminSU, "daemonica-helper.service", "stop", true, rpc.CodeLockout},
		{adminSU, "daemonica-helper.service", "mask", true, rpc.CodeLockout},
		{adminSU, "daemonica-helper.service", "restart", false, ""},
		{adminSU, "daemonica-web.service", "stop", false, rpc.CodeLockout},
		{adminSU, "daemonica-web.service", "stop", true, ""},
	}
	for _, c := range cases {
		got := errCode(serviceDecision(c.s, c.unit, c.action, c.confirm))
		if got != c.want {
			t.Errorf("%s %s %s confirm=%v: got %q want %q", c.s.Role, c.unit, c.action, c.confirm, got, c.want)
		}
	}
}

func TestProcSignalRules(t *testing.T) {
	root := t.TempDir()
	write := func(p, c string) {
		full := filepath.Join(root, p)
		_ = os.MkdirAll(filepath.Dir(full), 0o755)
		_ = os.WriteFile(full, []byte(c), 0o644)
	}
	write("proc/stat", "cpu  1 0 0 0 0 0 0 0\nbtime 1700000000\n")
	write("etc/passwd", "root:x:0:0::/root:/bin/bash\nbob:x:1001:1001::/home/bob:/bin/bash\n")
	proc := func(pid int, comm string, ppid int, uid int) {
		d := "proc/" + strconv.Itoa(pid) + "/"
		write(d+"stat", strconv.Itoa(pid)+" ("+comm+") S "+strconv.Itoa(ppid)+" 1 1 0 -1 0 0 0 0 0 1 1 0 0 20 0 1 0 100 0 0")
		write(d+"status", "Uid:\t"+strconv.Itoa(uid)+"\t0\t0\t0\n")
		write(d+"statm", "1 1 0 0 0 0 0")
	}
	proc(1, "systemd", 0, 0)
	proc(500, "sshd", 1, 0)
	proc(600, "daemonica-web", 1, 103)
	proc(700, "sleep", 500, 1001)
	proc(800, "cron", 1, 0)
	fs := sysinfo.FS{Root: root}
	start := fs.BootTime().Add(time.Second).UTC()
	var killed []int
	s := &SysOps{Collector: &sysinfo.Collector{FS: fs}, SelfPID: 999,
		Kill: func(pid int, _ syscall.Signal) error { killed = append(killed, pid); return nil }}
	ops := map[string]*Op{}
	s.Register(ops)
	call := func(subj policy.Subject, pid int, st time.Time, sig string) string {
		_, err := ops["proc.signal"].Handle(context.Background(), Call{Subject: &subj,
			Params: mustJSON(map[string]any{"pid": pid, "start": st, "signal": sig})})
		return errCode(err)
	}
	admin := policy.Subject{AccountID: "a", Role: policy.RoleAdmin, LinuxUID: 1000}
	bob := policy.Subject{AccountID: "b", Role: policy.RoleOperator, LinuxUID: 1001}
	for _, pid := range []int{1, 500, 600} {
		if got := call(admin, pid, start, "TERM"); got != rpc.CodeLockout {
			t.Errorf("pid %d must be protected, got %q", pid, got)
		}
	}
	if got := call(bob, 800, start, "TERM"); got != rpc.CodeForbidden {
		t.Errorf("operator signalled foreign process: %q", got)
	}
	if got := call(bob, 700, start, "SEGV"); got != rpc.CodeValidation {
		t.Errorf("non-allowlisted signal accepted: %q", got)
	}
	if got := call(bob, 700, start.Add(time.Hour), "TERM"); got != rpc.CodeConflict {
		t.Errorf("PID reuse not detected: %q", got)
	}
	if got := call(bob, 700, start, "TERM"); got != "" {
		t.Errorf("own process: %q", got)
	}
	if got := call(admin, 800, start, "HUP"); got != "" {
		t.Errorf("admin HUP cron: %q", got)
	}
	if len(killed) != 2 || killed[0] != 700 || killed[1] != 800 {
		t.Fatalf("killed %v", killed)
	}
}

func TestJournalQueryValidation(t *testing.T) {
	var got journal.Query
	l := &LogOps{Run: func(_ context.Context, q journal.Query) (journal.Result, error) {
		got = q
		return journal.Result{}, nil
	}}
	ops := map[string]*Op{}
	l.Register(ops)
	subj := policy.Subject{AccountID: "a", Role: policy.RoleAdmin, LinuxUID: 1000}
	if _, err := ops["journal.query"].Handle(context.Background(), Call{Subject: &subj, Params: mustJSON(map[string]any{"unit": "--all"})}); errCode(err) != rpc.CodeValidation {
		t.Fatal("option injection via unit accepted")
	}
	res, err := ops["journal.query"].Handle(context.Background(), Call{Subject: &subj, Params: mustJSON(map[string]any{"unit": "ssh.service", "lines": 10})})
	if err != nil || got.Unit != "ssh.service" {
		t.Fatalf("query: %v %+v", err, got)
	}
	if r := res.(journal.Result); r.Entries == nil {
		t.Fatal("entries must be an empty array, not null")
	}
	if policy.Decide(policy.Subject{Role: policy.RoleReadOnly}, ops["journal.query"].Action, 0, false) != policy.Deny {
		t.Fatal("read-only must not read logs (Annex A)")
	}
}

func TestProtectionClasses(t *testing.T) {
	for name, want := range map[string]int{
		"daemonica-helper.service": services.ProtHelper, "daemonica-web.service": services.ProtSelf,
		"ssh.socket": services.ProtNormal, "systemd-journald.service": services.ProtNormal, "nginx.service": services.ProtNone,
	} {
		if services.Protection(name) != want {
			t.Errorf("%s", name)
		}
	}
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}
