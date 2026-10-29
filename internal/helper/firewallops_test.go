package helper

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PanPakaPancake/daemonica/internal/execx"
	"github.com/PanPakaPancake/daemonica/internal/firewall"
	"github.com/PanPakaPancake/daemonica/internal/journal"
	"github.com/PanPakaPancake/daemonica/internal/netcfg"
	"github.com/PanPakaPancake/daemonica/internal/planner"
	"github.com/PanPakaPancake/daemonica/internal/policy"
	"github.com/PanPakaPancake/daemonica/internal/rpc"
)

// fakeUfw answers ufw status from the enable/disable calls it saw.
type fakeUfw struct {
	mu     sync.Mutex
	active bool
	calls  []string
}

func (f *fakeUfw) run(_ context.Context, _ time.Duration, path string, args ...string) (execx.Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	cmd := path + " " + strings.Join(args, " ")
	f.calls = append(f.calls, cmd)
	switch {
	case cmd == "/usr/sbin/ufw status":
		if f.active {
			return execx.Result{Stdout: []byte("Status: active\n")}, nil
		}
		return execx.Result{Stdout: []byte("Status: inactive\n")}, nil
	case cmd == "/usr/sbin/ufw --force enable":
		f.active = true
	case cmd == "/usr/sbin/ufw disable" || cmd == "/usr/sbin/ufw --force disable":
		f.active = false
	case path == "/usr/sbin/sshd":
		return execx.Result{Stdout: []byte("port 22\nport 2222\n")}, nil
	}
	return execx.Result{}, nil
}

func (f *fakeUfw) count(cmd string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.calls {
		if c == cmd {
			n++
		}
	}
	return n
}

const fwRules = "*filter\n### RULES ###\n\n### tuple ### allow tcp 2222 0.0.0.0/0 any 0.0.0.0/0 in\n-A ufw-user-input -p tcp --dport 2222 -j ACCEPT\n\n### END RULES ###\n"

func TestFirewallPlanEnable(t *testing.T) {
	e := newAuthEnv(t)
	g, sa, _ := setupAdmin(t, e)
	root := t.TempDir()
	files := map[string]string{"/usr/sbin/ufw": "", "/etc/ufw/user.rules": fwRules, "/etc/ufw/user6.rules": "*filter\n### RULES ###\n### END RULES ###\n",
		"/etc/ufw/ufw.conf": "ENABLED=no\nLOGLEVEL=low\n", "/etc/default/ufw": "IPV6=yes\nDEFAULT_INPUT_POLICY=\"DROP\"\nDEFAULT_OUTPUT_POLICY=\"ACCEPT\"\n"}
	for p, s := range files {
		full := filepath.Join(root, p)
		_ = os.MkdirAll(filepath.Dir(full), 0o755)
		if err := os.WriteFile(full, []byte(s), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	fu := &fakeUfw{}
	pm, err := planner.New(filepath.Join(e.dir, "journal"), 300*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	ufw := &firewall.Ufw{Root: root, Run: fu.run}
	pm.Register(&firewall.Handler{Ufw: ufw})
	st := netcfg.State{Hostname: "daemonica",
		Interfaces: []netcfg.Interface{{Name: "lo", Kind: "loopback"}, {Name: "eth0", Kind: "ethernet", Addresses: []string{"203.0.113.10/24"}}},
		Routes:     []netcfg.Route{{Family: 4, To: "default", Via: "203.0.113.1", Dev: "eth0"}},
	}
	(&FirewallOps{Ufw: ufw, Detector: &firewall.Detector{Root: root, Run: fu.run}, Net: fakeNet{st}, Config: e.cfg, Planner: pm, Run: fu.run}).Register(e.web.Ops)
	(&SettingsOps{Config: e.cfg, Planner: pm}).Register(e.web.Ops)
	const me = "198.51.100.7"

	r := e.callFrom(me, "firewall.get", g, nil)
	mustOK(t, r, "get")
	var v FirewallView
	_ = json.Unmarshal(r.Result, &v)
	if v.Backend != "ufw" || !v.Managed || v.Active || v.Light != "red" || v.Hints[0].Code != "inactive" || len(v.Config.Rules) != 1 ||
		len(v.SSHPorts) != 2 || v.SessionIface != "eth0" || len(v.Reach) != 1 {
		t.Fatalf("view: %+v", v)
	}

	plan := func(op firewall.Op, ack bool, name string) *rpc.Response {
		return e.callFrom(me, "firewall.plan", g, map[string]any{"op": op, "confirm_lockout": ack, "confirm_name": name})
	}
	if code(plan(firewall.Op{Kind: "enable"}, false, "")) != rpc.CodeStepUpNeeded {
		t.Fatal("plan without step-up")
	}
	g = stepUp(t, e, sa, g)
	// The allowlist holds only loopback, so the dashboard port gets no rule and
	// the caller (connected from outside) would be locked out.
	r = plan(firewall.Op{Kind: "enable"}, false, "")
	mustOK(t, r, "enable without ack")
	var pv FirewallPlanView
	_ = json.Unmarshal(r.Result, &pv)
	if !pv.Blocked || pv.ID != "" || len(pv.Lockout) != 1 || pv.Lockout[0] != "dashboard:8443" {
		t.Fatalf("enable without ack: %+v", pv)
	}
	r = plan(firewall.Op{Kind: "enable"}, true, "")
	mustOK(t, r, "enable")
	pv = FirewallPlanView{}
	_ = json.Unmarshal(r.Result, &pv)
	// 2222 is already allowed, so only 22 is added.
	if pv.Risk != "high" || len(pv.Auto) != 1 || pv.Auto[0].Port != "22" || len(pv.Lockout) != 1 ||
		!strings.Contains(pv.Diff, "+[ 2] allow in tcp 22 from any to any # daemonica:ssh:access") || !strings.Contains(pv.Diff, "+Status: active") {
		t.Fatalf("plan: %+v", pv)
	}

	mustOK(t, e.callFrom(me, "settings.change_apply", g, map[string]any{"id": pv.ID}), "apply")
	if fu.count("/usr/sbin/ufw allow in proto tcp from any to any port 22 comment daemonica:ssh:access") != 1 || fu.count("/usr/sbin/ufw --force enable") != 1 {
		t.Fatalf("calls: %v", fu.calls)
	}
	deadline := time.Now().Add(3 * time.Second)
	for fu.count("/usr/sbin/ufw --force disable") < 1 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if fu.active || fu.count("/usr/sbin/ufw --force disable") != 1 {
		t.Fatalf("no rollback: %v", fu.calls)
	}

	// Allowing the dashboard for everyone needs no lockout acknowledgement.
	mustOK(t, plan(firewall.Op{Kind: "add", Add: &firewall.AddSpec{Action: "allow", Proto: "tcp", Port: "8443"}}, false, ""), "add")
	if r := plan(firewall.Op{Kind: "add", Add: &firewall.AddSpec{Action: "allow", Port: "80,443"}}, false, ""); code(r) != rpc.CodeValidation {
		t.Fatalf("invalid add: %+v", r)
	}
	if r := plan(firewall.Op{Kind: "delete", Nums: []int{7}}, false, ""); code(r) != rpc.CodeValidation {
		t.Fatalf("delete unknown: %+v", r)
	}
	if r := plan(firewall.Op{Kind: "reset"}, true, "other"); code(r) != rpc.CodeValidation {
		t.Fatalf("reset with wrong name: %+v", r)
	}
	op, _ := e.web.Grants.Issue(policy.Subject{AccountID: "op", Role: policy.RoleOperator, LinuxUser: "bob", LinuxUID: 1001, StepUp: true}, time.Now())
	if r := e.callFrom(me, "firewall.plan", op, map[string]any{"op": firewall.Op{Kind: "disable"}}); code(r) != rpc.CodeForbidden {
		t.Fatalf("operator: %+v", r)
	}
	mustOK(t, e.callFrom(me, "firewall.get", op, nil), "operator reads")
}

func TestFirewallLogsAndBlockSource(t *testing.T) {
	e := newAuthEnv(t)
	g, sa, _ := setupAdmin(t, e)
	g = stepUp(t, e, sa, g)
	root := t.TempDir()
	open := "*filter\n### RULES ###\n### tuple ### allow tcp 22,2222,8443 0.0.0.0/0 any 0.0.0.0/0 in\n-A ufw-user-input -p tcp -m multiport --dports 22,2222,8443 -j ACCEPT\n### END RULES ###\n"
	for p, s := range map[string]string{"/usr/sbin/ufw": "", "/etc/ufw/user.rules": open, "/etc/default/ufw": "IPV6=yes\nDEFAULT_INPUT_POLICY=\"DROP\"\n"} {
		full := filepath.Join(root, p)
		_ = os.MkdirAll(filepath.Dir(full), 0o755)
		_ = os.WriteFile(full, []byte(s), 0o640)
	}
	fu := &fakeUfw{active: true}
	pm, _ := planner.New(filepath.Join(e.dir, "journal"), time.Minute)
	ufw := &firewall.Ufw{Root: root, Run: fu.run}
	pm.Register(&firewall.Handler{Ufw: ufw})
	var lastQuery journal.Query
	now := time.Now().UTC()
	jr := func(_ context.Context, q journal.Query) (journal.Result, error) {
		if q.Grep == "callbacks suppressed" {
			return journal.Result{Entries: []journal.Entry{{Time: now, Message: "net_ratelimit: 37 callbacks suppressed"}}}, nil
		}
		lastQuery = q
		return journal.Result{Cursor: "cur9", Entries: []journal.Entry{
			{Time: now, Message: "[UFW BLOCK] IN=eth0 OUT= SRC=203.0.113.9 DST=203.0.113.10 PROTO=TCP SPT=40000 DPT=5432 SYN"},
			{Time: now, Message: "eth0: link up, SRC=bogus"},
			{Time: now, Message: "[UFW ALLOW] IN=eth0 OUT= SRC=198.51.100.7 DST=203.0.113.10 PROTO=TCP SPT=40001 DPT=8443 SYN"},
			{Time: now, Message: "[UFW BLOCK] IN=eth0 OUT= SRC=192.0.2.44 DST=203.0.113.10 PROTO=UDP SPT=5353 DPT=161"},
		}}, nil
	}
	st := netcfg.State{Hostname: "daemonica", Interfaces: []netcfg.Interface{{Name: "eth0", Kind: "ethernet", Addresses: []string{"203.0.113.10/24"}}},
		Routes: []netcfg.Route{{Family: 4, To: "default", Via: "203.0.113.1", Dev: "eth0"}}}
	if _, err := e.cfg.Update(func(c *Config) error { c.Allowlist = []string{"127.0.0.0/8", "198.51.100.0/24"}; return nil }); err != nil {
		t.Fatal(err)
	}
	(&FirewallOps{Ufw: ufw, Detector: &firewall.Detector{Root: root, Run: fu.run}, Net: fakeNet{st}, Config: e.cfg, Planner: pm, Run: fu.run, Journal: jr}).Register(e.web.Ops)
	const me = "198.51.100.7"

	r := e.callFrom(me, "firewall.logs", g, map[string]any{"filter": map[string]string{"action": "block"}, "lines": 1})
	mustOK(t, r, "logs")
	var lv FirewallLogs
	_ = json.Unmarshal(r.Result, &lv)
	if lv.Scanned != 4 || len(lv.Entries) != 1 || lv.Entries[0].Src != "192.0.2.44" || !lv.Truncated || lv.Cursor != "cur9" || lv.Suppressed != 37 {
		t.Fatalf("logs: %+v", lv)
	}
	if lastQuery.Identifier != "kernel" || lastQuery.Grep != "SRC=" || !lastQuery.NoBudget {
		t.Fatalf("query: %+v", lastQuery)
	}
	if r := e.callFrom(me, "firewall.logs", g, map[string]any{"filter": map[string]string{"src": strings.Repeat("1", 200)}}); code(r) != rpc.CodeValidation {
		t.Fatalf("long filter: %+v", r)
	}
	ro, _ := e.web.Grants.Issue(policy.Subject{AccountID: "ro", Role: policy.RoleReadOnly, LinuxUser: "carl", LinuxUID: 1002}, time.Now())
	if r := e.callFrom(me, "firewall.logs", ro, map[string]any{}); code(r) != rpc.CodeForbidden {
		t.Fatalf("read-only: %+v", r)
	}

	block := func(src string) *rpc.Response {
		return e.callFrom(me, "firewall.plan", g, map[string]any{"op": firewall.Op{Kind: "add", Add: &firewall.AddSpec{Action: "deny", From: src, Prepend: true, Comment: "blocked from logs"}}})
	}
	for _, src := range []string{me, "198.51.0.0/16", "198.51.100.200"} {
		if r := block(src); code(r) != rpc.CodeLockout {
			t.Fatalf("block %s: %+v", src, r)
		}
	}
	r = block("192.0.2.44")
	mustOK(t, r, "block source")
	var pv FirewallPlanView
	_ = json.Unmarshal(r.Result, &pv)
	if !strings.Contains(pv.Diff, "+[ 1] deny in any any from 192.0.2.44 to any # blocked from logs") {
		t.Fatalf("diff: %s", pv.Diff)
	}
}
