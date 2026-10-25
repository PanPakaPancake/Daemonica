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
	if r := plan(firewall.Op{Kind: "enable"}, false, ""); code(r) != rpc.CodeLockout || !strings.Contains(r.Error.Message, "dashboard:8443") {
		t.Fatalf("enable without ack: %+v", r)
	}
	r = plan(firewall.Op{Kind: "enable"}, true, "")
	mustOK(t, r, "enable")
	var pv FirewallPlanView
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
