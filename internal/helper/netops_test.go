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
	"github.com/PanPakaPancake/daemonica/internal/netcfg"
	"github.com/PanPakaPancake/daemonica/internal/planner"
	"github.com/PanPakaPancake/daemonica/internal/policy"
	"github.com/PanPakaPancake/daemonica/internal/rpc"
)

type fakeNet struct{ st netcfg.State }

func (f fakeNet) Read() (netcfg.State, error) { return f.st, nil }
func (f fakeNet) Ports() ([]netcfg.Port, error) {
	return []netcfg.Port{{Proto: "tcp", Address: "0.0.0.0", Port: 22}}, nil
}

type netRuns struct {
	mu    sync.Mutex
	calls []string
}

func (n *netRuns) run(_ context.Context, _ time.Duration, path string, args ...string) (execx.Result, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.calls = append(n.calls, path+" "+strings.Join(args, " "))
	return execx.Result{}, nil
}

func (n *netRuns) count(prefix string) int {
	n.mu.Lock()
	defer n.mu.Unlock()
	c := 0
	for _, x := range n.calls {
		if strings.HasPrefix(x, prefix) {
			c++
		}
	}
	return c
}

const npBase = "network:\n  version: 2\n  ethernets:\n    eth0:\n      addresses: [203.0.113.10/24]\n      routes:\n        - to: default\n          via: 203.0.113.1\n    eth1:\n      dhcp4: true\n"

func TestNetworkPlanApplyRollback(t *testing.T) {
	e := newAuthEnv(t)
	g, sa, _ := setupAdmin(t, e)
	root := t.TempDir()
	for p, s := range map[string]string{"/usr/sbin/netplan": "", "/etc/netplan/50-cloud-init.yaml": npBase} {
		full := filepath.Join(root, p)
		_ = os.MkdirAll(filepath.Dir(full), 0o755)
		if err := os.WriteFile(full, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	runs := &netRuns{}
	pm, err := planner.New(filepath.Join(e.dir, "journal"), 300*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	pm.Register(&NetworkHandler{Root: root, Run: runs.run})
	st := netcfg.State{
		Interfaces: []netcfg.Interface{{Name: "lo", Kind: "loopback"}, {Name: "eth0", Kind: "ethernet"}, {Name: "eth1", Kind: "ethernet"}},
		Routes:     []netcfg.Route{{Family: 4, To: "default", Via: "203.0.113.1", Dev: "eth0"}, {Family: 4, To: "10.0.0.0/8", Dev: "eth1"}},
	}
	(&NetOps{Reader: fakeNet{st}, Detector: &netcfg.Detector{Root: root}, Run: runs.run, Planner: pm}).Register(e.web.Ops)
	(&SettingsOps{Config: e.cfg, Planner: pm}).Register(e.web.Ops)
	const me = "198.51.100.7" // reaches the server over eth0

	r := e.callFrom(me, "net.get", g, nil)
	mustOK(t, r, "get")
	var v NetView
	_ = json.Unmarshal(r.Result, &v)
	if v.SessionIface != "eth0" || v.Manager.Name != "netplan" || !v.Manager.Writable || !v.Interfaces[1].Session {
		t.Fatalf("view: %+v", v)
	}
	mustOK(t, e.callFrom(me, "net.ports", g, nil), "ports")
	r = e.callFrom(me, "net.config", g, map[string]string{"name": "eth0"})
	mustOK(t, r, "config")
	var cfg netcfg.IfaceConfig
	_ = json.Unmarshal(r.Result, &cfg)
	if !cfg.Editable || cfg.Gateway4 != "203.0.113.1" {
		t.Fatalf("config: %+v", cfg)
	}

	cfg.Gateway4 = "203.0.113.254"
	planOf := func(c netcfg.IfaceConfig, ack bool) *rpc.Response {
		return e.callFrom(me, "net.plan", g, map[string]any{"config": c, "confirm_lockout": ack})
	}
	if code(planOf(cfg, false)) != rpc.CodeStepUpNeeded {
		t.Fatal("plan without step-up")
	}
	g = stepUp(t, e, sa, g)
	if r := planOf(cfg, false); code(r) != rpc.CodeLockout {
		t.Fatalf("session interface without ack: %+v", r)
	}
	if r := planOf(netcfg.IfaceConfig{Name: "lo", DHCP4: true}, true); code(r) != rpc.CodeValidation {
		t.Fatalf("loopback: %+v", r)
	}
	if r := planOf(netcfg.IfaceConfig{Name: "eth9", DHCP4: true}, true); code(r) != rpc.CodeNotFound {
		t.Fatalf("unknown iface: %+v", r)
	}
	if r := planOf(netcfg.IfaceConfig{Name: "eth1", Addresses: []string{"nope"}}, true); code(r) != rpc.CodeValidation {
		t.Fatalf("invalid address: %+v", r)
	}
	r = planOf(cfg, true)
	mustOK(t, r, "plan")
	var pv NetPlanView
	_ = json.Unmarshal(r.Result, &pv)
	if pv.Risk != "high" || !pv.Session || !strings.Contains(pv.Diff, "+          via: 203.0.113.254") || (len(pv.Payload) != 0 && string(pv.Payload) != "null") {
		t.Fatalf("plan view: %+v", pv)
	}
	file := filepath.Join(root, "/etc/netplan/50-cloud-init.yaml")
	if b, _ := os.ReadFile(file); string(b) != npBase {
		t.Fatal("plan changed the file")
	}

	// Apply, no confirmation: the file is restored and netplan applied again.
	mustOK(t, e.callFrom(me, "settings.change_apply", g, map[string]any{"id": pv.ID}), "apply")
	if b, _ := os.ReadFile(file); !strings.Contains(string(b), "203.0.113.254") {
		t.Fatalf("not applied:\n%s", b)
	}
	if runs.count("/usr/sbin/netplan apply") != 1 {
		t.Fatalf("calls: %v", runs.calls)
	}
	deadline := time.Now().Add(3 * time.Second)
	for runs.count("/usr/sbin/netplan apply") < 2 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if b, _ := os.ReadFile(file); string(b) != npBase || runs.count("/usr/sbin/netplan apply") != 2 {
		t.Fatalf("no rollback:\n%s\n%v", b, runs.calls)
	}

	// A second plan on another interface is medium risk; operators are refused.
	r = planOf(netcfg.IfaceConfig{Name: "eth1", Addresses: []string{"10.0.0.5/8"}}, false)
	mustOK(t, r, "plan eth1")
	_ = json.Unmarshal(r.Result, &pv)
	if pv.Risk != "medium" || pv.Session {
		t.Fatalf("eth1 plan: %+v", pv)
	}
	op, _ := e.web.Grants.Issue(policy.Subject{AccountID: "op", Role: policy.RoleOperator, LinuxUser: "bob", LinuxUID: 1001, StepUp: true}, time.Now())
	if r := e.callFrom(me, "net.plan", op, map[string]any{"config": cfg}); code(r) != rpc.CodeForbidden {
		t.Fatalf("operator: %+v", r)
	}
	mustOK(t, e.callFrom(me, "net.get", op, nil), "operator reads")

	// Read-only manager.
	_ = os.Remove(filepath.Join(root, "/usr/sbin/netplan"))
	if r := planOf(cfg, true); code(r) != rpc.CodeNotSupported {
		t.Fatalf("read-only: %+v", r)
	}
}
