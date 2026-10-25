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

// fakeKernel plays systemd-networkd: each netplan apply takes over the
// gateway of the file, except the first `broken` ones, which leave the
// interface without routes (as when networkd cannot read its file).
type fakeKernel struct {
	mu     sync.Mutex
	file   string
	broken int
	gw     string
	applys int
}

func (k *fakeKernel) run(_ context.Context, _ time.Duration, path string, args ...string) (execx.Result, error) {
	if path == "/usr/sbin/netplan" && len(args) == 1 && args[0] == "apply" {
		k.mu.Lock()
		defer k.mu.Unlock()
		k.applys++
		b, _ := os.ReadFile(k.file)
		k.gw = ""
		if k.broken > 0 {
			k.broken--
			return execx.Result{}, nil
		}
		for _, l := range strings.Split(string(b), "\n") {
			if v, ok := strings.CutPrefix(strings.TrimSpace(l), "via: "); ok {
				k.gw = strings.Trim(v, `"`)
			}
		}
	}
	return execx.Result{}, nil
}

func (k *fakeKernel) state() (netcfg.State, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	st := netcfg.State{Interfaces: []netcfg.Interface{{Name: "eth0", Addresses: []string{"203.0.113.10/24"}}}}
	if k.gw != "" {
		st.Routes = []netcfg.Route{{Family: 4, To: "default", Via: k.gw, Dev: "eth0"}}
	}
	return st, nil
}

func TestNetworkHandlerVerifiesKernelState(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	file := filepath.Join(root, "/etc/netplan/50-cloud-init.yaml")
	_ = os.MkdirAll(filepath.Dir(file), 0o755)
	plan := func(k *fakeKernel) json.RawMessage {
		if err := os.WriteFile(file, []byte(npBase), 0o600); err != nil {
			t.Fatal(err)
		}
		np := &netcfg.Netplan{Root: root, Run: k.run}
		cfg, err := np.Config("eth0", "")
		if err != nil {
			t.Fatal(err)
		}
		cfg.Gateway4 = "203.0.113.254"
		p, err := np.Plan(ctx, cfg, "")
		if err != nil {
			t.Fatal(err)
		}
		b, _ := json.Marshal(p)
		return b
	}

	// Healthy: apply and rollback both take effect.
	k := &fakeKernel{file: file}
	h := &NetworkHandler{Root: root, Run: k.run, State: k.state, Settle: 200 * time.Millisecond}
	p := plan(k)
	if err := h.Apply(ctx, p); err != nil || k.gw != "203.0.113.254" {
		t.Fatalf("apply: %v gw=%s", err, k.gw)
	}
	if err := h.Rollback(ctx, p); err != nil || k.gw != "203.0.113.1" {
		t.Fatalf("rollback: %v gw=%s", err, k.gw)
	}

	// netplan apply exits 0 but the routes are gone: apply reports an error.
	k = &fakeKernel{file: file, broken: 1}
	h = &NetworkHandler{Root: root, Run: k.run, State: k.state, Settle: 200 * time.Millisecond}
	p = plan(k)
	if err := h.Apply(ctx, p); err == nil || !strings.Contains(err.Error(), "default route via 203.0.113.254") {
		t.Fatalf("broken apply: %v", err)
	}

	// A rollback whose first activation does not take effect activates again.
	k.broken = 1
	if err := h.Rollback(ctx, p); err != nil || k.gw != "203.0.113.1" || k.applys != 3 {
		t.Fatalf("rollback retry: %v gw=%s applys=%d", err, k.gw, k.applys)
	}
	// Never takes effect: the rollback fails instead of reporting ok.
	k.broken = 2
	if err := h.Rollback(ctx, p); err == nil {
		t.Fatal("failed rollback reported ok")
	}
}

func TestMissing(t *testing.T) {
	st := netcfg.State{
		Interfaces: []netcfg.Interface{{Name: "eth0", Addresses: []string{"148.230.104.4/24", "2a02:4780:41:abcd::1/48", "fe80::1/64"}}},
		Routes: []netcfg.Route{{Family: 4, To: "default", Via: "148.230.104.254", Dev: "eth0"}, {Family: 6, To: "default", Via: "2a02:4780:41::1", Dev: "eth0"},
			{Family: 4, To: "10.1.0.0/16", Via: "148.230.104.1", Dev: "eth0"}},
	}
	ok := netcfg.IfaceConfig{Name: "eth0", Addresses: []string{"148.230.104.4/24", "2a02:4780:41:abcd::1/48"}, Gateway4: "148.230.104.254", Gateway6: "2a02:4780:41::1",
		Routes: []netcfg.StaticRoute{{To: "10.1.0.0/16", Via: "148.230.104.1"}}}
	if m := netcfg.Missing(st, ok); len(m) != 0 {
		t.Fatalf("missing: %v", m)
	}
	bad := ok
	bad.Gateway4, bad.Addresses, bad.DHCP6 = "148.230.104.253", []string{"148.230.104.5/24"}, false
	if m := netcfg.Missing(st, bad); len(m) != 2 {
		t.Fatalf("missing: %v", m)
	}
	if m := netcfg.Missing(st, netcfg.IfaceConfig{Name: "eth1", DHCP4: true}); len(m) != 1 {
		t.Fatalf("missing iface: %v", m)
	}
	if m := netcfg.Missing(netcfg.State{Interfaces: []netcfg.Interface{{Name: "eth0", Addresses: []string{"fe80::1/64"}}}}, netcfg.IfaceConfig{Name: "eth0", DHCP4: true, DHCP6: true}); len(m) != 2 {
		t.Fatalf("dhcp: %v", m)
	}
}
