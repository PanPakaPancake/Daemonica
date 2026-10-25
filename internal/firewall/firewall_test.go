package firewall

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/PanPakaPancake/daemonica/internal/execx"
)

type fakeRun struct {
	calls  [][]string
	active bool
	out    map[string]string // program → stdout
}

func (f *fakeRun) run(_ context.Context, _ time.Duration, path string, args ...string) (execx.Result, error) {
	f.calls = append(f.calls, append([]string{path}, args...))
	if path == ufwBin && len(args) == 1 && args[0] == "status" {
		if f.active {
			return execx.Result{Stdout: []byte("Status: active\n")}, nil
		}
		return execx.Result{Stdout: []byte("Status: inactive\n")}, nil
	}
	return execx.Result{Stdout: []byte(f.out[path])}, nil
}

func write(t *testing.T, root, p, s string) {
	t.Helper()
	full := filepath.Join(root, p)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(s), 0o640); err != nil {
		t.Fatal(err)
	}
}

const user6 = `*filter
### RULES ###

### tuple ### allow tcp 22 ::/0 any ::/0 in comment=6461656d6f6e6963613a7373683a616363657373
-A ufw6-user-input -p tcp --dport 22 -j ACCEPT

### END RULES ###
`

func fixture(t *testing.T) (*Ufw, *fakeRun) {
	t.Helper()
	root := t.TempDir()
	rules, err := os.ReadFile("testdata/user.rules")
	if err != nil {
		t.Fatal(err)
	}
	write(t, root, userRules, string(rules))
	write(t, root, user6Rules, user6)
	write(t, root, ufwConf, "ENABLED=yes\nLOGLEVEL=low\n")
	write(t, root, ufwDefault, "IPV6=yes\nDEFAULT_INPUT_POLICY=\"DROP\"\nDEFAULT_OUTPUT_POLICY=\"ACCEPT\"\nDEFAULT_FORWARD_POLICY=\"DROP\"\n")
	write(t, root, "/proc/sys/net/ipv4/ip_forward", "0\n")
	fr := &fakeRun{active: true, out: map[string]string{}}
	return &Ufw{Root: root, Run: fr.run}, fr
}

func TestReadConfig(t *testing.T) {
	u, _ := fixture(t)
	c, err := u.ReadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if !c.Enabled || c.Logging != "low" || !c.IPv6 || c.Defaults != (Defaults{"deny", "allow", "disabled"}) {
		t.Fatalf("settings: %+v", c)
	}
	if len(c.Rules) != 10 {
		t.Fatalf("rules: %d", len(c.Rules))
	}
	r := c.Rules[1]
	if r.Num != 2 || r.Iface != "eth0" || r.Src != "10.0.0.0/8" || r.DPort != "8443" || r.Comment != "daemonica:dash:web" || !r.Managed {
		t.Fatalf("rule 2: %+v", r)
	}
	if r := c.Rules[2]; r.Action != "limit" || len(r.lines) != 3 {
		t.Fatalf("limit rule: %+v", r)
	}
	if r := c.Rules[3]; r.Direction != "out" || r.Proto != "any" {
		t.Fatalf("out rule: %+v", r)
	}
	if r := c.Rules[4]; r.App != "OpenSSH" || r.SApp != "" {
		t.Fatalf("app rule: %+v", r)
	}
	if r := c.Rules[7]; r.Direction != "route" || r.Iface != "eth0" || r.OutIface != "eth1" {
		t.Fatalf("route rule: %+v", r)
	}
	if r := c.Rules[8]; r.Action != "allow" || r.Log != "log" || r.Proto != "udp" {
		t.Fatalf("log rule: %+v", r)
	}
	if r := c.Rules[9]; !r.V6 || r.Num != 10 || !r.Managed {
		t.Fatalf("v6 rule: %+v", r)
	}
	if got := c.Rules[1].String(); got != "[ 2] allow in on eth0 tcp 8443 from 10.0.0.0/8 to any # daemonica:dash:web" {
		t.Fatalf("String: %q", got)
	}
}

func TestEvaluate(t *testing.T) {
	u, _ := fixture(t)
	c, _ := u.ReadConfig()
	ip := netip.MustParseAddr
	cases := []struct {
		p       Packet
		allowed bool
		rule    int
	}{
		{Packet{Src: ip("10.1.2.3"), Iface: "eth0", Proto: "tcp", Port: 8443}, true, 2},
		{Packet{Src: ip("10.1.2.3"), Iface: "eth1", Proto: "tcp", Port: 8443}, false, 0},
		{Packet{Src: ip("1.2.3.4"), Proto: "tcp", Port: 22}, true, 1}, // first match before the reject
		{Packet{Src: ip("1.2.3.4"), Proto: "tcp", Port: 8080}, false, 7},
		{Packet{Src: ip("5.6.7.8"), Proto: "tcp", Port: 443}, true, 6},
		{Packet{Src: ip("5.6.7.8"), Proto: "udp", Port: 443}, false, 0},
		{Packet{Src: ip("5.6.7.8"), Proto: "tcp", Port: 2222}, true, 3},
		{Packet{Src: ip("2001:db8::5"), Proto: "tcp", Port: 22}, true, 10},
		{Packet{Src: ip("2001:db8::5"), Proto: "tcp", Port: 80}, false, 0},
		{Packet{Src: ip("127.0.0.1"), Proto: "tcp", Port: 9}, true, 0},
	}
	for i, tc := range cases {
		v := Evaluate(c, true, tc.p)
		if v.Allowed != tc.allowed || v.Rule != tc.rule {
			t.Errorf("case %d: %+v", i, v)
		}
	}
	if v := Evaluate(c, false, Packet{Src: ip("5.6.7.8"), Proto: "tcp", Port: 9}); !v.Allowed || v.Reason != "inactive" {
		t.Errorf("inactive: %+v", v)
	}
	c6 := c
	c6.IPv6 = false
	if v := Evaluate(c6, true, Packet{Src: ip("2001:db8::5"), Proto: "tcp", Port: 80}); !v.Allowed || v.Reason != "unfiltered" {
		t.Errorf("v6 off: %+v", v)
	}
	if a := Reach(c, true, "tcp", 8443, false, nil); a.Allowed || !a.Restricted {
		t.Errorf("reach 8443: %+v", a)
	}
	if a := Reach(c, true, "tcp", 22, false, nil); !a.Allowed {
		t.Errorf("reach 22: %+v", a)
	}
	if !PortMatches("80,443,6000:6010", 6005) || PortMatches("80,443", 444) {
		t.Error("PortMatches")
	}
}

func TestLight(t *testing.T) {
	u, _ := fixture(t)
	c, _ := u.ReadConfig()
	ls := []Listener{{Proto: "tcp", Port: 22}, {Proto: "tcp", Port: 8443}, {Proto: "tcp", Port: 2222}, {Proto: "udp", Port: 53}, {Proto: "tcp", Port: 80, Local: true}}
	// port lists (rule 6) are not checked; port 80 listens only locally
	if light, hs := Light(c, true, false, ls); light != "green" || len(hs) != 0 {
		t.Fatalf("light %s %+v", light, hs)
	}
	if light, _ := Light(c, false, false, ls); light != "red" {
		t.Fatal("inactive must be red")
	}
	c.Logging, c.IPv6 = "off", false
	_, hs := Light(c, true, true, ls)
	if len(hs) != 2 || hs[0].Code != "ipv6_off" || hs[1].Code != "logging_off" {
		t.Fatalf("hints %+v", hs)
	}
	ls = ls[:1]
	_, hs = Light(c, true, false, ls)
	if len(hs) < 2 || hs[1].Code != "unused_allow" || hs[1].Arg != "8443/tcp" {
		t.Fatalf("unused %+v", hs)
	}
	c.Defaults.Incoming = "allow"
	if light, _ := Light(c, true, false, ls); light != "red" {
		t.Fatal("default allow must be red")
	}
}

func TestPlanSimulateSteps(t *testing.T) {
	u, _ := fixture(t)
	c, _ := u.ReadConfig()
	add, err := Op{Kind: "add", Add: &AddSpec{Action: "allow", Proto: "tcp", Port: "8080", From: "192.168.1.0/24", Comment: "test"}}.Validate(c)
	if err != nil {
		t.Fatal(err)
	}
	del, err := Op{Kind: "delete", Nums: []int{5, 3, 5}}.Validate(c)
	if err != nil || !slices.Equal(del.Nums, []int{3, 5}) {
		t.Fatal(err, del.Nums)
	}
	if _, err := (Op{Kind: "delete", Nums: []int{11}}).Validate(c); err == nil {
		t.Fatal("rule 11 does not exist")
	}
	ops := []Op{add, del, {Kind: "logging", Level: "medium"}}
	after, active := Simulate(c, true, ops)
	if !active || len(after.Rules) != 9 || after.Logging != "medium" {
		t.Fatalf("after: %d %s", len(after.Rules), after.Logging)
	}
	// v4 rules stay before v6 rules
	if !after.Rules[8].V6 || after.Rules[7].DPort != "8080" || after.Rules[7].Num != 8 {
		t.Fatalf("order: %v", after.Rules[7])
	}
	steps := Steps(ops)
	want := [][]string{
		{"allow", "in", "proto", "tcp", "from", "192.168.1.0/24", "to", "any", "port", "8080", "comment", "test"},
		{"--force", "delete", "5"}, {"--force", "delete", "3"}, {"logging", "medium"},
	}
	if len(steps) != len(want) {
		t.Fatalf("steps %v", steps)
	}
	for i := range want {
		if !slices.Equal(steps[i], want[i]) {
			t.Fatalf("step %d: %v", i, steps[i])
		}
	}
	d := Diff(c, true, after, active)
	for _, s := range []string{"-Logging: low", "+Logging: medium", "-[ 3] limit in tcp 2222", "+[ 8] allow in tcp 8080 from 192.168.1.0/24 to any # test"} {
		if !strings.Contains(d, s) {
			t.Errorf("diff lacks %q:\n%s", s, d)
		}
	}
	reset, _ := Simulate(c, true, []Op{{Kind: "reset"}})
	if len(reset.Rules) != 0 || reset.Enabled {
		t.Fatal("reset")
	}
}

func TestAddSpec(t *testing.T) {
	bad := []AddSpec{
		{Action: "drop"},
		{Action: "allow", Port: "70000", Proto: "tcp"},
		{Action: "allow", Port: "80,443"},
		{Action: "allow", From: "10.0.0.0/8", To: "::1"},
		{Action: "allow", Port: "22", Proto: "tcp", Comment: "x'; rm -rf /"},
		{Action: "limit"},
		{Action: "allow", App: "../x"},
		{Action: "allow", Iface: "eth0 -j"},
	}
	for i, s := range bad {
		if _, err := s.Normalize(); err == nil {
			t.Errorf("case %d accepted", i)
		}
	}
	s, err := AddSpec{Action: "allow", App: "OpenSSH", From: "2001:db8::/32", Iface: "eth0"}.Normalize()
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(s.Args(), " "); got != "allow in on eth0 from 2001:db8::/32 to any app OpenSSH" {
		t.Fatal(got)
	}
	s.AppPorts = []string{"22/tcp"}
	rs := s.Rules(true)
	if len(rs) != 1 || !rs[0].V6 || rs[0].DPort != "22" || rs[0].Proto != "tcp" {
		t.Fatalf("%+v", rs)
	}
}

func TestAccessRules(t *testing.T) {
	lo := []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("::1/128")}
	rs := AccessRules([]int{22, 2222}, 8443, lo)
	if len(rs) != 2 || rs[1].Port != "2222" || rs[0].Comment != "daemonica:ssh:access" {
		t.Fatalf("%+v", rs)
	}
	rs = AccessRules([]int{22}, 8443, append(lo, netip.MustParsePrefix("203.0.113.7/24")))
	if len(rs) != 2 || rs[1].From != "203.0.113.0/24" || rs[1].Comment != "daemonica:dashboard:access" {
		t.Fatalf("%+v", rs)
	}
	rs = AccessRules([]int{22}, 8443, []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("10.0.0.0/8")})
	if len(rs) != 2 || rs[1].From != "any" {
		t.Fatalf("%+v", rs)
	}
	if p := SSHPorts([]byte("port 22\nport 2222\nlistenaddress 0.0.0.0:22\n")); !slices.Equal(p, []int{22, 2222}) {
		t.Fatal(p)
	}
	if p := SSHPorts(nil); !slices.Equal(p, []int{22}) {
		t.Fatal(p)
	}
}

func TestCounters(t *testing.T) {
	u, fr := fixture(t)
	c, _ := u.ReadConfig()
	fr.out[iptablesSave] = `*filter
[0:0] -A ufw-user-input -p tcp -m tcp --dport 22 -j ACCEPT
[5:300] -A ufw-user-input -s 10.0.0.0/8 -i eth0 -p tcp -m tcp --dport 8443 -j ACCEPT
[1:60] -A ufw-user-input -p tcp -m tcp --dport 2222 -m conntrack --ctstate NEW -m recent --set
[1:60] -A ufw-user-input -p tcp --dport 2222 -m recent --update -j ufw-user-limit
[7:420] -A ufw-user-input -p tcp -m tcp --dport 2222 -j ufw-user-limit-accept
[3:180] -A ufw-user-output -p tcp --dport 25 -j DROP
[1:60] -A ufw-user-output -p udp --dport 25 -j DROP
`
	fr.out[ip6tablesSave] = "[9:900] -A ufw6-user-input -p tcp -m tcp --dport 22 -j ACCEPT\n"
	u.AddCounters(context.Background(), c.Rules)
	if r := c.Rules[1]; r.Packets != 5 || r.Bytes != 300 || !r.Counted {
		t.Fatalf("8443: %+v", r)
	}
	if r := c.Rules[2]; r.Packets != 7 {
		t.Fatalf("limit counts only the accepting line: %+v", r)
	}
	if r := c.Rules[3]; r.Packets != 4 || r.Bytes != 240 {
		t.Fatalf("out 25: %+v", r)
	}
	if r := c.Rules[9]; r.Packets != 9 {
		t.Fatalf("v6: %+v", r)
	}
}

func TestHandlerApplyRollback(t *testing.T) {
	u, fr := fixture(t)
	h := &Handler{Ufw: u}
	ctx := context.Background()
	snap, err := u.TakeSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !snap.Active || snap.Files[userRules] == nil || snap.Files["/etc/ufw/before.rules"] != nil {
		t.Fatalf("snapshot %+v", snap.Active)
	}
	raw, _ := json.Marshal(Payload{Token: "t1", Snapshot: snap, Steps: [][]string{{"logging", "high"}, {"--force", "delete", "3"}}})
	fr.calls = nil
	if err := h.Apply(ctx, raw); err != nil {
		t.Fatal(err)
	}
	if len(fr.calls) != 3 || !slices.Equal(fr.calls[2], []string{ufwBin, "--force", "delete", "3"}) {
		t.Fatalf("calls %v", fr.calls)
	}
	// ufw would have changed the files; the rollback writes them back and re-enables.
	write(t, u.Root, ufwConf, "ENABLED=yes\nLOGLEVEL=high\n")
	write(t, u.Root, "/etc/ufw/before.rules", "created by reset\n")
	fr.calls = nil
	if err := h.Rollback(ctx, raw); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(u.Root, ufwConf)); string(b) != "ENABLED=yes\nLOGLEVEL=low\n" {
		t.Fatalf("conf %q", b)
	}
	if st, err := os.Stat(filepath.Join(u.Root, ufwConf)); err != nil || st.Mode().Perm() != 0o644 {
		t.Fatal("mode", err)
	}
	if _, err := os.Stat(filepath.Join(u.Root, "/etc/ufw/before.rules")); !os.IsNotExist(err) {
		t.Fatal("file absent in the snapshot must be removed")
	}
	if !slices.Equal(fr.calls[len(fr.calls)-1], []string{ufwBin, "--force", "enable"}) {
		t.Fatalf("calls %v", fr.calls)
	}

	// stale: the files changed after the preview → refuse, and the rollback leaves them alone
	raw2, _ := json.Marshal(Payload{Token: "t2", Snapshot: snap, Steps: [][]string{{"disable"}}})
	write(t, u.Root, ufwConf, "ENABLED=yes\nLOGLEVEL=full\n")
	fr.calls = nil
	if err := h.Apply(ctx, raw2); !errors.Is(err, ErrStale) {
		t.Fatalf("want stale, got %v", err)
	}
	if err := h.Rollback(ctx, raw2); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(u.Root, ufwConf)); string(b) != "ENABLED=yes\nLOGLEVEL=full\n" {
		t.Fatal("stale rollback overwrote a foreign change")
	}
	for _, c := range fr.calls {
		if c[0] == ufwBin && c[1] != "status" {
			t.Fatalf("stale apply ran %v", c)
		}
	}
}

func TestDetect(t *testing.T) {
	root := t.TempDir()
	fr := &fakeRun{out: map[string]string{}}
	d := &Detector{Root: root, Run: fr.run, Active: func(string) bool { return false }}
	ctx := context.Background()
	if b := d.Detect(ctx); b != BackendNone {
		t.Fatal(b)
	}
	write(t, root, nftBin, "")
	fr.out[nftBin] = "table inet filter\n"
	if b := d.Detect(ctx); b != BackendNftables {
		t.Fatal(b)
	}
	write(t, root, ufwBin, "")
	if b := d.Detect(ctx); b != BackendUfw {
		t.Fatal(b)
	}
	d.Active = func(u string) bool { return u == "firewalld.service" }
	if b := d.Detect(ctx); b != BackendFirewalld {
		t.Fatal(b)
	}
	fr.out[nftBin] = "table inet filter {\n}\n"
	if src, text, err := d.Raw(ctx); err != nil || src != "nft list ruleset" || !strings.Contains(text, "inet filter") {
		t.Fatal(src, text, err)
	}
}
