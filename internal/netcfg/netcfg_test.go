package netcfg

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PanPakaPancake/daemonica/internal/execx"
)

type call struct {
	path string
	args []string
}

type fakeRun struct {
	calls []call
	code  int
	files map[string]string // snapshot of the netplan dir at generate time
	root  string
}

func (f *fakeRun) run(_ context.Context, _ time.Duration, path string, args ...string) (execx.Result, error) {
	f.calls = append(f.calls, call{path, args})
	return execx.Result{ExitCode: f.code, Stderr: []byte("bad config\n")}, nil
}

func write(t *testing.T, root, p, s string) {
	t.Helper()
	full := filepath.Join(root, p)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
}

const cloudInit = `# This file is generated from information provided by the datasource.
network:
    version: 2
    ethernets:
        eth0:
            match:
                macaddress: 52:54:00:12:34:56
            set-name: eth0
            addresses:
            - 203.0.113.10/24
            - 2001:db8::10/64
            nameservers:
                addresses: [1.1.1.1, 8.8.8.8]
                search: []
            routes:
            -   to: default
                via: 203.0.113.1
            -   to: default
                via: 2001:db8::1
`

func TestNetplanReadEdit(t *testing.T) {
	root := t.TempDir()
	write(t, root, "/etc/netplan/50-cloud-init.yaml", cloudInit)
	fr := &fakeRun{}
	n := &Netplan{Root: root, Run: fr.run}
	c, err := n.Config("eth0", "52:54:00:12:34:56")
	if err != nil {
		t.Fatal(err)
	}
	if !c.Editable || c.Source != "/etc/netplan/50-cloud-init.yaml" || c.Gateway4 != "203.0.113.1" || c.Gateway6 != "2001:db8::1" ||
		len(c.Addresses) != 2 || len(c.DNS) != 2 || len(c.Routes) != 0 {
		t.Fatalf("config: %+v", c)
	}
	c.Gateway4 = "203.0.113.254"
	c.Routes = []StaticRoute{{To: "10.0.0.0/8", Via: "203.0.113.2", Metric: 50}}
	c.MTU = 1400
	nc, err := Normalize(c)
	if err != nil {
		t.Fatal(err)
	}
	p, err := n.Plan(context.Background(), nc, "52:54:00:12:34:56")
	if err != nil {
		t.Fatal(err)
	}
	out := *p.Files[0].New
	for _, want := range []string{"# This file is generated", "via: 203.0.113.254", "to: 10.0.0.0/8", "metric: 50", "mtu: 1400", "macaddress: 52:54:00:12:34:56", "set-name: eth0"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "203.0.113.1\n") {
		t.Fatalf("old gateway kept:\n%s", out)
	}
	if !strings.Contains(p.Diff, "+") || !strings.Contains(p.Diff, "-") {
		t.Fatalf("diff: %s", p.Diff)
	}
	if len(fr.calls) != 1 || fr.calls[0].args[0] != "generate" || fr.calls[0].args[1] != "--root-dir" {
		t.Fatalf("validate: %+v", fr.calls)
	}

	// The re-read file gives back what was written.
	if err := WriteFiles(root, p.Files, false); err != nil {
		t.Fatal(err)
	}
	c2, _ := n.Config("eth0", "52:54:00:12:34:56")
	if c2.Gateway4 != "203.0.113.254" || c2.MTU != 1400 || len(c2.Routes) != 1 || c2.Routes[0].Metric != 50 || !c2.Editable {
		t.Fatalf("round trip: %+v", c2)
	}
	if fi, _ := os.Stat(filepath.Join(root, p.Files[0].Path)); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode())
	}
	// Rollback restores the original bytes.
	if err := WriteFiles(root, p.Files, true); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(root, p.Files[0].Path)); string(b) != cloudInit {
		t.Fatalf("rollback:\n%s", b)
	}

	// Validation failure is reported.
	fr.code = 1
	if _, err := n.Plan(context.Background(), nc, "52:54:00:12:34:56"); err == nil || !strings.Contains(err.Error(), "bad config") {
		t.Fatalf("validation: %v", err)
	}
}

func TestNetplanNewAndConflicts(t *testing.T) {
	root := t.TempDir()
	write(t, root, "/etc/netplan/01.yaml", "network:\n  version: 2\n  renderer: NetworkManager\n  ethernets:\n    eth1:\n      dhcp4: true\n")
	write(t, root, "/etc/netplan/02.yaml", "network:\n  ethernets:\n    eth1:\n      mtu: 9000\n    eth2:\n      addresses:\n        - 10.0.0.2/24:\n            lifetime: 0\n")
	fr := &fakeRun{}
	n := &Netplan{Root: root, Run: fr.run}
	if n.renderer() != "NetworkManager" {
		t.Fatal("renderer")
	}
	if c, _ := n.Config("eth1", ""); c.Editable || c.Reason != "several_files" {
		t.Fatalf("eth1: %+v", c)
	}
	if c, _ := n.Config("eth2", ""); c.Editable || c.Reason != "advanced" {
		t.Fatalf("eth2: %+v", c)
	}
	c, _ := n.Config("eth3", "")
	if !c.Editable || c.Reason != "not_configured" {
		t.Fatalf("eth3: %+v", c)
	}
	nc, _ := Normalize(IfaceConfig{Name: "eth3", DHCP4: true})
	p, err := n.Plan(context.Background(), nc, "")
	if err != nil {
		t.Fatal(err)
	}
	if p.Files[0].Path != NetplanOwnFile || p.Files[0].Old != nil || !strings.Contains(*p.Files[0].New, "eth3:\n      dhcp4: true") {
		t.Fatalf("new file: %+v %s", p.Files[0], *p.Files[0].New)
	}
	if _, err := n.Plan(context.Background(), IfaceConfig{Name: "eth1"}, ""); err == nil {
		t.Fatal("conflicting interface planned")
	}
}

const interfaces = `# The loopback network interface
auto lo
iface lo inet loopback

# primary
allow-hotplug ens3
iface ens3 inet static
    address 192.0.2.5
    netmask 255.255.255.0
    gateway 192.0.2.1
    dns-nameservers 9.9.9.9
iface ens3 inet6 static
    address 2001:db8::5/64
    gateway 2001:db8::1

auto br0
iface br0 inet dhcp
    bridge_ports ens4
`

func TestIfupdown(t *testing.T) {
	root := t.TempDir()
	write(t, root, interfacesFile, interfaces)
	fr := &fakeRun{}
	u := &Ifupdown{Root: root, Run: fr.run}
	c, err := u.Config("ens3", "")
	if err != nil {
		t.Fatal(err)
	}
	if !c.Editable || c.Gateway4 != "192.0.2.1" || c.Gateway6 != "2001:db8::1" || strings.Join(c.Addresses, ",") != "192.0.2.5/24,2001:db8::5/64" || c.DNS[0] != "9.9.9.9" {
		t.Fatalf("config: %+v", c)
	}
	if b, _ := u.Config("br0", ""); b.Editable || b.Reason != "advanced" {
		t.Fatalf("bridge: %+v", b)
	}
	c.Addresses = append(c.Addresses, "192.0.2.6/24")
	c.Routes = []StaticRoute{{To: "10.1.0.0/16", Via: "192.0.2.254"}}
	nc, _ := Normalize(c)
	p, err := u.Plan(context.Background(), nc, "")
	if err != nil {
		t.Fatal(err)
	}
	out := *p.Files[0].New
	for _, want := range []string{"allow-hotplug ens3\niface ens3 inet static\n    address 192.0.2.5/24\n    gateway 192.0.2.1\n    dns-nameservers 9.9.9.9\n    up ip route add 10.1.0.0/16 via 192.0.2.254\niface ens3 inet static\n    address 192.0.2.6/24\niface ens3 inet6 static\n    address 2001:db8::5/64\n    gateway 2001:db8::1\n\nauto br0", "bridge_ports ens4", "iface lo inet loopback"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
	if err := WriteFiles(root, p.Files, false); err != nil {
		t.Fatal(err)
	}
	c2, _ := u.Config("ens3", "")
	if len(c2.Addresses) != 3 || len(c2.Routes) != 1 || !c2.Editable {
		t.Fatalf("round trip: %+v", c2)
	}
	// A new interface is appended with auto.
	nc, _ = Normalize(IfaceConfig{Name: "ens5", DHCP4: true})
	p, err = u.Plan(context.Background(), nc, "")
	if err != nil || !strings.HasSuffix(*p.Files[0].New, "\nauto ens5\niface ens5 inet dhcp\n") {
		t.Fatalf("new: %v\n%s", err, *p.Files[0].New)
	}
	fr.calls = nil
	if err := u.Activate(context.Background(), p, false); err != nil {
		t.Fatal(err)
	}
	if len(fr.calls) != 2 || fr.calls[0].path != "/usr/sbin/ifdown" || fr.calls[1].path != "/usr/sbin/ifup" {
		t.Fatalf("activate: %+v", fr.calls)
	}
}

func TestNormalize(t *testing.T) {
	bad := []IfaceConfig{
		{Name: "eth0;rm"},
		{Name: "eth0", Addresses: []string{"10.0.0.1"}},
		{Name: "eth0", Addresses: []string{"127.0.0.1/8"}},
		{Name: "eth0", Gateway4: "10.0.0.1"},
		{Name: "eth0", DHCP4: true, Gateway4: "2001:db8::1"},
		{Name: "eth0", DHCP4: true, DNS: []string{"x"}},
		{Name: "eth0", DHCP4: true, Search: []string{"a b"}},
		{Name: "eth0", DHCP4: true, MTU: 100},
		{Name: "eth0", Addresses: []string{"2001:db8::2/64"}, MTU: 1000},
		{Name: "eth0", DHCP4: true, Routes: []StaticRoute{{To: "10.0.0.0/8", Via: "2001:db8::1"}}},
		{Name: "eth0", DHCP4: true, Routes: []StaticRoute{{To: "10.0.0.0/8", Via: "10.0.0.1", Metric: -1}}},
	}
	for i, c := range bad {
		if _, err := Normalize(c); err == nil {
			t.Errorf("%d accepted: %+v", i, c)
		}
	}
	c, err := Normalize(IfaceConfig{Name: "eth0", Addresses: []string{" 10.0.0.2/24", "10.0.0.2/24"}, Routes: []StaticRoute{{To: "default", Via: "10.0.0.1"}, {To: "10.9.1.7/16", Via: "10.0.0.3"}}})
	if err != nil || len(c.Addresses) != 1 || c.Gateway4 != "10.0.0.1" || len(c.Routes) != 1 || c.Routes[0].To != "10.9.0.0/16" {
		t.Fatalf("normalize: %+v %v", c, err)
	}
}

func TestParseHexAddrAndPorts(t *testing.T) {
	ip, port, ok := parseHexAddr("0100007F:0035")
	if !ok || ip.String() != "127.0.0.1" || port != 53 {
		t.Fatalf("%v %d", ip, port)
	}
	ip, port, ok = parseHexAddr("00000000000000000000000001000000:01BB")
	if !ok || ip.String() != "::1" || port != 443 {
		t.Fatalf("%v %d", ip, port)
	}
	root := t.TempDir()
	write(t, root, "/proc/net/tcp", "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"+
		"   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1111 1 0 100 0 0 10 0\n"+
		"   1: 0100007F:1F90 0100007F:9C40 01 00000000:00000000 00:00000000 00000000  1000        0 2222 1 0 100 0 0 10 0\n")
	write(t, root, "/proc/net/udp6", "  sl  local_address remote_address st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n"+
		"  10: 00000000000000000000000000000000:0222 00000000000000000000000000000000:0000 07 00000000:00000000 00:00000000 00000000   108        0 3333 2 0 0\n")
	write(t, root, "/proc/42/comm", "sshd\n")
	if err := os.MkdirAll(filepath.Join(root, "/proc/42/fd"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("socket:[1111]", filepath.Join(root, "/proc/42/fd/3")); err != nil {
		t.Fatal(err)
	}
	r := &Reader{Root: root}
	ps, err := r.Ports()
	if err != nil {
		t.Fatal(err)
	}
	if len(ps) != 2 || ps[0].Port != 22 || ps[0].Address != "0.0.0.0" || len(ps[0].Processes) != 1 || ps[0].Processes[0].Name != "sshd" ||
		ps[1].Proto != "udp6" || ps[1].Port != 546 || ps[1].UID != 108 {
		t.Fatalf("ports: %+v", ps)
	}
}

func TestRouteDevAndSession(t *testing.T) {
	routes := []Route{
		{Family: 4, To: "default", Via: "203.0.113.1", Dev: "eth0", Metric: 100},
		{Family: 4, To: "default", Via: "10.0.0.1", Dev: "eth1", Metric: 200},
		{Family: 4, To: "10.0.0.0/8", Dev: "eth1"},
		{Family: 6, To: "default", Via: "fe80::1", Dev: "eth0"},
	}
	cases := map[string]string{"198.51.100.7": "eth0", "10.2.3.4": "eth1", "2001:db8::9": "eth0", "::ffff:10.1.1.1": "eth1"}
	for ip, want := range cases {
		if got := RouteDev(routes, netip.MustParseAddr(ip)); got != want {
			t.Errorf("%s: %s, want %s", ip, got, want)
		}
	}
	st := State{Routes: routes, Interfaces: []Interface{{Name: "eth0"}, {Name: "eth1"}}}
	if st.MarkSession("10.9.9.9") != "eth1" || !st.Interfaces[1].Session || st.Interfaces[0].Session {
		t.Fatalf("session: %+v", st.Interfaces)
	}
	if st.MarkSession("127.0.0.1") != "" {
		t.Fatal("loopback session marked an interface")
	}
}

func TestDetectAndDNS(t *testing.T) {
	root := t.TempDir()
	write(t, root, "/usr/sbin/netplan", "")
	write(t, root, "/etc/netplan/50.yaml", "network: {version: 2}\n")
	d := &Detector{Root: root}
	m, b := d.Detect(nil)
	if m.Name != "netplan" || !m.Writable || b == nil || m.Renderer != "networkd" {
		t.Fatalf("netplan: %+v", m)
	}
	write(t, root, "/etc/network/interfaces", interfaces)
	if m, b = d.Detect(nil); m.Writable || m.Reason != "mixed" || b != nil {
		t.Fatalf("mixed: %+v", m)
	}
	_ = os.Remove(filepath.Join(root, "/etc/netplan/50.yaml"))
	write(t, root, "/usr/sbin/ifup", "")
	if m, b = d.Detect(nil); m.Name != "ifupdown" || !m.Writable || b == nil {
		t.Fatalf("ifupdown: %+v", m)
	}
	_ = os.Remove(filepath.Join(root, "/etc/network/interfaces"))
	d.Active = func(u string) bool { return u == "NetworkManager.service" }
	if m, _ = d.Detect(nil); m.Name != "networkmanager" || m.Writable {
		t.Fatalf("nm: %+v", m)
	}

	write(t, root, "/etc/resolv.conf", "# stub\nnameserver 127.0.0.53\nsearch example.org\n")
	write(t, root, "/run/systemd/resolve/resolv.conf", "nameserver 1.1.1.1\nnameserver 2606:4700::1111\nnameserver bogus\n")
	dns := (&Reader{Root: root}).DNS()
	if !dns.Resolved || len(dns.Servers) != 2 || dns.Search[0] != "example.org" {
		t.Fatalf("dns: %+v", dns)
	}
	write(t, root, "/proc/sys/kernel/hostname", "vm1\n")
	write(t, root, "/etc/hosts", "127.0.0.1 localhost\n127.0.1.1 vm1.example.org vm1 # main\n")
	if h, dom := (&Reader{Root: root}).Hostname(); h != "vm1" || dom != "example.org" {
		t.Fatalf("hostname %s %s", h, dom)
	}
}

func TestUnifiedDiff(t *testing.T) {
	a, b := "a\nb\nc\nd\n", "a\nB\nc\nd\ne\n"
	d := UnifiedDiff("/x", &a, &b)
	if !strings.Contains(d, "-b\n+B\n") || !strings.Contains(d, "+e") || !strings.HasPrefix(d, "--- a/x\n+++ b/x\n") {
		t.Fatalf("diff:\n%s", d)
	}
	if d := UnifiedDiff("/x", nil, &b); !strings.HasPrefix(d, "--- /dev/null") {
		t.Fatal(d)
	}
}

func TestReadLive(t *testing.T) {
	st, err := (&Reader{}).Read()
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Interfaces) == 0 || st.Interfaces[0].Kind != "loopback" || !strings.Contains(strings.Join(st.Interfaces[0].Addresses, ","), "127.0.0.1/8") {
		t.Fatalf("live: %+v", st.Interfaces)
	}
	if _, err := (&Reader{}).Ports(); err != nil {
		t.Fatal(err)
	}
}
