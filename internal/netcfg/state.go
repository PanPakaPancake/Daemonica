// Package netcfg reads the network state of the host and changes its
// configuration through the active network manager (SPEC §7.6, M1.5a).
//
// The state is read directly from the kernel (netlink, /sys, /proc) as
// SPEC §4.1 prefers; only applying a configuration runs the manager's tools.
package netcfg

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
)

// Interface is one network interface.
type Interface struct {
	Name  string `json:"name"`
	Index int    `json:"index"`
	// Kind is ethernet, loopback, vlan, bridge, bond, wireless, virtual or other.
	Kind      string   `json:"kind"`
	State     string   `json:"state"` // operstate: up, down, unknown, …
	MAC       string   `json:"mac,omitempty"`
	MTU       int      `json:"mtu"`
	SpeedMbit int      `json:"speed_mbit,omitempty"`
	Addresses []string `json:"addresses"` // CIDR, v4 and v6
	// Parent is the lower device of a VLAN; Members the ports of a bridge or bond.
	Parent  string   `json:"parent,omitempty"`
	VLANID  int      `json:"vlan_id,omitempty"`
	Members []string `json:"members,omitempty"`
	Master  string   `json:"master,omitempty"`
	// Session is true when the dashboard session of the caller runs over this interface.
	Session bool `json:"session,omitempty"`
}

// Route is one route of the main table.
type Route struct {
	Family   int    `json:"family"` // 4 or 6
	To       string `json:"to"`     // CIDR, "default" for 0.0.0.0/0 and ::/0
	Via      string `json:"via,omitempty"`
	Dev      string `json:"dev,omitempty"`
	Metric   int    `json:"metric,omitempty"`
	Protocol string `json:"protocol,omitempty"` // kernel, boot, static, dhcp, ra, …
	Src      string `json:"src,omitempty"`
}

// DNS is the resolver configuration.
type DNS struct {
	Servers []string `json:"servers"`
	Search  []string `json:"search"`
	// Resolved is true when systemd-resolved runs as stub (servers are its upstreams).
	Resolved bool `json:"resolved"`
}

// State is the read-only network view.
type State struct {
	Hostname   string      `json:"hostname"`
	Domain     string      `json:"domain,omitempty"`
	Interfaces []Interface `json:"interfaces"`
	Routes     []Route     `json:"routes"`
	Gateways   []string    `json:"gateways"`
	DNS        DNS         `json:"dns"`
	Manager    Manager     `json:"manager"`
}

// Reader reads the state; Root prefixes /sys, /proc and /etc (tests).
type Reader struct {
	Root string
	// links and rib are replaceable in tests.
	links func() ([]net.Interface, error)
	rib   func(proto int) ([]byte, error)
}

func (r *Reader) path(p string) string { return filepath.Join(r.Root, p) }

func (r *Reader) netLinks() ([]net.Interface, error) {
	if r.links != nil {
		return r.links()
	}
	return net.Interfaces()
}

func (r *Reader) netRIB(proto int) ([]byte, error) {
	if r.rib != nil {
		return r.rib(proto)
	}
	return syscall.NetlinkRIB(proto, syscall.AF_UNSPEC)
}

// Interfaces lists the interfaces with addresses and kernel details.
func (r *Reader) Interfaces() ([]Interface, error) {
	links, err := r.netLinks()
	if err != nil {
		return nil, err
	}
	addrs, err := r.addresses()
	if err != nil {
		return nil, err
	}
	byIndex := map[int]string{}
	for _, l := range links {
		byIndex[l.Index] = l.Name
	}
	out := make([]Interface, 0, len(links))
	for _, l := range links {
		sys := r.path("/sys/class/net/" + l.Name)
		it := Interface{Name: l.Name, Index: l.Index, MTU: l.MTU, Addresses: addrs[l.Index], State: readTrim(sys + "/operstate")}
		if it.Addresses == nil {
			it.Addresses = []string{}
		}
		if len(l.HardwareAddr) > 0 {
			it.MAC = l.HardwareAddr.String()
		}
		if v, err := strconv.Atoi(readTrim(sys + "/speed")); err == nil && v > 0 {
			it.SpeedMbit = v
		}
		it.Kind = r.kind(l, sys)
		if m, err := os.Readlink(sys + "/master"); err == nil {
			it.Master = filepath.Base(m)
		}
		switch it.Kind {
		case "bridge":
			it.Members = dirNames(sys + "/brif")
		case "bond":
			it.Members = strings.Fields(readTrim(sys + "/bonding/slaves"))
		case "vlan":
			it.Parent, it.VLANID = r.vlan(l.Name)
		}
		out = append(out, it)
	}
	slices.SortFunc(out, func(a, b Interface) int { return a.Index - b.Index })
	return out, nil
}

func (r *Reader) kind(l net.Interface, sys string) string {
	switch {
	case l.Flags&net.FlagLoopback != 0:
		return "loopback"
	case exists(sys + "/bridge"):
		return "bridge"
	case exists(sys + "/bonding"):
		return "bond"
	case exists(r.path("/proc/net/vlan/" + l.Name)):
		return "vlan"
	case exists(sys + "/wireless"), exists(sys + "/phy80211"):
		return "wireless"
	case !exists(sys + "/device"):
		return "virtual"
	case readTrim(sys+"/type") == "1":
		return "ethernet"
	}
	return "other"
}

// vlan reads the lower device and VLAN id from /proc/net/vlan/<name>.
func (r *Reader) vlan(name string) (string, int) {
	b, err := os.ReadFile(r.path("/proc/net/vlan/" + name)) //nolint:gosec // fixed /proc path
	if err != nil {
		return "", 0
	}
	var parent string
	var id int
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		for i := 0; i+1 < len(f); i++ {
			switch f[i] {
			case "VID:":
				id, _ = strconv.Atoi(f[i+1])
			case "Device:":
				parent = f[i+1]
			}
		}
	}
	return parent, id
}

// addresses returns the addresses per interface index from RTM_GETADDR.
func (r *Reader) addresses() (map[int][]string, error) {
	b, err := r.netRIB(syscall.RTM_GETADDR)
	if err != nil {
		return nil, err
	}
	msgs, err := syscall.ParseNetlinkMessage(b)
	if err != nil {
		return nil, err
	}
	out := map[int][]string{}
	for i := range msgs {
		m := &msgs[i]
		if m.Header.Type != syscall.RTM_NEWADDR || len(m.Data) < syscall.SizeofIfAddrmsg {
			continue
		}
		// struct ifaddrmsg: family, prefixlen, flags, scope (u8), index (u32).
		prefixLen, index := int(m.Data[1]), int(binary.NativeEndian.Uint32(m.Data[4:8]))
		attrs, err := syscall.ParseNetlinkRouteAttr(m)
		if err != nil {
			continue
		}
		var addr []byte
		for _, a := range attrs {
			// IFA_LOCAL is the own address on point-to-point links; IFA_ADDRESS otherwise.
			if a.Attr.Type == syscall.IFA_LOCAL || (a.Attr.Type == syscall.IFA_ADDRESS && addr == nil) {
				addr = a.Value
			}
		}
		ip, ok := netip.AddrFromSlice(addr)
		if !ok {
			continue
		}
		p := netip.PrefixFrom(ip.Unmap(), prefixLen)
		out[index] = append(out[index], p.String())
	}
	return out, nil
}

var routeProtocols = map[uint8]string{0: "unspec", 1: "redirect", 2: "kernel", 3: "boot", 4: "static", 16: "dhcp", 9: "ra", 11: "zebra", 12: "bird", 15: "dhcp", 42: "babel", 186: "bgp", 187: "isis", 188: "ospf"}

// Routes lists the unicast routes of the main table.
func (r *Reader) Routes(names map[int]string) ([]Route, error) {
	b, err := r.netRIB(syscall.RTM_GETROUTE)
	if err != nil {
		return nil, err
	}
	msgs, err := syscall.ParseNetlinkMessage(b)
	if err != nil {
		return nil, err
	}
	out := []Route{}
	for i := range msgs {
		m := &msgs[i]
		if m.Header.Type != syscall.RTM_NEWROUTE || len(m.Data) < syscall.SizeofRtMsg {
			continue
		}
		// struct rtmsg: family, dst_len, src_len, tos, table, protocol, scope, type (u8), flags (u32).
		rt := struct{ Family, DstLen, Table, Protocol, Type uint8 }{m.Data[0], m.Data[1], m.Data[4], m.Data[5], m.Data[7]}
		if rt.Type != syscall.RTN_UNICAST || (rt.Family != syscall.AF_INET && rt.Family != syscall.AF_INET6) {
			continue
		}
		attrs, err := syscall.ParseNetlinkRouteAttr(m)
		if err != nil {
			continue
		}
		table := uint32(rt.Table)
		ro := Route{Family: 4, Protocol: routeProtocols[rt.Protocol]}
		if rt.Family == syscall.AF_INET6 {
			ro.Family = 6
		}
		var dst netip.Addr
		for _, a := range attrs {
			switch a.Attr.Type {
			case syscall.RTA_DST:
				dst, _ = netip.AddrFromSlice(a.Value)
			case syscall.RTA_GATEWAY:
				if ip, ok := netip.AddrFromSlice(a.Value); ok {
					ro.Via = ip.Unmap().String()
				}
			case syscall.RTA_OIF:
				if len(a.Value) >= 4 {
					ro.Dev = names[int(binary.NativeEndian.Uint32(a.Value))]
				}
			case syscall.RTA_PRIORITY:
				if len(a.Value) >= 4 {
					ro.Metric = int(binary.NativeEndian.Uint32(a.Value))
				}
			case syscall.RTA_PREFSRC:
				if ip, ok := netip.AddrFromSlice(a.Value); ok {
					ro.Src = ip.Unmap().String()
				}
			case syscall.RTA_TABLE:
				if len(a.Value) >= 4 {
					table = binary.NativeEndian.Uint32(a.Value)
				}
			}
		}
		if table != syscall.RT_TABLE_MAIN {
			continue
		}
		if rt.DstLen == 0 {
			ro.To = "default"
		} else if dst.IsValid() {
			ro.To = netip.PrefixFrom(dst.Unmap(), int(rt.DstLen)).String()
		} else {
			continue
		}
		// fe80::/64 on every interface is noise.
		if ro.Family == 6 && strings.HasPrefix(ro.To, "fe80::/64") {
			continue
		}
		out = append(out, ro)
	}
	return out, nil
}

// DNS reads the resolver configuration. With the systemd-resolved stub the
// upstream servers come from /run/systemd/resolve/resolv.conf.
func (r *Reader) DNS() DNS {
	d := parseResolvConf(r.path("/etc/resolv.conf"))
	if len(d.Servers) == 1 && d.Servers[0] == "127.0.0.53" {
		up := parseResolvConf(r.path("/run/systemd/resolve/resolv.conf"))
		up.Resolved = true
		if len(up.Search) == 0 {
			up.Search = d.Search
		}
		return up
	}
	return d
}

func parseResolvConf(path string) DNS {
	d := DNS{Servers: []string{}, Search: []string{}}
	f, err := os.Open(path) //nolint:gosec // fixed resolver paths
	if err != nil {
		return d
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fl := strings.Fields(sc.Text())
		if len(fl) < 2 || strings.HasPrefix(fl[0], "#") || strings.HasPrefix(fl[0], ";") {
			continue
		}
		switch fl[0] {
		case "nameserver":
			if _, err := netip.ParseAddr(fl[1]); err == nil {
				d.Servers = append(d.Servers, fl[1])
			}
		case "search", "domain":
			d.Search = fl[1:]
		}
	}
	return d
}

// Hostname returns the host name and the domain from /etc/hosts (the FQDN
// listed for the host name), as `hostname -d` would without DNS lookups.
func (r *Reader) Hostname() (string, string) {
	host := readTrim(r.path("/proc/sys/kernel/hostname"))
	if host == "" {
		host, _ = os.Hostname()
	}
	b, _ := os.ReadFile(r.path("/etc/hosts"))
	for _, line := range bytes.Split(b, []byte("\n")) {
		if i := bytes.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		f := strings.Fields(string(line))
		if len(f) < 2 || !slices.Contains(f[1:], host) {
			continue
		}
		for _, n := range f[1:] {
			if strings.HasPrefix(n, host+".") {
				return host, strings.TrimPrefix(n, host+".")
			}
		}
	}
	return host, ""
}

// Read collects the whole state.
func (r *Reader) Read() (State, error) {
	ifs, err := r.Interfaces()
	if err != nil {
		return State{}, err
	}
	names := map[int]string{}
	for _, i := range ifs {
		names[i.Index] = i.Name
	}
	routes, err := r.Routes(names)
	if err != nil {
		return State{}, err
	}
	st := State{Interfaces: ifs, Routes: routes, Gateways: []string{}, DNS: r.DNS()}
	st.Hostname, st.Domain = r.Hostname()
	for _, ro := range routes {
		if ro.To == "default" && ro.Via != "" && !slices.Contains(st.Gateways, ro.Via) {
			st.Gateways = append(st.Gateways, ro.Via)
		}
	}
	return st, nil
}

// RouteDev returns the interface the kernel would use to reach ip (longest
// prefix match over the main table; ties broken by the lower metric).
func RouteDev(routes []Route, ip netip.Addr) string {
	ip = ip.Unmap()
	best, bestLen, bestMetric := "", -1, 0
	for _, ro := range routes {
		if (ro.Family == 4) != ip.Is4() || ro.Dev == "" {
			continue
		}
		var p netip.Prefix
		if ro.To == "default" {
			if ip.Is4() {
				p = netip.MustParsePrefix("0.0.0.0/0")
			} else {
				p = netip.MustParsePrefix("::/0")
			}
		} else {
			var err error
			if p, err = netip.ParsePrefix(ro.To); err != nil {
				continue
			}
		}
		if !p.Contains(ip) {
			continue
		}
		if p.Bits() > bestLen || (p.Bits() == bestLen && ro.Metric < bestMetric) {
			best, bestLen, bestMetric = ro.Dev, p.Bits(), ro.Metric
		}
	}
	return best
}

// MarkSession flags the interface that carries traffic to the client.
func (st *State) MarkSession(client string) string {
	ip, err := netip.ParseAddr(client)
	if err != nil {
		return ""
	}
	dev := RouteDev(st.Routes, ip)
	if ip.IsLoopback() {
		dev = ""
	}
	for i := range st.Interfaces {
		st.Interfaces[i].Session = dev != "" && st.Interfaces[i].Name == dev
	}
	return dev
}

func readTrim(p string) string {
	b, err := os.ReadFile(p) //nolint:gosec // /sys and /proc paths built from kernel names
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func dirNames(p string) []string {
	ents, err := os.ReadDir(p)
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(ents))
	for _, e := range ents {
		out = append(out, e.Name())
	}
	return out
}
