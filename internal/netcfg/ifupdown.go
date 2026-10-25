package netcfg

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Ifupdown edits /etc/network/interfaces (Debian's classic configuration).
// The stanzas of the edited interface are replaced; everything else in the
// file stays as it is.
type Ifupdown struct {
	Root string
	Run  Runner
}

const interfacesFile = "/etc/network/interfaces"

type stanza struct {
	iface, family, method string
	opts                  [][2]string // option, value
	start, end            int         // line range [start, end)
}

type ifState struct {
	lines     []string
	stanzas   []stanza
	auto      map[string]bool
	hasSource bool
}

var stanzaStarts = []string{"iface", "auto", "allow-", "mapping", "source", "source-directory", "rename"}

func isStanzaStart(f string) bool {
	return slices.ContainsFunc(stanzaStarts, func(s string) bool { return f == s || (s == "allow-" && strings.HasPrefix(f, s)) })
}

func parseInterfaces(text string) (ifState, error) {
	st := ifState{lines: strings.Split(strings.TrimSuffix(text, "\n"), "\n"), auto: map[string]bool{}}
	cur := -1
	closeCur := func(i int) {
		if cur >= 0 {
			st.stanzas[cur].end = i
			cur = -1
		}
	}
	for i, line := range st.lines {
		f := strings.Fields(line)
		if len(f) == 0 || strings.HasPrefix(f[0], "#") {
			continue
		}
		if isStanzaStart(f[0]) {
			closeCur(i)
			switch {
			case f[0] == "iface" && len(f) >= 4:
				st.stanzas = append(st.stanzas, stanza{iface: f[1], family: f[2], method: f[3], start: i, end: i + 1})
				cur = len(st.stanzas) - 1
			case f[0] == "auto" || strings.HasPrefix(f[0], "allow-"):
				for _, n := range f[1:] {
					st.auto[n] = true
				}
			case f[0] == "source" || f[0] == "source-directory":
				st.hasSource = true
			}
			continue
		}
		if cur >= 0 {
			st.stanzas[cur].opts = append(st.stanzas[cur].opts, [2]string{f[0], strings.Join(f[1:], " ")})
			st.stanzas[cur].end = i + 1
		}
	}
	closeCur(len(st.lines))
	// Trailing blank/comment lines belong to no stanza.
	for i := range st.stanzas {
		for st.stanzas[i].end > st.stanzas[i].start+1 && strings.TrimSpace(st.lines[st.stanzas[i].end-1]) == "" {
			st.stanzas[i].end--
		}
	}
	return st, nil
}

var routeUpRE = regexp.MustCompile(`^ip (-6 )?route add (\S+) via (\S+)(?: metric (\d+))?$`)

var ifupManaged = []string{"address", "netmask", "gateway", "mtu", "dns-nameservers", "dns-search", "up", "down"}

func (u *Ifupdown) load() (ifState, string, error) {
	b, err := os.ReadFile(filepath.Join(u.Root, interfacesFile))
	if err != nil {
		return ifState{}, "", err
	}
	st, err := parseInterfaces(string(b))
	return st, string(b), err
}

// Config implements Backend.
func (u *Ifupdown) Config(name, _ string) (IfaceConfig, error) {
	st, _, err := u.load()
	if err != nil {
		return IfaceConfig{}, err
	}
	c := IfaceConfig{Name: name, Addresses: []string{}, DNS: []string{}, Search: []string{}, Routes: []StaticRoute{}, Source: interfacesFile, Editable: true}
	found := false
	for _, s := range st.stanzas {
		if s.iface != name {
			continue
		}
		found = true
		switch s.family + " " + s.method {
		case "inet dhcp":
			c.DHCP4 = true
		case "inet6 dhcp":
			c.DHCP6 = true
		case "inet static", "inet6 static":
			addr, mask := "", ""
			for _, o := range s.opts {
				switch o[0] {
				case "address":
					addr = o[1]
				case "netmask":
					mask = o[1]
				case "gateway":
					if s.family == "inet" {
						c.Gateway4 = o[1]
					} else {
						c.Gateway6 = o[1]
					}
				}
			}
			if a := cidr(addr, mask, s.family == "inet6"); a != "" {
				c.Addresses = append(c.Addresses, a)
			} else {
				c.Editable = false
			}
		case "inet manual", "inet6 manual":
		default:
			c.Editable = false // loopback, auto (SLAAC), ppp, …
		}
		for _, o := range s.opts {
			switch o[0] {
			case "address", "netmask", "gateway":
			case "mtu":
				c.MTU, _ = strconv.Atoi(o[1])
			case "dns-nameservers":
				c.DNS = append(c.DNS, strings.Fields(o[1])...)
			case "dns-search":
				c.Search = append(c.Search, strings.Fields(o[1])...)
			case "up":
				m := routeUpRE.FindStringSubmatch(o[1])
				if m == nil {
					c.Editable = false
					continue
				}
				r := StaticRoute{To: m[2], Via: m[3]}
				r.Metric, _ = strconv.Atoi(m[4])
				c.Routes = append(c.Routes, r)
			case "down":
				if !strings.HasPrefix(o[1], "ip route del ") && !strings.HasPrefix(o[1], "ip -6 route del ") {
					c.Editable = false
				}
			default:
				if !slices.Contains(ifupManaged, o[0]) {
					c.Editable = false
				}
			}
		}
	}
	switch {
	case !found && st.hasSource:
		c.Editable, c.Reason = false, "several_files"
	case !found:
		c.Reason = "not_configured"
	case !c.Editable:
		c.Reason = "advanced"
	}
	return c, nil
}

// cidr combines "address" and the optional "netmask" (dotted or prefix length).
func cidr(addr, mask string, v6 bool) string {
	if p, err := netip.ParsePrefix(addr); err == nil {
		return p.String()
	}
	ip, err := netip.ParseAddr(addr)
	if err != nil || ip.Is6() != v6 {
		return ""
	}
	if mask == "" {
		if v6 {
			return netip.PrefixFrom(ip, 64).String()
		}
		return netip.PrefixFrom(ip, 32).String()
	}
	if n, err := strconv.Atoi(mask); err == nil {
		return netip.PrefixFrom(ip, n).String()
	}
	m, err := netip.ParseAddr(mask)
	if err != nil || !m.Is4() {
		return ""
	}
	b := m.As4()
	bits := 0
	for _, x := range b {
		for i := 7; i >= 0; i-- {
			if x&(1<<i) != 0 {
				bits++
			}
		}
	}
	return netip.PrefixFrom(ip, bits).String()
}

// render builds the stanzas for cfg.
func render(cfg IfaceConfig) []string {
	var v4, v6 []string
	for _, a := range cfg.Addresses {
		if strings.Contains(a, ":") {
			v6 = append(v6, a)
		} else {
			v4 = append(v4, a)
		}
	}
	var out []string
	extra := func() {
		if cfg.MTU > 0 {
			out = append(out, "    mtu "+strconv.Itoa(cfg.MTU))
		}
		if len(cfg.DNS) > 0 {
			out = append(out, "    dns-nameservers "+strings.Join(cfg.DNS, " "))
		}
		if len(cfg.Search) > 0 {
			out = append(out, "    dns-search "+strings.Join(cfg.Search, " "))
		}
		for _, r := range cfg.Routes {
			fam := ""
			if strings.Contains(r.Via, ":") {
				fam = "-6 "
			}
			m := ""
			if r.Metric > 0 {
				m = " metric " + strconv.Itoa(r.Metric)
			}
			out = append(out, "    up ip "+fam+"route add "+r.To+" via "+r.Via+m)
		}
	}
	first := true
	stanzaFor := func(family, method, addr, gw string) {
		out = append(out, "iface "+cfg.Name+" "+family+" "+method)
		if addr != "" {
			out = append(out, "    address "+addr)
		}
		if gw != "" {
			out = append(out, "    gateway "+gw)
		}
		if first {
			extra()
			first = false
		}
	}
	switch {
	case cfg.DHCP4:
		stanzaFor("inet", "dhcp", "", "")
	case len(v4) > 0:
		stanzaFor("inet", "static", v4[0], cfg.Gateway4)
		v4 = v4[1:]
	case !cfg.DHCP6 && len(v6) == 0:
		stanzaFor("inet", "manual", "", "")
	}
	for _, a := range v4 {
		stanzaFor("inet", "static", a, "")
	}
	switch {
	case cfg.DHCP6:
		stanzaFor("inet6", "dhcp", "", "")
	case len(v6) > 0:
		stanzaFor("inet6", "static", v6[0], cfg.Gateway6)
		v6 = v6[1:]
	}
	for _, a := range v6 {
		stanzaFor("inet6", "static", a, "")
	}
	return out
}

// Plan implements Backend.
func (u *Ifupdown) Plan(ctx context.Context, cfg IfaceConfig, mac string) (Plan, error) {
	cur, err := u.Config(cfg.Name, mac)
	if err != nil {
		return Plan{}, err
	}
	if !cur.Editable {
		return Plan{}, invalid("this interface cannot be edited here (%s)", cur.Reason)
	}
	st, raw, err := u.load()
	if err != nil {
		return Plan{}, err
	}
	var lines []string
	inserted := false
	newStanzas := render(cfg)
	skip := map[int]bool{}
	for _, s := range st.stanzas {
		if s.iface == cfg.Name {
			for i := s.start; i < s.end; i++ {
				skip[i] = true
			}
		}
	}
	for i, l := range st.lines {
		if skip[i] {
			if !inserted {
				lines = append(lines, newStanzas...)
				inserted = true
			}
			continue
		}
		lines = append(lines, l)
	}
	if !inserted {
		if len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) != "" {
			lines = append(lines, "")
		}
		if !st.auto[cfg.Name] {
			lines = append(lines, "auto "+cfg.Name)
		}
		lines = append(lines, newStanzas...)
	}
	out := strings.Join(lines, "\n") + "\n"
	if out == raw {
		return Plan{}, invalid("no change")
	}
	fc := FileChange{Path: interfacesFile, Old: ptr(raw), New: ptr(out)}
	p := Plan{Manager: "ifupdown", Iface: cfg.Name, Files: []FileChange{fc}, Diff: UnifiedDiff(fc.Path, fc.Old, fc.New), Old: &cur, New: &cfg}
	return p, u.validate(ctx, p)
}

func (u *Ifupdown) validate(ctx context.Context, p Plan) error {
	f, err := os.CreateTemp("", "daemonica-interfaces-")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(f.Name()) }()
	_, err = f.WriteString(*p.Files[0].New)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	res, err := u.Run(ctx, 30*time.Second, "/usr/sbin/ifquery", "--interfaces="+f.Name(), p.Iface)
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return invalid("ifupdown rejects the configuration: %s", firstLine(res.Stderr))
	}
	return nil
}

// Activate implements Backend: take the interface down with the configuration
// it was brought up with, switch the file and bring it up again.
func (u *Ifupdown) Activate(ctx context.Context, p Plan, rollback bool) error {
	_, _ = u.Run(ctx, time.Minute, "/usr/sbin/ifdown", "--force", p.Iface)
	if err := WriteFiles(u.Root, p.Files, rollback); err != nil {
		return err
	}
	res, err := u.Run(ctx, 2*time.Minute, "/usr/sbin/ifup", p.Iface)
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return invalid("ifup failed: %s", firstLine(res.Stderr))
	}
	return nil
}
