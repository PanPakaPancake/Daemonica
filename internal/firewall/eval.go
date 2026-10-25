package firewall

import (
	"net/netip"
	"strconv"
	"strings"
)

// Packet is a new incoming connection to evaluate against the rules.
type Packet struct {
	// Src is the client address; the zero value means "some host on the
	// internet" (rules that allow only specific sources do not match).
	Src   netip.Addr
	V6    bool   // address family when Src is unset
	Iface string // interface the packet arrives on ("" = unknown)
	Proto string // tcp or udp
	Port  int
	// Host are the server's addresses on that interface (destination match).
	Host []netip.Addr
}

// Verdict is the effect of the firewall on a packet.
type Verdict struct {
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason"` // inactive, unfiltered, loopback, rule, default
	Rule    int    `json:"rule,omitempty"`
	Action  string `json:"action,omitempty"`
	Limited bool   `json:"limited,omitempty"`
}

// Evaluate simulates ufw's first-match evaluation of the user rules for a new
// incoming connection. It is conservative where the rule set cannot be decided
// from the packet: deny rules for specific destinations or source ports are
// assumed to match, allow rules for them are not.
func Evaluate(c Config, active bool, p Packet) Verdict {
	switch {
	case !active:
		return Verdict{Allowed: true, Reason: "inactive"}
	case p.Src.IsValid() && p.Src.IsLoopback():
		return Verdict{Allowed: true, Reason: "loopback"} // before.rules accept lo
	}
	v6 := p.V6
	if p.Src.IsValid() {
		v6 = p.Src.Is6() && !p.Src.Is4In6()
	}
	if v6 && !c.IPv6 {
		return Verdict{Allowed: true, Reason: "unfiltered"}
	}
	for _, r := range c.Rules {
		if r.V6 != v6 || r.Direction != "in" {
			continue
		}
		deny := r.Action == "deny" || r.Action == "reject"
		if !ruleMatches(r, p, deny) {
			continue
		}
		return Verdict{Allowed: !deny, Reason: "rule", Rule: r.Num, Action: r.Action, Limited: r.Action == "limit"}
	}
	return Verdict{Allowed: c.Defaults.Incoming == "allow", Reason: "default", Action: c.Defaults.Incoming}
}

func ruleMatches(r Rule, p Packet, deny bool) bool {
	if r.Iface != "" && p.Iface != "" && r.Iface != p.Iface {
		return false
	}
	if r.Iface != "" && p.Iface == "" && !deny {
		return false
	}
	if r.Proto != "any" && r.Proto != p.Proto {
		return false
	}
	if !PortMatches(r.DPort, p.Port) {
		return false
	}
	if r.SPort != "any" && r.SPort != "" && !deny {
		return false
	}
	if r.Src != "any" {
		pre, ok := prefix(r.Src)
		if !ok || !p.Src.IsValid() || !pre.Contains(p.Src.Unmap()) {
			return false
		}
	}
	if r.Dst != "any" {
		pre, ok := prefix(r.Dst)
		if !ok {
			return deny
		}
		hit := false
		for _, h := range p.Host {
			hit = hit || pre.Contains(h.Unmap())
		}
		if !hit && !(deny && len(p.Host) == 0) {
			return false
		}
	}
	return true
}

func prefix(s string) (netip.Prefix, bool) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p, true
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return netip.PrefixFrom(a, a.BitLen()), true
	}
	return netip.Prefix{}, false
}

// PortMatches reports whether port is in a ufw port spec (any, 22, 80,443, 6000:6010).
func PortMatches(spec string, port int) bool {
	if spec == "any" || spec == "" {
		return true
	}
	for _, part := range strings.Split(spec, ",") {
		lo, hi, rng := strings.Cut(part, ":")
		a, err := strconv.Atoi(lo)
		if err != nil {
			continue
		}
		b := a
		if rng {
			if b, err = strconv.Atoi(hi); err != nil {
				continue
			}
		}
		if port >= a && port <= b {
			return true
		}
	}
	return false
}

// Access describes how a port can be reached from outside.
type Access struct {
	Verdict
	// Restricted: blocked for arbitrary hosts, but rules allow specific sources.
	Restricted bool `json:"restricted,omitempty"`
}

// Reach evaluates a listening port for an arbitrary internet host.
func Reach(c Config, active bool, proto string, port int, v6 bool, host []netip.Addr) Access {
	v := Evaluate(c, active, Packet{V6: v6, Proto: proto, Port: port, Host: host})
	a := Access{Verdict: v}
	if !v.Allowed {
		for _, r := range c.Rules {
			if r.V6 == v6 && r.Direction == "in" && (r.Action == "allow" || r.Action == "limit") && r.Src != "any" &&
				(r.Proto == "any" || r.Proto == proto) && PortMatches(r.DPort, port) {
				a.Restricted = true
				break
			}
		}
	}
	return a
}
