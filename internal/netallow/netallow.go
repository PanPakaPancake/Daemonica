// Package netallow enforces the dashboard's network allowlist at accept time,
// before any TLS handshake (SPEC §3.6). The remote address is always the TCP
// peer address; forwarding headers are never consulted.
package netallow

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync/atomic"
)

// Allowlist is a concurrency-safe, atomically replaceable set of prefixes.
type Allowlist struct {
	p atomic.Pointer[[]netip.Prefix]
	// OnReject is called for each rejected connection (for rate-limited logging/audit).
	OnReject func(addr netip.Addr)
	// OnChange is called after Set; used to terminate live sessions/terminals
	// whose source IP is no longer allowed (SPEC M1.4).
	OnChange func()
}

// Loopback is the default allowlist (setup mode and fresh installs).
var Loopback = []netip.Prefix{
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("::1/128"),
}

// New returns an allowlist initialized to the given prefixes (loopback if empty).
func New(prefixes []netip.Prefix) *Allowlist {
	a := &Allowlist{}
	if len(prefixes) == 0 {
		prefixes = Loopback
	}
	a.Set(prefixes)
	return a
}

// Set atomically replaces the allowlist.
func (a *Allowlist) Set(prefixes []netip.Prefix) {
	cp := make([]netip.Prefix, len(prefixes))
	for i, p := range prefixes {
		cp[i] = p.Masked()
	}
	a.p.Store(&cp)
	if a.OnChange != nil {
		a.OnChange()
	}
}

// Prefixes returns a copy of the current list.
func (a *Allowlist) Prefixes() []netip.Prefix {
	cur := *a.p.Load()
	out := make([]netip.Prefix, len(cur))
	copy(out, cur)
	return out
}

// Contains reports whether addr is allowed. IPv4-mapped IPv6 addresses are unmapped first.
func (a *Allowlist) Contains(addr netip.Addr) bool {
	addr = addr.Unmap()
	for _, p := range *a.p.Load() {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// ParseList parses a list of CIDR strings (or bare addresses, as /32 or /128).
// It rejects zones and empty input entries.
func ParseList(items []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(items))
	seen := map[netip.Prefix]bool{}
	for _, raw := range items {
		s := strings.TrimSpace(raw)
		if s == "" {
			return nil, errors.New("empty allowlist entry")
		}
		var p netip.Prefix
		if strings.Contains(s, "/") {
			pp, err := netip.ParsePrefix(s)
			if err != nil {
				return nil, fmt.Errorf("invalid CIDR %q", s)
			}
			p = pp.Masked()
		} else {
			addr, err := netip.ParseAddr(s)
			if err != nil || addr.Zone() != "" {
				return nil, fmt.Errorf("invalid address %q", s)
			}
			addr = addr.Unmap()
			p = netip.PrefixFrom(addr, addr.BitLen())
		}
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out, nil
}

// IsPublic reports whether the list effectively exposes the dashboard to the
// whole Internet (0.0.0.0/0 or ::/0, or very short prefixes).
func IsPublic(prefixes []netip.Prefix) bool {
	for _, p := range prefixes {
		if (p.Addr().Is4() && p.Bits() < 8) || (p.Addr().Is6() && p.Bits() < 7) {
			return true
		}
	}
	return false
}

// Listener wraps a net.Listener and drops connections from disallowed peers
// immediately after accept, before any bytes are read.
type Listener struct {
	net.Listener
	Allow *Allowlist
}

// Accept returns only connections from allowed peers.
func (l *Listener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		addr, ok := peerAddr(c)
		if ok && l.Allow.Contains(addr) {
			return c, nil
		}
		if tc, isTCP := c.(*net.TCPConn); isTCP {
			_ = tc.SetLinger(0) // RST, no lingering state
		}
		_ = c.Close()
		if l.Allow.OnReject != nil && ok {
			l.Allow.OnReject(addr)
		}
	}
}

func peerAddr(c net.Conn) (netip.Addr, bool) {
	ta, ok := c.RemoteAddr().(*net.TCPAddr)
	if !ok {
		return netip.Addr{}, false
	}
	ap := ta.AddrPort()
	return ap.Addr().Unmap(), ap.Addr().IsValid()
}

// RemoteAddr extracts the peer IP from an http.Request.RemoteAddr style string.
func RemoteAddr(hostport string) (netip.Addr, bool) {
	ap, err := netip.ParseAddrPort(hostport)
	if err != nil {
		return netip.Addr{}, false
	}
	return ap.Addr().Unmap(), true
}
