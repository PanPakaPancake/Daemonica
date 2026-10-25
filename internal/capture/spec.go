package capture

import (
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Defaults and maxima (SPEC §7.6 M1.5d).
const (
	DefaultDuration = 5 * time.Minute
	MaxDuration     = 30 * time.Minute
	DefaultPackets  = 100_000
	MaxPackets      = 10_000_000
	DefaultSize     = 100 << 20
	MaxSize         = 1 << 30
	HeaderSnaplen   = 96
	FullSnaplen     = 65535
)

var (
	ifaceRE = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,15}$`)
	// exprRE is the character allowlist for free BPF expressions: no quotes,
	// no shell or option characters beyond those BPF needs.
	exprRE = regexp.MustCompile(`^[A-Za-z0-9 .:/()\[\]!&|=<>+*-]{1,512}$`)
)

// Builder is the guided filter (the BPF expression is generated here).
type Builder struct {
	Proto string   `json:"proto,omitempty"` // tcp, udp, icmp, arp, "" = any
	Host  string   `json:"host,omitempty"`  // IP or CIDR
	Ports []int    `json:"ports,omitempty"`
	Dir   string   `json:"dir,omitempty"` // src, dst, "" = both
}

// Spec is a capture request.
type Spec struct {
	Template string  `json:"template,omitempty"` // shown in the list only
	Iface    string  `json:"iface"`
	Builder  Builder `json:"builder"`
	// Expr is the free BPF expression ("Erweitert"); it replaces the builder.
	Expr           string `json:"expr,omitempty"`
	DurationSec    int    `json:"duration_sec,omitempty"`
	Packets        int    `json:"packets,omitempty"`
	SizeBytes      int64  `json:"size_bytes,omitempty"`
	FullPackets    bool   `json:"full_packets,omitempty"`
	Promisc        bool   `json:"promisc,omitempty"`
	IncludeDash    bool   `json:"include_dashboard,omitempty"` // do not exclude the dashboard traffic
	DashboardPort  int    `json:"-"`
	AcceptWarning  bool   `json:"accept_warning"`
	AcceptFullWarn bool   `json:"accept_full_warning,omitempty"`
}

// ErrValidation reports an invalid spec; the message is safe to show.
type ErrValidation struct{ Msg string }

func (e *ErrValidation) Error() string { return e.Msg }

func invalid(f string, a ...any) error { return &ErrValidation{Msg: fmt.Sprintf(f, a...)} }

// ValidIface checks the interface name (existence is checked by the caller).
func ValidIface(s string) bool { return ifaceRE.MatchString(s) }

// Normalize fills defaults and validates the spec.
func (s Spec) Normalize() (Spec, error) {
	if !s.AcceptWarning {
		return s, invalid("the privacy warning must be accepted")
	}
	if !ValidIface(s.Iface) || s.Iface == "any" {
		return s, invalid("invalid interface")
	}
	if s.DurationSec == 0 {
		s.DurationSec = int(DefaultDuration / time.Second)
	}
	if s.DurationSec < 1 || time.Duration(s.DurationSec)*time.Second > MaxDuration {
		return s, invalid("duration must be 1 s to 30 min")
	}
	if s.Packets == 0 {
		s.Packets = DefaultPackets
	}
	if s.Packets < 1 || s.Packets > MaxPackets {
		return s, invalid("packet limit must be 1 to %d", MaxPackets)
	}
	if s.SizeBytes == 0 {
		s.SizeBytes = DefaultSize
	}
	if s.SizeBytes < 1<<20 || s.SizeBytes > MaxSize {
		return s, invalid("size limit must be 1 MiB to 1 GiB")
	}
	if s.FullPackets && !s.AcceptFullWarn {
		return s, invalid("full packets need the additional warning to be accepted")
	}
	if len(s.Template) > 32 || strings.ContainsAny(s.Template, "\x00\n\r") {
		return s, invalid("invalid template")
	}
	if s.Expr != "" {
		s.Expr = strings.Join(strings.Fields(s.Expr), " ")
		if !exprRE.MatchString(s.Expr) || strings.HasPrefix(s.Expr, "-") {
			return s, invalid("the filter expression contains characters that are not allowed")
		}
		return s, nil
	}
	b := s.Builder
	if b.Proto != "" && !slices.Contains([]string{"tcp", "udp", "icmp", "arp"}, b.Proto) {
		return s, invalid("invalid protocol")
	}
	if b.Dir != "" && b.Dir != "src" && b.Dir != "dst" {
		return s, invalid("invalid direction")
	}
	if b.Host != "" {
		if p, err := netip.ParsePrefix(b.Host); err == nil {
			b.Host = p.Masked().String()
		} else if a, err := netip.ParseAddr(b.Host); err == nil && a.Zone() == "" {
			b.Host = a.String()
		} else {
			return s, invalid("invalid host or network")
		}
	}
	if len(b.Ports) > 10 {
		return s, invalid("at most 10 ports")
	}
	for _, p := range b.Ports {
		if p < 1 || p > 65535 {
			return s, invalid("ports must be 1–65535")
		}
	}
	if len(b.Ports) > 0 && (b.Proto == "icmp" || b.Proto == "arp") {
		return s, invalid("%s has no ports", b.Proto)
	}
	s.Builder = b
	return s, nil
}

// Snaplen is the bytes captured per packet.
func (s Spec) Snaplen() int {
	if s.FullPackets {
		return FullSnaplen
	}
	return HeaderSnaplen
}

// Filter returns the BPF expression passed to tcpdump (one argv element).
func (s Spec) Filter() string {
	var parts []string
	if s.Expr != "" {
		parts = append(parts, "("+s.Expr+")")
	} else {
		b := s.Builder
		dir := ""
		if b.Dir != "" {
			dir = b.Dir + " "
		}
		switch b.Proto {
		case "icmp":
			parts = append(parts, "(icmp or icmp6)")
		case "tcp", "udp", "arp":
			parts = append(parts, b.Proto)
		}
		if b.Host != "" {
			kw := "host "
			if strings.Contains(b.Host, "/") {
				kw = "net "
			}
			parts = append(parts, dir+kw+b.Host)
		}
		if len(b.Ports) > 0 {
			ps := make([]string, len(b.Ports))
			for i, p := range b.Ports {
				ps[i] = dir + "port " + strconv.Itoa(p)
			}
			parts = append(parts, "("+strings.Join(ps, " or ")+")")
		}
	}
	if !s.IncludeDash && s.DashboardPort > 0 {
		parts = append(parts, "not (tcp port "+strconv.Itoa(s.DashboardPort)+")")
	}
	return strings.Join(parts, " and ")
}

// Args is the tcpdump argv (after the program path). Capture only: the raw
// pcap stream goes to stdout, no name resolution, no dissection.
func (s Spec) Args() []string {
	a := []string{"tcpdump", "-i", s.Iface, "-s", strconv.Itoa(s.Snaplen()), "-U", "-n", "-w", "-", "-c", strconv.Itoa(s.Packets)}
	if !s.Promisc {
		a = append(a, "-p")
	}
	if f := s.Filter(); f != "" {
		a = append(a, "--", f)
	}
	return a
}

// CompileArgs checks the filter without capturing (tcpdump -d).
func (s Spec) CompileArgs() []string {
	a := []string{"-d", "-i", s.Iface, "-s", strconv.Itoa(s.Snaplen())}
	if f := s.Filter(); f != "" {
		a = append(a, "--", f)
	}
	return a
}
