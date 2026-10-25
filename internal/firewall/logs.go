package firewall

import (
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/PanPakaPancake/daemonica/internal/netcfg"
)

// LogEntry is one parsed firewall log line (SPEC §7.6 M1.5c). Only parsed and
// validated fields leave the helper; the kernel line itself is untrusted.
type LogEntry struct {
	Time      time.Time `json:"time"`
	Action    string    `json:"action"` // allow, block, audit, log
	Limit     bool      `json:"limit,omitempty"`
	Prefix    string    `json:"prefix"` // e.g. "UFW BLOCK" (sanitised)
	Direction string    `json:"direction"`
	In        string    `json:"in,omitempty"`
	Out       string    `json:"out,omitempty"`
	Src       string    `json:"src"`
	Dst       string    `json:"dst"`
	Proto     string    `json:"proto"`
	SPort     int       `json:"spt,omitempty"`
	DPort     int       `json:"dpt,omitempty"`
	Flags     []string  `json:"flags,omitempty"`
	Len       int       `json:"len,omitempty"`
	TTL       int       `json:"ttl,omitempty"`
	V6        bool      `json:"v6,omitempty"`
}

var (
	prefixRE = regexp.MustCompile(`^[A-Za-z0-9 _:.\-]{0,40}$`)
	protoRE  = regexp.MustCompile(`^[A-Za-z0-9]{1,12}$`)
	tcpFlags = []string{"SYN", "ACK", "FIN", "RST", "PSH", "URG"}
)

// ParseLog parses a netfilter LOG line ("[UFW BLOCK] IN=eth0 OUT= MAC=…
// SRC=… DST=… LEN=60 … PROTO=TCP SPT=… DPT=… SYN URGP=0"). Lines without
// valid SRC and DST addresses are not firewall logs.
func ParseLog(msg string, at time.Time) (LogEntry, bool) {
	i := strings.Index(msg, "IN=")
	if i < 0 {
		return LogEntry{}, false
	}
	e := LogEntry{Time: at}
	prefix := strings.TrimSpace(msg[:i])
	prefix = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(prefix, "["), "]"))
	if !prefixRE.MatchString(prefix) {
		prefix = "?"
	}
	e.Prefix = prefix
	up := strings.ToUpper(prefix)
	switch {
	case strings.Contains(up, "BLOCK") || strings.Contains(up, "DROP") || strings.Contains(up, "DENY") || strings.Contains(up, "REJECT"):
		e.Action = "block"
	case strings.Contains(up, "ALLOW") || strings.Contains(up, "ACCEPT"):
		e.Action = "allow"
	case strings.Contains(up, "AUDIT"):
		e.Action = "audit"
	default:
		e.Action = "log"
	}
	e.Limit = strings.Contains(up, "LIMIT")
	for _, f := range strings.Fields(msg[i:]) {
		k, v, kv := strings.Cut(f, "=")
		if !kv {
			if slices.Contains(tcpFlags, f) {
				e.Flags = append(e.Flags, f)
			}
			continue
		}
		switch k {
		case "IN":
			if v == "" || netcfg.ValidIface(v) {
				e.In = v
			}
		case "OUT":
			if v == "" || netcfg.ValidIface(v) {
				e.Out = v
			}
		case "SRC", "DST":
			a, err := netip.ParseAddr(v)
			if err != nil {
				return LogEntry{}, false
			}
			if k == "SRC" {
				e.Src = a.String()
			} else {
				e.Dst = a.String()
			}
			e.V6 = a.Is6() && !a.Is4In6()
		case "PROTO":
			if protoRE.MatchString(v) {
				e.Proto = strings.ToLower(v)
			}
		case "SPT":
			e.SPort = port(v)
		case "DPT":
			e.DPort = port(v)
		case "LEN":
			if e.Len == 0 { // the first LEN is the IP length
				e.Len, _ = strconv.Atoi(v)
			}
		case "TTL", "HOPLIMIT":
			e.TTL, _ = strconv.Atoi(v)
		}
	}
	if e.Src == "" || e.Dst == "" {
		return LogEntry{}, false
	}
	switch {
	case e.In != "" && e.Out != "":
		e.Direction = "forward"
	case e.Out != "":
		e.Direction = "out"
	default:
		e.Direction = "in"
	}
	return e, true
}

func port(v string) int {
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 || n > 65535 {
		return 0
	}
	return n
}

// LogFilter selects log entries; empty fields match everything.
type LogFilter struct {
	Action string `json:"action,omitempty"`
	Src    string `json:"src,omitempty"` // IP, CIDR or substring
	Dst    string `json:"dst,omitempty"`
	SPort  string `json:"spt,omitempty"`
	DPort  string `json:"dpt,omitempty"`
	Proto  string `json:"proto,omitempty"`
	Iface  string `json:"iface,omitempty"` // IN or OUT
	Dir    string `json:"direction,omitempty"`
	Text   string `json:"text,omitempty"` // substring of any field
}

// Validate checks the lengths.
func (f LogFilter) Validate() error {
	for _, v := range []string{f.Action, f.Src, f.Dst, f.SPort, f.DPort, f.Proto, f.Iface, f.Dir, f.Text} {
		if len(v) > 100 || strings.ContainsAny(v, "\x00\n\r") {
			return invalid("invalid filter")
		}
	}
	return nil
}

func addrMatch(filter, addr string) bool {
	if filter == "" {
		return true
	}
	if p, ok := prefix(filter); ok {
		a, err := netip.ParseAddr(addr)
		return err == nil && p.Contains(a)
	}
	return strings.Contains(addr, filter)
}

func portMatch(filter string, p int) bool {
	return filter == "" || PortMatches(strings.ReplaceAll(filter, "-", ":"), p) && p != 0
}

// Match reports whether e passes the filter.
func (f LogFilter) Match(e LogEntry) bool {
	switch {
	case f.Action != "" && f.Action != e.Action:
		return false
	case f.Proto != "" && !strings.EqualFold(f.Proto, e.Proto):
		return false
	case f.Dir != "" && f.Dir != e.Direction:
		return false
	case f.Iface != "" && !strings.Contains(e.In, f.Iface) && !strings.Contains(e.Out, f.Iface):
		return false
	case !addrMatch(f.Src, e.Src) || !addrMatch(f.Dst, e.Dst):
		return false
	case !portMatch(f.SPort, e.SPort) || !portMatch(f.DPort, e.DPort):
		return false
	}
	if f.Text != "" {
		t := strings.ToLower(f.Text)
		hay := strings.ToLower(strings.Join([]string{e.Prefix, e.Action, e.In, e.Out, e.Src, e.Dst, e.Proto, strconv.Itoa(e.SPort), strconv.Itoa(e.DPort), strings.Join(e.Flags, " ")}, " "))
		if !strings.Contains(hay, t) {
			return false
		}
	}
	return true
}
