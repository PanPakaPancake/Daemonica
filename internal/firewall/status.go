package firewall

import (
	"context"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"
)

// Backends.
const (
	BackendUfw       = "ufw"
	BackendFirewalld = "firewalld"
	BackendNftables  = "nftables"
	BackendIptables  = "iptables"
	BackendNone      = "none"
)

// Detector finds the firewall in use. Active reports whether a systemd unit runs.
type Detector struct {
	Root   string
	Run    Runner
	Active func(unit string) bool
}

func (d *Detector) exists(p string) bool { _, err := os.Stat(d.Root + p); return err == nil }

// Detect returns the backend. ufw is managed; firewalld wins over it because
// it would overwrite ufw's rules, and plain nftables/iptables are read-only.
func (d *Detector) Detect(ctx context.Context) string {
	switch {
	case d.Active != nil && d.Active("firewalld.service"):
		return BackendFirewalld
	case d.exists(ufwBin):
		return BackendUfw
	}
	if d.exists(nftBin) {
		if res, err := d.Run(ctx, 30*time.Second, nftBin, "list", "tables"); err == nil && res.ExitCode == 0 && strings.TrimSpace(string(res.Stdout)) != "" {
			return BackendNftables
		}
	}
	if d.exists(iptablesSave) {
		if res, err := d.Run(ctx, 30*time.Second, iptablesSave); err == nil && res.ExitCode == 0 && strings.Contains(string(res.Stdout), "\n-A ") {
			return BackendIptables
		}
	}
	return BackendNone
}

const (
	nftBin        = "/usr/sbin/nft"
	iptablesSave  = "/usr/sbin/iptables-save"
	ip6tablesSave = "/usr/sbin/ip6tables-save"
	maxRaw        = 2 << 20
)

// Raw returns the kernel rule set as text with counters: nft list ruleset,
// or iptables-save -c for both families.
func (d *Detector) Raw(ctx context.Context) (source, text string, err error) {
	if d.exists(nftBin) {
		res, err := d.Run(ctx, 30*time.Second, nftBin, "list", "ruleset")
		if err == nil && res.ExitCode == 0 {
			return "nft list ruleset", clip(string(res.Stdout)), nil
		}
	}
	var b strings.Builder
	for _, bin := range []string{iptablesSave, ip6tablesSave} {
		if !d.exists(bin) {
			continue
		}
		res, err := d.Run(ctx, 30*time.Second, bin, "-c")
		if err != nil {
			return "", "", err
		}
		b.Write(res.Stdout)
	}
	return "iptables-save -c", clip(b.String()), nil
}

func clip(s string) string {
	if len(s) > maxRaw {
		return s[:maxRaw] + "\n… (truncated)\n"
	}
	return s
}

// Hint is one finding of the status light; the UI words it via i18n.
type Hint struct {
	Code  string `json:"code"`
	Level string `json:"level"` // red, yellow
	Arg   string `json:"arg,omitempty"`
}

// Listener is a listening socket (from netcfg.Ports) reduced to what the
// status needs.
type Listener struct {
	Proto   string // tcp, udp
	Port    int
	V6      bool
	Local   bool // bound to loopback only
	Process string
}

// Light computes the status light (SPEC §7.6 M1.5b). host6 says whether the
// server has a global IPv6 address.
func Light(c Config, active bool, host6 bool, ls []Listener) (string, []Hint) {
	var hs []Hint
	if !active {
		hs = append(hs, Hint{Code: "inactive", Level: "red"})
	}
	if c.Defaults.Incoming == "allow" {
		hs = append(hs, Hint{Code: "default_allow", Level: "red"})
	}
	if active && !c.Enabled {
		hs = append(hs, Hint{Code: "not_persistent", Level: "yellow"})
	}
	if active && !c.IPv6 && host6 {
		hs = append(hs, Hint{Code: "ipv6_off", Level: "yellow"})
	}
	if active && c.Logging == "off" {
		hs = append(hs, Hint{Code: "logging_off", Level: "yellow"})
	}
	seen := map[string]bool{}
	for _, r := range c.Rules {
		if r.Direction != "in" || (r.Action != "allow" && r.Action != "limit") || r.DPort == "any" || strings.ContainsAny(r.DPort, ",:") {
			continue
		}
		port, err := strconv.Atoi(r.DPort)
		if err != nil || seen[r.DPort+r.Proto] {
			continue
		}
		listening := false
		for _, l := range ls {
			if l.Port == port && !l.Local && (r.Proto == "any" || r.Proto == l.Proto) {
				listening = true
			}
		}
		if !listening {
			seen[r.DPort+r.Proto] = true
			arg := r.DPort
			if r.Proto != "any" {
				arg += "/" + r.Proto
			}
			hs = append(hs, Hint{Code: "unused_allow", Level: "yellow", Arg: arg})
		}
	}
	light := "green"
	for _, h := range hs {
		if h.Level == "red" {
			return "red", hs
		}
		light = "yellow"
	}
	if hs == nil {
		hs = []Hint{}
	}
	return light, hs
}

// HasGlobal6 reports whether any address is a global unicast IPv6 address.
func HasGlobal6(addrs []netip.Addr) bool {
	for _, a := range addrs {
		if a.Is6() && !a.Is4In6() && a.IsGlobalUnicast() && !a.IsPrivate() {
			return true
		}
	}
	return false
}
