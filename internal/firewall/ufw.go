// Package firewall reads the host firewall and changes it through ufw
// (SPEC §7.6 M1.5b, A-12: ufw is the managed backend, others are read-only).
package firewall

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/PanPakaPancake/daemonica/internal/netcfg"
)

// Runner runs a program (netcfg.ExecRunner in production).
type Runner = netcfg.Runner

// Rule is one ufw rule as stored in user.rules / user6.rules.
type Rule struct {
	Num       int    `json:"num"` // ufw's rule number (status numbered)
	V6        bool   `json:"v6"`
	Action    string `json:"action"` // allow, deny, reject, limit
	Log       string `json:"log,omitempty"`
	Direction string `json:"direction"` // in, out, route
	Iface     string `json:"iface,omitempty"`
	OutIface  string `json:"out_iface,omitempty"`
	Proto     string `json:"proto"` // tcp, udp, any, …
	DPort     string `json:"dport"` // any, 22, 80,443, 1000:2000
	SPort     string `json:"sport"`
	Dst       string `json:"dst"` // any or CIDR
	Src       string `json:"src"`
	App       string `json:"app,omitempty"`
	SApp      string `json:"sapp,omitempty"`
	Comment   string `json:"comment,omitempty"`
	Managed   bool   `json:"managed"` // comment daemonica:<app>:<purpose> (SPEC §9.1)
	Packets   uint64 `json:"packets"`
	Bytes     uint64 `json:"bytes"`
	Counted   bool   `json:"counted"`
	tuple     string
	lines     []string // iptables rules ufw generated for the tuple
}

// Tuple is the rule's identity in the rules file (used to verify deletes).
func (r Rule) Tuple() string { return r.tuple }

// Defaults are the default policies (allow, deny, reject; routed may be disabled).
type Defaults struct {
	Incoming string `json:"incoming"`
	Outgoing string `json:"outgoing"`
	Routed   string `json:"routed"`
}

// Ufw reads and changes ufw. Root prefixes files (tests).
type Ufw struct {
	Root string
	Run  Runner
}

const (
	ufwBin     = "/usr/sbin/ufw"
	userRules  = "/etc/ufw/user.rules"
	user6Rules = "/etc/ufw/user6.rules"
	ufwConf    = "/etc/ufw/ufw.conf"
	ufwDefault = "/etc/default/ufw"
)

// SnapshotFiles are the files that hold ufw's whole configurable state
// ("ufw reset" also replaces the before/after rules).
var SnapshotFiles = []string{userRules, user6Rules, ufwConf, ufwDefault,
	"/etc/ufw/before.rules", "/etc/ufw/before6.rules", "/etc/ufw/after.rules", "/etc/ufw/after6.rules", "/etc/ufw/sysctl.conf"}

// fileMode is the mode ufw's packages give each file.
func fileMode(f string) os.FileMode {
	if strings.HasSuffix(f, ".rules") {
		return 0o640
	}
	return 0o644
}

func (u *Ufw) path(p string) string { return filepath.Join(u.Root, p) }

// Installed reports whether ufw is present.
func (u *Ufw) Installed() bool { _, err := os.Stat(u.path(ufwBin)); return err == nil }

// keyValues reads KEY=value lines (shell syntax, quotes removed).
func keyValues(p string) map[string]string {
	out := map[string]string{}
	b, err := os.ReadFile(p) //nolint:gosec // fixed ufw paths
	if err != nil {
		return out
	}
	for _, l := range strings.Split(string(b), "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		k, v, ok := strings.Cut(l, "=")
		if ok {
			out[k] = strings.Trim(v, `"'`)
		}
	}
	return out
}

func policyName(p string) string {
	switch strings.ToUpper(p) {
	case "ACCEPT":
		return "allow"
	case "REJECT":
		return "reject"
	case "DROP":
		return "deny"
	}
	return strings.ToLower(p)
}

// Config is ufw's stored configuration (independent of whether it runs).
type Config struct {
	Enabled  bool     `json:"enabled"` // ENABLED=yes: active after reboot
	Logging  string   `json:"logging"` // off, low, medium, high, full
	IPv6     bool     `json:"ipv6"`
	Defaults Defaults `json:"defaults"`
	Rules    []Rule   `json:"rules"`
}

// ReadConfig reads the rule files and settings.
func (u *Ufw) ReadConfig() (Config, error) {
	conf := keyValues(u.path(ufwConf))
	def := keyValues(u.path(ufwDefault))
	c := Config{Enabled: strings.EqualFold(conf["ENABLED"], "yes"), Logging: strings.ToLower(conf["LOGLEVEL"]), IPv6: strings.EqualFold(def["IPV6"], "yes"),
		Defaults: Defaults{Incoming: policyName(def["DEFAULT_INPUT_POLICY"]), Outgoing: policyName(def["DEFAULT_OUTPUT_POLICY"]), Routed: policyName(def["DEFAULT_FORWARD_POLICY"])}}
	if c.Logging == "" {
		c.Logging = "off"
	}
	if c.Defaults.Incoming == "" {
		c.Defaults = Defaults{"deny", "allow", "deny"}
	}
	if readTrim(u.path("/proc/sys/net/ipv4/ip_forward")) == "0" {
		c.Defaults.Routed = "disabled"
	}
	r4, err := parseRules(u.path(userRules), false)
	if err != nil && !os.IsNotExist(err) {
		return c, err
	}
	r6, err := parseRules(u.path(user6Rules), true)
	if err != nil && !os.IsNotExist(err) {
		return c, err
	}
	c.Rules = append(r4, r6...)
	for i := range c.Rules {
		c.Rules[i].Num = i + 1
	}
	if c.Rules == nil {
		c.Rules = []Rule{}
	}
	return c, nil
}

func readTrim(p string) string {
	b, err := os.ReadFile(p) //nolint:gosec // /proc paths
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func parseRules(p string, v6 bool) ([]Rule, error) {
	f, err := os.Open(p) //nolint:gosec // fixed ufw paths
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	var out []Rule
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	cur := -1
	for sc.Scan() {
		l := sc.Text()
		switch {
		case strings.HasPrefix(l, "### tuple ### "):
			r, ok := parseTuple(strings.TrimPrefix(l, "### tuple ### "))
			if !ok {
				cur = -1
				continue
			}
			r.V6 = v6
			out = append(out, r)
			cur = len(out) - 1
		case strings.HasPrefix(l, "-A ") && cur >= 0:
			out[cur].lines = append(out[cur].lines, l)
		case strings.HasPrefix(l, "### "):
			cur = -1
		}
	}
	return out, sc.Err()
}

func anyAddr(a string) string {
	if a == "0.0.0.0/0" || a == "::/0" || a == "" {
		return "any"
	}
	return a
}

func unescapeApp(s string) string {
	if s == "-" {
		return ""
	}
	return strings.ReplaceAll(s, "%20", " ")
}

// parseTuple reads "action proto dport dst sport src [dapp sapp] direction [comment=hex]".
func parseTuple(s string) (Rule, bool) {
	f := strings.Fields(s)
	var comment string
	if n := len(f); n > 0 && strings.HasPrefix(f[n-1], "comment=") {
		if b, err := hex.DecodeString(strings.TrimPrefix(f[n-1], "comment=")); err == nil {
			comment = string(b)
		}
		f = f[:n-1]
	}
	if len(f) != 7 && len(f) != 9 {
		return Rule{}, false
	}
	r := Rule{tuple: s, Proto: f[1], DPort: f[2], Dst: anyAddr(f[3]), SPort: f[4], Src: anyAddr(f[5]), Comment: comment}
	dir := f[6]
	if len(f) == 9 {
		r.App, r.SApp, dir = unescapeApp(f[6]), unescapeApp(f[7]), f[8]
	}
	action := f[0]
	if a, ok := strings.CutPrefix(action, "route:"); ok {
		action, r.Direction = a, "route"
	}
	if a, l, ok := strings.Cut(action, "_"); ok { // allow_log, allow_log-all
		action, r.Log = a, strings.ReplaceAll(l, "_", "-")
	}
	r.Action = action
	// direction: in, out, in_eth0, out_eth0, in_eth0!out_eth1 (route)
	for _, part := range strings.Split(dir, "!") {
		d, iface, _ := strings.Cut(part, "_")
		switch {
		case r.Direction == "route" && d == "out":
			r.OutIface = iface
		case r.Direction == "route":
			r.Iface = iface
		default:
			r.Direction, r.Iface = d, iface
		}
	}
	r.Managed = strings.HasPrefix(r.Comment, "daemonica:")
	return r, true
}

// Active asks ufw whether the firewall is running.
func (u *Ufw) Active(ctx context.Context) (bool, error) {
	res, err := u.Run(ctx, 30*time.Second, ufwBin, "status")
	if err != nil {
		return false, err
	}
	return strings.HasPrefix(strings.TrimSpace(string(res.Stdout)), "Status: active"), nil
}

var counterRE = regexp.MustCompile(`^\[(\d+):(\d+)\] (-A \S+) `)

// AddCounters fills packet/byte counters from iptables-save -c: the n-th rule
// ufw generated in a chain is the n-th rule of that chain in the kernel.
func (u *Ufw) AddCounters(ctx context.Context, rules []Rule) {
	for _, v6 := range []bool{false, true} {
		bin := "/usr/sbin/iptables-save"
		if v6 {
			bin = "/usr/sbin/ip6tables-save"
		}
		res, err := u.Run(ctx, 30*time.Second, bin, "-c", "-t", "filter")
		if err != nil || res.ExitCode != 0 {
			continue
		}
		live := map[string][][2]uint64{} // chain → counters in order
		for _, l := range strings.Split(string(res.Stdout), "\n") {
			m := counterRE.FindStringSubmatch(l)
			if m == nil {
				continue
			}
			p, _ := strconv.ParseUint(m[1], 10, 64)
			b, _ := strconv.ParseUint(m[2], 10, 64)
			live[m[3]] = append(live[m[3]], [2]uint64{p, b})
		}
		pos := map[string]int{}
		for i := range rules {
			r := &rules[i]
			if r.V6 != v6 {
				continue
			}
			for _, l := range r.lines {
				f := strings.Fields(l)
				if len(f) < 2 {
					continue
				}
				chain := "-A " + f[1]
				n := pos[chain]
				pos[chain]++
				if n >= len(live[chain]) || !terminal(l) {
					continue
				}
				r.Packets += live[chain][n][0]
				r.Bytes += live[chain][n][1]
				r.Counted = true
			}
		}
	}
}

// terminal reports the rule line that decides (and so counts) the packet.
func terminal(l string) bool {
	for _, t := range []string{"-j ACCEPT", "-j DROP", "-j REJECT", "-j ufw-user-limit-accept"} {
		if strings.Contains(l, t) {
			return true
		}
	}
	return false
}

// Apps lists ufw's application profiles.
func (u *Ufw) Apps(ctx context.Context) ([]string, error) {
	res, err := u.Run(ctx, 30*time.Second, ufwBin, "app", "list")
	if err != nil {
		return nil, err
	}
	var out []string
	for _, l := range strings.Split(string(res.Stdout), "\n") {
		if strings.HasPrefix(l, "  ") && strings.TrimSpace(l) != "" {
			out = append(out, strings.TrimSpace(l))
		}
	}
	slices.Sort(out)
	return out, nil
}

// AppPorts returns the ports of an application profile ("22/tcp", "80,443/tcp").
func (u *Ufw) AppPorts(ctx context.Context, app string) ([]string, error) {
	res, err := u.Run(ctx, 30*time.Second, ufwBin, "app", "info", app)
	if err != nil {
		return nil, err
	}
	var out []string
	in := false
	for _, l := range strings.Split(string(res.Stdout), "\n") {
		t := strings.TrimSpace(l)
		switch {
		case strings.HasPrefix(t, "Port:") || strings.HasPrefix(t, "Ports:"):
			in = true
			if v := strings.TrimSpace(t[strings.IndexByte(t, ':')+1:]); v != "" {
				out = append(out, v)
			}
		case in && t != "":
			out = append(out, t)
		}
	}
	return out, nil
}

// --- changes ---

var (
	portRE    = regexp.MustCompile(`^([0-9]{1,5}(:[0-9]{1,5})?)(,[0-9]{1,5}(:[0-9]{1,5})?){0,14}$`)
	commentRE = regexp.MustCompile(`^[\p{L}\p{N} _.,:;/()@+#=-]{0,80}$`)
	appRE     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._+-]{0,63}$`)
)

// AddSpec is a rule to add.
type AddSpec struct {
	Action    string `json:"action"`    // allow, deny, reject, limit
	Direction string `json:"direction"` // in, out
	Iface     string `json:"iface,omitempty"`
	Proto     string `json:"proto"` // tcp, udp, any
	Port      string `json:"port,omitempty"`
	App       string `json:"app,omitempty"`
	From      string `json:"from"` // any or IP/CIDR
	To        string `json:"to"`
	Comment   string `json:"comment,omitempty"`
	// AppPorts are filled by the planner for app rules (lockout evaluation).
	AppPorts []string `json:"app_ports,omitempty"`
}

func validAddr(a string) (string, bool) {
	if a == "" || a == "any" {
		return "any", true
	}
	if p, err := netip.ParsePrefix(a); err == nil {
		return p.Masked().String(), true
	}
	if ip, err := netip.ParseAddr(a); err == nil && !ip.Is4In6() {
		return ip.String(), true
	}
	return "", false
}

// Normalize validates the spec.
func (s AddSpec) Normalize() (AddSpec, error) {
	if !slices.Contains([]string{"allow", "deny", "reject", "limit"}, s.Action) {
		return s, invalid("invalid action")
	}
	if s.Direction == "" {
		s.Direction = "in"
	}
	if s.Direction != "in" && s.Direction != "out" {
		return s, invalid("invalid direction")
	}
	if s.Iface != "" && !netcfg.ValidIface(s.Iface) {
		return s, invalid("invalid interface")
	}
	var ok bool
	if s.From, ok = validAddr(strings.TrimSpace(s.From)); !ok {
		return s, invalid("invalid source address")
	}
	if s.To, ok = validAddr(strings.TrimSpace(s.To)); !ok {
		return s, invalid("invalid destination address")
	}
	f, t := s.From, s.To
	if f != "any" && t != "any" && strings.Contains(f, ":") != strings.Contains(t, ":") {
		return s, invalid("source and destination must be the same IP version")
	}
	if !commentRE.MatchString(s.Comment) {
		return s, invalid("the comment may contain letters, digits and simple punctuation (max. 80)")
	}
	if s.App != "" {
		if !appRE.MatchString(s.App) {
			return s, invalid("invalid application profile")
		}
		s.Port, s.Proto = "", "any"
		return s, nil
	}
	if s.Proto == "" {
		s.Proto = "any"
	}
	if !slices.Contains([]string{"tcp", "udp", "any"}, s.Proto) {
		return s, invalid("invalid protocol")
	}
	s.Port = strings.ReplaceAll(strings.TrimSpace(s.Port), " ", "")
	if s.Port != "" {
		if !portRE.MatchString(s.Port) {
			return s, invalid("invalid port (e.g. 22, 80,443 or 6000:6010)")
		}
		for _, part := range strings.Split(strings.ReplaceAll(s.Port, ":", ","), ",") {
			if n, _ := strconv.Atoi(part); n < 1 || n > 65535 {
				return s, invalid("ports must be 1–65535")
			}
		}
		if (strings.ContainsAny(s.Port, ",:")) && s.Proto == "any" {
			return s, invalid("port lists and ranges need tcp or udp")
		}
	}
	if s.Port == "" && s.Action == "limit" {
		return s, invalid("limit needs a port")
	}
	return s, nil
}

// Args builds the ufw command line (argv, never a shell).
func (s AddSpec) Args() []string {
	a := []string{s.Action, s.Direction}
	if s.Iface != "" {
		a = append(a, "on", s.Iface)
	}
	if s.App == "" && s.Proto != "any" {
		a = append(a, "proto", s.Proto)
	}
	a = append(a, "from", s.From, "to", s.To)
	switch {
	case s.App != "":
		a = append(a, "app", s.App)
	case s.Port != "":
		a = append(a, "port", s.Port)
	}
	if s.Comment != "" {
		a = append(a, "comment", s.Comment)
	}
	return a
}

// Rules returns the ufw rules this spec creates (ufw adds a v4 and a v6
// rule when no address pins the version and IPv6 is on).
func (s AddSpec) Rules(ipv6 bool) []Rule {
	base := Rule{Action: s.Action, Direction: s.Direction, Iface: s.Iface, Proto: s.Proto, DPort: s.Port, SPort: "any", Dst: s.To, Src: s.From,
		App: s.App, Comment: s.Comment, Managed: strings.HasPrefix(s.Comment, "daemonica:")}
	if base.DPort == "" {
		base.DPort = "any"
	}
	if s.App != "" && len(s.AppPorts) > 0 {
		base.DPort, base.Proto = portsOf(s.AppPorts)
	}
	v6only := strings.Contains(s.From, ":") || strings.Contains(s.To, ":")
	v4only := (s.From != "any" && !strings.Contains(s.From, ":")) || (s.To != "any" && !strings.Contains(s.To, ":"))
	var out []Rule
	if !v6only {
		out = append(out, base)
	}
	if ipv6 && !v4only {
		r := base
		r.V6 = true
		out = append(out, r)
	}
	return out
}

// portsOf turns app ports ("80,443/tcp", "22/tcp") into one dport/proto.
func portsOf(ps []string) (string, string) {
	var ports []string
	proto := ""
	for _, p := range ps {
		pp, pr, _ := strings.Cut(p, "/")
		ports = append(ports, pp)
		if proto == "" {
			proto = pr
		} else if pr != proto {
			proto = "any"
		}
	}
	if proto == "" {
		proto = "any"
	}
	return strings.Join(ports, ","), proto
}

// ErrValidation reports an invalid request; the message is safe to show.
type ErrValidation struct{ Msg string }

func (e *ErrValidation) Error() string { return e.Msg }

func invalid(format string, a ...any) error { return &ErrValidation{Msg: fmt.Sprintf(format, a...)} }

// Snapshot is the saved ufw state for a rollback.
type Snapshot struct {
	Files  map[string]*string `json:"files"`
	Active bool               `json:"active"`
}

// TakeSnapshot saves the configuration files and whether ufw runs.
func (u *Ufw) TakeSnapshot(ctx context.Context) (Snapshot, error) {
	s := Snapshot{Files: map[string]*string{}}
	for _, f := range SnapshotFiles {
		b, err := os.ReadFile(u.path(f)) //nolint:gosec // fixed ufw paths
		switch {
		case err == nil:
			v := string(b)
			s.Files[f] = &v
		case os.IsNotExist(err):
			s.Files[f] = nil
		default:
			return s, err
		}
	}
	var err error
	s.Active, err = u.Active(ctx)
	return s, err
}

// Restore writes the saved files back and brings ufw into the saved state.
func (u *Ufw) Restore(ctx context.Context, s Snapshot) error {
	var changes []netcfg.FileChange
	for _, f := range SnapshotFiles {
		v, ok := s.Files[f]
		if !ok {
			continue
		}
		changes = append(changes, netcfg.FileChange{Path: f, New: v})
	}
	if err := netcfg.WriteFiles(u.Root, changes, false); err != nil {
		return err
	}
	// netcfg writes 0600 outside /etc/network; restore ufw's modes.
	for _, f := range SnapshotFiles {
		if v, ok := s.Files[f]; ok && v != nil {
			_ = os.Chmod(u.path(f), fileMode(f))
		}
	}
	args := []string{"--force", "disable"}
	if s.Active {
		args = []string{"--force", "enable"} // reloads the restored rules
	}
	return u.ufw(ctx, args...)
}

func (u *Ufw) ufw(ctx context.Context, args ...string) error {
	res, err := u.Run(ctx, 2*time.Minute, ufwBin, args...)
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		msg := strings.TrimSpace(string(res.Stderr) + " " + string(res.Stdout))
		if len(msg) > 300 {
			msg = msg[:300]
		}
		return invalid("ufw %s failed: %s", args[0], msg)
	}
	return nil
}
