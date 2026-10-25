package firewall

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/PanPakaPancake/daemonica/internal/netcfg"
)

// Op is one requested firewall change.
type Op struct {
	Kind      string   `json:"kind"` // add, delete, logging, default, enable, disable, reset
	Add       *AddSpec `json:"add,omitempty"`
	Nums      []int    `json:"nums,omitempty"`      // delete
	Level     string   `json:"level,omitempty"`     // logging
	Direction string   `json:"direction,omitempty"` // default: incoming, outgoing, routed
	Policy    string   `json:"policy,omitempty"`    // default: allow, deny, reject
}

// Payload is what the planner stores: the state before and the ufw calls.
type Payload struct {
	Token    string     `json:"token"`
	Snapshot Snapshot   `json:"snapshot"`
	Steps    [][]string `json:"steps"`
}

var levels = []string{"off", "low", "medium", "high", "full"}

// Validate checks an op against the current rules (numbers must exist).
func (o Op) Validate(c Config) (Op, error) {
	switch o.Kind {
	case "add":
		if o.Add == nil {
			return o, invalid("missing rule")
		}
		a, err := o.Add.Normalize()
		if err != nil {
			return o, err
		}
		o.Add = &a
	case "delete":
		if len(o.Nums) == 0 || len(o.Nums) > 100 {
			return o, invalid("select 1–100 rules to delete")
		}
		o.Nums = slices.Compact(slices.Sorted(slices.Values(o.Nums)))
		for _, n := range o.Nums {
			if n < 1 || n > len(c.Rules) {
				return o, invalid("rule %d does not exist", n)
			}
		}
	case "logging":
		if !slices.Contains(levels, o.Level) {
			return o, invalid("invalid logging level")
		}
	case "default":
		if !slices.Contains([]string{"incoming", "outgoing", "routed"}, o.Direction) || !slices.Contains([]string{"allow", "deny", "reject"}, o.Policy) {
			return o, invalid("invalid default policy")
		}
	case "enable", "disable", "reset":
	default:
		return o, invalid("unknown firewall change")
	}
	return o, nil
}

// Simulate returns the configuration and activity after the ops. auto are
// rules added before enabling.
func Simulate(c Config, active bool, ops []Op) (Config, bool) {
	n := c
	n.Rules = slices.Clone(c.Rules)
	for _, o := range ops {
		switch o.Kind {
		case "add":
			if o.Add.Prepend {
				n.Rules = append(o.Add.Rules(n.IPv6), n.Rules...)
			} else {
				n.Rules = append(n.Rules, o.Add.Rules(n.IPv6)...)
			}
		case "delete":
			n.Rules = slices.DeleteFunc(n.Rules, func(r Rule) bool { return slices.Contains(o.Nums, r.Num) })
		case "logging":
			n.Logging = o.Level
		case "default":
			switch o.Direction {
			case "incoming":
				n.Defaults.Incoming = o.Policy
			case "outgoing":
				n.Defaults.Outgoing = o.Policy
			default:
				n.Defaults.Routed = o.Policy
			}
		case "enable":
			active, n.Enabled = true, true
		case "disable":
			active, n.Enabled = false, false
		case "reset":
			active, n.Enabled = false, false
			n.Rules = nil
			n.Defaults.Incoming, n.Defaults.Outgoing = "deny", "allow"
		}
		renumber(n.Rules)
	}
	if n.Rules == nil {
		n.Rules = []Rule{}
	}
	return n, active
}

// renumber orders v4 before v6 rules (as ufw numbers them).
func renumber(rs []Rule) {
	slices.SortStableFunc(rs, func(a, b Rule) int {
		switch {
		case a.V6 == b.V6:
			return 0
		case !a.V6:
			return -1
		}
		return 1
	})
	for i := range rs {
		rs[i].Num = i + 1
	}
}

// Steps turns ops into ufw argument lists, run in order by Apply.
func Steps(ops []Op) [][]string {
	var out [][]string
	for _, o := range ops {
		switch o.Kind {
		case "add":
			out = append(out, o.Add.Args())
		case "delete":
			for _, n := range slices.Backward(o.Nums) { // high numbers first keep the others stable
				out = append(out, []string{"--force", "delete", strconv.Itoa(n)})
			}
		case "logging":
			out = append(out, []string{"logging", o.Level})
		case "default":
			out = append(out, []string{"default", o.Policy, o.Direction})
		case "enable":
			out = append(out, []string{"--force", "enable"})
		case "disable":
			out = append(out, []string{"disable"})
		case "reset":
			out = append(out, []string{"--force", "reset"})
		}
	}
	return out
}

// Render is a readable listing of the state, used for the plan diff.
func Render(c Config, active bool) string {
	var b strings.Builder
	st := "inactive"
	if active {
		st = "active"
	}
	fmt.Fprintf(&b, "Status: %s (on boot: %v)\n", st, c.Enabled)
	fmt.Fprintf(&b, "Logging: %s\n", c.Logging)
	fmt.Fprintf(&b, "Default: %s (incoming), %s (outgoing), %s (routed)\n", c.Defaults.Incoming, c.Defaults.Outgoing, c.Defaults.Routed)
	fmt.Fprintf(&b, "IPv6: %v\n\n", c.IPv6)
	for _, r := range c.Rules {
		b.WriteString(r.String())
		b.WriteByte('\n')
	}
	return b.String()
}

// String renders a rule like "[ 3] allow in tcp 22 from any to any (v6) # x".
func (r Rule) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "[%2d] %s", r.Num, r.Action)
	if r.Log != "" {
		b.WriteString(" " + r.Log)
	}
	b.WriteString(" " + r.Direction)
	if r.Iface != "" {
		b.WriteString(" on " + r.Iface)
	}
	if r.OutIface != "" {
		b.WriteString(" out on " + r.OutIface)
	}
	if r.App != "" {
		b.WriteString(" app " + r.App)
	} else {
		b.WriteString(" " + r.Proto + " " + r.DPort)
	}
	b.WriteString(" from " + r.Src)
	if r.SPort != "any" && r.SPort != "" {
		b.WriteString(" port " + r.SPort)
	}
	b.WriteString(" to " + r.Dst)
	if r.V6 {
		b.WriteString(" (v6)")
	}
	if r.Comment != "" {
		b.WriteString(" # " + r.Comment)
	}
	return b.String()
}

// Diff renders the before/after listing as a unified diff.
func Diff(before Config, beforeActive bool, after Config, afterActive bool) string {
	a, b := Render(before, beforeActive), Render(after, afterActive)
	return netcfg.UnifiedDiff("ufw", &a, &b)
}

// AccessRules proposes the rules that keep SSH and the dashboard reachable
// when ufw is enabled (SPEC §7.6: SSH port from sshd -T, dashboard port for
// the allowlist networks; loopback needs none).
func AccessRules(sshPorts []int, dashPort int, allow []netip.Prefix) []AddSpec {
	var out []AddSpec
	for _, p := range sshPorts {
		out = append(out, AddSpec{Action: "allow", Direction: "in", Proto: "tcp", Port: strconv.Itoa(p), From: "any", To: "any", Comment: "daemonica:ssh:access"})
	}
	var srcs []string
	for _, p := range allow {
		if p.Bits() == 0 {
			srcs = []string{"any"}
			break
		}
		if !p.Addr().IsLoopback() {
			srcs = append(srcs, p.Masked().String())
		}
	}
	for _, s := range srcs {
		out = append(out, AddSpec{Action: "allow", Direction: "in", Proto: "tcp", Port: strconv.Itoa(dashPort), From: s, To: "any", Comment: "daemonica:dashboard:access"})
	}
	return out
}

// Handler applies firewall plans through ufw and rolls back by restoring
// the snapshot (planner kind "firewall").
type Handler struct {
	Ufw *Ufw
	mu  sync.Mutex
	// stale holds tokens whose apply was refused because the firewall changed
	// after the preview; their rollback must not overwrite that change.
	stale map[string]bool
}

// Kind is the planner kind.
const Kind = "firewall"

// Kind implements planner.Handler.
func (h *Handler) Kind() string { return Kind }

// ErrStale reports that the firewall changed between preview and apply.
var ErrStale = errors.New("the firewall was changed after the preview; create a new preview")

// Apply implements planner.Handler.
func (h *Handler) Apply(ctx context.Context, raw json.RawMessage) error {
	var p Payload
	if err := json.Unmarshal(raw, &p); err != nil {
		return err
	}
	cur, err := h.Ufw.TakeSnapshot(ctx)
	if err != nil {
		return err
	}
	if !sameSnapshot(cur, p.Snapshot) {
		h.mu.Lock()
		if h.stale == nil {
			h.stale = map[string]bool{}
		}
		h.stale[p.Token] = true
		h.mu.Unlock()
		return ErrStale
	}
	for _, s := range p.Steps {
		if err := h.Ufw.ufw(ctx, s...); err != nil {
			return err
		}
	}
	return nil
}

// Rollback implements planner.Handler.
func (h *Handler) Rollback(ctx context.Context, raw json.RawMessage) error {
	var p Payload
	if err := json.Unmarshal(raw, &p); err != nil {
		return err
	}
	h.mu.Lock()
	skip := h.stale[p.Token]
	delete(h.stale, p.Token)
	h.mu.Unlock()
	if skip {
		return nil
	}
	return h.Ufw.Restore(ctx, p.Snapshot)
}

func sameSnapshot(a, b Snapshot) bool {
	if a.Active != b.Active {
		return false
	}
	for _, f := range SnapshotFiles {
		x, y := a.Files[f], b.Files[f]
		if (x == nil) != (y == nil) || (x != nil && *x != *y) {
			return false
		}
	}
	return true
}

// InstallArgs is the command that installs ufw (Debian/Ubuntu).
var InstallArgs = []string{"/usr/bin/env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "install", "-y", "--no-install-recommends", "ufw"}

// SSHPorts reads the ports sshd listens on from "sshd -T" output.
func SSHPorts(out []byte) []int {
	var ps []int
	for _, l := range strings.Split(string(out), "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(l), "port "); ok {
			if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && n > 0 && n < 65536 && !slices.Contains(ps, n) {
				ps = append(ps, n)
			}
		}
	}
	if len(ps) == 0 {
		ps = []int{22}
	}
	return ps
}
