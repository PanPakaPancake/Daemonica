package helper

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/PanPakaPancake/daemonica/internal/netcfg"
	"github.com/PanPakaPancake/daemonica/internal/planner"
	"github.com/PanPakaPancake/daemonica/internal/policy"
	"github.com/PanPakaPancake/daemonica/internal/rpc"
)

// KindNetwork is the planner kind for network configuration changes.
const KindNetwork = "network"

// NetworkHandler applies planned network changes and rolls them back by
// restoring the saved files and re-applying them (SPEC §7.6, §3.2 rule 10).
type NetworkHandler struct {
	Root string
	Run  netcfg.Runner
	// State reads the kernel state; when set, every apply and rollback is
	// checked against the planned settings (a zero exit code of netplan
	// apply does not mean networkd uses the configuration).
	State func() (netcfg.State, error)
	// Settle is how long the check waits for the settings (default 30 s).
	Settle time.Duration
}

// Kind implements planner.Handler.
func (h *NetworkHandler) Kind() string { return KindNetwork }

func (h *NetworkHandler) backend(p netcfg.Plan) (netcfg.Backend, error) {
	switch p.Manager {
	case "netplan":
		return &netcfg.Netplan{Root: h.Root, Run: h.Run}, nil
	case "ifupdown":
		return &netcfg.Ifupdown{Root: h.Root, Run: h.Run}, nil
	}
	return nil, fmt.Errorf("unknown network manager %q", p.Manager)
}

func (h *NetworkHandler) activate(ctx context.Context, payload json.RawMessage, rollback bool) error {
	var p netcfg.Plan
	if err := json.Unmarshal(payload, &p); err != nil {
		return err
	}
	b, err := h.backend(p)
	if err != nil {
		return err
	}
	if err := b.Activate(ctx, p, rollback); err != nil {
		return err
	}
	want := p.New
	if rollback {
		want = p.Old
	}
	if h.State == nil || want == nil {
		return nil
	}
	missing := h.settle(ctx, *want)
	if len(missing) > 0 && rollback {
		// The old configuration must come back: activate once more.
		if err := b.Activate(ctx, p, true); err != nil {
			return err
		}
		missing = h.settle(ctx, *want)
	}
	if len(missing) > 0 {
		return fmt.Errorf("network configuration not in effect after activation: %s", strings.Join(missing, ", "))
	}
	return nil
}

// settle waits until the kernel state shows cfg or the settle time is over.
func (h *NetworkHandler) settle(ctx context.Context, cfg netcfg.IfaceConfig) []string {
	wait := h.Settle
	if wait <= 0 {
		wait = 30 * time.Second
	}
	deadline := time.Now().Add(wait)
	for {
		st, err := h.State()
		var missing []string
		if err != nil {
			missing = []string{"state: " + err.Error()}
		} else {
			missing = netcfg.Missing(st, cfg)
		}
		if len(missing) == 0 || !time.Now().Before(deadline) {
			return missing
		}
		select {
		case <-ctx.Done():
			return missing
		case <-time.After(500 * time.Millisecond):
		}
	}
}

// Apply implements planner.Handler.
func (h *NetworkHandler) Apply(ctx context.Context, payload json.RawMessage) error {
	return h.activate(ctx, payload, false)
}

// Rollback implements planner.Handler.
func (h *NetworkHandler) Rollback(ctx context.Context, payload json.RawMessage) error {
	return h.activate(ctx, payload, true)
}

// NetReader reads the network state (netcfg.Reader; fakes in tests).
type NetReader interface {
	Read() (netcfg.State, error)
	Ports() ([]netcfg.Port, error)
}

// NetOps exposes the network view and configuration (SPEC §7.6 M1.5a).
type NetOps struct {
	Reader   NetReader
	Detector *netcfg.Detector
	Run      netcfg.Runner
	Planner  *planner.Manager
}

// NetView is the net.get result.
type NetView struct {
	netcfg.State
	SessionIface string `json:"session_iface,omitempty"`
	ClientIP     string `json:"client_ip"`
}

type netConfigParams struct {
	Name string `json:"name"`
}

type netPlanParams struct {
	Config         netcfg.IfaceConfig `json:"config"`
	ConfirmLockout bool               `json:"confirm_lockout,omitempty"`
}

// NetPlanView is returned by net.plan: the change plus what the UI needs to
// show the new address of the dashboard.
type NetPlanView struct {
	planner.Change
	Addresses []string `json:"addresses"`
	Session   bool     `json:"session"`
}

func (n *NetOps) state(c Call) (NetView, netcfg.Backend, error) {
	st, err := n.Reader.Read()
	if err != nil {
		return NetView{}, nil, err
	}
	var b netcfg.Backend
	st.Manager, b = n.Detector.Detect(n.Run)
	v := NetView{State: st, ClientIP: c.SourceIP}
	v.SessionIface = v.MarkSession(c.SourceIP)
	return v, b, nil
}

func (n *NetOps) iface(st netcfg.State, name string) (netcfg.Interface, bool) {
	for _, i := range st.Interfaces {
		if i.Name == name {
			return i, true
		}
	}
	return netcfg.Interface{}, false
}

func netErr(err error) error {
	var ve *netcfg.ErrValidation
	if errors.As(err, &ve) {
		return Errf(rpc.CodeValidation, "%s", ve.Msg)
	}
	return err
}

// Register installs net.* operations.
func (n *NetOps) Register(ops map[string]*Op) {
	Register(ops, &Op{Name: "net.get", Action: policy.ActOverviewRead, NoAudit: true,
		Handle: func(_ context.Context, c Call) (any, error) {
			v, _, err := n.state(c)
			return v, err
		}})

	Register(ops, &Op{Name: "net.ports", Action: policy.ActOverviewRead, NoAudit: true,
		Handle: func(context.Context, Call) (any, error) {
			ps, err := n.Reader.Ports()
			return map[string]any{"ports": ps}, err
		}})

	Register(ops, &Op{Name: "net.config", Action: policy.ActOverviewRead, NoAudit: true,
		Handle: func(_ context.Context, c Call) (any, error) {
			var p netConfigParams
			if err := decode(c, &p); err != nil {
				return nil, err
			}
			v, b, err := n.state(c)
			if err != nil {
				return nil, err
			}
			it, ok := n.iface(v.State, p.Name)
			if !ok {
				return nil, Errf(rpc.CodeNotFound, "")
			}
			if b == nil {
				return netcfg.IfaceConfig{Name: p.Name, Addresses: []string{}, DNS: []string{}, Search: []string{}, Routes: []netcfg.StaticRoute{}, Reason: "manager"}, nil
			}
			cfg, err := b.Config(it.Name, it.MAC)
			if err == nil && it.Kind == "loopback" {
				cfg.Editable, cfg.Reason = false, "advanced"
			}
			return cfg, netErr(err)
		}})

	Register(ops, &Op{Name: "net.plan", Action: policy.ActNetWrite, Timeout: time.Minute, AuditTarget: func(c Call) string {
		var p netPlanParams
		_ = json.Unmarshal(c.Params, &p)
		return "iface:" + p.Config.Name
	},
		Handle: func(ctx context.Context, c Call) (any, error) {
			var p netPlanParams
			if err := decode(c, &p); err != nil {
				return nil, err
			}
			cfg, err := netcfg.Normalize(p.Config)
			if err != nil {
				return nil, netErr(err)
			}
			v, b, err := n.state(c)
			if err != nil {
				return nil, err
			}
			if b == nil {
				return nil, Errf(rpc.CodeNotSupported, "the network configuration of this server can only be viewed (%s)", v.Manager.Reason)
			}
			it, ok := n.iface(v.State, cfg.Name)
			if !ok {
				return nil, Errf(rpc.CodeNotFound, "")
			}
			if it.Kind == "loopback" {
				return nil, Errf(rpc.CodeValidation, "the loopback interface cannot be changed")
			}
			plan, err := b.Plan(ctx, cfg, it.MAC)
			if err != nil {
				return nil, netErr(err)
			}
			risk := "medium"
			if it.Session {
				if !p.ConfirmLockout {
					return nil, Errf(rpc.CodeLockout, "this interface carries your current connection")
				}
				risk = "high"
			}
			payload, _ := json.Marshal(plan)
			ch, err := n.Planner.Plan(KindNetwork, c.Subject.AccountID, "Network: "+cfg.Name+" ("+plan.Manager+")", plan.Diff, risk, payload)
			if err != nil {
				return nil, mapPlannerErr(err)
			}
			addrs := cfg.Addresses
			if cfg.DHCP4 || cfg.DHCP6 {
				addrs = append(addrs, "dhcp")
			}
			return NetPlanView{Change: redact(ch), Addresses: addrs, Session: it.Session}, nil
		}})
}
