package helper

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/PanPakaPancake/daemonica/internal/audit"
	"github.com/PanPakaPancake/daemonica/internal/firewall"
	"github.com/PanPakaPancake/daemonica/internal/netallow"
	"github.com/PanPakaPancake/daemonica/internal/netcfg"
	"github.com/PanPakaPancake/daemonica/internal/planner"
	"github.com/PanPakaPancake/daemonica/internal/policy"
	"github.com/PanPakaPancake/daemonica/internal/rpc"
)

// FirewallOps exposes the firewall status, rules and changes (SPEC §7.6 M1.5b).
type FirewallOps struct {
	Ufw      *firewall.Ufw
	Detector *firewall.Detector
	Net      NetReader
	Config   *ConfigStore
	Planner  *planner.Manager
	Run      netcfg.Runner
	// AuditPath is read for the last firewall change; AccountName resolves its actor.
	AuditPath   string
	AccountName func(ctx context.Context, id string) string
}

// ReachRow is a listening socket and how the firewall treats it.
type ReachRow struct {
	Proto   string          `json:"proto"`
	Address string          `json:"address"`
	Port    int             `json:"port"`
	Process string          `json:"process,omitempty"`
	Local   bool            `json:"local"`
	Access  firewall.Access `json:"access"`
}

// LastChange is the newest firewall change from the audit log.
type LastChange struct {
	TS    string `json:"ts"`
	Event string `json:"event"`
	Actor string `json:"actor,omitempty"`
}

// FirewallView is the firewall.get result.
type FirewallView struct {
	Backend       string           `json:"backend"`
	Managed       bool             `json:"managed"`
	Installed     bool             `json:"installed"`
	Installable   bool             `json:"installable"`
	Active        bool             `json:"active"`
	Config        *firewall.Config `json:"config,omitempty"`
	Light         string           `json:"light"`
	Hints         []firewall.Hint  `json:"hints"`
	Reach         []ReachRow       `json:"reach"`
	Apps          []string         `json:"apps"`
	ClientIP      string           `json:"client_ip"`
	SessionIface  string           `json:"session_iface,omitempty"`
	DashboardPort int              `json:"dashboard_port"`
	SSHPorts      []int            `json:"ssh_ports"`
	Hostname      string           `json:"hostname"`
	LastChange    *LastChange      `json:"last_change,omitempty"`
}

type fwPlanParams struct {
	Op             firewall.Op `json:"op"`
	ConfirmLockout bool        `json:"confirm_lockout,omitempty"`
	ConfirmName    string      `json:"confirm_name,omitempty"` // reset: the hostname
}

// FirewallPlanView is returned by firewall.plan.
type FirewallPlanView struct {
	planner.Change
	Auto    []firewall.AddSpec `json:"auto"`    // rules added to keep access when enabling
	Lockout []string           `json:"lockout"` // lockout findings (dashboard:8443, ssh:22, ssh_closed:22)
	// Blocked: lockout findings need confirm_lockout; no change was planned.
	Blocked bool `json:"blocked,omitempty"`
}

type fwEnv struct {
	view    FirewallView
	cfg     firewall.Config
	host    []netip.Addr // addresses of the session interface
	allHost []netip.Addr
}

func (f *FirewallOps) sshPorts(ctx context.Context) []int {
	res, err := f.Run(ctx, 10*time.Second, "/usr/sbin/sshd", "-T")
	if err != nil || res.ExitCode != 0 {
		return []int{22}
	}
	return firewall.SSHPorts(res.Stdout)
}

func addrsOf(cidrs []string) []netip.Addr {
	var out []netip.Addr
	for _, c := range cidrs {
		if p, err := netip.ParsePrefix(c); err == nil {
			out = append(out, p.Addr())
		}
	}
	return out
}

func (f *FirewallOps) env(ctx context.Context, c Call, counters bool) (fwEnv, error) {
	st, err := f.Net.Read()
	if err != nil {
		return fwEnv{}, err
	}
	e := fwEnv{view: FirewallView{ClientIP: c.SourceIP, DashboardPort: f.Config.Get().Port, Hostname: st.Hostname, Hints: []firewall.Hint{}, Reach: []ReachRow{}, Apps: []string{}}}
	e.view.SessionIface = st.MarkSession(c.SourceIP)
	for _, i := range st.Interfaces {
		a := addrsOf(i.Addresses)
		e.allHost = append(e.allHost, a...)
		if i.Name == e.view.SessionIface {
			e.host = a
		}
	}
	e.view.SSHPorts = f.sshPorts(ctx)
	e.view.Backend = f.Detector.Detect(ctx)
	e.view.Installed = f.Ufw.Installed()
	_, aptErr := os.Stat(f.Ufw.Root + "/usr/bin/apt-get")
	e.view.Installable = !e.view.Installed && aptErr == nil && e.view.Backend != firewall.BackendFirewalld
	e.view.Managed = e.view.Backend == firewall.BackendUfw
	if !e.view.Managed {
		code := "no_firewall"
		if e.view.Backend != firewall.BackendNone {
			code = "readonly"
		}
		e.view.Light = "red"
		if code == "readonly" {
			e.view.Light = "yellow"
		}
		e.view.Hints = []firewall.Hint{{Code: code, Level: e.view.Light, Arg: e.view.Backend}}
		return e, nil
	}
	e.cfg, err = f.Ufw.ReadConfig()
	if err != nil {
		return e, err
	}
	e.view.Active, err = f.Ufw.Active(ctx)
	if err != nil {
		return e, err
	}
	if counters && e.view.Active {
		f.Ufw.AddCounters(ctx, e.cfg.Rules)
	}
	e.view.Config = &e.cfg
	return e, nil
}

func listeners(ps []netcfg.Port) []firewall.Listener {
	var out []firewall.Listener
	for _, p := range ps {
		a, err := netip.ParseAddr(p.Address)
		l := firewall.Listener{Proto: strings.TrimSuffix(p.Proto, "6"), Port: p.Port, V6: strings.HasSuffix(p.Proto, "6"), Local: err == nil && a.IsLoopback()}
		if len(p.Processes) > 0 {
			l.Process = p.Processes[0].Name
		}
		out = append(out, l)
	}
	return out
}

func (f *FirewallOps) lastChange(ctx context.Context) *LastChange {
	if f.AuditPath == "" {
		return nil
	}
	fh, err := os.Open(f.AuditPath)
	if err != nil {
		return nil
	}
	defer func() { _ = fh.Close() }()
	page, err := audit.Query(fh, audit.Filter{ActionPrefix: "change.", Limit: audit.MaxQueryLimit})
	if err != nil {
		return nil
	}
	for _, ev := range page.Events {
		if ev.Params["kind"] != firewall.Kind || ev.Action == "change.planned" {
			continue
		}
		lc := &LastChange{TS: ev.TS, Event: strings.TrimPrefix(ev.Action, "change."), Actor: ev.Actor.Name}
		if lc.Actor == "" && f.AccountName != nil && ev.Actor.AccountID != "" {
			lc.Actor = f.AccountName(ctx, ev.Actor.AccountID)
		}
		return lc
	}
	return nil
}

func (f *FirewallOps) get(ctx context.Context, c Call) (FirewallView, error) {
	e, err := f.env(ctx, c, true)
	if err != nil {
		return e.view, err
	}
	v := e.view
	v.LastChange = f.lastChange(ctx)
	ports, err := f.Net.Ports()
	if err != nil {
		return v, err
	}
	ls := listeners(ports)
	if v.Managed {
		v.Light, v.Hints = firewall.Light(e.cfg, v.Active, firewall.HasGlobal6(e.allHost), ls)
		if apps, err := f.Ufw.Apps(ctx); err == nil && apps != nil {
			v.Apps = apps
		}
	}
	for i, p := range ports {
		l := ls[i]
		row := ReachRow{Proto: l.Proto, Address: p.Address, Port: p.Port, Process: l.Process, Local: l.Local}
		if v.Managed {
			row.Access = firewall.Reach(e.cfg, v.Active, l.Proto, p.Port, l.V6, e.allHost)
		}
		v.Reach = append(v.Reach, row)
	}
	return v, nil
}

// lockout lists what the planned state would block for the caller.
func (f *FirewallOps) lockout(e fwEnv, after firewall.Config, active bool) []string {
	var out []string
	client, err := netip.ParseAddr(e.view.ClientIP)
	if err != nil {
		return nil
	}
	pk := firewall.Packet{Src: client.Unmap(), Iface: e.view.SessionIface, Proto: "tcp", Host: e.host}
	pk.Port = e.view.DashboardPort
	if !firewall.Evaluate(after, active, pk).Allowed {
		out = append(out, "dashboard:"+strconv.Itoa(pk.Port))
	}
	for _, p := range e.view.SSHPorts {
		pk.Port = p
		if !firewall.Evaluate(after, active, pk).Allowed {
			out = append(out, "ssh:"+strconv.Itoa(p))
			continue
		}
		v6 := client.Is6() && !client.Is4In6()
		if a := firewall.Reach(after, active, "tcp", p, v6, e.allHost); !a.Allowed && !a.Restricted {
			out = append(out, "ssh_closed:"+strconv.Itoa(p))
		}
	}
	return out
}

func fwErr(err error) error {
	var ve *firewall.ErrValidation
	if errors.As(err, &ve) {
		return Errf(rpc.CodeValidation, "%s", ve.Msg)
	}
	return err
}

func fwSummary(o firewall.Op, cfg firewall.Config) string {
	switch o.Kind {
	case "add":
		return "Firewall: add " + strings.Join(o.Add.Args(), " ")
	case "delete":
		var rs []string
		for _, n := range o.Nums {
			rs = append(rs, strings.TrimSpace(cfg.Rules[n-1].String()))
		}
		return "Firewall: delete " + strings.Join(rs, "; ")
	case "logging":
		return "Firewall: logging " + o.Level
	case "default":
		return "Firewall: default " + o.Direction + " " + o.Policy
	}
	return "Firewall: " + o.Kind
}

func token() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (f *FirewallOps) plan(ctx context.Context, c Call, p fwPlanParams) (any, error) {
	e, err := f.env(ctx, c, false)
	if err != nil {
		return nil, err
	}
	if !e.view.Managed {
		return nil, Errf(rpc.CodeNotSupported, "this firewall (%s) can only be viewed", e.view.Backend)
	}
	op, err := p.Op.Validate(e.cfg)
	if err != nil {
		return nil, fwErr(err)
	}
	if op.Kind == "reset" && !strings.EqualFold(strings.TrimSpace(p.ConfirmName), e.view.Hostname) {
		return nil, Errf(rpc.CodeValidation, "type the server name to confirm the reset")
	}
	ops := []firewall.Op{op}
	var auto []firewall.AddSpec
	if op.Kind == "add" && op.Add.App != "" {
		ports, err := f.Ufw.AppPorts(ctx, op.Add.App)
		if err != nil || len(ports) == 0 {
			return nil, Errf(rpc.CodeValidation, "unknown application profile")
		}
		op.Add.AppPorts = ports
	}
	if op.Kind == "enable" {
		allow, _ := netallow.ParseList(f.Config.Get().Allowlist)
		pre, _ := firewall.Simulate(e.cfg, true, nil)
		var adds []firewall.Op
		for _, a := range firewall.AccessRules(e.view.SSHPorts, e.view.DashboardPort, allow) {
			if covered(pre, a, e.allHost) {
				continue
			}
			add := firewall.Op{Kind: "add", Add: &a}
			auto, adds = append(auto, a), append(adds, add)
			pre, _ = firewall.Simulate(pre, true, []firewall.Op{add})
		}
		ops = append(adds, op)
	}
	after, active := firewall.Simulate(e.cfg, e.view.Active, ops)
	lock := f.lockout(e, after, active)
	risk := "medium"
	if op.Kind == "enable" || op.Kind == "reset" || op.Kind == "default" {
		risk = "high"
	}
	if len(lock) > 0 {
		if !p.ConfirmLockout {
			// The UI shows the findings and asks for the acknowledgement.
			return FirewallPlanView{Auto: nonNil(auto), Lockout: lock, Blocked: true}, nil
		}
		risk = "high"
	}
	snap, err := f.Ufw.TakeSnapshot(ctx)
	if err != nil {
		return nil, err
	}
	payload, _ := json.Marshal(firewall.Payload{Token: token(), Snapshot: snap, Steps: firewall.Steps(ops)})
	diff := firewall.Diff(e.cfg, e.view.Active, after, active)
	ch, err := f.Planner.Plan(firewall.Kind, c.Subject.AccountID, fwSummary(op, e.cfg), diff, risk, payload)
	if err != nil {
		return nil, mapPlannerErr(err)
	}
	return FirewallPlanView{Change: redact(ch), Auto: nonNil(auto), Lockout: nonNil(lock)}, nil
}

func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

// covered reports whether the rules already let the access rule's traffic in.
func covered(c firewall.Config, a firewall.AddSpec, host []netip.Addr) bool {
	port, _ := strconv.Atoi(a.Port)
	if a.From == "any" {
		return firewall.Reach(c, true, a.Proto, port, false, host).Allowed
	}
	pre, err := netip.ParsePrefix(a.From)
	if err != nil {
		return false
	}
	return firewall.Evaluate(c, true, firewall.Packet{Src: pre.Addr(), Proto: a.Proto, Port: port, Host: host}).Allowed
}

// Register installs firewall.* operations.
func (f *FirewallOps) Register(ops map[string]*Op) {
	Register(ops, &Op{Name: "firewall.get", Action: policy.ActOverviewRead, NoAudit: true, Timeout: time.Minute,
		Handle: func(ctx context.Context, c Call) (any, error) { return f.get(ctx, c) }})

	Register(ops, &Op{Name: "firewall.raw", Action: policy.ActOverviewRead, NoAudit: true, Timeout: time.Minute,
		Handle: func(ctx context.Context, _ Call) (any, error) {
			src, text, err := f.Detector.Raw(ctx)
			return map[string]string{"source": src, "text": text}, err
		}})

	Register(ops, &Op{Name: "firewall.plan", Action: policy.ActFirewallWrite, Timeout: time.Minute, AuditTarget: func(c Call) string {
		var p fwPlanParams
		_ = json.Unmarshal(c.Params, &p)
		return "firewall:" + p.Op.Kind
	},
		Handle: func(ctx context.Context, c Call) (any, error) {
			var p fwPlanParams
			if err := decode(c, &p); err != nil {
				return nil, err
			}
			return f.plan(ctx, c, p)
		}})

	Register(ops, &Op{Name: "firewall.install", Action: policy.ActFirewallWrite, Timeout: 115 * time.Second, // below the web write timeout
		Handle: func(ctx context.Context, c Call) (any, error) {
			e, err := f.env(ctx, c, false)
			if err != nil {
				return nil, err
			}
			if !e.view.Installable {
				return nil, Errf(rpc.CodeConflict, "ufw cannot be installed here")
			}
			res, err := f.Run(ctx, 110*time.Second, firewall.InstallArgs[0], firewall.InstallArgs[1:]...)
			if err != nil {
				return nil, err
			}
			if res.ExitCode != 0 {
				msg := strings.TrimSpace(string(res.Stderr))
				if len(msg) > 400 {
					msg = msg[len(msg)-400:]
				}
				return nil, Errf(rpc.CodeInternal, "apt-get failed: %s", msg)
			}
			return map[string]bool{"installed": true}, nil
		}})
}
