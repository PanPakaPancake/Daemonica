package helper

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/PanPakaPancake/daemonica/internal/apt"
	"github.com/PanPakaPancake/daemonica/internal/policy"
	"github.com/PanPakaPancake/daemonica/internal/rpc"
	"github.com/PanPakaPancake/daemonica/internal/sysinfo"
)

// AptOps exposes updates and packages (SPEC §7.8, DEC-031). Reading is open
// to all roles (Annex A: update view); every change needs admin + step-up.
// Changing jobs run as transient units (apt.Runner) and are watched by
// polling packages.job.
type AptOps struct {
	Sys  apt.System
	Jobs *apt.Runner
	// UnattendedPath is the managed configuration file (apt.UnattendedFile).
	UnattendedPath string
	// Root is prepended to /run and /etc paths read directly (tests); "" = "/".
	Root string
	// Kernel returns the running kernel release (apt.RunningKernel).
	Kernel func() string

	mu     sync.Mutex
	counts *sysinfo.Updates
}

// Updates returns the counts of the last simulation for the system
// overview (sysinfo.Extras.Updates).
func (o *AptOps) Updates() (sysinfo.Updates, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.counts == nil {
		return sysinfo.Updates{}, errors.New("no simulation yet")
	}
	return *o.counts, nil
}

func (o *AptOps) remember(sim apt.Sim, auto *bool) {
	u := sysinfo.Updates{Security: securityCount(sim)}
	for _, x := range sim.Install {
		if x.Old != "" {
			u.Total++
		}
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if auto == nil && o.counts != nil {
		auto = o.counts.AutoSecurity
	}
	u.AutoSecurity = auto
	o.counts = &u
}

func securityCount(sim apt.Sim) int {
	n := 0
	for _, x := range sim.Install {
		if x.Security && x.Old != "" {
			n++
		}
	}
	return n
}

func autoSecurity(st apt.UnattendedStatus) *bool {
	v := st.Installed && st.UpdateLists && st.Upgrade && st.SecurityOnly
	return &v
}

// Refresh simulates the upgrade and reads the unattended-upgrades state for
// the overview counts.
func (o *AptOps) Refresh(ctx context.Context) {
	var auto *bool
	if st, err := o.Sys.Unattended(ctx); err == nil {
		auto = autoSecurity(st)
	}
	if sim, err := o.Sys.Simulate(ctx, apt.KindUpgrade, nil); err == nil {
		o.remember(sim, auto)
	}
}

// Watch refreshes the counts now and then every interval.
func (o *AptOps) Watch(ctx context.Context, every time.Duration) {
	for {
		rctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
		o.Refresh(rctx)
		cancel()
		select {
		case <-ctx.Done():
			return
		case <-time.After(every):
		}
	}
}

// Error codes of the package operations (translated by the UI).
const (
	CodeAptBusy        = "package_job_running"
	CodeAptPlanChanged = "plan_changed"
	CodeAptCritical    = "critical_unconfirmed"
	CodeAptProtected   = "protected_package"
	CodeAptSimFailed   = "simulation_failed"
)

// AptOverview is the packages.overview result.
type AptOverview struct {
	Distro     apt.Distro  `json:"distro"`
	Kernel     string      `json:"kernel"`
	LastUpdate *time.Time  `json:"last_update,omitempty"`
	Upgrade    apt.Sim     `json:"upgrade"`
	Security   int         `json:"security"`
	SimError   string      `json:"sim_error,omitempty"`
	Reboot     bool        `json:"reboot"`
	RebootPkgs []string    `json:"reboot_pkgs"`
	Lock       *apt.Holder `json:"lock,omitempty"`
	// Broken are packages left half-installed or half-configured.
	Broken  []string `json:"broken"`
	Running *apt.Job `json:"running,omitempty"`
	Last    *apt.Job `json:"last,omitempty"`
}

// AptPlan is the packages.simulate result: what a job would change.
type AptPlan struct {
	Kind apt.Kind `json:"kind"`
	Sim  apt.Sim  `json:"sim"`
	// Critical are removals that need an explicit acknowledgement.
	Critical []string `json:"critical"`
	// Protected: the plan removes Daemonica itself and is refused.
	Protected bool `json:"protected"`
	// Error is apt's message when the simulation failed.
	Error string `json:"error,omitempty"`
}

// AptJobLog is the packages.job result.
type AptJobLog struct {
	Job  apt.Job `json:"job"`
	Log  string  `json:"log"`
	Next int64   `json:"next"`
}

// AptSearch is the packages.search result.
type AptSearch struct {
	Results []apt.Found `json:"results"`
	More    bool        `json:"more"`
}

// AptUnattended is the packages.unattended result.
type AptUnattended struct {
	apt.UnattendedStatus
	Supported bool `json:"supported"`
}

type aptJobParams struct {
	Kind     apt.Kind `json:"kind"`
	Packages []string `json:"packages"`
	// ExpectRemove are the removals the user confirmed (sorted names).
	ExpectRemove []string `json:"expect_remove"`
	// AckCritical confirms removing critical packages.
	AckCritical bool `json:"ack_critical"`
}

func (p *aptJobParams) valid() bool {
	if !slices.Contains(apt.Kinds, p.Kind) || len(p.Packages) > 500 {
		return false
	}
	if p.Kind.NeedsPackages() != (len(p.Packages) > 0) {
		return false
	}
	for _, n := range append(append([]string{}, p.Packages...), p.ExpectRemove...) {
		if !apt.ValidName(n) {
			return false
		}
	}
	slices.Sort(p.Packages)
	p.Packages = slices.Compact(p.Packages)
	return true
}

func (o *AptOps) root(p string) string {
	if o.Root == "" {
		return p
	}
	return filepath.Join(o.Root, p)
}

func (o *AptOps) kernel() string {
	if o.Kernel == nil {
		return apt.RunningKernel()
	}
	return o.Kernel()
}

// plan simulates a job and checks it against the protection rules.
func (o *AptOps) plan(ctx context.Context, k apt.Kind, pkgs []string) (AptPlan, error) {
	p := AptPlan{Kind: k, Critical: []string{}, Sim: apt.Sim{Install: []apt.Pkg{}, Remove: []apt.Pkg{}, Kept: []string{}}}
	if k == apt.KindUpdate || k == apt.KindDryRun {
		return p, nil
	}
	sim, err := o.Sys.Simulate(ctx, k, pkgs)
	var se *apt.ErrSim
	if errors.As(err, &se) {
		p.Error = se.Msg
		return p, nil
	}
	if err != nil {
		return p, err
	}
	p.Sim = sim
	if c := apt.Critical(sim.Remove, o.kernel()); c != nil {
		p.Critical = c
	}
	p.Protected = slices.ContainsFunc(sim.Remove, func(x apt.Pkg) bool {
		n, _, _ := strings.Cut(x.Name, ":")
		return n == apt.Protected
	})
	return p, nil
}

// lastUpdate combines the system's stamp with the last successful update job.
func (o *AptOps) lastUpdate(jobs []apt.Job) *time.Time {
	t := o.Sys.LastUpdate()
	for _, j := range jobs {
		if j.Kind == apt.KindUpdate && j.State == apt.StateSucceeded && j.Ended != nil && j.Ended.After(t) {
			t = *j.Ended
		}
	}
	if t.IsZero() {
		return nil
	}
	return &t
}

func aptErr(err error) error {
	switch {
	case errors.Is(err, apt.ErrBusy):
		return Errf(CodeAptBusy, "")
	case errors.Is(err, apt.ErrNotFound):
		return Errf(rpc.CodeNotFound, "")
	}
	return err
}

// writeUnattended replaces the managed file atomically (0644 like the other
// apt configuration).
func writeUnattended(path, text string) error {
	tmp := path + ".daemonica-tmp"
	if err := os.WriteFile(tmp, []byte(text), 0o600); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o644); err != nil { //nolint:gosec // apt configuration is world-readable
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func aptTarget(c Call) string {
	var p aptJobParams
	_ = json.Unmarshal(c.Params, &p)
	if p.Kind == "" {
		return "packages"
	}
	return "packages:" + string(p.Kind)
}

// Register installs the packages.* operations.
func (o *AptOps) Register(ops map[string]*Op) {
	Register(ops, &Op{Name: "packages.overview", Action: policy.ActOverviewRead, NoAudit: true, Timeout: 3 * time.Minute,
		Handle: func(ctx context.Context, _ Call) (any, error) {
			jobs := o.Jobs.List(ctx)
			res := AptOverview{Distro: apt.ReadDistro(o.root("/")), Kernel: o.kernel(), LastUpdate: o.lastUpdate(jobs), Lock: apt.LockHolder()}
			res.Reboot, res.RebootPkgs = apt.RebootRequired(o.Root)
			if res.Broken, _ = o.Sys.Broken(ctx); res.Broken == nil {
				res.Broken = []string{}
			}
			if res.RebootPkgs == nil {
				res.RebootPkgs = []string{}
			}
			for i := range jobs {
				if jobs[i].State == apt.StateRunning {
					res.Running = &jobs[i]
				} else if res.Last == nil {
					res.Last = &jobs[i]
				}
			}
			p, err := o.plan(ctx, apt.KindUpgrade, nil)
			if err != nil {
				return nil, err
			}
			res.Upgrade, res.SimError, res.Security = p.Sim, p.Error, securityCount(p.Sim)
			if p.Error == "" {
				o.remember(p.Sim, nil)
			}
			return res, nil
		}})

	Register(ops, &Op{Name: "packages.needrestart", Action: policy.ActOverviewRead, NoAudit: true, Timeout: 3 * time.Minute,
		Handle: func(ctx context.Context, _ Call) (any, error) { return o.Sys.NeedRestart(ctx) }})

	Register(ops, &Op{Name: "packages.installed", Action: policy.ActOverviewRead, NoAudit: true, Timeout: 2 * time.Minute,
		Handle: func(ctx context.Context, _ Call) (any, error) { return o.Sys.Installed(ctx) }})

	Register(ops, &Op{Name: "packages.sources", Action: policy.ActOverviewRead, NoAudit: true,
		Handle: func(_ context.Context, _ Call) (any, error) { return apt.ReadSources(o.root("/")), nil }})

	Register(ops, &Op{Name: "packages.search", Action: policy.ActOverviewRead, NoAudit: true, Timeout: 2 * time.Minute,
		Handle: func(ctx context.Context, c Call) (any, error) {
			var p struct {
				Q string `json:"q"`
			}
			if err := decode(c, &p); err != nil {
				return nil, err
			}
			if !apt.ValidTerm(p.Q) {
				return nil, Errf(rpc.CodeValidation, "invalid search term")
			}
			list, more, err := o.Sys.Search(ctx, p.Q)
			if err != nil {
				return nil, err
			}
			return AptSearch{Results: list, More: more}, nil
		}})

	Register(ops, &Op{Name: "packages.simulate", Action: policy.ActOverviewRead, NoAudit: true, Timeout: 3 * time.Minute,
		Handle: func(ctx context.Context, c Call) (any, error) {
			var p aptJobParams
			if err := decode(c, &p); err != nil {
				return nil, err
			}
			if !p.valid() {
				return nil, Errf(rpc.CodeValidation, "invalid job")
			}
			return o.plan(ctx, p.Kind, p.Packages)
		}})

	Register(ops, &Op{Name: "packages.start", Action: policy.ActPackagesWrite, Timeout: 3 * time.Minute, AuditTarget: aptTarget,
		Handle: func(ctx context.Context, c Call) (any, error) {
			var p aptJobParams
			if err := decode(c, &p); err != nil {
				return nil, err
			}
			if !p.valid() {
				return nil, Errf(rpc.CodeValidation, "invalid job")
			}
			// The plan the user saw must still hold: same removals, critical
			// ones acknowledged, never Daemonica itself.
			pl, err := o.plan(ctx, p.Kind, p.Packages)
			if err != nil {
				return nil, err
			}
			if pl.Error != "" {
				return nil, Errf(CodeAptSimFailed, "")
			}
			if pl.Protected {
				return nil, Errf(CodeAptProtected, "")
			}
			expect := slices.Clone(p.ExpectRemove)
			slices.Sort(expect)
			if !slices.Equal(apt.Names(pl.Sim.Remove), slices.Compact(expect)) {
				return nil, Errf(CodeAptPlanChanged, "")
			}
			if len(pl.Critical) > 0 && !p.AckCritical {
				return nil, Errf(CodeAptCritical, "")
			}
			var restore []string
			if p.Kind == apt.KindSelected {
				if restore, err = o.Sys.Auto(ctx, p.Packages); err != nil {
					return nil, err
				}
			}
			j, err := o.Jobs.Start(ctx, p.Kind, p.Packages, restore, c.Subject.AccountID)
			if err != nil {
				return nil, aptErr(err)
			}
			c.AuditKV["job"] = j.ID
			if len(p.Packages) > 0 {
				c.AuditKV["packages"] = clipList(p.Packages)
			}
			if len(pl.Sim.Remove) > 0 {
				c.AuditKV["removes"] = clipList(apt.Names(pl.Sim.Remove))
			}
			if n := len(pl.Sim.Install); n > 0 {
				c.AuditKV["installs"] = strconv.Itoa(n)
			}
			if len(pl.Critical) > 0 {
				c.AuditKV["critical"] = clipList(pl.Critical)
			}
			return j, nil
		}})

	Register(ops, &Op{Name: "packages.jobs", Action: policy.ActOverviewRead, NoAudit: true,
		Handle: func(ctx context.Context, _ Call) (any, error) { return o.Jobs.List(ctx), nil }})

	Register(ops, &Op{Name: "packages.job", Action: policy.ActOverviewRead, NoAudit: true,
		Handle: func(ctx context.Context, c Call) (any, error) {
			var p struct {
				ID     string `json:"id"`
				Offset int64  `json:"offset"`
			}
			if err := decode(c, &p); err != nil {
				return nil, err
			}
			j, err := o.Jobs.Get(ctx, p.ID)
			if err != nil {
				return nil, aptErr(err)
			}
			text, next, err := o.Jobs.Log(p.ID, p.Offset)
			if err != nil {
				return nil, aptErr(err)
			}
			return AptJobLog{Job: j, Log: text, Next: next}, nil
		}})

	Register(ops, &Op{Name: "packages.unattended", Action: policy.ActOverviewRead, NoAudit: true, Timeout: time.Minute,
		Handle: func(ctx context.Context, _ Call) (any, error) {
			st, err := o.Sys.Unattended(ctx)
			if err != nil {
				return nil, err
			}
			o.mu.Lock()
			if o.counts != nil {
				o.counts.AutoSecurity = autoSecurity(st)
			}
			o.mu.Unlock()
			_, err = apt.SecurityOrigins(apt.ReadDistro(o.root("/")).ID)
			return AptUnattended{UnattendedStatus: st, Supported: err == nil}, nil
		}})

	Register(ops, &Op{Name: "packages.unattended.set", Action: policy.ActPackagesWrite, Timeout: time.Minute,
		AuditTarget: func(Call) string { return "file:" + o.UnattendedPath },
		Handle: func(ctx context.Context, c Call) (any, error) {
			var u apt.Unattended
			if err := decode(c, &u); err != nil {
				return nil, err
			}
			if !u.Valid() {
				return nil, Errf(rpc.CodeValidation, "invalid reboot time")
			}
			if o.Sys.Version(ctx, "unattended-upgrades") == "" {
				return nil, Errf(rpc.CodeNotSupported, "unattended-upgrades is not installed")
			}
			text, err := apt.RenderUnattended(u, apt.ReadDistro(o.root("/")).ID)
			if err != nil {
				return nil, Errf(rpc.CodeNotSupported, "%v", err)
			}
			if err := writeUnattended(o.UnattendedPath, text); err != nil {
				return nil, err
			}
			c.AuditKV["enabled"] = strconv.FormatBool(u.Enabled)
			c.AuditKV["auto_reboot"] = strconv.FormatBool(u.AutoReboot)
			if u.AutoReboot {
				c.AuditKV["reboot_time"] = u.RebootTime
			}
			st, err := o.Sys.Unattended(ctx)
			if err != nil {
				return nil, err
			}
			return AptUnattended{UnattendedStatus: st, Supported: true}, nil
		}})
}

// clipList joins names for an audit value (bounded).
func clipList(names []string) string {
	s := strings.Join(names, ",")
	if len(s) > 500 {
		s = s[:500] + "…"
	}
	return s
}
