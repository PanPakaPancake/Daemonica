package helper

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/PanPakaPancake/daemonica/internal/netcfg"
	"github.com/PanPakaPancake/daemonica/internal/policy"
	"github.com/PanPakaPancake/daemonica/internal/rpc"
	"github.com/PanPakaPancake/daemonica/internal/timehost"
)

// Error codes of the time, host and power operations.
const (
	CodeConfirmMismatch = "confirm_mismatch"
)

// TimeHostBus is what TimeHostOps needs from systemd (timehost.Bus in
// production).
type TimeHostBus interface {
	Time(ctx context.Context) (timehost.Time, error)
	Timezones(ctx context.Context) ([]string, error)
	SetTimezone(ctx context.Context, tz string) error
	SetNTP(ctx context.Context, on bool) error
	Host(ctx context.Context) (timehost.Host, error)
	SetHostname(ctx context.Context, static, pretty string) error
	Scheduled(ctx context.Context) (*timehost.Scheduled, error)
	Inhibitors(ctx context.Context) ([]timehost.Inhibitor, error)
	Schedule(ctx context.Context, action string, t time.Time) error
	Now(ctx context.Context, action string) error
	Cancel(ctx context.Context) (bool, error)
}

// TimeHostOps exposes time zone, NTP, host name and reboot/power-off
// (SPEC §7.8, DEC-033). Reading is open to all roles; changes need admin +
// step-up, power actions additionally the typed host name.
type TimeHostOps struct {
	Bus       TimeHostBus
	HostsPath string
	// Root is "/" in production (cloud-init config); ProcRoot is "/proc".
	Root     string
	ProcRoot string
	Now      func() time.Time
	// After runs f after d (time.AfterFunc in production); used to let the
	// answer of an immediate reboot reach the browser first.
	After func(d time.Duration, f func())

	tzOnce sync.Once
	tzList []string
	tzErr  error
}

// TimeHostState is the timehost.get result.
type TimeHostState struct {
	Time      *timehost.Time `json:"time"`
	Host      *timehost.Host `json:"host"`
	HostsLine string         `json:"hosts_line"`
	CloudInit bool           `json:"cloud_init_resets"`
	// CloudHosts is cloud-init's manage_etc_hosts mode ("", template, localhost).
	CloudHosts string               `json:"cloud_init_hosts"`
	BootID     string               `json:"boot_id"`
	Scheduled  *timehost.Scheduled  `json:"scheduled"`
	Inhibitors []timehost.Inhibitor `json:"inhibitors"`
	Errors     []string             `json:"errors,omitempty"`
}

// HostnamePlan is the timehost.hostname_plan result.
type HostnamePlan struct {
	Diff       string `json:"diff"`
	CloudInit  bool   `json:"cloud_init_resets"`
	CloudHosts string `json:"cloud_init_hosts"`
	Changed    bool   `json:"hosts_changed"`
}

// PowerResult is the power.schedule result.
type PowerResult struct {
	Action string    `json:"action"`
	At     time.Time `json:"at"`
	BootID string    `json:"boot_id"`
}

type hostnameParams struct {
	Hostname string `json:"hostname"`
	Pretty   string `json:"pretty"`
	// Hosts also renames the host in /etc/hosts (default in the UI).
	Hosts bool `json:"update_hosts"`
}

type powerParams struct {
	Action   string `json:"action"`
	DelayMin int    `json:"delay_min"`
	Confirm  string `json:"confirm"`
}

func (o *TimeHostOps) now() time.Time {
	if o.Now != nil {
		return o.Now()
	}
	return time.Now()
}

func (o *TimeHostOps) root() string {
	if o.Root == "" || o.Root == "/" {
		return ""
	}
	return o.Root
}

func (o *TimeHostOps) proc() string {
	if o.ProcRoot == "" {
		return "/proc"
	}
	return o.ProcRoot
}

func (o *TimeHostOps) timezones(ctx context.Context) ([]string, error) {
	o.tzOnce.Do(func() { o.tzList, o.tzErr = o.Bus.Timezones(ctx) })
	if o.tzErr != nil {
		err := o.tzErr
		o.tzOnce = sync.Once{} // retry next time
		return nil, err
	}
	return o.tzList, nil
}

func hostsLine(text string) string {
	for l := range strings.SplitSeq(text, "\n") {
		if f := strings.Fields(l); len(f) > 0 && f[0] == "127.0.1.1" {
			return strings.TrimSpace(l)
		}
	}
	return ""
}

// current returns the name a power action must be confirmed with.
func confirmName(h timehost.Host) string {
	if h.Static != "" {
		return h.Static
	}
	return h.Hostname
}

func (o *TimeHostOps) hostsChange(old, nw string) (string, string, error) {
	b, err := os.ReadFile(o.HostsPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", "", err
	}
	cur := string(b)
	return cur, timehost.RenameHosts(cur, old, nw), nil
}

// Register installs the timehost.* and power.* operations.
func (o *TimeHostOps) Register(ops map[string]*Op) {
	Register(ops, &Op{Name: "timehost.get", Action: policy.ActOverviewRead, NoAudit: true,
		Handle: func(ctx context.Context, _ Call) (any, error) {
			res := TimeHostState{BootID: timehost.BootID(o.proc()), CloudInit: timehost.CloudInitResets(o.root()),
				CloudHosts: timehost.CloudInitHostsMode(o.root()), Inhibitors: []timehost.Inhibitor{}}
			if t, err := o.Bus.Time(ctx); err == nil {
				res.Time = &t
			} else {
				res.Errors = append(res.Errors, "timedated")
			}
			if h, err := o.Bus.Host(ctx); err == nil {
				res.Host = &h
			} else {
				res.Errors = append(res.Errors, "hostnamed")
			}
			if b, err := os.ReadFile(o.HostsPath); err == nil {
				res.HostsLine = hostsLine(string(b))
			}
			var err error
			if res.Scheduled, err = o.Bus.Scheduled(ctx); err != nil {
				res.Errors = append(res.Errors, "logind")
			}
			if in, err := o.Bus.Inhibitors(ctx); err == nil {
				res.Inhibitors = in
			}
			return res, nil
		}})

	Register(ops, &Op{Name: "timehost.timezones", Action: policy.ActOverviewRead, NoAudit: true,
		Handle: func(ctx context.Context, _ Call) (any, error) {
			return o.timezones(ctx)
		}})

	Register(ops, &Op{Name: "timehost.set_timezone", Action: policy.ActTimeHostWrite,
		AuditTarget: func(Call) string { return "timezone" },
		Handle: func(ctx context.Context, c Call) (any, error) {
			var p struct {
				Timezone string `json:"timezone"`
			}
			if err := decode(c, &p); err != nil {
				return nil, err
			}
			list, err := o.timezones(ctx)
			if err != nil {
				return nil, err
			}
			if !timehost.ValidTimezone(p.Timezone, list) {
				return nil, Errf(rpc.CodeValidation, "unknown time zone")
			}
			c.AuditKV["timezone"] = p.Timezone
			if err := o.Bus.SetTimezone(ctx, p.Timezone); err != nil {
				return nil, err
			}
			return o.Bus.Time(ctx)
		}})

	Register(ops, &Op{Name: "timehost.set_ntp", Action: policy.ActTimeHostWrite,
		AuditTarget: func(Call) string { return "ntp" },
		Handle: func(ctx context.Context, c Call) (any, error) {
			var p struct {
				On bool `json:"on"`
			}
			if err := decode(c, &p); err != nil {
				return nil, err
			}
			c.AuditKV["on"] = strconv.FormatBool(p.On)
			if err := o.Bus.SetNTP(ctx, p.On); err != nil {
				return nil, err
			}
			return o.Bus.Time(ctx)
		}})

	validHost := func(p hostnameParams) error {
		if !timehost.ValidHostname(p.Hostname) {
			return Errf(rpc.CodeValidation, "invalid host name")
		}
		if !timehost.ValidPretty(p.Pretty) {
			return Errf(rpc.CodeValidation, "invalid pretty name")
		}
		return nil
	}

	Register(ops, &Op{Name: "timehost.hostname_plan", Action: policy.ActOverviewRead, NoAudit: true,
		Handle: func(ctx context.Context, c Call) (any, error) {
			var p hostnameParams
			if err := decode(c, &p); err != nil {
				return nil, err
			}
			if err := validHost(p); err != nil {
				return nil, err
			}
			h, err := o.Bus.Host(ctx)
			if err != nil {
				return nil, err
			}
			cur, nw, err := o.hostsChange(confirmName(h), p.Hostname)
			if err != nil {
				return nil, err
			}
			res := HostnamePlan{CloudInit: timehost.CloudInitResets(o.root()), CloudHosts: timehost.CloudInitHostsMode(o.root()), Changed: cur != nw}
			if res.Changed {
				res.Diff = netcfg.UnifiedDiff(o.HostsPath, &cur, &nw)
			}
			return res, nil
		}})

	Register(ops, &Op{Name: "timehost.set_hostname", Action: policy.ActTimeHostWrite,
		AuditTarget: func(Call) string { return "hostname" },
		Handle: func(ctx context.Context, c Call) (any, error) {
			var p hostnameParams
			if err := decode(c, &p); err != nil {
				return nil, err
			}
			if err := validHost(p); err != nil {
				return nil, err
			}
			h, err := o.Bus.Host(ctx)
			if err != nil {
				return nil, err
			}
			old := confirmName(h)
			c.AuditKV["old"], c.AuditKV["new"] = old, p.Hostname
			// /etc/hosts first, so sudo can resolve the new name at once.
			var restore func()
			if p.Hosts {
				cur, nw, err := o.hostsChange(old, p.Hostname)
				if err != nil {
					return nil, err
				}
				if cur != nw {
					backup := o.HostsPath + ".daemonica-" + o.now().UTC().Format("20060102-150405")
					if err := os.WriteFile(backup, []byte(cur), 0o644); err != nil { //nolint:gosec // copy of a world-readable file
						return nil, err
					}
					if err := writeFstab(o.HostsPath, nw); err != nil {
						return nil, err
					}
					c.AuditKV["backup"] = backup
					restore = func() { _ = writeFstab(o.HostsPath, cur) }
				}
			}
			if err := o.Bus.SetHostname(ctx, p.Hostname, p.Pretty); err != nil {
				if restore != nil {
					restore()
				}
				return nil, err
			}
			return o.Bus.Host(ctx)
		}})

	Register(ops, &Op{Name: "power.schedule", Action: policy.ActPower,
		AuditTarget: func(c Call) string {
			var p powerParams
			_ = json.Unmarshal(c.Params, &p)
			return "power:" + p.Action
		},
		Handle: func(ctx context.Context, c Call) (any, error) {
			var p powerParams
			if err := decode(c, &p); err != nil {
				return nil, err
			}
			if p.Action != timehost.Reboot && p.Action != timehost.PowerOff {
				return nil, Errf(rpc.CodeValidation, "unknown action")
			}
			if p.DelayMin < 0 || p.DelayMin > 1440 {
				return nil, Errf(rpc.CodeValidation, "delay out of range")
			}
			h, err := o.Bus.Host(ctx)
			if err != nil {
				return nil, err
			}
			if p.Confirm != confirmName(h) {
				return nil, Errf(CodeConfirmMismatch, "")
			}
			res := PowerResult{Action: p.Action, BootID: timehost.BootID(o.proc()), At: o.now().UTC().Add(time.Duration(p.DelayMin) * time.Minute)}
			c.AuditKV["delay_min"] = strconv.Itoa(p.DelayMin)
			if p.DelayMin > 0 {
				if err := o.Bus.Schedule(ctx, p.Action, res.At); err != nil {
					return nil, err
				}
				return res, nil
			}
			// Immediately: answer first, then let logind act.
			after := o.After
			if after == nil {
				after = func(d time.Duration, f func()) { time.AfterFunc(d, f) }
			}
			after(2*time.Second, func() {
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				_ = o.Bus.Now(ctx, p.Action)
			})
			return res, nil
		}})

	Register(ops, &Op{Name: "power.cancel", Action: policy.ActPower,
		AuditTarget: func(Call) string { return "power:cancel" },
		Handle: func(ctx context.Context, c Call) (any, error) {
			ok, err := o.Bus.Cancel(ctx)
			if err != nil {
				return nil, err
			}
			c.AuditKV["cancelled"] = strconv.FormatBool(ok)
			return map[string]bool{"cancelled": ok}, nil
		}})
}
