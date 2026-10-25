package helper

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/PanPakaPancake/daemonica/internal/netallow"
	"github.com/PanPakaPancake/daemonica/internal/planner"
	"github.com/PanPakaPancake/daemonica/internal/policy"
	"github.com/PanPakaPancake/daemonica/internal/rpc"
)

// KindAllowlist is the planner kind for dashboard allowlist changes.
const KindAllowlist = "allowlist"

// loopback is always kept so the console (SSH tunnel) path never locks out.
var loopback = []string{"127.0.0.0/8", "::1/128"}

type allowlistPayload struct {
	Old []string `json:"old"`
	New []string `json:"new"`
}

// AllowlistHandler applies allowlist changes to the helper config; the web
// process picks them up immediately (reload hook) or within its poll interval.
type AllowlistHandler struct{ Config *ConfigStore }

// Kind implements planner.Handler.
func (h *AllowlistHandler) Kind() string { return KindAllowlist }

func (h *AllowlistHandler) set(payload json.RawMessage, pick func(allowlistPayload) []string) error {
	var p allowlistPayload
	if err := json.Unmarshal(payload, &p); err != nil {
		return err
	}
	list := pick(p)
	if _, err := netallow.ParseList(list); err != nil || len(list) == 0 {
		return errors.New("invalid allowlist in payload")
	}
	_, err := h.Config.Update(func(cf *Config) error { cf.Allowlist = list; return nil })
	return err
}

// Apply implements planner.Handler.
func (h *AllowlistHandler) Apply(_ context.Context, payload json.RawMessage) error {
	return h.set(payload, func(p allowlistPayload) []string { return p.New })
}

// Rollback implements planner.Handler.
func (h *AllowlistHandler) Rollback(_ context.Context, payload json.RawMessage) error {
	return h.set(payload, func(p allowlistPayload) []string { return p.Old })
}

// SettingsOps exposes dashboard settings and the Plan→Apply→Confirm flow (SPEC §3.2 rule 10, §3.6).
type SettingsOps struct {
	Config  *ConfigStore
	Planner *planner.Manager
	Now     func() time.Time
}

func (s *SettingsOps) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// SettingsView is returned by settings.get.
type SettingsView struct {
	Domain      string   `json:"domain"`
	Port        int      `json:"port"`
	Allowlist   []string `json:"allowlist"`
	Public      bool     `json:"public"`
	TLSSource   string   `json:"tls_source,omitempty"`
	Language    string   `json:"language"`
	IdleMinutes int      `json:"idle_minutes"`
	AbsHours    int      `json:"absolute_hours"`
	UploadMiB   int      `json:"upload_limit_mib"`
	ClientIP    string   `json:"client_ip"`
	ClientOK    bool     `json:"client_allowed"`
}

type allowlistPlanParams struct {
	Allowlist      []string `json:"allowlist"`
	ConfirmPublic  bool     `json:"confirm_public,omitempty"`
	ConfirmLockout bool     `json:"confirm_lockout,omitempty"`
}

type changeParams struct {
	ID string `json:"id"`
	// ConnectionSince is the accept time of the TCP connection carrying the
	// confirmation (set by the web layer). It must be later than the apply:
	// a confirmation proves the new settings admit a fresh connection.
	ConnectionSince time.Time `json:"connection_since,omitempty"`
}

func contains(pfx []netip.Prefix, ip string) bool {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	return netallow.New(pfx).Contains(a.Unmap())
}

func mapPlannerErr(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, planner.ErrNotFound), errors.Is(err, planner.ErrNotOwner):
		return Errf(rpc.CodeNotFound, "")
	case errors.Is(err, planner.ErrWrongState):
		return Errf(rpc.CodeConflict, "change is not in the required state (expired?)")
	case errors.Is(err, planner.ErrBusy):
		return Errf(rpc.CodeConflict, "another change of this kind is pending")
	}
	return err
}

// redact drops the payload from the public view (it may grow secrets for other kinds).
func redact(c planner.Change) planner.Change { c.Payload = nil; return c }

// Register installs the settings operations.
func (s *SettingsOps) Register(ops map[string]*Op) {
	Register(ops, &Op{Name: "settings.get", Action: policy.ActSettingsRead, NoAudit: true,
		Handle: func(_ context.Context, c Call) (any, error) {
			cfg := s.Config.Get()
			pfx, _ := netallow.ParseList(cfg.Allowlist)
			return SettingsView{Domain: cfg.Domain, Port: cfg.Port, Allowlist: cfg.Allowlist, Public: netallow.IsPublic(pfx),
				TLSSource: cfg.TLSSource, Language: cfg.Language, IdleMinutes: cfg.IdleMinutes, AbsHours: cfg.AbsHours,
				UploadMiB: cfg.UploadMiB, ClientIP: c.SourceIP, ClientOK: contains(pfx, c.SourceIP)}, nil
		}})

	Register(ops, &Op{Name: "settings.allowlist_plan", Action: policy.ActSettingsWrite,
		Handle: func(_ context.Context, c Call) (any, error) {
			var p allowlistPlanParams
			if err := decode(c, &p); err != nil {
				return nil, err
			}
			if len(p.Allowlist) == 0 || len(p.Allowlist) > 64 {
				return nil, Errf(rpc.CodeValidation, "allowlist must have 1–64 entries")
			}
			pfx, err := netallow.ParseList(p.Allowlist)
			if err != nil {
				return nil, Errf(rpc.CodeValidation, "invalid CIDR")
			}
			// Canonical, de-duplicated, loopback always present.
			list := slices.Clone(loopback)
			for _, x := range pfx {
				if v := x.String(); !slices.Contains(list, v) {
					list = append(list, v)
				}
			}
			all, _ := netallow.ParseList(list)
			if netallow.IsPublic(all) && !p.ConfirmPublic {
				return nil, Errf(rpc.CodeValidation, "public allowlist requires explicit confirmation")
			}
			risk := "medium"
			if !contains(all, c.SourceIP) {
				if !p.ConfirmLockout {
					return nil, Errf(rpc.CodeLockout, "the new allowlist does not include your current IP address")
				}
				risk = "high"
			}
			old := s.Config.Get().Allowlist
			if slices.Equal(old, list) {
				return nil, Errf(rpc.CodeValidation, "no change")
			}
			payload, _ := json.Marshal(allowlistPayload{Old: old, New: list})
			ch, err := s.Planner.Plan(KindAllowlist, c.Subject.AccountID, "Dashboard allowlist", diffLines(old, list), risk, payload)
			if err != nil {
				return nil, mapPlannerErr(err)
			}
			return redact(ch), nil
		}})

	Register(ops, &Op{Name: "settings.change_get", Action: policy.ActSettingsRead, NoAudit: true,
		Handle: func(_ context.Context, c Call) (any, error) {
			var p changeParams
			if err := decode(c, &p); err != nil {
				return nil, err
			}
			ch, err := s.Planner.Get(p.ID)
			if err != nil || ch.Owner != c.Subject.AccountID {
				return nil, Errf(rpc.CodeNotFound, "")
			}
			return redact(ch), nil
		}})

	Register(ops, &Op{Name: "settings.change_apply", Action: policy.ActSettingsWrite, AuditTarget: changeTarget, Timeout: 4 * time.Minute,
		Handle: func(ctx context.Context, c Call) (any, error) {
			var p changeParams
			if err := decode(c, &p); err != nil {
				return nil, err
			}
			ch, err := s.Planner.Apply(ctx, p.ID, c.Subject.AccountID)
			if err != nil {
				return nil, mapPlannerErr(err)
			}
			return redact(ch), nil
		}})

	Register(ops, &Op{Name: "settings.change_confirm", Action: policy.ActSettingsWrite, AuditTarget: changeTarget,
		Handle: func(_ context.Context, c Call) (any, error) {
			var p changeParams
			if err := decode(c, &p); err != nil {
				return nil, err
			}
			cur, err := s.Planner.Get(p.ID)
			if err != nil || cur.Owner != c.Subject.AccountID {
				return nil, Errf(rpc.CodeNotFound, "")
			}
			if p.ConnectionSince.IsZero() || !p.ConnectionSince.After(cur.AppliedAt) {
				return nil, Errf(rpc.CodeConflict, "confirm over a new connection")
			}
			ch, err := s.Planner.Confirm(p.ID, c.Subject.AccountID)
			if err != nil {
				return nil, mapPlannerErr(err)
			}
			return redact(ch), nil
		}})

	Register(ops, &Op{Name: "settings.change_rollback", Action: policy.ActSettingsWrite, AuditTarget: changeTarget, Timeout: 4 * time.Minute,
		Handle: func(_ context.Context, c Call) (any, error) {
			var p changeParams
			if err := decode(c, &p); err != nil {
				return nil, err
			}
			ch, err := s.Planner.Rollback(p.ID, c.Subject.AccountID)
			if err != nil {
				return nil, mapPlannerErr(err)
			}
			return redact(ch), nil
		}})
}

func changeTarget(c Call) string {
	var p changeParams
	_ = json.Unmarshal(c.Params, &p)
	return "change:" + p.ID
}

// diffLines renders a minimal unified-style diff of two lists.
func diffLines(old, cur []string) string {
	var b strings.Builder
	for _, o := range old {
		if !slices.Contains(cur, o) {
			b.WriteString("- " + o + "\n")
		}
	}
	for _, n := range cur {
		if slices.Contains(old, n) {
			b.WriteString("  " + n + "\n")
		} else {
			b.WriteString("+ " + n + "\n")
		}
	}
	return b.String()
}
