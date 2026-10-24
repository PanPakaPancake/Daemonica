package helper

import (
	"context"
	"encoding/json"
	"time"

	"github.com/PanPakaPancake/daemonica/internal/policy"
	"github.com/PanPakaPancake/daemonica/internal/rpc"
	"github.com/PanPakaPancake/daemonica/internal/services"
)

// Systemd is the subset of the D-Bus client used by ServiceOps (mockable).
type Systemd interface {
	List(ctx context.Context) ([]services.Unit, error)
	Get(ctx context.Context, name string) (services.Detail, error)
	Do(ctx context.Context, name, action string) error
	FailedCount(ctx context.Context) (int, error)
}

// ServiceOps exposes systemd units (SPEC §7.2 "Dienststatus").
type ServiceOps struct{ Systemd Systemd }

type unitParams struct {
	Unit    string `json:"unit"`
	Action  string `json:"action,omitempty"`
	Confirm bool   `json:"confirm,omitempty"` // explicit extra confirmation (self-lockout protection)
}

// serviceDecision applies Annex A and the protected-unit rules:
//   - enable/disable/mask/unmask: admin + step-up
//   - start/stop/restart/reload on protected units: admin + step-up
//   - daemonica-helper cannot be stopped/disabled/masked via the UI at all
//   - stopping/disabling/masking daemonica-web needs explicit confirmation (lock-out)
func serviceDecision(s policy.Subject, unit, action string, confirm bool) error {
	prot := services.Protection(unit)
	destructive := action == services.ActStop || action == services.ActDisable || action == services.ActMask
	if prot == services.ProtHelper && destructive {
		return Errf(rpc.CodeLockout, "daemonica-helper cannot be stopped, disabled or masked from the dashboard")
	}
	act := policy.ActServiceControl
	switch {
	case services.IsFileAction(action):
		act = policy.ActServiceEnable
	case prot != services.ProtNone:
		act = policy.ActServiceControlProt
	}
	switch policy.Decide(s, act, 0, false) {
	case policy.Deny:
		return Errf(rpc.CodeForbidden, "")
	case policy.NeedStepUp:
		return Errf(rpc.CodeStepUpNeeded, "")
	}
	if prot == services.ProtSelf && destructive && !confirm {
		return Errf(rpc.CodeLockout, "confirmation required: this ends access to the dashboard")
	}
	return nil
}

// Register installs services.* operations.
func (s *ServiceOps) Register(ops map[string]*Op) {
	Register(ops, &Op{Name: "services.list", Action: policy.ActOverviewRead, NoAudit: true, Timeout: 20 * time.Second,
		Handle: func(ctx context.Context, _ Call) (any, error) { return s.Systemd.List(ctx) }})

	Register(ops, &Op{Name: "services.get", Action: policy.ActOverviewRead, NoAudit: true,
		Handle: func(ctx context.Context, c Call) (any, error) {
			var p unitParams
			if err := decode(c, &p); err != nil {
				return nil, err
			}
			d, err := s.Systemd.Get(ctx, p.Unit)
			if err != nil {
				return nil, Errf(rpc.CodeNotFound, "unit not found")
			}
			// Unit files are world-readable on the host; Annex A grants the service
			// view to all roles. The unit's journal is a separate op (logs.read).
			return d, nil
		}})

	Register(ops, &Op{Name: "services.action", Action: policy.ActServiceControl, Timeout: 90 * time.Second,
		AuditTarget: func(c Call) string {
			var p unitParams
			_ = json.Unmarshal(c.Params, &p)
			return "unit:" + p.Unit + " action:" + p.Action
		},
		Handle: func(ctx context.Context, c Call) (any, error) {
			var p unitParams
			if err := decode(c, &p); err != nil {
				return nil, err
			}
			if !services.ValidAction(p.Action) {
				return nil, Errf(rpc.CodeValidation, "invalid action")
			}
			if err := serviceDecision(*c.Subject, p.Unit, p.Action, p.Confirm); err != nil {
				return nil, err
			}
			if err := s.Systemd.Do(ctx, p.Unit, p.Action); err != nil {
				return nil, Errf(rpc.CodeConflict, "systemd refused the action")
			}
			d, err := s.Systemd.Get(ctx, p.Unit)
			if err != nil {
				return nil, nil //nolint:nilerr // action succeeded; detail refresh is best effort
			}
			d.UnitFile = ""
			return d, nil
		}})
}
