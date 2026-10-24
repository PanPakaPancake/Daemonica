package helper

import (
	"context"
	"os"
	"strings"
	"time"

	"github.com/PanPakaPancake/daemonica/internal/audit"
	"github.com/PanPakaPancake/daemonica/internal/auth"
	"github.com/PanPakaPancake/daemonica/internal/netallow"
	"github.com/PanPakaPancake/daemonica/internal/policy"
	"github.com/PanPakaPancake/daemonica/internal/rpc"
)

// Core bundles the helper's shared state and registers the M1.0 operations.
type Core struct {
	Config    *ConfigStore
	Tokens    auth.TokenStore
	Grants    *GrantStore
	AuditPath string
	Version   string
	Now       func() time.Time
}

func (c *Core) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// StatusResult is returned by admin.status.
type StatusResult struct {
	Version    string   `json:"version"`
	SetupDone  bool     `json:"setup_done"`
	Domain     string   `json:"domain,omitempty"`
	Port       int      `json:"port"`
	Allowlist  []string `json:"allowlist"`
	PublicWarn bool     `json:"allowlist_public"`
	LiveGrants int      `json:"live_sessions"`
	AuditHead  string   `json:"audit_head,omitempty"`
}

// BootstrapParams are the inputs of admin.bootstrap.
type BootstrapParams struct {
	Allow []string `json:"allow,omitempty"`
}

// BootstrapResult carries the clear token exactly once.
type BootstrapResult struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
	Allowlist []string  `json:"allowlist"`
}

// WebConfig is the subset of Config the web process needs.
type WebConfig struct {
	SetupDone bool     `json:"setup_done"`
	Domain    string   `json:"domain,omitempty"`
	Port      int      `json:"port"`
	Allowlist []string `json:"allowlist"`
	Language  string   `json:"language"`
	UploadMiB int      `json:"upload_limit_mib"`
}

// TokenParams carries a presented one-time token.
type TokenParams struct {
	Token string `json:"token"`
}

// WhoAmI describes the authenticated subject.
type WhoAmI struct {
	AccountID string `json:"account_id"`
	Role      string `json:"role"`
	LinuxUser string `json:"linux_user"`
	StepUp    bool   `json:"step_up"`
}

// Register installs the M1.0 core operations.
func (c *Core) Register(ops map[string]*Op, al *audit.Logger) {
	// --- admin channel (root only) ---
	Register(ops, &Op{Name: "admin.status", AdminChannel: true, NoAudit: true,
		Handle: func(context.Context, Call) (any, error) {
			cfg := c.Config.Get()
			pfx, _ := netallow.ParseList(cfg.Allowlist)
			res := StatusResult{Version: c.Version, SetupDone: cfg.SetupDone, Domain: cfg.Domain, Port: cfg.Port,
				Allowlist: cfg.Allowlist, PublicWarn: netallow.IsPublic(pfx), LiveGrants: c.Grants.Count()}
			if al != nil {
				res.AuditHead = al.LastHash()
			}
			return res, nil
		}})

	Register(ops, &Op{Name: "admin.bootstrap", AdminChannel: true,
		Handle: func(_ context.Context, call Call) (any, error) {
			var p BootstrapParams
			if len(call.Params) > 0 {
				if err := rpc.DecodeStrict(call.Params, &p); err != nil {
					return nil, Errf(rpc.CodeBadRequest, "invalid parameters")
				}
			}
			cfg := c.Config.Get()
			if cfg.SetupDone {
				return nil, Errf(rpc.CodeSetupComplete, "setup already completed; use 'recover'")
			}
			if len(p.Allow) > 0 {
				pfx, err := netallow.ParseList(p.Allow)
				if err != nil {
					return nil, Errf(rpc.CodeValidation, "invalid --allow CIDR")
				}
				if netallow.IsPublic(pfx) {
					return nil, Errf(rpc.CodeValidation, "refusing a public allowlist during bootstrap")
				}
				merged := append([]string{"127.0.0.0/8", "::1/128"}, p.Allow...)
				if _, err := c.Config.Update(func(cf *Config) error { cf.Allowlist = merged; return nil }); err != nil {
					return nil, Errf(rpc.CodeValidation, "cannot store allowlist")
				}
			}
			tok, err := auth.Issue(c.Tokens, auth.PurposeBootstrap, "", auth.BootstrapTTL, c.now())
			if err != nil {
				return nil, err
			}
			return BootstrapResult{Token: tok, ExpiresAt: c.now().Add(auth.BootstrapTTL).UTC(),
				Allowlist: c.Config.Get().Allowlist}, nil
		}})

	Register(ops, &Op{Name: "admin.allowlist_reset", AdminChannel: true,
		Handle: func(context.Context, Call) (any, error) {
			cfg, err := c.Config.Update(func(cf *Config) error {
				cf.Allowlist = []string{"127.0.0.0/8", "::1/128"}
				return nil
			})
			if err != nil {
				return nil, err
			}
			return cfg.Allowlist, nil
		}})

	Register(ops, &Op{Name: "admin.audit_verify", AdminChannel: true, NoAudit: true, Timeout: 5 * time.Minute,
		Handle: func(context.Context, Call) (any, error) {
			f, err := os.Open(c.AuditPath)
			if err != nil {
				return nil, Errf(rpc.CodeNotFound, "audit log not readable")
			}
			defer func() { _ = f.Close() }()
			return audit.Verify(f, ""), nil
		}})

	// --- web channel, pre-auth (setup mode only) ---
	Register(ops, &Op{Name: "setup.check_token", PreAuth: true,
		Handle: func(_ context.Context, call Call) (any, error) {
			if c.Config.Get().SetupDone {
				return nil, Errf(rpc.CodeSetupComplete, "")
			}
			var p TokenParams
			if err := rpc.DecodeStrict(call.Params, &p); err != nil || len(p.Token) > 128 || strings.ContainsAny(p.Token, " \n") {
				return nil, Errf(rpc.CodeTokenInvalid, "")
			}
			if _, err := c.Tokens.Peek(auth.PurposeBootstrap, p.Token, c.now()); err != nil {
				return nil, Errf(rpc.CodeTokenInvalid, "")
			}
			return map[string]bool{"valid": true}, nil
		}})

	Register(ops, &Op{Name: "setup.state", PreAuth: true, NoAudit: true,
		Handle: func(context.Context, Call) (any, error) {
			cfg := c.Config.Get()
			return map[string]any{"setup_done": cfg.SetupDone, "language": cfg.Language}, nil
		}})

	// config.web hands the web process the non-secret listener settings. It is
	// reachable only over helper.sock (peer UID daemonia-web), never via HTTP.
	Register(ops, &Op{Name: "config.web", PreAuth: true, NoAudit: true,
		Handle: func(context.Context, Call) (any, error) {
			cfg := c.Config.Get()
			return WebConfig{SetupDone: cfg.SetupDone, Domain: cfg.Domain, Port: cfg.Port, Allowlist: cfg.Allowlist,
				Language: cfg.Language, UploadMiB: cfg.UploadMiB}, nil
		}})

	// --- web channel, authenticated ---
	Register(ops, &Op{Name: "session.whoami", Action: policy.ActOwnSessions, NoAudit: true,
		Handle: func(_ context.Context, call Call) (any, error) {
			s := call.Subject
			return WhoAmI{AccountID: s.AccountID, Role: string(s.Role), LinuxUser: s.LinuxUser, StepUp: s.StepUp}, nil
		}})
}
