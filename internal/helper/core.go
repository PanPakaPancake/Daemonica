package helper

import (
	"context"
	"os"
	"path/filepath"
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
	TLSDir    string
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
	TLSSource string   `json:"tls_source,omitempty"`
	// CertVersion changes whenever the certificate files are replaced.
	CertVersion int64 `json:"cert_version"`
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
			if cfg.SetupDone {
				// Minimal pre-login surface once set up (SPEC §3.1).
				return map[string]any{"setup_done": true, "language": cfg.Language}, nil
			}
			hasCert := false
			if c.TLSDir != "" {
				if _, err := os.Stat(filepath.Join(c.TLSDir, "fullchain.pem")); err == nil {
					hasCert = true
				}
			}
			return map[string]any{"setup_done": cfg.SetupDone, "language": cfg.Language, "domain": cfg.Domain,
				"port": cfg.Port, "has_certificate": hasCert, "tls_source": cfg.TLSSource}, nil
		}})

	// config.web hands the web process the non-secret listener settings. It is
	// reachable only over helper.sock (peer UID daemonica-web), never via HTTP.
	Register(ops, &Op{Name: "config.web", PreAuth: true, NoAudit: true,
		Handle: func(context.Context, Call) (any, error) {
			cfg := c.Config.Get()
			wc := WebConfig{SetupDone: cfg.SetupDone, Domain: cfg.Domain, Port: cfg.Port, Allowlist: cfg.Allowlist,
				Language: cfg.Language, UploadMiB: cfg.UploadMiB, TLSSource: cfg.TLSSource}
			if c.TLSDir != "" {
				if fi, err := os.Stat(filepath.Join(c.TLSDir, "fullchain.pem")); err == nil {
					wc.CertVersion = fi.ModTime().UnixNano()
				}
			}
			return wc, nil
		}})

	// --- web channel, authenticated ---
	Register(ops, &Op{Name: "audit.query", Action: policy.ActAuditRead, NoAudit: true, Timeout: time.Minute,
		Handle: func(_ context.Context, call Call) (any, error) {
			var f audit.Filter
			if len(call.Params) > 0 {
				if err := rpc.DecodeStrict(call.Params, &f); err != nil {
					return nil, Errf(rpc.CodeBadRequest, "invalid parameters")
				}
			}
			for _, v := range []string{f.ActionPrefix, f.Result, f.Actor, f.Text, f.Since, f.Until, f.Before} {
				if len(v) > 128 {
					return nil, Errf(rpc.CodeValidation, "filter too long")
				}
			}
			fh, err := os.Open(c.AuditPath)
			if err != nil {
				return nil, Errf(rpc.CodeNotFound, "audit log not readable")
			}
			defer func() { _ = fh.Close() }()
			page, err := audit.Query(fh, f)
			if err != nil {
				return nil, Errf(rpc.CodeValidation, "invalid query")
			}
			return page, nil
		}})

	Register(ops, &Op{Name: "audit.verify", Action: policy.ActAuditRead, Timeout: 5 * time.Minute,
		Handle: func(context.Context, Call) (any, error) {
			fh, err := os.Open(c.AuditPath)
			if err != nil {
				return nil, Errf(rpc.CodeNotFound, "audit log not readable")
			}
			defer func() { _ = fh.Close() }()
			return audit.Verify(fh, ""), nil
		}})

	Register(ops, &Op{Name: "session.whoami", Action: policy.ActOwnSessions, NoAudit: true,
		Handle: func(_ context.Context, call Call) (any, error) {
			s := call.Subject
			return WhoAmI{AccountID: s.AccountID, Role: string(s.Role), LinuxUser: s.LinuxUser, StepUp: s.StepUp}, nil
		}})
}
