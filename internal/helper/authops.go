package helper

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/user"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/PanPakaPancake/daemonica/internal/audit"
	"github.com/PanPakaPancake/daemonica/internal/auth"
	"github.com/PanPakaPancake/daemonica/internal/netallow"
	"github.com/PanPakaPancake/daemonica/internal/policy"
	"github.com/PanPakaPancake/daemonica/internal/rpc"
	"github.com/PanPakaPancake/daemonica/internal/validate"
)

// AuthOps implements setup, login, step-up, passkey management and recovery.
// All WebAuthn verification happens here, in the helper (SPEC §3.2 rule 5).
type AuthOps struct {
	DB      *DB
	Config  *ConfigStore
	Grants  *GrantStore
	Tokens  auth.TokenStore
	Audit   *audit.Logger
	Now     func() time.Time
	Passwd  string // /etc/passwd (overridable in tests)
	LoginDf string // /etc/login.defs

	mu       sync.Mutex
	pk       *auth.Passkeys
	pkKey    string
	pending  map[string]pendingSetup // ceremony ID → account draft (setup only)
	pendingM sync.Mutex
}

type pendingSetup struct {
	name      string
	linuxUser string
	uid       uint32
	handle    []byte
}

func (a *AuthOps) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

// Origins returns the exact WebAuthn origins for a domain/port.
func Origins(domain string, port int) []string {
	o := []string{"https://" + net.JoinHostPort(domain, strconv.Itoa(port))}
	if port == 443 {
		o = append(o, "https://"+domain)
	}
	return o
}

// passkeys returns the verifier for the currently configured domain.
func (a *AuthOps) passkeys() (*auth.Passkeys, error) {
	cfg := a.Config.Get()
	if cfg.Domain == "" {
		return nil, Errf(rpc.CodeValidation, "domain not configured")
	}
	key := cfg.Domain + ":" + strconv.Itoa(cfg.Port)
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.pk == nil || a.pkKey != key {
		pk, err := auth.NewPasskeys(cfg.Domain, Origins(cfg.Domain, cfg.Port))
		if err != nil {
			return nil, err
		}
		a.pk, a.pkKey = pk, key
	}
	return a.pk, nil
}

func (a *AuthOps) webUser(ctx context.Context, acc Account) (*auth.User, error) {
	pks, err := a.DB.Passkeys(ctx, acc.ID)
	if err != nil {
		return nil, err
	}
	u := &auth.User{Handle: acc.WebAuthnID, Name: acc.Name, DisplayName: acc.Name}
	for _, p := range pks {
		var c webauthn.Credential
		if err := json.Unmarshal(p.credential, &c); err == nil {
			u.Credentials = append(u.Credentials, c)
		}
	}
	return u, nil
}

// --- Linux user helpers ---

// LinuxUserInfo describes a Linux account eligible for mapping.
type LinuxUserInfo struct {
	Name string `json:"name"`
	UID  uint32 `json:"uid"`
	Home string `json:"home"`
}

func (a *AuthOps) uidRange() (uint32, uint32) {
	lo, hi := uint32(1000), uint32(60000)
	path := a.LoginDf
	if path == "" {
		path = "/etc/login.defs"
	}
	f, err := os.Open(path) //nolint:gosec // fixed system path
	if err != nil {
		return lo, hi
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fs := strings.Fields(sc.Text())
		if len(fs) != 2 {
			continue
		}
		if v, err := strconv.ParseUint(fs[1], 10, 32); err == nil {
			switch fs[0] {
			case "UID_MIN":
				lo = uint32(v)
			case "UID_MAX":
				hi = uint32(v)
			}
		}
	}
	return lo, hi
}

// EligibleLinuxUsers lists regular users (UID_MIN..UID_MAX) from /etc/passwd.
func (a *AuthOps) EligibleLinuxUsers() ([]LinuxUserInfo, error) {
	path := a.Passwd
	if path == "" {
		path = "/etc/passwd"
	}
	f, err := os.Open(path) //nolint:gosec // fixed system path
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	lo, hi := a.uidRange()
	var out []LinuxUserInfo
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		p := strings.Split(sc.Text(), ":")
		if len(p) < 7 || validate.LinuxUser(p[0]) != nil {
			continue
		}
		uid, err := strconv.ParseUint(p[2], 10, 32)
		if err != nil || uint32(uid) < lo || uint32(uid) > hi || uid == 0 {
			continue
		}
		out = append(out, LinuxUserInfo{Name: p[0], UID: uint32(uid), Home: p[5]})
	}
	return out, sc.Err()
}

func (a *AuthOps) resolveLinuxUser(name string) (LinuxUserInfo, error) {
	if validate.LinuxUser(name) != nil {
		return LinuxUserInfo{}, Errf(rpc.CodeValidation, "invalid linux user")
	}
	users, err := a.EligibleLinuxUsers()
	if err != nil {
		return LinuxUserInfo{}, err
	}
	for _, u := range users {
		if u.Name == name {
			return u, nil
		}
	}
	// Fallback through NSS for users not in /etc/passwd (still UID-range checked).
	if u, err := user.Lookup(name); err == nil {
		uid, _ := strconv.ParseUint(u.Uid, 10, 32)
		lo, hi := a.uidRange()
		if uid != 0 && uint32(uid) >= lo && uint32(uid) <= hi {
			return LinuxUserInfo{Name: name, UID: uint32(uid), Home: u.HomeDir}, nil
		}
	}
	return LinuxUserInfo{}, Errf(rpc.CodeValidation, "linux user not eligible (must exist, UID in UID_MIN..UID_MAX, not root)")
}

// --- parameter types ---

type setupTokenParams struct {
	Token string `json:"token"`
}

type setDomainParams struct {
	Token  string `json:"token"`
	Domain string `json:"domain"`
	Port   int    `json:"port,omitempty"`
}

type setAllowlistParams struct {
	Token         string   `json:"token"`
	Allowlist     []string `json:"allowlist"`
	ConfirmPublic bool     `json:"confirm_public,omitempty"`
}

type beginSetupParams struct {
	Token       string `json:"token"`
	AccountName string `json:"account_name"`
	LinuxUser   string `json:"linux_user"`
}

type finishParams struct {
	Token       string          `json:"token,omitempty"`
	CeremonyID  string          `json:"ceremony_id"`
	Response    json.RawMessage `json:"response"`
	PasskeyName string          `json:"passkey_name,omitempty"`
}

// CeremonyStart is returned by every begin_* operation.
type CeremonyStart struct {
	CeremonyID string          `json:"ceremony_id"`
	Options    json.RawMessage `json:"options"`
}

// GrantResult is returned when a session is created.
type GrantResult struct {
	Grant   string  `json:"grant"`
	Account Account `json:"account"`
}

func decode(call Call, v any) error {
	if err := rpc.DecodeStrict(call.Params, v); err != nil {
		return Errf(rpc.CodeBadRequest, "invalid parameters")
	}
	return nil
}

func passkeyName(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || validate.NoControl(s, 64) != nil {
		return "Passkey"
	}
	return s
}

// SetupGuard is the exported form of setupGuard for other op groups.
func (a *AuthOps) SetupGuard(tok string) error { return a.setupGuard(tok) }

// setupGuard ensures setup mode is active and the bootstrap token is valid.
func (a *AuthOps) setupGuard(tok string) error {
	if a.Config.Get().SetupDone {
		return Errf(rpc.CodeSetupComplete, "")
	}
	if _, err := a.Tokens.Peek(auth.PurposeBootstrap, tok, a.now()); err != nil {
		return Errf(rpc.CodeTokenInvalid, "")
	}
	return nil
}

// Register installs all authentication-related operations.
func (a *AuthOps) Register(ops map[string]*Op) {
	a.pending = map[string]pendingSetup{}

	// ----- setup mode (pre-auth, bootstrap token on every call) -----
	Register(ops, &Op{Name: "setup.set_domain", PreAuth: true,
		AuditTarget: func(c Call) string { var p setDomainParams; _ = json.Unmarshal(c.Params, &p); return "domain:" + p.Domain },
		Handle: func(_ context.Context, c Call) (any, error) {
			var p setDomainParams
			if err := decode(c, &p); err != nil {
				return nil, err
			}
			if err := a.setupGuard(p.Token); err != nil {
				return nil, err
			}
			p.Domain = strings.ToLower(strings.TrimSpace(p.Domain))
			if validate.Domain(p.Domain) != nil {
				return nil, Errf(rpc.CodeValidation, "invalid domain")
			}
			if p.Port == 0 {
				p.Port = DefaultPort
			}
			cfg, err := a.Config.Update(func(cf *Config) error { cf.Domain, cf.Port = p.Domain, p.Port; return nil })
			if err != nil {
				return nil, Errf(rpc.CodeValidation, "invalid domain or port")
			}
			return map[string]any{"domain": cfg.Domain, "port": cfg.Port, "origin": Origins(cfg.Domain, cfg.Port)[0]}, nil
		}})

	Register(ops, &Op{Name: "setup.set_allowlist", PreAuth: true,
		Handle: func(_ context.Context, c Call) (any, error) {
			var p setAllowlistParams
			if err := decode(c, &p); err != nil {
				return nil, err
			}
			if err := a.setupGuard(p.Token); err != nil {
				return nil, err
			}
			pfx, err := netallow.ParseList(p.Allowlist)
			if err != nil || len(pfx) == 0 {
				return nil, Errf(rpc.CodeValidation, "invalid allowlist")
			}
			if netallow.IsPublic(pfx) && !p.ConfirmPublic {
				return nil, Errf(rpc.CodeValidation, "public allowlist requires explicit confirmation")
			}
			list := []string{"127.0.0.0/8", "::1/128"}
			for _, x := range pfx {
				list = append(list, x.String())
			}
			cfg, err := a.Config.Update(func(cf *Config) error { cf.Allowlist = list; return nil })
			if err != nil {
				return nil, Errf(rpc.CodeValidation, "invalid allowlist")
			}
			return map[string]any{"allowlist": cfg.Allowlist, "public": netallow.IsPublic(pfx)}, nil
		}})

	Register(ops, &Op{Name: "setup.linux_users", PreAuth: true, NoAudit: true,
		Handle: func(_ context.Context, c Call) (any, error) {
			var p setupTokenParams
			if err := decode(c, &p); err != nil {
				return nil, err
			}
			if err := a.setupGuard(p.Token); err != nil {
				return nil, err
			}
			return a.EligibleLinuxUsers()
		}})

	Register(ops, &Op{Name: "setup.begin_register", PreAuth: true,
		Handle: func(ctx context.Context, c Call) (any, error) {
			var p beginSetupParams
			if err := decode(c, &p); err != nil {
				return nil, err
			}
			if err := a.setupGuard(p.Token); err != nil {
				return nil, err
			}
			if validate.AccountName(p.AccountName) != nil {
				return nil, Errf(rpc.CodeValidation, "invalid account name")
			}
			lu, err := a.resolveLinuxUser(p.LinuxUser)
			if err != nil {
				return nil, err
			}
			if n, err := a.DB.CountAccounts(ctx); err != nil || n > 0 {
				return nil, Errf(rpc.CodeSetupComplete, "")
			}
			pk, err := a.passkeys()
			if err != nil {
				return nil, err
			}
			handle := make([]byte, 32)
			if _, err := rand.Read(handle); err != nil {
				return nil, err
			}
			u := &auth.User{Handle: handle, Name: p.AccountName, DisplayName: p.AccountName}
			id, opts, err := pk.BeginRegistration("setup", u)
			if err != nil {
				return nil, err
			}
			a.pendingM.Lock()
			a.pending[id] = pendingSetup{name: p.AccountName, linuxUser: lu.Name, uid: lu.UID, handle: handle}
			a.pendingM.Unlock()
			return CeremonyStart{CeremonyID: id, Options: opts}, nil
		}})

	Register(ops, &Op{Name: "setup.finish_register", PreAuth: true,
		Handle: func(ctx context.Context, c Call) (any, error) {
			var p finishParams
			if err := decode(c, &p); err != nil {
				return nil, err
			}
			if err := a.setupGuard(p.Token); err != nil {
				return nil, err
			}
			a.pendingM.Lock()
			draft, ok := a.pending[p.CeremonyID]
			delete(a.pending, p.CeremonyID)
			a.pendingM.Unlock()
			if !ok {
				return nil, Errf(rpc.CodeUnauthorized, "")
			}
			pk, err := a.passkeys()
			if err != nil {
				return nil, err
			}
			u := &auth.User{Handle: draft.handle, Name: draft.name, DisplayName: draft.name}
			cred, err := pk.FinishRegistration(p.CeremonyID, "setup", u, p.Response)
			if err != nil {
				return nil, Errf(rpc.CodeUnauthorized, "")
			}
			// Consuming the token makes setup irrevocably single-use (SPEC §3.3 Bootstrap 4).
			if _, err := a.Tokens.Consume(auth.PurposeBootstrap, p.Token, a.now()); err != nil {
				return nil, Errf(rpc.CodeTokenInvalid, "")
			}
			acc, err := a.DB.CreateAccount(ctx, draft.name, policy.RoleAdmin, draft.linuxUser, draft.uid, draft.handle, a.now())
			if err != nil {
				return nil, err
			}
			if err := a.storeNewCredential(ctx, acc, cred, p.PasskeyName); err != nil {
				return nil, err
			}
			if _, err := a.Config.Update(func(cf *Config) error { cf.SetupDone = true; return nil }); err != nil {
				return nil, err
			}
			acc, _ = a.DB.AccountByID(ctx, acc.ID)
			return a.issue(acc, c.SourceIP)
		}})

	// ----- login (pre-auth) -----
	Register(ops, &Op{Name: "auth.begin_login", PreAuth: true, NoAudit: true,
		Handle: func(context.Context, Call) (any, error) {
			if !a.Config.Get().SetupDone {
				return nil, Errf(rpc.CodeUnavailable, "setup not completed")
			}
			pk, err := a.passkeys()
			if err != nil {
				return nil, err
			}
			id, opts, err := pk.BeginLogin()
			if err != nil {
				return nil, err
			}
			return CeremonyStart{CeremonyID: id, Options: opts}, nil
		}})

	Register(ops, &Op{Name: "auth.finish_login", PreAuth: true,
		Handle: func(ctx context.Context, c Call) (any, error) {
			var p finishParams
			if err := decode(c, &p); err != nil {
				return nil, Errf(rpc.CodeUnauthorized, "")
			}
			pk, err := a.passkeys()
			if err != nil {
				return nil, Errf(rpc.CodeUnauthorized, "")
			}
			var acc Account
			handle, cred, err := pk.FinishLogin(p.CeremonyID, p.Response, func(h []byte) (*auth.User, error) {
				x, err := a.DB.AccountByWebAuthnID(ctx, h)
				if err != nil || x.Disabled {
					return nil, errors.New("unknown")
				}
				acc = x
				return a.webUser(ctx, x)
			})
			if err != nil || handle == nil {
				return nil, Errf(rpc.CodeUnauthorized, "") // uniform error, no enumeration
			}
			if err := a.updateCredential(ctx, cred); err != nil {
				return nil, err
			}
			return a.issue(acc, c.SourceIP)
		}})

	// ----- authenticated session operations -----
	Register(ops, &Op{Name: "auth.begin_stepup", Action: policy.ActOwnSessions, NoAudit: true,
		Handle: func(ctx context.Context, c Call) (any, error) {
			acc, u, pk, err := a.selfUser(ctx, c)
			if err != nil {
				return nil, err
			}
			id, opts, err := pk.BeginStepUp(acc.ID, u)
			if err != nil {
				return nil, err
			}
			return CeremonyStart{CeremonyID: id, Options: opts}, nil
		}})

	Register(ops, &Op{Name: "auth.finish_stepup", Action: policy.ActOwnSessions,
		Handle: func(ctx context.Context, c Call) (any, error) {
			var p finishParams
			if err := decode(c, &p); err != nil {
				return nil, err
			}
			acc, u, pk, err := a.selfUser(ctx, c)
			if err != nil {
				return nil, err
			}
			cred, err := pk.FinishStepUp(p.CeremonyID, acc.ID, u, p.Response)
			if err != nil {
				return nil, Errf(rpc.CodeUnauthorized, "")
			}
			if err := a.updateCredential(ctx, cred); err != nil {
				return nil, err
			}
			// Rotate the session token on step-up (no fixation, SPEC §3.5).
			tok, err := a.Grants.RotateWithStepUp(c.Grant, a.now())
			if err != nil {
				return nil, Errf(rpc.CodeUnauthorized, "")
			}
			return map[string]any{"grant": tok, "step_up_until": a.now().Add(auth.StepUpTTL).UTC()}, nil
		}})

	Register(ops, &Op{Name: "auth.logout", Action: policy.ActOwnSessions,
		Handle: func(_ context.Context, c Call) (any, error) {
			a.Grants.Revoke(c.Grant)
			return nil, nil
		}})

	Register(ops, &Op{Name: "sessions.list", Action: policy.ActOwnSessions, NoAudit: true,
		Handle: func(ctx context.Context, c Call) (any, error) {
			var p struct {
				All bool `json:"all,omitempty"`
			}
			if len(c.Params) > 0 {
				if err := decode(c, &p); err != nil {
					return nil, err
				}
			}
			scope := c.Subject.AccountID
			if p.All {
				if c.Subject.Role != policy.RoleAdmin {
					return nil, Errf(rpc.CodeForbidden, "")
				}
				scope = ""
			}
			list := a.Grants.List(scope, c.GrantID, a.now())
			names := map[string]string{}
			if accs, err := a.DB.ListAccounts(ctx); err == nil {
				for _, x := range accs {
					names[x.ID] = x.Name
				}
			}
			for i := range list {
				list[i].AccountName = names[list[i].AccountID]
			}
			return list, nil
		}})

	Register(ops, &Op{Name: "sessions.revoke", Action: policy.ActOwnSessions,
		AuditTarget: func(c Call) string { var p struct{ ID string `json:"id"` }; _ = json.Unmarshal(c.Params, &p); return "session:" + p.ID },
		Handle: func(_ context.Context, c Call) (any, error) {
			var p struct {
				ID string `json:"id"`
			}
			if err := decode(c, &p); err != nil {
				return nil, err
			}
			scope := c.Subject.AccountID
			if c.Subject.Role == policy.RoleAdmin {
				scope = "" // admins may end any session (SPEC §3.5)
			}
			if !a.Grants.RevokeByID(p.ID, scope) {
				return nil, Errf(rpc.CodeNotFound, "")
			}
			return nil, nil
		}})

	Register(ops, &Op{Name: "passkeys.list", Action: policy.ActOwnSessions, NoAudit: true,
		Handle: func(ctx context.Context, c Call) (any, error) {
			return a.DB.Passkeys(ctx, c.Subject.AccountID)
		}})

	Register(ops, &Op{Name: "passkeys.begin_add", Action: policy.ActOwnPasskeys,
		Handle: func(ctx context.Context, c Call) (any, error) {
			acc, u, pk, err := a.selfUser(ctx, c)
			if err != nil {
				return nil, err
			}
			id, opts, err := pk.BeginRegistration(acc.ID, u)
			if err != nil {
				return nil, err
			}
			return CeremonyStart{CeremonyID: id, Options: opts}, nil
		}})

	Register(ops, &Op{Name: "passkeys.finish_add", Action: policy.ActOwnPasskeys,
		Handle: func(ctx context.Context, c Call) (any, error) {
			var p finishParams
			if err := decode(c, &p); err != nil {
				return nil, err
			}
			acc, u, pk, err := a.selfUser(ctx, c)
			if err != nil {
				return nil, err
			}
			cred, err := pk.FinishRegistration(p.CeremonyID, acc.ID, u, p.Response)
			if err != nil {
				return nil, Errf(rpc.CodeUnauthorized, "")
			}
			return nil, a.storeNewCredential(ctx, acc, cred, p.PasskeyName)
		}})

	type pkParams struct {
		ID   string `json:"id"`
		Name string `json:"name,omitempty"`
	}
	Register(ops, &Op{Name: "passkeys.rename", Action: policy.ActOwnSessions,
		Handle: func(ctx context.Context, c Call) (any, error) {
			var p pkParams
			if err := decode(c, &p); err != nil {
				return nil, err
			}
			if err := a.DB.RenamePasskey(ctx, c.Subject.AccountID, p.ID, passkeyName(p.Name)); err != nil {
				return nil, Errf(rpc.CodeNotFound, "")
			}
			return nil, nil
		}})

	Register(ops, &Op{Name: "passkeys.remove", Action: policy.ActOwnPasskeys,
		Handle: func(ctx context.Context, c Call) (any, error) {
			var p pkParams
			if err := decode(c, &p); err != nil {
				return nil, err
			}
			err := a.DB.RemovePasskey(ctx, c.Subject.AccountID, p.ID)
			switch {
			case errors.Is(err, ErrLastPasskey):
				return nil, Errf(rpc.CodeLockout, "the last passkey cannot be removed")
			case err != nil:
				return nil, Errf(rpc.CodeNotFound, "")
			}
			return nil, nil
		}})

	// ----- recovery (SPEC §3.3: console only) -----
	type recoverParams struct {
		Account   string `json:"account"`
		RevokeAll bool   `json:"revoke_all"`
	}
	Register(ops, &Op{Name: "admin.recover", AdminChannel: true,
		Handle: func(ctx context.Context, c Call) (any, error) {
			var p recoverParams
			if err := decode(c, &p); err != nil {
				return nil, err
			}
			acc, err := a.DB.AccountByName(ctx, p.Account)
			if err != nil {
				return nil, Errf(rpc.CodeNotFound, "account not found")
			}
			ended := a.Grants.RevokeAccount(acc.ID)
			var removed int64
			if p.RevokeAll {
				if removed, err = a.DB.RemoveAllPasskeys(ctx, acc.ID); err != nil {
					return nil, err
				}
			}
			tok, err := auth.Issue(a.Tokens, auth.PurposeRecovery, acc.ID, auth.RecoveryTTL, a.now())
			if err != nil {
				return nil, err
			}
			return map[string]any{"token": tok, "expires_at": a.now().Add(auth.RecoveryTTL).UTC(),
				"sessions_ended": ended, "passkeys_removed": removed, "account": acc.Name}, nil
		}})

	Register(ops, &Op{Name: "admin.list_accounts", AdminChannel: true, NoAudit: true,
		Handle: func(ctx context.Context, _ Call) (any, error) { return a.DB.ListAccounts(ctx) }})

	Register(ops, &Op{Name: "recovery.begin_register", PreAuth: true,
		Handle: func(ctx context.Context, c Call) (any, error) {
			var p setupTokenParams
			if err := decode(c, &p); err != nil {
				return nil, err
			}
			t, err := a.Tokens.Peek(auth.PurposeRecovery, p.Token, a.now())
			if err != nil {
				return nil, Errf(rpc.CodeTokenInvalid, "")
			}
			acc, err := a.DB.AccountByID(ctx, t.Subject)
			if err != nil || acc.Disabled {
				return nil, Errf(rpc.CodeTokenInvalid, "")
			}
			u, err := a.webUser(ctx, acc)
			if err != nil {
				return nil, err
			}
			pk, err := a.passkeys()
			if err != nil {
				return nil, err
			}
			id, opts, err := pk.BeginRegistration(acc.ID, u)
			if err != nil {
				return nil, err
			}
			return CeremonyStart{CeremonyID: id, Options: opts}, nil
		}})

	Register(ops, &Op{Name: "recovery.finish_register", PreAuth: true,
		Handle: func(ctx context.Context, c Call) (any, error) {
			var p finishParams
			if err := decode(c, &p); err != nil {
				return nil, err
			}
			t, err := a.Tokens.Peek(auth.PurposeRecovery, p.Token, a.now())
			if err != nil {
				return nil, Errf(rpc.CodeTokenInvalid, "")
			}
			acc, err := a.DB.AccountByID(ctx, t.Subject)
			if err != nil || acc.Disabled {
				return nil, Errf(rpc.CodeTokenInvalid, "")
			}
			u, err := a.webUser(ctx, acc)
			if err != nil {
				return nil, err
			}
			pk, err := a.passkeys()
			if err != nil {
				return nil, err
			}
			cred, err := pk.FinishRegistration(p.CeremonyID, acc.ID, u, p.Response)
			if err != nil {
				return nil, Errf(rpc.CodeUnauthorized, "")
			}
			if _, err := a.Tokens.Consume(auth.PurposeRecovery, p.Token, a.now()); err != nil {
				return nil, Errf(rpc.CodeTokenInvalid, "")
			}
			if err := a.storeNewCredential(ctx, acc, cred, p.PasskeyName); err != nil {
				return nil, err
			}
			acc, _ = a.DB.AccountByID(ctx, acc.ID)
			return a.issue(acc, c.SourceIP)
		}})
}

func (a *AuthOps) selfUser(ctx context.Context, c Call) (Account, *auth.User, *auth.Passkeys, error) {
	acc, err := a.DB.AccountByID(ctx, c.Subject.AccountID)
	if err != nil || acc.Disabled {
		return acc, nil, nil, Errf(rpc.CodeUnauthorized, "")
	}
	u, err := a.webUser(ctx, acc)
	if err != nil {
		return acc, nil, nil, err
	}
	pk, err := a.passkeys()
	return acc, u, pk, err
}

func (a *AuthOps) storeNewCredential(ctx context.Context, acc Account, cred *webauthn.Credential, name string) error {
	raw, err := json.Marshal(cred)
	if err != nil {
		return err
	}
	return a.DB.AddPasskey(ctx, acc.ID, passkeyName(name), cred.ID, raw, cred.Flags.BackupEligible, cred.Flags.BackupState, a.now())
}

func (a *AuthOps) updateCredential(ctx context.Context, cred *webauthn.Credential) error {
	raw, err := json.Marshal(cred)
	if err != nil {
		return err
	}
	return a.DB.UpdatePasskeyAfterUse(ctx, cred.ID, raw, cred.Flags.BackupState, a.now())
}

func (a *AuthOps) issue(acc Account, ip string) (any, error) {
	tok, err := a.Grants.IssueFrom(policy.Subject{AccountID: acc.ID, Role: acc.Role, LinuxUser: acc.LinuxUser, LinuxUID: acc.LinuxUID}, a.now(), ip)
	if err != nil {
		return nil, err
	}
	return GrantResult{Grant: tok, Account: acc}, nil
}
