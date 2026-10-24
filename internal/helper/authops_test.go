package helper

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/PanPakaPancake/daemonica/internal/audit"
	"github.com/PanPakaPancake/daemonica/internal/auth"
	"github.com/PanPakaPancake/daemonica/internal/policy"
	"github.com/PanPakaPancake/daemonica/internal/rpc"
	"github.com/PanPakaPancake/daemonica/internal/testutil/softauthn"
)

const (
	testDomain = "dash.example.org"
	testOrigin = "https://dash.example.org:8443"
)

type authEnv struct {
	web, admin *Server
	db         *DB
	cfg        *ConfigStore
	tokens     auth.TokenStore
	dir        string
}

func newAuthEnv(t *testing.T) *authEnv {
	t.Helper()
	dir := t.TempDir()
	ctx := context.Background()
	db, err := OpenDB(ctx, filepath.Join(dir, "accounts.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	cfg, _ := OpenConfig(filepath.Join(dir, "config.json"))
	al, _ := audit.Open(filepath.Join(dir, "audit.log"), "")
	t.Cleanup(func() { _ = al.Close() })
	passwd := filepath.Join(dir, "passwd")
	_ = os.WriteFile(passwd, []byte("root:x:0:0:root:/root:/bin/bash\nsshd:x:105:65534::/run/sshd:/usr/sbin/nologin\npancake:x:1000:1000::/home/pancake:/bin/bash\n"), 0o600)
	grants := NewGrantStore(0, 0)
	tokens := db.TokenStore()
	ops := map[string]*Op{}
	(&Core{Config: cfg, Tokens: tokens, Grants: grants, Version: "t"}).Register(ops, al)
	a := &AuthOps{DB: db, Config: cfg, Grants: grants, Tokens: tokens, Audit: al, Passwd: passwd, LoginDf: filepath.Join(dir, "none")}
	a.Register(ops)
	Register(ops, &Op{Name: "test.privileged", Action: policy.ActSettingsWrite,
		Handle: func(context.Context, Call) (any, error) { return "ok", nil }})
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	return &authEnv{
		web:   &Server{Channel: ChannelWeb, Ops: ops, Grants: grants, Audit: al, Log: log},
		admin: &Server{Channel: ChannelAdmin, Ops: ops, Grants: grants, Audit: al, Log: log},
		db:    db, cfg: cfg, tokens: tokens, dir: dir,
	}
}

func (e *authEnv) call(t *testing.T, s *Server, op, grant string, params any) (*rpc.Response, json.RawMessage) {
	t.Helper()
	r := s.Dispatch(context.Background(), req(op, grant, params))
	return r, r.Result
}

func mustOK(t *testing.T, r *rpc.Response, what string) {
	t.Helper()
	if !r.OK {
		t.Fatalf("%s failed: %+v", what, r.Error)
	}
}

// setupAdmin runs the complete first-run flow and returns grant, authenticator and token.
func setupAdmin(t *testing.T, e *authEnv) (string, *softauthn.Authenticator, string) {
	t.Helper()
	tok, err := auth.Issue(e.tokens, auth.PurposeBootstrap, "", auth.BootstrapTTL, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	r, _ := e.call(t, e.web, "setup.set_domain", "", map[string]any{"token": tok, "domain": testDomain})
	mustOK(t, r, "set_domain")
	r, res := e.call(t, e.web, "setup.linux_users", "", map[string]any{"token": tok})
	mustOK(t, r, "linux_users")
	var users []LinuxUserInfo
	_ = json.Unmarshal(res, &users)
	if len(users) != 1 || users[0].Name != "pancake" {
		t.Fatalf("eligible users wrong (root/system users must be excluded): %+v", users)
	}
	r, res = e.call(t, e.web, "setup.begin_register", "", map[string]any{"token": tok, "account_name": "Pancake", "linux_user": "pancake"})
	mustOK(t, r, "begin_register")
	var cs CeremonyStart
	_ = json.Unmarshal(res, &cs)
	sa := softauthn.New()
	resp, _, err := sa.Create(cs.Options, testOrigin)
	if err != nil {
		t.Fatal(err)
	}
	r, res = e.call(t, e.web, "setup.finish_register", "", map[string]any{"token": tok, "ceremony_id": cs.CeremonyID, "response": json.RawMessage(resp), "passkey_name": "Laptop"})
	mustOK(t, r, "finish_register")
	var gr GrantResult
	_ = json.Unmarshal(res, &gr)
	if gr.Grant == "" || gr.Account.Role != policy.RoleAdmin || gr.Account.LinuxUser != "pancake" {
		t.Fatalf("bad grant result %+v", gr)
	}
	return gr.Grant, sa, tok
}

func login(t *testing.T, e *authEnv, sa *softauthn.Authenticator, origin string) (*rpc.Response, string) {
	t.Helper()
	r, res := e.call(t, e.web, "auth.begin_login", "", nil)
	mustOK(t, r, "begin_login")
	var cs CeremonyStart
	_ = json.Unmarshal(res, &cs)
	resp, err := sa.Get(cs.Options, origin, nil)
	if err != nil {
		t.Fatal(err)
	}
	r, res = e.call(t, e.web, "auth.finish_login", "", map[string]any{"ceremony_id": cs.CeremonyID, "response": json.RawMessage(resp)})
	var gr GrantResult
	_ = json.Unmarshal(res, &gr)
	return r, gr.Grant
}

func TestSetupLoginStepUp(t *testing.T) {
	e := newAuthEnv(t)
	grant, sa, tok := setupAdmin(t, e)

	if !e.cfg.Get().SetupDone {
		t.Fatal("setup not marked done")
	}
	// Bootstrap token is consumed and setup ops are closed for good.
	if r, _ := e.call(t, e.web, "setup.set_domain", "", map[string]any{"token": tok, "domain": "evil.example.org"}); r.OK {
		t.Fatal("setup reachable after completion")
	}

	// Login (username-less).
	r, g2 := login(t, e, sa, testOrigin)
	mustOK(t, r, "login")
	if g2 == "" || g2 == grant {
		t.Fatal("login must issue a fresh grant")
	}

	// Step-up gate.
	if r, _ := e.call(t, e.web, "test.privileged", g2, nil); code(r) != rpc.CodeStepUpNeeded {
		t.Fatalf("want step-up required, got %+v", r)
	}
	r, res := e.call(t, e.web, "auth.begin_stepup", g2, nil)
	mustOK(t, r, "begin_stepup")
	var cs CeremonyStart
	_ = json.Unmarshal(res, &cs)
	resp, _ := sa.Get(cs.Options, testOrigin, nil)
	r, _ = e.call(t, e.web, "auth.finish_stepup", g2, map[string]any{"ceremony_id": cs.CeremonyID, "response": json.RawMessage(resp)})
	mustOK(t, r, "finish_stepup")
	if r, _ := e.call(t, e.web, "test.privileged", g2, nil); !r.OK {
		t.Fatalf("privileged op after step-up failed: %+v", r.Error)
	}
	// Step-up is bound to the grant: the other session still needs its own.
	if r, _ := e.call(t, e.web, "test.privileged", grant, nil); code(r) != rpc.CodeStepUpNeeded {
		t.Fatal("step-up leaked to another session")
	}
	// Ceremony replay is rejected.
	r, _ = e.call(t, e.web, "auth.finish_stepup", g2, map[string]any{"ceremony_id": cs.CeremonyID, "response": json.RawMessage(resp)})
	if r.OK {
		t.Fatal("step-up ceremony replay accepted")
	}

	// Logout ends the session.
	mustOK(t, e.web.Dispatch(context.Background(), req("auth.logout", g2, nil)), "logout")
	if r, _ := e.call(t, e.web, "session.whoami", g2, nil); code(r) != rpc.CodeUnauthorized {
		t.Fatal("grant valid after logout")
	}
}

func TestLoginRejectsWrongOriginAndNoUV(t *testing.T) {
	e := newAuthEnv(t)
	_, sa, _ := setupAdmin(t, e)
	if r, _ := login(t, e, sa, "https://evil.example.org:8443"); r.OK || code(r) != rpc.CodeUnauthorized {
		t.Fatalf("wrong origin accepted: %+v", r)
	}
	if r, _ := login(t, e, sa, "https://dash.example.org"); r.OK {
		t.Fatal("origin without port accepted")
	}
	sa.Flags = softauthn.FlagUP // no user verification
	if r, _ := login(t, e, sa, testOrigin); r.OK {
		t.Fatal("assertion without UV accepted (D-06)")
	}
}

func TestLoginRejectsClonedAuthenticator(t *testing.T) {
	e := newAuthEnv(t)
	_, sa, _ := setupAdmin(t, e)
	mustOK(t, func() *rpc.Response { r, _ := login(t, e, sa, testOrigin); return r }(), "first login")
	// Roll the counter back as a cloned authenticator would.
	sa.Creds[0].Counter = 0
	if r, _ := login(t, e, sa, testOrigin); r.OK {
		t.Fatal("counter regression (clone) accepted")
	}
}

func TestSetupRefusesRootAndUnknownUsers(t *testing.T) {
	e := newAuthEnv(t)
	tok, _ := auth.Issue(e.tokens, auth.PurposeBootstrap, "", auth.BootstrapTTL, time.Now())
	e.call(t, e.web, "setup.set_domain", "", map[string]any{"token": tok, "domain": testDomain})
	for _, u := range []string{"root", "sshd", "nobody", "../x", "pancake; id"} {
		r, _ := e.call(t, e.web, "setup.begin_register", "", map[string]any{"token": tok, "account_name": "A", "linux_user": u})
		if r.OK {
			t.Errorf("linux user %q accepted", u)
		}
	}
	if r, _ := e.call(t, e.web, "setup.begin_register", "", map[string]any{"token": "dmn_bootstrap_wrong", "account_name": "A", "linux_user": "pancake"}); code(r) != rpc.CodeTokenInvalid {
		t.Fatal("wrong token accepted")
	}
	if r, _ := e.call(t, e.web, "setup.set_allowlist", "", map[string]any{"token": tok, "allowlist": []string{"0.0.0.0/0"}}); r.OK {
		t.Fatal("public allowlist without confirmation accepted")
	}
	if r, _ := e.call(t, e.web, "setup.set_allowlist", "", map[string]any{"token": tok, "allowlist": []string{"0.0.0.0/0"}, "confirm_public": true}); !r.OK {
		t.Fatalf("confirmed public allowlist refused: %+v", r.Error)
	}
}

func TestPasskeyManagementAndRecovery(t *testing.T) {
	e := newAuthEnv(t)
	grant, sa, _ := setupAdmin(t, e)

	// Removing the last passkey is refused (needs step-up first).
	r, res := e.call(t, e.web, "passkeys.list", grant, nil)
	mustOK(t, r, "list")
	var pks []Passkey
	_ = json.Unmarshal(res, &pks)
	if len(pks) != 1 || pks[0].Name != "Laptop" {
		t.Fatalf("passkeys %+v", pks)
	}
	if r, _ := e.call(t, e.web, "passkeys.remove", grant, map[string]any{"id": pks[0].ID}); code(r) != rpc.CodeStepUpNeeded {
		t.Fatal("remove without step-up")
	}
	_ = e.web.Grants.MarkStepUp(grant, time.Now())
	if r, _ := e.call(t, e.web, "passkeys.remove", grant, map[string]any{"id": pks[0].ID}); code(r) != rpc.CodeLockout {
		t.Fatalf("last passkey removal not refused: %+v", r)
	}

	// Add a second passkey.
	r, res = e.call(t, e.web, "passkeys.begin_add", grant, nil)
	mustOK(t, r, "begin_add")
	var cs CeremonyStart
	_ = json.Unmarshal(res, &cs)
	resp, _, _ := sa.Create(cs.Options, testOrigin)
	r, _ = e.call(t, e.web, "passkeys.finish_add", grant, map[string]any{"ceremony_id": cs.CeremonyID, "response": json.RawMessage(resp), "passkey_name": "Phone"})
	mustOK(t, r, "finish_add")

	// Recovery: console revokes sessions and all passkeys.
	r, res = e.call(t, e.admin, "admin.recover", "", map[string]any{"account": "Pancake", "revoke_all": true})
	mustOK(t, r, "recover")
	var rec struct {
		Token           string `json:"token"`
		SessionsEnded   int    `json:"sessions_ended"`
		PasskeysRemoved int    `json:"passkeys_removed"`
	}
	_ = json.Unmarshal(res, &rec)
	if rec.SessionsEnded < 1 || rec.PasskeysRemoved != 2 {
		t.Fatalf("recover result %+v", rec)
	}
	if r, _ := e.call(t, e.web, "session.whoami", grant, nil); code(r) != rpc.CodeUnauthorized {
		t.Fatal("session survived recovery")
	}
	if r, _ := login(t, e, sa, testOrigin); r.OK {
		t.Fatal("old passkey still works after --revoke-all")
	}
	// Recovery tokens are not accepted by the admin channel ops of the web and vice versa.
	r, res = e.call(t, e.web, "recovery.begin_register", "", map[string]any{"token": rec.Token})
	mustOK(t, r, "recovery begin")
	_ = json.Unmarshal(res, &cs)
	sa2 := softauthn.New()
	resp, _, _ = sa2.Create(cs.Options, testOrigin)
	r, _ = e.call(t, e.web, "recovery.finish_register", "", map[string]any{"token": rec.Token, "ceremony_id": cs.CeremonyID, "response": json.RawMessage(resp)})
	mustOK(t, r, "recovery finish")
	if r, _ := login(t, e, sa2, testOrigin); !r.OK {
		t.Fatalf("login with recovered passkey failed: %+v", r.Error)
	}
	// Recovery token is single-use.
	if r, _ := e.call(t, e.web, "recovery.begin_register", "", map[string]any{"token": rec.Token}); r.OK {
		t.Fatal("recovery token reusable")
	}
}

func TestTokensPersistAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()
	db, _ := OpenDB(ctx, filepath.Join(dir, "a.db"))
	tok, _ := auth.Issue(db.TokenStore(), auth.PurposeBootstrap, "", time.Hour, time.Now())
	_ = db.Close()
	db2, err := OpenDB(ctx, filepath.Join(dir, "a.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db2.Close() }()
	if _, err := db2.TokenStore().Consume(auth.PurposeBootstrap, tok, time.Now()); err != nil {
		t.Fatal("token lost across restart")
	}
	if _, err := db2.TokenStore().Consume(auth.PurposeBootstrap, tok, time.Now()); err == nil {
		t.Fatal("token consumed twice")
	}
	if fi, _ := os.Stat(filepath.Join(dir, "a.db")); fi.Mode().Perm() != 0o600 {
		t.Fatalf("db mode %v", fi.Mode().Perm())
	}
}
