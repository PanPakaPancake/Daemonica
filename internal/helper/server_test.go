package helper

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/PanPakaPancake/daemonica/internal/audit"
	"github.com/PanPakaPancake/daemonica/internal/auth"
	"github.com/PanPakaPancake/daemonica/internal/policy"
	"github.com/PanPakaPancake/daemonica/internal/rpc"
)

type env struct {
	web, admin *Server
	core       *Core
	grants     *GrantStore
	al         *audit.Logger
	dir        string
}

func newEnv(t *testing.T) *env {
	t.Helper()
	dir := t.TempDir()
	cfg, err := OpenConfig(filepath.Join(dir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	al, err := audit.Open(filepath.Join(dir, "audit.log"), "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = al.Close() })
	grants := NewGrantStore(0, 0)
	core := &Core{Config: cfg, Tokens: auth.NewMemTokenStore(), Grants: grants, AuditPath: filepath.Join(dir, "audit.log"), Version: "test"}
	ops := map[string]*Op{}
	core.Register(ops, al)
	// A test operation guarded by a step-up action.
	Register(ops, &Op{Name: "test.privileged", Action: policy.ActSettingsWrite,
		Handle: func(context.Context, Call) (any, error) { return "done", nil }})
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	return &env{
		web:   &Server{Channel: ChannelWeb, Ops: ops, Grants: grants, Audit: al, Log: log},
		admin: &Server{Channel: ChannelAdmin, Ops: ops, Grants: grants, Audit: al, Log: log},
		core:  core, grants: grants, al: al, dir: dir,
	}
}

func req(op, grant string, params any) *rpc.Request {
	var raw json.RawMessage
	if params != nil {
		raw, _ = json.Marshal(params)
	}
	return &rpc.Request{V: rpc.Version, ID: 1, Op: op, Grant: grant, Params: raw}
}

func code(r *rpc.Response) string {
	if r.Error == nil {
		return ""
	}
	return r.Error.Code
}

func TestChannelSeparation(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if r := e.web.Dispatch(ctx, req("admin.bootstrap", "", nil)); code(r) != rpc.CodeUnknownOp {
		t.Fatalf("admin op reachable from web channel: %+v", r)
	}
	if r := e.admin.Dispatch(ctx, req("session.whoami", "", nil)); code(r) != rpc.CodeUnknownOp {
		t.Fatalf("web op reachable from admin channel: %+v", r)
	}
	if r := e.web.Dispatch(ctx, req("system.exec", "", nil)); code(r) != rpc.CodeUnknownOp {
		t.Fatal("unknown op must be rejected")
	}
}

func TestBootstrapFlow(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	r := e.admin.Dispatch(ctx, req("admin.bootstrap", "", BootstrapParams{Allow: []string{"198.51.100.0/24"}}))
	if !r.OK {
		t.Fatalf("bootstrap failed: %+v", r.Error)
	}
	var br BootstrapResult
	_ = json.Unmarshal(r.Result, &br)
	if len(br.Allowlist) != 3 {
		t.Fatalf("allowlist not merged: %v", br.Allowlist)
	}
	if r := e.web.Dispatch(ctx, req("setup.check_token", "", TokenParams{Token: br.Token})); !r.OK {
		t.Fatalf("valid token rejected: %+v", r.Error)
	}
	if r := e.web.Dispatch(ctx, req("setup.check_token", "", TokenParams{Token: br.Token + "x"})); code(r) != rpc.CodeTokenInvalid {
		t.Fatal("tampered token accepted")
	}
	// Public allowlists are refused.
	if r := e.admin.Dispatch(ctx, req("admin.bootstrap", "", BootstrapParams{Allow: []string{"0.0.0.0/0"}})); r.OK {
		t.Fatal("public bootstrap allowlist accepted")
	}
}

func TestGrantAndStepUpEnforcement(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if r := e.web.Dispatch(ctx, req("session.whoami", "", nil)); code(r) != rpc.CodeUnauthorized {
		t.Fatal("no grant must be unauthorized")
	}
	tok, err := e.grants.Issue(policy.Subject{AccountID: "a1", Role: policy.RoleAdmin, LinuxUser: "alice", LinuxUID: 1000}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if r := e.web.Dispatch(ctx, req("session.whoami", tok, nil)); !r.OK {
		t.Fatalf("whoami failed: %+v", r.Error)
	}
	if r := e.web.Dispatch(ctx, req("test.privileged", tok, nil)); code(r) != rpc.CodeStepUpNeeded {
		t.Fatalf("step-up not enforced: %+v", r)
	}
	_ = e.grants.MarkStepUp(tok, time.Now())
	if r := e.web.Dispatch(ctx, req("test.privileged", tok, nil)); !r.OK {
		t.Fatal("step-up not honoured")
	}
	// Operator cannot even with step-up.
	op, _ := e.grants.Issue(policy.Subject{AccountID: "a2", Role: policy.RoleOperator, LinuxUser: "bob", LinuxUID: 1001}, time.Now())
	_ = e.grants.MarkStepUp(op, time.Now())
	if r := e.web.Dispatch(ctx, req("test.privileged", op, nil)); code(r) != rpc.CodeForbidden {
		t.Fatal("operator allowed settings write")
	}
	// Revocation ends sessions.
	e.grants.RevokeAccount("a1")
	if r := e.web.Dispatch(ctx, req("session.whoami", tok, nil)); code(r) != rpc.CodeUnauthorized {
		t.Fatal("revoked grant still valid")
	}
}

func TestGrantRefusesRoot(t *testing.T) {
	g := NewGrantStore(0, 0)
	if _, err := g.Issue(policy.Subject{AccountID: "x", Role: policy.RoleAdmin, LinuxUser: "root", LinuxUID: 0}, time.Now()); err == nil {
		t.Fatal("UID 0 mapping must be refused (SPEC §3.4)")
	}
}

func TestGrantIdleExpiry(t *testing.T) {
	g := NewGrantStore(5*time.Minute, time.Hour)
	now := time.Now()
	tok, _ := g.Issue(policy.Subject{AccountID: "x", Role: policy.RoleReadOnly, LinuxUID: 1000}, now)
	if _, _, err := g.Resolve(tok, now.Add(4*time.Minute)); err != nil {
		t.Fatal("expired too early")
	}
	if _, _, err := g.Resolve(tok, now.Add(10*time.Minute)); err == nil {
		t.Fatal("idle timeout not enforced")
	}
}

func TestDeniedOperationsAreAudited(t *testing.T) {
	e := newEnv(t)
	_ = e.web.Dispatch(context.Background(), req("test.privileged", "bogus", nil))
	f, _ := os.Open(filepath.Join(e.dir, "audit.log"))
	defer func() { _ = f.Close() }()
	res := audit.Verify(f, "")
	if !res.OK || res.Records == 0 {
		t.Fatalf("denied op not audited / chain broken: %+v", res)
	}
}

func TestPeerCredOverRealSocket(t *testing.T) {
	e := newEnv(t)
	sock := filepath.Join(e.dir, "h.sock")
	l, err := ListenUnix(sock, 0o600, -1)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	e.web.AllowedUID = uint32(os.Getuid()) //nolint:gosec // test
	go func() { _ = e.web.Serve(ctx, l) }()

	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if err := rpc.WriteFrame(c, req("setup.state", "", nil)); err != nil {
		t.Fatal(err)
	}
	resp, err := rpc.ReadResponse(c)
	if err != nil || !resp.OK {
		t.Fatalf("round trip failed: %v %+v", err, resp)
	}
	if fi, _ := os.Stat(sock); fi.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode %v", fi.Mode().Perm())
	}

	// A peer with a different UID is dropped.
	e2 := newEnv(t)
	sock2 := filepath.Join(e2.dir, "h2.sock")
	l2, _ := ListenUnix(sock2, 0o600, -1)
	e2.web.AllowedUID = uint32(os.Getuid()) + 1 //nolint:gosec // test
	go func() { _ = e2.web.Serve(ctx, l2) }()
	c2, err := net.Dial("unix", sock2)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c2.Close() }()
	_ = rpc.WriteFrame(c2, req("setup.state", "", nil))
	_ = c2.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := rpc.ReadResponse(c2); err == nil {
		t.Fatal("foreign UID was served")
	}
}
