package helper

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PanPakaPancake/daemonica/internal/audit"
	"github.com/PanPakaPancake/daemonica/internal/policy"
	"github.com/PanPakaPancake/daemonica/internal/pty"
	"github.com/PanPakaPancake/daemonica/internal/rpc"
	"github.com/PanPakaPancake/daemonica/internal/worker"
)

// termBinary is a copy of the test binary that other users can execute
// (the ExecLauncher re-executes it as the terminal child).
var termBinary string

func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == pty.ChildArg {
		pty.ChildMain(os.Args[2:])
	}
	code := func() int {
		dir, err := os.MkdirTemp("", "termbin")
		if err == nil {
			defer func() { _ = os.RemoveAll(dir) }()
			if b, err := os.ReadFile(os.Args[0]); err == nil {
				termBinary = filepath.Join(dir, "helper.test")
				_ = os.WriteFile(termBinary, b, 0o755) //nolint:gosec // test binary
				_ = os.Chmod(dir, 0o755)               //nolint:gosec // test binary
			}
		}
		return m.Run()
	}()
	os.Exit(code)
}

type termEnv struct {
	client *rpc.Client
	grants *GrantStore
	ops    *TermOps
	al     *audit.Logger
	audit  string
	offset atomic.Int64 // fake clock offset
}

func newTermEnv(t *testing.T) *termEnv {
	t.Helper()
	if os.Getuid() != 0 {
		t.Skip("terminal tests switch users and need root")
	}
	dir := t.TempDir()
	cfg, err := OpenConfig(filepath.Join(dir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	e := &termEnv{audit: filepath.Join(dir, "audit.log")}
	e.al, err = audit.Open(e.audit, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.al.Close() })
	e.grants = NewGrantStore(MaxIdle, 0)
	now := func() time.Time { return time.Now().Add(time.Duration(e.offset.Load())) }
	e.ops = &TermOps{Launcher: pty.ExecLauncher{Binary: termBinary}, Grants: e.grants, Config: cfg, Audit: e.al, Now: now,
		Lookup: func(name string) (worker.Identity, error) {
			if name == "root" {
				return worker.Identity{Name: "root", Home: "/"}, nil
			}
			return worker.Identity{Name: name, UID: 65534, GID: 65534, Home: "/"}, nil
		},
		Shell: func(string) (string, error) { return "/bin/sh", nil }}
	ops := map[string]*Op{}
	e.ops.Register(ops)
	srv := &Server{Channel: ChannelWeb, AllowedUID: uint32(os.Getuid()), Ops: ops, Grants: e.grants, Audit: e.al, //nolint:gosec // test
		Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	sock := filepath.Join(dir, "h.sock")
	l, err := ListenUnix(sock, 0o600, -1)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = srv.Serve(ctx, l) }()
	e.client = &rpc.Client{Socket: sock}
	return e
}

func (e *termEnv) grant(t *testing.T, role policy.Role) string {
	t.Helper()
	g, err := e.grants.Issue(policy.Subject{AccountID: "acc-" + string(role), Role: role, LinuxUser: "nobody", LinuxUID: 65534}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return g
}

type term struct {
	d    *rpc.Duplex
	info TermInfo
	out  bytes.Buffer
	done chan struct{}
}

func (e *termEnv) open(t *testing.T, grant string, mode pty.Mode) (*term, error) {
	t.Helper()
	tm := &term{done: make(chan struct{})}
	d, err := e.client.OpenDuplex(context.Background(), "pty.open", grant, "127.0.0.1", TermParams{Mode: mode, Cols: 100, Rows: 30}, &tm.info)
	if err != nil {
		return nil, err
	}
	tm.d = d
	t.Cleanup(func() { _ = d.Close() })
	go func() { _, _ = io.Copy(&tm.out, d); close(tm.done) }()
	return tm, nil
}

func (tm *term) send(s string) error { return tm.d.Send(append([]byte{'d'}, s...)) }

func (tm *term) end(t *testing.T, within time.Duration) TermEnd {
	t.Helper()
	select {
	case <-tm.done:
	case <-time.After(within):
		t.Fatal("terminal did not end")
	}
	var res TermEnd
	if err := tm.d.Finish(&res); err != nil {
		t.Fatalf("finish: %v", err)
	}
	return res
}

func codeOf(err error) string {
	var re *rpc.Error
	if errors.As(err, &re) {
		return re.Code
	}
	return ""
}

func TestTerminalStandardShell(t *testing.T) {
	e := newTermEnv(t)
	g := e.grant(t, policy.RoleOperator)
	tm, err := e.open(t, g, pty.ModeStandard)
	if err != nil {
		t.Fatal(err)
	}
	if tm.info.User != "nobody" || tm.info.IdleMinutes != DefaultTerminalIdle || !tm.info.Until.IsZero() {
		t.Fatalf("info: %+v", tm.info)
	}
	resize := make([]byte, 5)
	resize[0] = 'r'
	binary.BigEndian.PutUint16(resize[1:], 132)
	binary.BigEndian.PutUint16(resize[3:], 43)
	_ = tm.d.Send(resize)
	time.Sleep(100 * time.Millisecond)
	_ = tm.send("id -u; grep NoNewPrivs /proc/self/status; stty size; exit 7\n")
	res := tm.end(t, 10*time.Second)
	if res.Reason != "exit" || res.ExitCode != 7 {
		t.Fatalf("end: %+v", res)
	}
	out := tm.out.String()
	for _, want := range []string{"65534", "NoNewPrivs:\t1", "43 132"} {
		if !strings.Contains(out, want) {
			t.Fatalf("output lacks %q:\n%s", want, out)
		}
	}
	// Start and end are audited (no input).
	b, _ := os.ReadFile(e.audit)
	if !strings.Contains(string(b), `"pty.start"`) || !strings.Contains(string(b), `"end":"exit"`) || strings.Contains(string(b), "NoNewPrivs") {
		t.Fatalf("audit:\n%s", b)
	}
}

func TestTerminalReadOnlyDenied(t *testing.T) {
	e := newTermEnv(t)
	if _, err := e.open(t, e.grant(t, policy.RoleReadOnly), pty.ModeStandard); codeOf(err) != rpc.CodeForbidden {
		t.Fatalf("read-only: %v", err)
	}
	if _, err := e.open(t, e.grant(t, policy.RoleOperator), pty.ModeRoot); codeOf(err) != rpc.CodeForbidden {
		t.Fatalf("operator elevated: %v", err)
	}
}

func TestTerminalElevatedNeedsFreshStepUp(t *testing.T) {
	e := newTermEnv(t)
	g := e.grant(t, policy.RoleAdmin)
	if _, err := e.open(t, g, pty.ModeRoot); codeOf(err) != rpc.CodeStepUpNeeded {
		t.Fatalf("without step-up: %v", err)
	}
	if err := e.grants.MarkStepUp(g, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := e.client.Call(context.Background(), "pty.check", g, "", TermParams{Mode: pty.ModeRoot}, nil); err != nil {
		t.Fatalf("check: %v", err)
	}
	tm, err := e.open(t, g, pty.ModeRoot)
	if err != nil {
		t.Fatal(err)
	}
	if tm.info.Until.IsZero() || tm.info.User != "root" {
		t.Fatalf("info: %+v", tm.info)
	}
	// The same step-up does not open a second elevated terminal.
	if _, err := e.open(t, g, pty.ModeSudo); codeOf(err) != rpc.CodeStepUpNeeded {
		t.Fatalf("reused step-up: %v", err)
	}
	_ = tm.send("id -u; grep NoNewPrivs /proc/self/status\n")
	time.Sleep(300 * time.Millisecond)
	// Elevated sessions end after 30 minutes.
	e.offset.Store(int64(ElevatedTerminalTTL + time.Second))
	if res := tm.end(t, 6*time.Second); res.Reason != "expired" {
		t.Fatalf("end: %+v", res)
	}
	if out := tm.out.String(); !regexp.MustCompile(`(^|\s)0\r?\n`).MatchString(out) || !strings.Contains(out, "NoNewPrivs:\t0") {
		t.Fatalf("root shell output:\n%s", out)
	}
}

func TestTerminalEndsWithSessionAndIdle(t *testing.T) {
	e := newTermEnv(t)
	g := e.grant(t, policy.RoleOperator)
	a, err := e.open(t, g, pty.ModeStandard)
	if err != nil {
		t.Fatal(err)
	}
	e.grants.Revoke(g)
	if res := a.end(t, 6*time.Second); res.Reason != "session_ended" {
		t.Fatalf("logout: %+v", res)
	}

	g = e.grant(t, policy.RoleOperator)
	b, err := e.open(t, g, pty.ModeStandard)
	if err != nil {
		t.Fatal(err)
	}
	e.offset.Store(int64(DefaultTerminalIdle*time.Minute + time.Second))
	if res := b.end(t, 6*time.Second); res.Reason != "idle" {
		t.Fatalf("idle: %+v", res)
	}
}

func TestTerminalCutWhenAllowlistChanges(t *testing.T) {
	e := newTermEnv(t)
	tm, err := e.open(t, e.grant(t, policy.RoleOperator), pty.ModeStandard)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.ops.Config.Update(func(c *Config) error { c.Allowlist = []string{"10.0.0.0/8"}; return nil }); err != nil {
		t.Fatal(err)
	}
	if res := tm.end(t, 6*time.Second); res.Reason != "allowlist" {
		t.Fatalf("end: %+v", res)
	}
}

func TestTerminalLimitPerAccount(t *testing.T) {
	e := newTermEnv(t)
	g := e.grant(t, policy.RoleOperator)
	for i := range MaxTerminals {
		if _, err := e.open(t, g, pty.ModeStandard); err != nil {
			t.Fatalf("terminal %d: %v", i, err)
		}
	}
	if _, err := e.open(t, g, pty.ModeStandard); codeOf(err) != "limit_exceeded" {
		t.Fatalf("6th terminal: %v", err)
	}
}

func TestTerminalClientCloseStopsShell(t *testing.T) {
	e := newTermEnv(t)
	tm, err := e.open(t, e.grant(t, policy.RoleOperator), pty.ModeStandard)
	if err != nil {
		t.Fatal(err)
	}
	_ = tm.send("echo $$ > /dev/null; sleep 300 &\n")
	time.Sleep(300 * time.Millisecond)
	_ = tm.d.Close()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		e.ops.mu.Lock()
		n := len(e.ops.open)
		e.ops.mu.Unlock()
		if n == 0 {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("terminal still registered after the client closed")
}
