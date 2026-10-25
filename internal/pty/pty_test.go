package pty

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PanPakaPancake/daemonica/internal/worker"
)

func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == ChildArg {
		ChildMain(os.Args[2:])
	}
	os.Exit(m.Run())
}

func TestLoginShell(t *testing.T) {
	d := t.TempDir()
	passwd := filepath.Join(d, "passwd")
	shells := filepath.Join(d, "shells")
	_ = os.WriteFile(passwd, []byte("root:x:0:0:root:/root:/bin/sh\nsvc:x:998:998::/:/usr/sbin/nologin\nodd:x:997:997::/:/opt/evil\n"), 0o600)
	_ = os.WriteFile(shells, []byte("# comment\n/bin/sh\n/usr/sbin/nologin\n"), 0o600)
	if s, err := loginShell(passwd, shells, "root"); err != nil || s != "/bin/sh" {
		t.Fatalf("root: %q %v", s, err)
	}
	for _, n := range []string{"svc", "odd", "missing"} {
		if _, err := loginShell(passwd, shells, n); err != ErrNoShell {
			t.Fatalf("%s: %v", n, err)
		}
	}
}

func self(t *testing.T) worker.Identity {
	t.Helper()
	u, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	uid, _ := strconv.ParseUint(u.Uid, 10, 32)
	gid, _ := strconv.ParseUint(u.Gid, 10, 32)
	return worker.Identity{Name: u.Username, UID: uint32(uid), GID: uint32(gid), Home: t.TempDir()}
}

// run starts /bin/sh on a pty, types input and returns everything printed until the shell exits.
func run(t *testing.T, nnp bool, input string) (string, *Session) {
	t.Helper()
	s, err := Open(context.Background(), ExecLauncher{Binary: os.Args[0]}, Spec{Name: "t", User: self(t), Shell: "/bin/sh", NoNewPrivs: nnp}, 120, 40)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	var out bytes.Buffer
	read := make(chan struct{})
	go func() { _, _ = io.Copy(&out, s.Master); close(read) }()
	_, _ = s.Master.Write([]byte(input))
	select {
	case <-s.Done():
	case <-time.After(10 * time.Second):
		t.Fatal("shell did not exit")
	}
	s.Close()
	<-read
	return out.String(), s
}

func TestExecShellNoNewPrivs(t *testing.T) {
	out, s := run(t, true, "grep NoNewPrivs /proc/self/status; stty size; exit 3\n")
	if !strings.Contains(out, "NoNewPrivs:\t1") {
		t.Fatalf("no_new_privs not set:\n%s", out)
	}
	if !strings.Contains(out, "40 120") {
		t.Fatalf("size not applied:\n%s", out)
	}
	if s.ExitCode() != 3 {
		t.Fatalf("exit code %d", s.ExitCode())
	}
	out, _ = run(t, false, "grep NoNewPrivs /proc/self/status; exit\n")
	if !strings.Contains(out, "NoNewPrivs:\t0") {
		t.Fatalf("privileged mode has no_new_privs:\n%s", out)
	}
}

func TestStopKillsProcessTree(t *testing.T) {
	s, err := Open(context.Background(), ExecLauncher{Binary: os.Args[0]}, Spec{Name: "t", User: self(t), Shell: "/bin/sh"}, 80, 24)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _, _ = io.Copy(io.Discard, s.Master) }()
	// A background job that ignores SIGHUP must be killed after the grace time.
	_, _ = s.Master.Write([]byte("trap '' HUP; sleep 300 & sleep 300 &\n"))
	sid := s.proc.(*execProc).pid
	deadline := time.Now().Add(5 * time.Second)
	for len(SessionPIDs(sid)) < 3 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if n := len(SessionPIDs(sid)); n < 3 {
		t.Fatalf("expected shell + 2 jobs, got %d", n)
	}
	start := time.Now()
	s.Close()
	if left := SessionPIDs(sid); len(left) != 0 {
		t.Fatalf("processes left: %v", left)
	}
	if time.Since(start) > 9*time.Second {
		t.Fatalf("stop took %s", time.Since(start))
	}
}

func TestResizeBounds(t *testing.T) {
	s, err := Open(context.Background(), ExecLauncher{Binary: os.Args[0]}, Spec{Name: "t", User: self(t), Shell: "/bin/sh"}, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if s.Resize(0, 10) == nil || s.Resize(MaxCols+1, 10) == nil || s.Resize(100, 30) != nil {
		t.Fatal("resize bounds")
	}
}

func TestUnitProperties(t *testing.T) {
	props := unitProperties(Spec{Name: "x", User: worker.Identity{Name: "alice"}, Shell: "/bin/bash", NoNewPrivs: true, TasksMax: 10}, "/dev/pts/7")
	got := map[string]any{}
	for _, p := range props {
		got[p.Name] = p.Value.Value()
	}
	if got["User"] != "alice" || got["TTYPath"] != "/dev/pts/7" || got["NoNewPrivileges"] != true || got["TasksMax"] != uint64(10) {
		t.Fatalf("props: %v", got)
	}
	if _, ok := got["MemoryMax"]; ok {
		t.Fatal("unset MemoryMax must be omitted")
	}
	ex := got["ExecStart"].([]execCommand)
	if ex[0].Path != "/bin/bash" || ex[0].Argv[0] != "-bash" {
		t.Fatalf("exec: %+v", ex)
	}
}

// fakeUnits simulates systemd: a started unit runs until it is stopped or
// "exits" with code; successful units vanish, failed ones stay until reset.
type fakeUnits struct {
	mu      sync.Mutex
	units   map[string]string // unit → state
	code    int32
	started []string
	resets  int
	failErr error
}

func (f *fakeUnits) StartTransient(_ context.Context, unit string, _ []property) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failErr != nil {
		return f.failErr
	}
	f.units[unit] = "active"
	f.started = append(f.started, unit)
	return nil
}

func (f *fakeUnits) exit(unit string, code int32) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.code = code
	if code == 0 {
		delete(f.units, unit)
	} else {
		f.units[unit] = "failed"
	}
}

func (f *fakeUnits) Stop(_ context.Context, unit string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.units, unit)
	return nil
}

func (f *fakeUnits) State(_ context.Context, unit string) (string, int32, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.units[unit]
	if !ok {
		return "", 0, errors.New("no such unit")
	}
	return s, f.code, nil
}

func (f *fakeUnits) Reset(_ context.Context, unit string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.units, unit)
	f.resets++
	return nil
}

func TestSystemdLauncherLifecycle(t *testing.T) {
	f := &fakeUnits{units: map[string]string{}}
	l := &SystemdLauncher{bus: f, Poll: 10 * time.Millisecond}
	tty, _ := os.Open(os.DevNull)
	defer func() { _ = tty.Close() }()
	if _, err := l.Launch(context.Background(), Spec{Name: "Bad/Name"}, tty); err == nil {
		t.Fatal("invalid name accepted")
	}

	// Failed exit: the status is read and the unit reset.
	p, err := l.Launch(context.Background(), Spec{Name: "a1"}, tty)
	if err != nil || f.started[0] != UnitPrefix+"a1.service" {
		t.Fatalf("launch: %v %v", err, f.started)
	}
	time.Sleep(50 * time.Millisecond)
	if p.ExitCode() != -1 {
		t.Fatal("running unit has an exit code")
	}
	f.exit(UnitPrefix+"a1.service", 4)
	waitDone(t, p)
	if p.ExitCode() != 4 || f.resets != 1 {
		t.Fatalf("failed exit: code %d resets %d", p.ExitCode(), f.resets)
	}

	// Successful exit: the unit vanishes.
	p, _ = l.Launch(context.Background(), Spec{Name: "a2"}, tty)
	time.Sleep(50 * time.Millisecond)
	f.exit(UnitPrefix+"a2.service", 0)
	waitDone(t, p)
	if p.ExitCode() != 0 {
		t.Fatalf("clean exit: %d", p.ExitCode())
	}

	// Stop ends the unit and returns once it is gone.
	p, _ = l.Launch(context.Background(), Spec{Name: "a3"}, tty)
	time.Sleep(50 * time.Millisecond)
	p.Stop()
	waitDone(t, p)

	f.failErr = errors.New("denied")
	if _, err := Open(context.Background(), l, Spec{Name: "a4"}, 80, 24); err == nil {
		t.Fatal("launch error not returned")
	}
}

func waitDone(t *testing.T, p Process) {
	t.Helper()
	select {
	case <-p.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("not done")
	}
}

func TestModes(t *testing.T) {
	if !ModeStandard.Valid() || ModeStandard.Elevated() || !ModeRoot.Elevated() || !ModeSudo.Elevated() || Mode("x").Valid() {
		t.Fatal("modes")
	}
}
