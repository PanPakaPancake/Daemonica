//go:build integration

package integration

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PanPakaPancake/daemonica/internal/helper"
	"github.com/PanPakaPancake/daemonica/internal/policy"
	"github.com/PanPakaPancake/daemonica/internal/pty"
	"github.com/PanPakaPancake/daemonica/internal/rpc"
	"github.com/PanPakaPancake/daemonica/internal/worker"
)

const termUser = "dmn-it14"

// sudoersFile lets termUser run exactly /usr/bin/true via sudo (removed afterwards).
const sudoersFile = "/etc/sudoers.d/daemonica-it14"

// TestTerminalOnHost runs real shells as transient systemd units (SPEC §7.5
// acceptance): sudo fails in the standard shell, works in the sudo mode,
// the root shell is root, every shell sits in its own unit, and ending the
// session kills the whole process tree.
func TestTerminalOnHost(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		t.Skip("needs systemd")
	}
	_ = exec.Command("/usr/sbin/userdel", "--remove", "--", termUser).Run()
	if out, err := exec.Command("/usr/sbin/useradd", "--create-home", "--user-group", "--shell", "/bin/bash", "--", termUser).CombinedOutput(); err != nil {
		t.Fatalf("useradd: %v %s", err, out)
	}
	t.Cleanup(func() {
		// Shells of a failed run may still be stopping; userdel refuses a busy user.
		for i := 0; i < 50 && exec.Command("pgrep", "-u", termUser).Run() == nil; i++ {
			time.Sleep(200 * time.Millisecond)
		}
		if out, err := exec.Command("/usr/sbin/userdel", "--remove", "--", termUser).CombinedOutput(); err != nil {
			t.Errorf("userdel %s: %v %s", termUser, err, out)
		}
	})
	if err := os.WriteFile(sudoersFile, []byte(termUser+" ALL=(root) NOPASSWD: /usr/bin/true\n"), 0o440); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(sudoersFile) })
	id, err := worker.Lookup(termUser)
	if err != nil {
		t.Fatal(err)
	}

	launcher, err := pty.ConnectSystemd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = launcher.Conn.Close() })
	dir := t.TempDir()
	cfg, err := helper.OpenConfig(filepath.Join(dir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	gs := helper.NewGrantStore(30*time.Minute, 12*time.Hour)
	ops := map[string]*helper.Op{}
	(&helper.TermOps{Launcher: launcher, Grants: gs, Config: cfg, Lookup: worker.Lookup, Shell: pty.LoginShell,
		TasksMax: 256, MemoryMax: 512 << 20}).Register(ops)
	sock := filepath.Join(dir, "h.sock")
	l, err := helper.ListenUnix(sock, 0o600, -1)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	srv := &helper.Server{Channel: helper.ChannelWeb, AllowedUID: 0, Ops: ops, Grants: gs, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	go func() { _ = srv.Serve(ctx, l) }()
	c := &rpc.Client{Socket: sock, Timeout: time.Minute}

	g, err := gs.Issue(policy.Subject{AccountID: "it14", Role: policy.RoleAdmin, LinuxUser: termUser, LinuxUID: id.UID}, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	// run opens a terminal, types script and returns the output until the shell exits.
	run := func(mode pty.Mode, script string) (string, helper.TermEnd) {
		t.Helper()
		var info helper.TermInfo
		d, err := c.OpenDuplex(context.Background(), "pty.open", g, "127.0.0.1", helper.TermParams{Mode: mode, Cols: 120, Rows: 40}, &info)
		if err != nil {
			t.Fatalf("open %s: %v", mode, err)
		}
		defer func() { _ = d.Close() }()
		out := &termOutput{}
		done := make(chan struct{})
		go func() { _, _ = io.Copy(out, d); close(done) }()
		waitPrompt(t, out, done)
		_ = d.Send(append([]byte{'d'}, script...))
		select {
		case <-done:
		case <-time.After(30 * time.Second):
			t.Fatalf("%s shell did not exit; output:\n%s", mode, out.String())
		}
		var end helper.TermEnd
		if err := d.Finish(&end); err != nil {
			t.Fatalf("finish: %v", err)
		}
		return out.String(), end
	}

	out, end := run(pty.ModeStandard, "id -un; cat /proc/self/cgroup; sudo -n /usr/bin/true; echo sudo_rc=$?; exit 4\n")
	if end.Reason != "exit" || end.ExitCode != 4 {
		t.Fatalf("standard end: %+v\n%s", end, out)
	}
	if !strings.Contains(out, termUser) || !strings.Contains(out, pty.UnitPrefix) || strings.Contains(out, "sudo_rc=0") {
		t.Fatalf("standard shell (sudo must fail, own unit):\n%s", out)
	}

	_ = gs.MarkStepUp(g, time.Now())
	out, _ = run(pty.ModeSudo, "sudo -n /usr/bin/true; echo sudo_rc=$?; exit\n")
	if !strings.Contains(out, "sudo_rc=0") {
		t.Fatalf("sudo mode:\n%s", out)
	}
	time.Sleep(10 * time.Millisecond)
	_ = gs.MarkStepUp(g, time.Now().Add(time.Second))
	out, _ = run(pty.ModeRoot, "id -u; exit\n")
	if !strings.Contains(out, "\n0\r") {
		t.Fatalf("root mode:\n%s", out)
	}

	// Closing the session ends background jobs, even ones that ignore SIGHUP.
	var info helper.TermInfo
	d, err := c.OpenDuplex(context.Background(), "pty.open", g, "127.0.0.1", helper.TermParams{Mode: pty.ModeStandard}, &info)
	if err != nil {
		t.Fatal(err)
	}
	bg := &termOutput{}
	bgDone := make(chan struct{})
	go func() { _, _ = io.Copy(bg, d); close(bgDone) }()
	waitPrompt(t, bg, bgDone)
	_ = d.Send([]byte("dnohup sh -c 'trap \"\" HUP; exec sleep 4242' >/dev/null 2>&1 &\n"))
	deadline := time.Now().Add(10 * time.Second)
	for !sleeping() && time.Now().Before(deadline) {
		time.Sleep(200 * time.Millisecond)
	}
	if !sleeping() {
		t.Fatal("background job did not start")
	}
	_ = d.Close()
	deadline = time.Now().Add(15 * time.Second)
	for sleeping() && time.Now().Before(deadline) {
		time.Sleep(200 * time.Millisecond)
	}
	if sleeping() {
		t.Fatal("background job survived the end of the session")
	}
	out2, _ := exec.Command("systemctl", "list-units", "--all", "--no-legend", pty.UnitPrefix+info.ID+".service").CombinedOutput()
	if strings.Contains(string(out2), "active") && !strings.Contains(string(out2), "inactive") {
		t.Fatalf("unit still active: %s", out2)
	}
}

// termOutput collects terminal output for concurrent reads.
type termOutput struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (o *termOutput) Write(p []byte) (int, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.buf.Write(p)
}

func (o *termOutput) String() string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.buf.String()
}

// waitPrompt waits until the shell shows its prompt, so input is not typed
// while systemd still sets up the terminal.
func waitPrompt(t *testing.T, out *termOutput, done <-chan struct{}) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		s := strings.TrimRight(out.String(), " ")
		if strings.HasSuffix(s, "$") || strings.HasSuffix(s, "#") {
			return
		}
		select {
		case <-done:
			t.Fatalf("shell ended before its prompt:\n%s", out.String())
		case <-time.After(50 * time.Millisecond):
		}
	}
	t.Fatalf("no prompt; output:\n%s", out.String())
}

func sleeping() bool {
	return exec.Command("pgrep", "-u", termUser, "-f", "sleep 4242").Run() == nil
}
