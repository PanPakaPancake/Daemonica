package pty

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// ChildArg is the argv[1] that switches the helper binary into terminal
// child mode (ExecLauncher): argv = [bin, ChildArg, "nnp"|"priv", shell].
const ChildArg = "__pty"

// ExecLauncher starts the shell as a direct child of the helper. It is used
// by tests and as a fallback; it cannot limit resources and the shell
// inherits the helper's sandbox.
type ExecLauncher struct {
	// Binary is the helper executable (default /proc/self/exe).
	Binary string
}

type execProc struct {
	cmd  *exec.Cmd
	pid  int
	done chan struct{}
	code int
	stop sync.Once
}

// Launch implements Launcher.
func (l ExecLauncher) Launch(_ context.Context, spec Spec, tty *os.File) (Process, error) {
	bin := l.Binary
	if bin == "" {
		bin = "/proc/self/exe"
	}
	flag := "priv"
	if spec.NoNewPrivs {
		flag = "nnp"
	}
	cmd := exec.Command(bin, ChildArg, flag, spec.Shell) //nolint:gosec // own binary, validated shell
	cmd.Env = append(append([]string{}, Env...), "HOME="+spec.User.Home, "USER="+spec.User.Name, "LOGNAME="+spec.User.Name,
		"SHELL="+spec.Shell, "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
	cmd.Dir = "/"
	cmd.Stdin, cmd.Stdout, cmd.Stderr = tty, tty, tty
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0, Pdeathsig: syscall.SIGKILL}
	if os.Getuid() == 0 {
		cmd.SysProcAttr.Credential = &syscall.Credential{Uid: spec.User.UID, Gid: spec.User.GID, Groups: spec.User.Groups}
	} else if uint32(os.Getuid()) != spec.User.UID { //nolint:gosec // uid fits
		return nil, errors.New("pty: cannot switch user without root")
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	p := &execProc{cmd: cmd, pid: cmd.Process.Pid, done: make(chan struct{}), code: -1}
	go func() {
		_ = cmd.Wait()
		if cmd.ProcessState != nil {
			p.code = cmd.ProcessState.ExitCode()
		}
		close(p.done)
	}()
	return p, nil
}

func (p *execProc) Done() <-chan struct{} { return p.done }

func (p *execProc) ExitCode() int {
	select {
	case <-p.done:
		return p.code
	default:
		return -1
	}
}

// Stop signals every process of the shell's session (the shell is the
// session leader, so its session ID is its PID): SIGHUP, then SIGKILL for
// whatever is left after 5 s.
func (p *execProc) Stop() {
	p.stop.Do(func() {
		KillSession(p.pid, 5*time.Second)
		select {
		case <-p.done:
		case <-time.After(time.Second):
		}
	})
}

// KillSession sends SIGHUP to all processes in session sid, waits up to
// grace for them to exit and SIGKILLs the rest.
func KillSession(sid int, grace time.Duration) {
	signalSession(sid, syscall.SIGHUP)
	deadline := time.Now().Add(grace)
	for time.Now().Before(deadline) {
		if len(SessionPIDs(sid)) == 0 {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	signalSession(sid, syscall.SIGKILL)
}

func signalSession(sid int, sig syscall.Signal) {
	for _, pid := range SessionPIDs(sid) {
		_ = syscall.Kill(pid, sig)
	}
}

// SessionPIDs lists the live (non-zombie) processes whose session ID is sid.
func SessionPIDs(sid int) []int {
	if sid <= 1 {
		return nil
	}
	ents, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	var out []int
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		b, err := os.ReadFile(filepath.Join("/proc", e.Name(), "stat")) //nolint:gosec // /proc/<pid>/stat
		if err != nil {
			continue
		}
		// pid (comm) state ppid pgrp session …; comm may contain spaces and ')'.
		s := string(b)
		i := strings.LastIndexByte(s, ')')
		if i < 0 {
			continue
		}
		f := strings.Fields(s[i+1:])
		if len(f) < 4 || f[0] == "Z" {
			continue
		}
		if v, err := strconv.Atoi(f[3]); err == nil && v == sid {
			out = append(out, pid)
		}
	}
	return out
}

// ChildMain runs in the re-executed helper binary (argv[1] == ChildArg): it
// sets no_new_privs if asked and replaces itself with the login shell. It
// never returns.
func ChildMain(args []string) {
	if len(args) != 2 || !filepath.IsAbs(args[1]) {
		os.Exit(127)
	}
	if args[0] == "nnp" {
		if _, _, errno := syscall.RawSyscall(syscall.SYS_PRCTL, 38 /* PR_SET_NO_NEW_PRIVS */, 1, 0); errno != 0 {
			os.Exit(126)
		}
	}
	if home := os.Getenv("HOME"); home != "" {
		_ = os.Chdir(home)
	}
	shell := args[1]
	err := syscall.Exec(shell, []string{"-" + filepath.Base(shell)}, os.Environ()) //nolint:gosec // validated login shell
	_ = err
	os.Exit(127)
}
