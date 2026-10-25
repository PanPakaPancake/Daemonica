// Package pty runs the web terminal's shells (SPEC §7.5, M1.4). The helper
// allocates a pseudo terminal and hands its slave side to a launcher that
// starts the mapped user's login shell on it:
//
//   - In production the shell runs as a transient systemd service
//     (SystemdLauncher). It is therefore outside the helper's own sandbox, gets
//     its own cgroup with TasksMax/MemoryMax, and systemd ends every process of
//     the session when it stops (SIGHUP, SIGKILL after 5 s).
//   - ExecLauncher starts the shell directly as a child (tests, hosts without
//     systemd); ending the session signals every process of its session ID.
//
// Standard shells run with no_new_privs, so sudo, su and setuid programs have
// no effect; only the admin's elevated modes (root shell, user shell with
// sudo) run without it.
package pty

import (
	"bufio"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"

	cpty "github.com/creack/pty"

	"github.com/PanPakaPancake/daemonica/internal/worker"
)

// Mode is the terminal mode.
type Mode string

// Modes (D-09).
const (
	ModeStandard Mode = "standard" // mapped user, no_new_privs
	ModeRoot     Mode = "root"     // elevated: root shell
	ModeSudo     Mode = "sudo"     // elevated: mapped user without no_new_privs (sudo per sudoers)
)

// Valid reports whether m is a known mode.
func (m Mode) Valid() bool { return m == ModeStandard || m == ModeRoot || m == ModeSudo }

// Elevated reports whether m is one of the admin-only elevated modes.
func (m Mode) Elevated() bool { return m == ModeRoot || m == ModeSudo }

// Size bounds of a terminal.
const (
	MaxCols = 1000
	MaxRows = 500
)

// Spec describes the shell to start.
type Spec struct {
	// Name identifies the session (unit name suffix, [a-z0-9-]).
	Name       string
	User       worker.Identity
	Shell      string
	NoNewPrivs bool
	// TasksMax and MemoryMax limit the session's cgroup (SystemdLauncher; 0 = unlimited).
	TasksMax  uint64
	MemoryMax uint64
	// Cols and Rows are the initial terminal size (set by Open).
	Cols, Rows uint16
}

// Process is a started shell session.
type Process interface {
	// Done is closed when the session has ended (shell exited or stopped).
	Done() <-chan struct{}
	// ExitCode is the shell's exit status once Done is closed (-1 if unknown).
	ExitCode() int
	// Stop ends every process of the session (SIGHUP, SIGKILL after 5 s) and
	// returns once they are gone or the grace time is over.
	Stop()
}

// Launcher starts a shell on the given terminal (the pty slave).
type Launcher interface {
	Launch(ctx context.Context, spec Spec, tty *os.File) (Process, error)
}

// Session is a running terminal: the pty master plus the shell process.
type Session struct {
	Master *os.File
	tty    *os.File
	proc   Process
	once   sync.Once
}

// ErrNoShell is returned when the user has no usable login shell.
var ErrNoShell = errors.New("pty: no login shell")

// Open allocates a pty of the given size and launches spec on it.
func Open(ctx context.Context, l Launcher, spec Spec, cols, rows uint16) (*Session, error) {
	master, tty, err := cpty.Open()
	if err != nil {
		return nil, err
	}
	spec.Cols, spec.Rows = clampSize(cols, MaxCols, 80), clampSize(rows, MaxRows, 24)
	if err := cpty.Setsize(master, &cpty.Winsize{Cols: spec.Cols, Rows: spec.Rows}); err != nil {
		_ = master.Close()
		_ = tty.Close()
		return nil, err
	}
	proc, err := l.Launch(ctx, spec, tty)
	if err != nil {
		_ = master.Close()
		_ = tty.Close()
		return nil, err
	}
	return &Session{Master: master, tty: tty, proc: proc}, nil
}

func clampSize(v, maxV, def uint16) uint16 {
	if v == 0 {
		return def
	}
	return min(v, maxV)
}

// Resize changes the terminal size (the shell receives SIGWINCH).
func (s *Session) Resize(cols, rows uint16) error {
	if cols == 0 || rows == 0 || cols > MaxCols || rows > MaxRows {
		return errors.New("pty: size out of range")
	}
	return cpty.Setsize(s.Master, &cpty.Winsize{Cols: cols, Rows: rows})
}

// Done is closed when the shell session has ended.
func (s *Session) Done() <-chan struct{} { return s.proc.Done() }

// ExitCode is the shell's exit status (-1 if unknown).
func (s *Session) ExitCode() int { return s.proc.ExitCode() }

// Close stops the session and releases the terminal. The master is closed
// last, so pending reads end with an error.
func (s *Session) Close() {
	s.once.Do(func() {
		s.proc.Stop()
		_ = s.tty.Close()
		_ = s.Master.Close()
	})
}

// LoginShell returns the login shell of user name from /etc/passwd if it is
// listed in /etc/shells and is not a "no login" shell.
func LoginShell(name string) (string, error) {
	return loginShell("/etc/passwd", "/etc/shells", name)
}

func loginShell(passwd, shells, name string) (string, error) {
	f, err := os.Open(passwd) //nolint:gosec // fixed system path
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	shell := ""
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		parts := strings.Split(sc.Text(), ":")
		if len(parts) == 7 && parts[0] == name {
			shell = parts[6]
			break
		}
	}
	if shell == "" || !filepath.IsAbs(shell) || strings.HasSuffix(shell, "/nologin") || strings.HasSuffix(shell, "/false") {
		return "", ErrNoShell
	}
	allowed, err := os.ReadFile(shells) //nolint:gosec // fixed system path
	if err != nil {
		return "", ErrNoShell
	}
	for _, l := range strings.Split(string(allowed), "\n") {
		if strings.TrimSpace(l) == shell {
			if _, err := os.Stat(shell); err != nil {
				return "", ErrNoShell
			}
			return shell, nil
		}
	}
	return "", ErrNoShell
}

// Env is the environment of a terminal shell (the launchers add HOME, USER,
// LOGNAME and SHELL).
var Env = []string{"TERM=xterm-256color", "COLORTERM=truecolor", "LANG=C.UTF-8"}
