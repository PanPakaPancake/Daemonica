package pty

import (
	"context"
	"errors"
	"os"
	"regexp"
	"sync"
	"time"

	"github.com/godbus/dbus/v5"
)

const (
	sdDest    = "org.freedesktop.systemd1"
	sdPath    = dbus.ObjectPath("/org/freedesktop/systemd1")
	sdManager = "org.freedesktop.systemd1.Manager"
	sdUnit    = "org.freedesktop.systemd1.Unit"
	sdService = "org.freedesktop.systemd1.Service"
	// UnitPrefix names the transient units of terminal sessions.
	UnitPrefix = "daemonica-term-"
)

var nameRE = regexp.MustCompile(`^[a-z0-9-]{1,64}$`)

// SystemdLauncher starts each shell as a transient service unit
// daemonica-term-<name>.service on the given terminal.
type SystemdLauncher struct {
	Conn *dbus.Conn
	// Poll is the interval for checking whether the unit is still active (default 500 ms).
	Poll time.Duration
	bus  unitBus // nil: systemd over Conn
}

// unitBus is the part of systemd's D-Bus API the launcher uses.
type unitBus interface {
	StartTransient(ctx context.Context, unit string, props []property) error
	Stop(ctx context.Context, unit string) error
	// State returns the unit's ActiveState and the main process's exit
	// status; an error means the unit does not exist (any more).
	State(ctx context.Context, unit string) (string, int32, error)
	// Reset unloads a failed unit.
	Reset(ctx context.Context, unit string) error
	// List names the loaded terminal units.
	List(ctx context.Context) ([]string, error)
}

type dbusUnits struct{ conn *dbus.Conn }

func (d dbusUnits) mgr() dbus.BusObject { return d.conn.Object(sdDest, sdPath) }

func (d dbusUnits) StartTransient(ctx context.Context, unit string, props []property) error {
	var job dbus.ObjectPath
	return d.mgr().CallWithContext(ctx, sdManager+".StartTransientUnit", 0, unit, "fail", props, []struct {
		Name  string
		Props []property
	}{}).Store(&job)
}

func (d dbusUnits) Stop(ctx context.Context, unit string) error {
	var job dbus.ObjectPath
	return d.mgr().CallWithContext(ctx, sdManager+".StopUnit", 0, unit, "replace").Store(&job)
}

func (d dbusUnits) Reset(ctx context.Context, unit string) error {
	return d.mgr().CallWithContext(ctx, sdManager+".ResetFailedUnit", 0, unit).Err
}

func (d dbusUnits) List(ctx context.Context) ([]string, error) {
	var units []struct {
		Name, Description, LoadState, ActiveState, SubState, Following string
		Path                                                           dbus.ObjectPath
		JobID                                                          uint32
		JobType                                                        string
		JobPath                                                        dbus.ObjectPath
	}
	err := d.mgr().CallWithContext(ctx, sdManager+".ListUnitsByPatterns", 0, []string{}, []string{UnitPrefix + "*.service"}).Store(&units)
	names := make([]string, 0, len(units))
	for _, u := range units {
		names = append(names, u.Name)
	}
	return names, err
}

func (d dbusUnits) State(ctx context.Context, unit string) (string, int32, error) {
	var path dbus.ObjectPath
	if err := d.mgr().CallWithContext(ctx, sdManager+".GetUnit", 0, unit).Store(&path); err != nil {
		return "", 0, err
	}
	obj := d.conn.Object(sdDest, path)
	var state, status dbus.Variant
	if err := obj.CallWithContext(ctx, "org.freedesktop.DBus.Properties.Get", 0, sdUnit, "ActiveState").Store(&state); err != nil {
		return "", 0, err
	}
	s, _ := state.Value().(string)
	var code int32
	if obj.CallWithContext(ctx, "org.freedesktop.DBus.Properties.Get", 0, sdService, "ExecMainStatus").Store(&status) == nil {
		code, _ = status.Value().(int32)
	}
	return s, code, nil
}

func (l *SystemdLauncher) units() unitBus {
	if l.bus != nil {
		return l.bus
	}
	return dbusUnits{conn: l.Conn}
}

// Cleanup ends the terminal units left from an earlier helper run (no
// client can reach them any more) and unloads failed ones, so none stays
// listed as failed. Call it once at start, before terminals are opened.
// It returns the number of units it found.
func (l *SystemdLauncher) Cleanup(ctx context.Context) int {
	names, err := l.units().List(ctx)
	if err != nil {
		return 0
	}
	for _, u := range names {
		_ = l.units().Stop(ctx, u)
	}
	poll := l.Poll
	if poll == 0 {
		poll = 500 * time.Millisecond
	}
	for _, u := range names {
		for {
			state, _, err := l.units().State(ctx, u)
			if err != nil || state == "inactive" {
				break // unloaded or ended
			}
			if state == "failed" {
				_ = l.units().Reset(ctx, u)
				break
			}
			select {
			case <-time.After(poll):
			case <-ctx.Done():
				return len(names)
			}
		}
	}
	return len(names)
}

// ConnectSystemd opens a private system bus connection for the launcher.
func ConnectSystemd() (*SystemdLauncher, error) {
	c, err := dbus.ConnectSystemBus()
	if err != nil {
		return nil, err
	}
	return &SystemdLauncher{Conn: c}, nil
}

type property struct {
	Name  string
	Value dbus.Variant
}

type execCommand struct {
	Path          string
	Argv          []string
	IgnoreFailure bool
}

func prop(name string, v any) property { return property{Name: name, Value: dbus.MakeVariant(v)} }

// unitProperties builds the transient unit. The shell is a login shell
// (argv[0] "-bash"); systemd opens the terminal, makes it the controlling
// terminal, hands it to the user and sets HOME, USER, LOGNAME and SHELL.
func unitProperties(spec Spec, tty string) []property {
	props := []property{
		prop("Description", "Daemonica web terminal ("+spec.User.Name+")"),
		prop("ExecStart", []execCommand{{Path: spec.Shell, Argv: []string{"-" + baseName(spec.Shell)}}}),
		prop("User", spec.User.Name),
		prop("WorkingDirectory", "~"),
		prop("Environment", Env),
		prop("StandardInput", "tty-force"),
		prop("StandardOutput", "tty"),
		prop("StandardError", "tty"),
		prop("TTYPath", tty),
		// The pty is fresh, so no TTYReset: systemd ≥ 258 would then write
		// reset sequences and flush input typed early. A known size keeps
		// systemd from asking the terminal for it (DSR), whose answer would
		// otherwise reach the shell as typed input.
		prop("TTYRows", uint32(spec.Rows)), // the setter takes "u", the getter "q"
		prop("TTYColumns", uint32(spec.Cols)),
		prop("NoNewPrivileges", spec.NoNewPrivs),
		// Pipelines behave as in an SSH session (yes | head).
		prop("IgnoreSIGPIPE", false),
		// End of the session: SIGHUP to every process of the unit, SIGKILL after 5 s.
		prop("KillMode", "control-group"),
		prop("KillSignal", int32(1)),
		prop("TimeoutStopUSec", uint64(5*time.Second/time.Microsecond)),
		prop("SendSIGKILL", true),
	}
	if spec.TasksMax > 0 {
		props = append(props, prop("TasksMax", spec.TasksMax))
	}
	if spec.MemoryMax > 0 {
		props = append(props, prop("MemoryMax", spec.MemoryMax))
	}
	return props
}

func baseName(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' {
			return p[i+1:]
		}
	}
	return p
}

// Launch implements Launcher.
func (l *SystemdLauncher) Launch(ctx context.Context, spec Spec, tty *os.File) (Process, error) {
	if !nameRE.MatchString(spec.Name) {
		return nil, errors.New("pty: invalid session name")
	}
	unit := UnitPrefix + spec.Name + ".service"
	if err := l.units().StartTransient(ctx, unit, unitProperties(spec, tty.Name())); err != nil {
		return nil, err
	}
	p := &unitProc{bus: l.units(), poll: l.Poll, unit: unit, done: make(chan struct{}), code: -1}
	if p.poll == 0 {
		p.poll = 500 * time.Millisecond
	}
	go p.watch()
	return p, nil
}

type unitProc struct {
	bus  unitBus
	poll time.Duration
	unit string
	done chan struct{}
	mu   sync.Mutex
	code int
	stop sync.Once
}

func (p *unitProc) Done() <-chan struct{} { return p.done }

func (p *unitProc) ExitCode() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.code
}

// watch polls the unit until it has ended. systemd unloads a unit that
// ended successfully right away (exit status 0); a failed one stays loaded
// with its exit status until it is reset here.
func (p *unitProc) watch() {
	defer close(p.done)
	seen := false
	for start := time.Now(); ; time.Sleep(p.poll) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		state, code, err := p.bus.State(ctx, p.unit)
		switch {
		case err != nil:
			if seen {
				p.setCode(0)
			}
			if seen || time.Since(start) > 10*time.Second {
				cancel()
				return
			}
		case state == "inactive" || state == "failed":
			p.setCode(int(code))
			if state == "failed" {
				_ = p.bus.Reset(ctx, p.unit)
			}
			cancel()
			return
		default:
			seen = true
		}
		cancel()
	}
}

func (p *unitProc) setCode(c int) {
	p.mu.Lock()
	p.code = c
	p.mu.Unlock()
}

// Stop stops the unit; systemd sends SIGHUP to all its processes and SIGKILL
// after 5 s. It waits until the unit has ended (bounded).
func (p *unitProc) Stop() {
	p.stop.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = p.bus.Stop(ctx, p.unit)
		cancel()
		select {
		case <-p.done:
		case <-time.After(8 * time.Second):
		}
	})
}
