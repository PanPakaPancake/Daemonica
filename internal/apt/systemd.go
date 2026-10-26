package apt

import (
	"context"
	"time"

	"github.com/godbus/dbus/v5"
)

// SystemdUnits starts package jobs as transient units over D-Bus. They run
// outside the helper's sandbox (apt and dpkg need the whole system) and
// write their output to the job log.
type SystemdUnits struct{ Conn *dbus.Conn }

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

func (s SystemdUnits) mgr() dbus.BusObject {
	return s.Conn.Object("org.freedesktop.systemd1", "/org/freedesktop/systemd1")
}

// Properties builds the unit.
func Properties(u Unit) []property {
	exec := make([]execCommand, 0, len(u.Exec))
	for _, c := range u.Exec {
		exec = append(exec, execCommand{Path: c[0], Argv: c})
	}
	return []property{
		prop("Description", "Daemonica package job"),
		prop("Type", "oneshot"),
		prop("ExecStart", exec),
		prop("ExecStopPost", []execCommand{{Path: u.Post[0], Argv: u.Post}}),
		prop("Environment", u.Env),
		prop("StandardInput", "null"),
		prop("StandardOutputFileToAppend", u.Log),
		prop("StandardErrorFileToAppend", u.Log),
		prop("TimeoutStartUSec", uint64(3*time.Hour/time.Microsecond)),
		// Interrupting dpkg leaves a half-configured system: stop gently.
		prop("KillMode", "mixed"),
		prop("TimeoutStopUSec", uint64(5*time.Minute/time.Microsecond)),
		prop("CollectMode", "inactive-or-failed"),
	}
}

// Start implements Units.
func (s SystemdUnits) Start(ctx context.Context, u Unit) error {
	var job dbus.ObjectPath
	return s.mgr().CallWithContext(ctx, "org.freedesktop.systemd1.Manager.StartTransientUnit", 0, u.Name, "fail",
		Properties(u), []struct {
			Name  string
			Props []property
		}{}).Store(&job)
}

// Exists implements Units.
func (s SystemdUnits) Exists(ctx context.Context, unit string) bool {
	var p dbus.ObjectPath
	return s.mgr().CallWithContext(ctx, "org.freedesktop.systemd1.Manager.GetUnit", 0, unit).Store(&p) == nil
}
