package services

import (
	"context"
	"errors"
	"time"

	"github.com/godbus/dbus/v5"
	"golang.org/x/sys/unix"
)

const timerIfc = "org.freedesktop.systemd1.Timer"

// Timer is one row of the timer overview (SPEC §7.7).
type Timer struct {
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Active      string    `json:"active"`
	FileState   string    `json:"file_state"`
	Unit        string    `json:"unit"` // triggered unit
	Next        time.Time `json:"next,omitzero"`
	Last        time.Time `json:"last,omitzero"`
	Schedule    []string  `json:"schedule,omitempty"` // OnCalendar=… / OnUnitActiveSec=…
	Result      string    `json:"result,omitempty"`   // Result of the triggered service
	ExitCode    *int      `json:"exit_code,omitempty"`
	ServiceSub  string    `json:"service_active,omitempty"`
}

func usecTime(us uint64) time.Time {
	if us == 0 || us == ^uint64(0) {
		return time.Time{}
	}
	return time.UnixMicro(int64(us)).UTC() //nolint:gosec // timestamp fits
}

// monoToReal converts a CLOCK_MONOTONIC timestamp (µs) to wall time.
func monoToReal(us uint64) time.Time {
	if us == 0 || us == ^uint64(0) {
		return time.Time{}
	}
	var ts unix.Timespec
	if unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts) != nil {
		return time.Time{}
	}
	now := uint64(ts.Nano() / 1000)                                                                           //nolint:gosec // monotonic clock is positive
	return time.Now().UTC().Add(time.Duration(int64(us)-int64(now)) * time.Microsecond).Truncate(time.Second) //nolint:gosec // bounded
}

func (c *Client) timerInfo(ctx context.Context, name string, path dbus.ObjectPath) Timer {
	t := Timer{Name: name}
	var props map[string]dbus.Variant
	if err := c.conn.Object(dest, path).CallWithContext(ctx, "org.freedesktop.DBus.Properties.GetAll", 0, timerIfc).Store(&props); err == nil {
		t.Unit, _ = props["Unit"].Value().(string)
		rt, _ := props["NextElapseUSecRealtime"].Value().(uint64)
		mono, _ := props["NextElapseUSecMonotonic"].Value().(uint64)
		t.Next = usecTime(rt)
		if m := monoToReal(mono); !m.IsZero() && (t.Next.IsZero() || m.Before(t.Next)) {
			t.Next = m
		}
		last, _ := props["LastTriggerUSec"].Value().(uint64)
		t.Last = usecTime(last)
		if cal, ok := props["TimersCalendar"].Value().([][]any); ok {
			for _, x := range cal {
				if len(x) >= 2 {
					base, _ := x[0].(string)
					expr, _ := x[1].(string)
					t.Schedule = append(t.Schedule, base+"="+expr)
				}
			}
		}
		if mon, ok := props["TimersMonotonic"].Value().([][]any); ok {
			for _, x := range mon {
				if len(x) >= 2 {
					base, _ := x[0].(string)
					us, _ := x[1].(uint64)
					t.Schedule = append(t.Schedule, base+"="+(time.Duration(us)*time.Microsecond).String()) //nolint:gosec // bounded
				}
			}
		}
	}
	if t.Unit != "" && validUnitName(t.Unit) {
		var sp dbus.ObjectPath
		if err := c.mgr().CallWithContext(ctx, mgrIface+".LoadUnit", 0, t.Unit).Store(&sp); err == nil {
			if v, err := c.prop(ctx, sp, unitIfc, "ActiveState"); err == nil {
				t.ServiceSub, _ = v.Value().(string)
			}
			if v, err := c.prop(ctx, sp, svcIfc, "Result"); err == nil {
				t.Result, _ = v.Value().(string)
			}
			if v, err := c.prop(ctx, sp, svcIfc, "ExecMainExitTimestamp"); err == nil {
				if us, _ := v.Value().(uint64); us > 0 {
					if v, err := c.prop(ctx, sp, svcIfc, "ExecMainStatus"); err == nil {
						if code, ok := v.Value().(int32); ok {
							n := int(code)
							t.ExitCode = &n
						}
					}
				}
			}
		}
	}
	return t
}

func validUnitName(n string) bool { return checkName(n) == nil }

// Timers lists all timer units with their next and last run and the result
// of the unit they trigger.
func (c *Client) Timers(ctx context.Context) ([]Timer, error) {
	var raw []rawUnit
	if err := c.mgr().CallWithContext(ctx, mgrIface+".ListUnitsByPatterns", 0, []string{}, []string{"*.timer"}).Store(&raw); err != nil {
		return nil, err
	}
	var files []struct{ Path, State string }
	states := map[string]string{}
	if err := c.mgr().CallWithContext(ctx, mgrIface+".ListUnitFilesByPatterns", 0, []string{}, []string{"*.timer"}).Store(&files); err == nil {
		for _, f := range files {
			states[baseName(f.Path)] = f.State
		}
	}
	out := make([]Timer, 0, len(raw))
	for _, r := range raw {
		t := c.timerInfo(ctx, r.Name, r.Path)
		t.Description, t.Active, t.FileState = r.Description, r.Active, states[r.Name]
		out = append(out, t)
	}
	return out, nil
}

func baseName(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' {
			return p[i+1:]
		}
	}
	return p
}

// TimerState returns the timer row of one timer (loading it if needed).
func (c *Client) TimerState(ctx context.Context, name string) (Timer, error) {
	if checkName(name) != nil {
		return Timer{}, errors.New("invalid unit name")
	}
	var path dbus.ObjectPath
	if err := c.mgr().CallWithContext(ctx, mgrIface+".LoadUnit", 0, name).Store(&path); err != nil {
		return Timer{}, err
	}
	t := c.timerInfo(ctx, name, path)
	if v, err := c.prop(ctx, path, unitIfc, "ActiveState"); err == nil {
		t.Active, _ = v.Value().(string)
	}
	if v, err := c.prop(ctx, path, unitIfc, "UnitFileState"); err == nil {
		t.FileState, _ = v.Value().(string)
	}
	if v, err := c.prop(ctx, path, unitIfc, "Description"); err == nil {
		t.Description, _ = v.Value().(string)
	}
	return t, nil
}

// DaemonReload reloads unit files.
func (c *Client) DaemonReload(ctx context.Context) error {
	return c.mgr().CallWithContext(ctx, mgrIface+".Reload", 0).Err
}

// ResetFailed clears a unit's failed state, so a deleted unit does not
// linger as "not-found failed".
func (c *Client) ResetFailed(ctx context.Context, name string) error {
	if checkName(name) != nil {
		return errors.New("invalid unit name")
	}
	return c.mgr().CallWithContext(ctx, mgrIface+".ResetFailedUnit", 0, name).Err
}

// StartNoWait queues a start job and returns at once.
func (c *Client) StartNoWait(ctx context.Context, name string) error {
	if checkName(name) != nil {
		return errors.New("invalid unit name")
	}
	var job dbus.ObjectPath
	return c.mgr().CallWithContext(ctx, mgrIface+".StartUnit", 0, name, "replace").Store(&job)
}
