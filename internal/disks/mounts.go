package disks

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/godbus/dbus/v5"
)

// UnitName escapes a mount point to its systemd mount unit name
// (systemd-escape --path --suffix=mount).
func UnitName(path string) string {
	p := strings.Trim(filepath.Clean(path), "/")
	if p == "" {
		return "-.mount"
	}
	var b strings.Builder
	for i := 0; i < len(p); i++ {
		c := p[i]
		switch {
		case c == '/':
			b.WriteByte('-')
		case c == '.' && i == 0:
			fmt.Fprintf(&b, `\x%02x`, c)
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == ':', c == '_', c == '.':
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, `\x%02x`, c)
		}
	}
	return b.String() + ".mount"
}

// Critical reports whether a mount point must not be unmounted from the
// dashboard (the system and Daemonica itself depend on it).
func Critical(mp string) bool {
	switch mp {
	case "/", "/boot", "/boot/efi", "/efi", "/usr", "/var", "/var/log", "/var/lib", "/home", "/tmp", "/etc", "/opt":
		return true
	}
	for _, p := range []string{"/proc", "/sys", "/dev", "/run"} {
		if mp == p || strings.HasPrefix(mp, p+"/") {
			return true
		}
	}
	return false
}

// User is a process that keeps a mount busy.
type User struct {
	PID  int    `json:"pid"`
	Comm string `json:"comm"`
	// Why: "cwd", "root", "exe" or "file".
	Why string `json:"why"`
}

// Users finds processes using files below mp (cwd, root, exe, open files),
// at most limit. procRoot is "/proc" in production.
func Users(procRoot, mp string, limit int) []User {
	under := func(p string) bool { return p == mp || strings.HasPrefix(p, strings.TrimSuffix(mp, "/")+"/") }
	ents, _ := os.ReadDir(procRoot)
	out := []User{}
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid == os.Getpid() {
			continue
		}
		dir := filepath.Join(procRoot, e.Name())
		why := ""
		for _, l := range []string{"cwd", "root", "exe"} {
			if t, err := os.Readlink(filepath.Join(dir, l)); err == nil && under(t) && !(l == "root" && mp == "/") {
				why = l
				break
			}
		}
		if why == "" {
			fds, _ := os.ReadDir(filepath.Join(dir, "fd"))
			for _, fd := range fds {
				if t, err := os.Readlink(filepath.Join(dir, "fd", fd.Name())); err == nil && under(t) {
					why = "file"
					break
				}
			}
		}
		if why == "" {
			continue
		}
		comm, _ := os.ReadFile(filepath.Join(dir, "comm")) //nolint:gosec // procfs
		out = append(out, User{PID: pid, Comm: clip(strings.TrimSpace(string(comm)), 64), Why: why})
		if len(out) >= limit {
			break
		}
	}
	return out
}

// Systemd mounts and unmounts through mount units, so the helper's seccomp
// filter (no @mount) does not apply and systemd keeps its view consistent.
type Systemd struct{ Conn *dbus.Conn }

func (s Systemd) mgr() dbus.BusObject {
	return s.Conn.Object("org.freedesktop.systemd1", "/org/freedesktop/systemd1")
}

// Reload runs daemon-reload (regenerates the fstab mount units).
func (s Systemd) Reload(ctx context.Context) error {
	return s.mgr().CallWithContext(ctx, "org.freedesktop.systemd1.Manager.Reload", 0).Err
}

// ErrTimeout: the job did not finish in time.
var ErrTimeout = errors.New("disks: systemd job did not finish in time")

// Unit starts or stops a mount unit and waits for the job.
func (s Systemd) Unit(ctx context.Context, unit string, start bool) error {
	method := "StopUnit"
	if start {
		method = "StartUnit"
	}
	var job dbus.ObjectPath
	if err := s.mgr().CallWithContext(ctx, "org.freedesktop.systemd1.Manager."+method, 0, unit, "replace").Store(&job); err != nil {
		return err
	}
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		var v dbus.Variant
		if s.Conn.Object("org.freedesktop.systemd1", job).CallWithContext(ctx, "org.freedesktop.DBus.Properties.Get", 0,
			"org.freedesktop.systemd1.Job", "State").Store(&v) != nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
	return ErrTimeout
}

// Mounted reports whether mp is a mount point now (from mountinfo).
func Mounted(procRoot, mp string) bool {
	b, err := os.ReadFile(filepath.Join(procRoot, "self/mountinfo")) //nolint:gosec // procfs
	if err != nil {
		return false
	}
	for l := range strings.SplitSeq(string(b), "\n") {
		f := strings.Fields(l)
		if len(f) > 4 && unescape(f[4]) == mp {
			return true
		}
	}
	return false
}

// ReloadSystemd runs daemon-reload over its own bus connection (for the
// fstab change handler, which is registered before other connections exist).
func ReloadSystemd(ctx context.Context) error {
	c, err := dbus.ConnectSystemBus()
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	return Systemd{Conn: c}.Reload(ctx)
}
