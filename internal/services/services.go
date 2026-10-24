// Package services talks to systemd over D-Bus (org.freedesktop.systemd1),
// never by parsing systemctl output (SPEC §7.2).
package services

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/godbus/dbus/v5"

	"github.com/PanPakaPancake/daemonica/internal/validate"
)

const (
	dest     = "org.freedesktop.systemd1"
	mgrPath  = dbus.ObjectPath("/org/freedesktop/systemd1")
	mgrIface = "org.freedesktop.systemd1.Manager"
	unitIfc  = "org.freedesktop.systemd1.Unit"
	svcIfc   = "org.freedesktop.systemd1.Service"
)

// Types shown in the UI (SPEC §7.2).
var listedTypes = map[string]bool{"service": true, "timer": true, "socket": true}

// Unit is one row of the unit list.
type Unit struct {
	Name        string    `json:"name"`
	Type        string    `json:"type"`
	Description string    `json:"description"`
	Load        string    `json:"load"`
	Active      string    `json:"active"`
	Sub         string    `json:"sub"`
	FileState   string    `json:"file_state"` // enabled/disabled/static/masked/…
	Since       time.Time `json:"since,omitempty"`
	Memory      uint64    `json:"memory,omitempty"`
	Protected   bool      `json:"protected"`
}

// Detail is the detail view of one unit.
type Detail struct {
	Unit
	FragmentPath string   `json:"fragment_path,omitempty"`
	MainPID      uint32   `json:"main_pid,omitempty"`
	Requires     []string `json:"requires,omitempty"`
	Wants        []string `json:"wants,omitempty"`
	After        []string `json:"after,omitempty"`
	WantedBy     []string `json:"wanted_by,omitempty"`
	TriggeredBy  []string `json:"triggered_by,omitempty"`
	Triggers     []string `json:"triggers,omitempty"`
	UnitFile     string   `json:"unit_file,omitempty"` // read-only content, untrusted text
}

// Protection classes.
const (
	ProtNone   = 0
	ProtNormal = 1 // daemonica-*, ssh, systemd-*: admin + step-up + warning
	ProtSelf   = 2 // daemonica-web: additionally requires explicit confirmation for stop/disable/mask
	ProtHelper = 3 // daemonica-helper: never stop/disable/mask via UI
)

// Protection classifies a unit name.
func Protection(name string) int {
	base := strings.TrimSuffix(strings.TrimSuffix(strings.TrimSuffix(name, ".service"), ".socket"), ".timer")
	switch {
	case base == "daemonica-helper":
		return ProtHelper
	case base == "daemonica-web":
		return ProtSelf
	case strings.HasPrefix(base, "daemonica-"), base == "ssh", base == "sshd", strings.HasPrefix(base, "systemd-"):
		return ProtNormal
	}
	return ProtNone
}

// Client is a systemd D-Bus client.
type Client struct{ conn *dbus.Conn }

// Connect opens a private connection to the system bus.
func Connect() (*Client, error) {
	c, err := dbus.ConnectSystemBus()
	if err != nil {
		return nil, err
	}
	return &Client{conn: c}, nil
}

// Close closes the connection.
func (c *Client) Close() error { return c.conn.Close() }

func (c *Client) mgr() dbus.BusObject { return c.conn.Object(dest, mgrPath) }

type rawUnit struct {
	Name, Description, Load, Active, Sub, Following string
	Path                                            dbus.ObjectPath
	JobID                                           uint32
	JobType                                         string
	JobPath                                         dbus.ObjectPath
}

func unitType(name string) string {
	i := strings.LastIndexByte(name, '.')
	if i < 0 {
		return ""
	}
	return name[i+1:]
}

// List returns all loaded service/timer/socket units plus installed unit files
// that are not loaded (e.g. disabled services).
func (c *Client) List(ctx context.Context) ([]Unit, error) {
	var raw []rawUnit
	if err := c.mgr().CallWithContext(ctx, mgrIface+".ListUnits", 0).Store(&raw); err != nil {
		return nil, err
	}
	var files []struct{ Path, State string }
	fileStates := map[string]string{}
	if err := c.mgr().CallWithContext(ctx, mgrIface+".ListUnitFiles", 0).Store(&files); err == nil {
		for _, f := range files {
			fileStates[filepath.Base(f.Path)] = f.State
		}
	}
	seen := map[string]bool{}
	var out []Unit
	for _, r := range raw {
		t := unitType(r.Name)
		if !listedTypes[t] {
			continue
		}
		seen[r.Name] = true
		u := Unit{Name: r.Name, Type: t, Description: r.Description, Load: r.Load, Active: r.Active, Sub: r.Sub,
			FileState: fileStates[r.Name], Protected: Protection(r.Name) != ProtNone}
		if since, err := c.prop(ctx, r.Path, unitIfc, "ActiveEnterTimestamp"); err == nil {
			if us, ok := since.Value().(uint64); ok && us > 0 {
				u.Since = time.UnixMicro(int64(us)).UTC() //nolint:gosec // timestamp fits
			}
		}
		if t == "service" && r.Active == "active" {
			if m, err := c.prop(ctx, r.Path, svcIfc, "MemoryCurrent"); err == nil {
				if v, ok := m.Value().(uint64); ok && v != ^uint64(0) {
					u.Memory = v
				}
			}
		}
		out = append(out, u)
	}
	for name, st := range fileStates {
		t := unitType(name)
		if seen[name] || !listedTypes[t] || strings.Contains(name, "@.") {
			continue
		}
		out = append(out, Unit{Name: name, Type: t, Load: "not-loaded", Active: "inactive", Sub: "dead", FileState: st,
			Protected: Protection(name) != ProtNone})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (c *Client) prop(ctx context.Context, path dbus.ObjectPath, iface, name string) (dbus.Variant, error) {
	var v dbus.Variant
	err := c.conn.Object(dest, path).CallWithContext(ctx, "org.freedesktop.DBus.Properties.Get", 0, iface, name).Store(&v)
	return v, err
}

// FailedCount returns the number of failed units (all types).
func (c *Client) FailedCount(ctx context.Context) (int, error) {
	var raw []rawUnit
	if err := c.mgr().CallWithContext(ctx, mgrIface+".ListUnitsFiltered", 0, []string{"failed"}).Store(&raw); err != nil {
		return 0, err
	}
	return len(raw), nil
}

func checkName(name string) error {
	if validate.Unit(name) != nil || !listedTypes[unitType(name)] {
		return errors.New("invalid unit name")
	}
	return nil
}

// Get returns details of one unit (loading it if necessary).
func (c *Client) Get(ctx context.Context, name string) (Detail, error) {
	if err := checkName(name); err != nil {
		return Detail{}, err
	}
	var path dbus.ObjectPath
	if err := c.mgr().CallWithContext(ctx, mgrIface+".LoadUnit", 0, name).Store(&path); err != nil {
		return Detail{}, err
	}
	var props map[string]dbus.Variant
	if err := c.conn.Object(dest, path).CallWithContext(ctx, "org.freedesktop.DBus.Properties.GetAll", 0, unitIfc).Store(&props); err != nil {
		return Detail{}, err
	}
	str := func(k string) string { s, _ := props[k].Value().(string); return s }
	strs := func(k string) []string { s, _ := props[k].Value().([]string); return s }
	d := Detail{Unit: Unit{Name: name, Type: unitType(name), Description: str("Description"), Load: str("LoadState"),
		Active: str("ActiveState"), Sub: str("SubState"), FileState: str("UnitFileState"), Protected: Protection(name) != ProtNone},
		FragmentPath: str("FragmentPath"), Requires: strs("Requires"), Wants: strs("Wants"), After: strs("After"),
		WantedBy: strs("WantedBy"), TriggeredBy: strs("TriggeredBy"), Triggers: strs("Triggers")}
	if us, ok := props["ActiveEnterTimestamp"].Value().(uint64); ok && us > 0 {
		d.Since = time.UnixMicro(int64(us)).UTC() //nolint:gosec // timestamp fits
	}
	if d.Type == "service" {
		if v, err := c.prop(ctx, path, svcIfc, "MainPID"); err == nil {
			d.MainPID, _ = v.Value().(uint32)
		}
		if v, err := c.prop(ctx, path, svcIfc, "MemoryCurrent"); err == nil {
			if m, ok := v.Value().(uint64); ok && m != ^uint64(0) {
				d.Memory = m
			}
		}
	}
	d.UnitFile = readUnitFile(d.FragmentPath)
	return d, nil
}

// unit files are read only from systemd's own directories (no arbitrary reads).
var unitDirs = []string{"/etc/systemd/", "/usr/lib/systemd/", "/lib/systemd/", "/run/systemd/"}

func readUnitFile(p string) string {
	if p == "" || !filepath.IsAbs(p) || filepath.Clean(p) != p {
		return ""
	}
	ok := false
	for _, d := range unitDirs {
		if strings.HasPrefix(p, d) {
			ok = true
		}
	}
	if !ok {
		return ""
	}
	f, err := os.Open(p) //nolint:gosec // restricted to systemd unit directories above
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()
	buf := make([]byte, 256<<10)
	n, _ := f.Read(buf)
	return string(buf[:n])
}

// Action names.
const (
	ActStart   = "start"
	ActStop    = "stop"
	ActRestart = "restart"
	ActReload  = "reload"
	ActEnable  = "enable"
	ActDisable = "disable"
	ActMask    = "mask"
	ActUnmask  = "unmask"
)

// IsFileAction reports enable/disable/mask/unmask (Annex A: admin + step-up).
func IsFileAction(a string) bool {
	return a == ActEnable || a == ActDisable || a == ActMask || a == ActUnmask
}

// ValidAction reports whether a is a known action.
func ValidAction(a string) bool {
	switch a {
	case ActStart, ActStop, ActRestart, ActReload, ActEnable, ActDisable, ActMask, ActUnmask:
		return true
	}
	return false
}

// Do performs an action and waits (bounded) for the job to finish.
func (c *Client) Do(ctx context.Context, name, action string) error {
	if err := checkName(name); err != nil {
		return err
	}
	m := c.mgr()
	var job dbus.ObjectPath
	switch action {
	case ActStart, ActStop, ActRestart, ActReload:
		method := map[string]string{ActStart: "StartUnit", ActStop: "StopUnit", ActRestart: "RestartUnit", ActReload: "ReloadUnit"}[action]
		if err := m.CallWithContext(ctx, mgrIface+"."+method, 0, name, "replace").Store(&job); err != nil {
			return err
		}
		return c.waitJob(ctx, job)
	case ActEnable:
		var carries bool
		var changes []unitFileChange
		if err := m.CallWithContext(ctx, mgrIface+".EnableUnitFiles", 0, []string{name}, false, false).Store(&carries, &changes); err != nil {
			return err
		}
	case ActDisable:
		var changes []unitFileChange
		if err := m.CallWithContext(ctx, mgrIface+".DisableUnitFiles", 0, []string{name}, false).Store(&changes); err != nil {
			return err
		}
	case ActMask:
		var changes []unitFileChange
		if err := m.CallWithContext(ctx, mgrIface+".MaskUnitFiles", 0, []string{name}, false, false).Store(&changes); err != nil {
			return err
		}
	case ActUnmask:
		var changes []unitFileChange
		if err := m.CallWithContext(ctx, mgrIface+".UnmaskUnitFiles", 0, []string{name}, false).Store(&changes); err != nil {
			return err
		}
	default:
		return errors.New("unknown action")
	}
	return m.CallWithContext(ctx, mgrIface+".Reload", 0).Err
}

// unitFileChange is one entry of the a(sss) change list returned by systemd.
type unitFileChange struct{ Type, Filename, Destination string }

// waitJob polls until the job object disappears (job finished) or ctx ends.
func (c *Client) waitJob(ctx context.Context, job dbus.ObjectPath) error {
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		var v dbus.Variant
		err := c.conn.Object(dest, job).CallWithContext(ctx, "org.freedesktop.DBus.Properties.Get", 0, "org.freedesktop.systemd1.Job", "State").Store(&v)
		if err != nil {
			return nil // job object gone → finished
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
	return errors.New("job did not finish in time")
}
