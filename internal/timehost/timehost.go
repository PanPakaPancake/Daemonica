// Package timehost reads and changes time zone, NTP, host name and power
// state through systemd's timedated, hostnamed and logind (SPEC §7.8 M1.7,
// DEC-033), and keeps /etc/hosts consistent with the host name.
package timehost

import (
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/godbus/dbus/v5"
)

const (
	timedate  = "org.freedesktop.timedate1"
	hostname1 = "org.freedesktop.hostname1"
	login1    = "org.freedesktop.login1"
)

// Time is the timedated state.
type Time struct {
	Now      time.Time `json:"now"`
	Timezone string    `json:"timezone"`
	LocalRTC bool      `json:"local_rtc"`
	CanNTP   bool      `json:"can_ntp"`
	NTP      bool      `json:"ntp"`
	Synced   bool      `json:"ntp_synced"`
	RTC      time.Time `json:"rtc,omitzero"`
	// Server is the NTP server systemd-timesyncd talks to (empty with
	// another NTP daemon or none).
	Server string `json:"ntp_server,omitempty"`
}

// Host is the hostnamed state.
type Host struct {
	Hostname string `json:"hostname"` // transient (kernel)
	Static   string `json:"static"`
	Pretty   string `json:"pretty"`
	Chassis  string `json:"chassis,omitempty"`
	OS       string `json:"os,omitempty"`
}

// Scheduled is a pending shutdown or reboot.
type Scheduled struct {
	Type string    `json:"type"` // reboot, poweroff …
	At   time.Time `json:"at"`
}

// Inhibitor is a logind inhibitor lock.
type Inhibitor struct {
	What string `json:"what"`
	Who  string `json:"who"`
	Why  string `json:"why"`
	Mode string `json:"mode"`
	UID  uint32 `json:"uid"`
	PID  uint32 `json:"pid"`
}

// Bus talks to the systemd daemons.
type Bus struct{ Conn *dbus.Conn }

func (b Bus) obj(dest, path string) dbus.BusObject {
	return b.Conn.Object(dest, dbus.ObjectPath(path))
}

func prop[T any](ctx context.Context, o dbus.BusObject, iface, name string) (T, error) {
	var v dbus.Variant
	var zero T
	if err := o.CallWithContext(ctx, "org.freedesktop.DBus.Properties.Get", 0, iface, name).Store(&v); err != nil {
		return zero, err
	}
	t, ok := v.Value().(T)
	if !ok {
		return zero, fmt.Errorf("timehost: %s.%s has type %T", iface, name, v.Value())
	}
	return t, nil
}

func usec(u uint64) time.Time {
	if u == 0 {
		return time.Time{}
	}
	return time.UnixMicro(int64(u)).UTC() //nolint:gosec // microseconds since epoch fit
}

// Time reads timedated.
func (b Bus) Time(ctx context.Context) (Time, error) {
	o := b.obj(timedate, "/org/freedesktop/timedate1")
	var t Time
	var err error
	if t.Timezone, err = prop[string](ctx, o, timedate, "Timezone"); err != nil {
		return t, err
	}
	t.LocalRTC, _ = prop[bool](ctx, o, timedate, "LocalRTC")
	t.CanNTP, _ = prop[bool](ctx, o, timedate, "CanNTP")
	t.NTP, _ = prop[bool](ctx, o, timedate, "NTP")
	t.Synced, _ = prop[bool](ctx, o, timedate, "NTPSynchronized")
	if u, err := prop[uint64](ctx, o, timedate, "TimeUSec"); err == nil {
		t.Now = usec(u)
	}
	if u, err := prop[uint64](ctx, o, timedate, "RTCTimeUSec"); err == nil {
		t.RTC = usec(u)
	}
	ts := b.obj("org.freedesktop.timesync1", "/org/freedesktop/timesync1")
	if s, err := prop[string](ctx, ts, "org.freedesktop.timesync1.Manager", "ServerName"); err == nil {
		t.Server = clip(s, 200)
	}
	return t, nil
}

// Timezones lists the time zones timedated accepts.
func (b Bus) Timezones(ctx context.Context) ([]string, error) {
	var zs []string
	err := b.obj(timedate, "/org/freedesktop/timedate1").CallWithContext(ctx, timedate+".ListTimezones", 0).Store(&zs)
	return zs, err
}

// SetTimezone sets the system time zone.
func (b Bus) SetTimezone(ctx context.Context, tz string) error {
	return b.obj(timedate, "/org/freedesktop/timedate1").CallWithContext(ctx, timedate+".SetTimezone", 0, tz, false).Err
}

// SetNTP switches network time synchronisation (timedated starts or stops
// the first available NTP unit: systemd-timesyncd, chrony …).
func (b Bus) SetNTP(ctx context.Context, on bool) error {
	return b.obj(timedate, "/org/freedesktop/timedate1").CallWithContext(ctx, timedate+".SetNTP", 0, on, false).Err
}

// Host reads hostnamed.
func (b Bus) Host(ctx context.Context) (Host, error) {
	o := b.obj(hostname1, "/org/freedesktop/hostname1")
	var h Host
	var err error
	if h.Hostname, err = prop[string](ctx, o, hostname1, "Hostname"); err != nil {
		return h, err
	}
	h.Static, _ = prop[string](ctx, o, hostname1, "StaticHostname")
	h.Pretty, _ = prop[string](ctx, o, hostname1, "PrettyHostname")
	h.Chassis, _ = prop[string](ctx, o, hostname1, "Chassis")
	h.OS, _ = prop[string](ctx, o, hostname1, "OperatingSystemPrettyName")
	return h, nil
}

// SetHostname sets the static (and with it the transient) and the pretty name.
func (b Bus) SetHostname(ctx context.Context, static, pretty string) error {
	o := b.obj(hostname1, "/org/freedesktop/hostname1")
	if err := o.CallWithContext(ctx, hostname1+".SetStaticHostname", 0, static, false).Err; err != nil {
		return err
	}
	if err := o.CallWithContext(ctx, hostname1+".SetHostname", 0, static, false).Err; err != nil {
		return err
	}
	return o.CallWithContext(ctx, hostname1+".SetPrettyHostname", 0, pretty, false).Err
}

// Scheduled reads logind's pending shutdown (nil if none).
func (b Bus) Scheduled(ctx context.Context) (*Scheduled, error) {
	var v dbus.Variant
	err := b.obj(login1, "/org/freedesktop/login1").CallWithContext(ctx, "org.freedesktop.DBus.Properties.Get", 0,
		login1+".Manager", "ScheduledShutdown").Store(&v)
	if err != nil {
		return nil, err
	}
	var s struct {
		Type string
		USec uint64
	}
	if err := dbus.Store([]any{v.Value()}, &s); err != nil || s.Type == "" || s.USec == 0 {
		return nil, nil //nolint:nilerr // no schedule
	}
	return &Scheduled{Type: s.Type, At: usec(s.USec)}, nil
}

// Inhibitors lists logind's inhibitor locks.
func (b Bus) Inhibitors(ctx context.Context) ([]Inhibitor, error) {
	var list []struct {
		What, Who, Why, Mode string
		UID, PID             uint32
	}
	err := b.obj(login1, "/org/freedesktop/login1").CallWithContext(ctx, login1+".Manager.ListInhibitors", 0).Store(&list)
	out := []Inhibitor{}
	for _, i := range list {
		out = append(out, Inhibitor{What: clip(i.What, 100), Who: clip(i.Who, 100), Why: clip(i.Why, 200), Mode: clip(i.Mode, 20), UID: i.UID, PID: i.PID})
	}
	return out, err
}

// Power actions.
const (
	Reboot   = "reboot"
	PowerOff = "poweroff"
)

// Schedule plans a reboot or power-off at t (logind sends wall messages
// and blocks new logins shortly before).
func (b Bus) Schedule(ctx context.Context, action string, t time.Time) error {
	if action != Reboot && action != PowerOff {
		return errors.New("timehost: unknown power action")
	}
	return b.obj(login1, "/org/freedesktop/login1").CallWithContext(ctx, login1+".Manager.ScheduleShutdown", 0,
		action, uint64(t.UnixMicro())).Err //nolint:gosec // future time
}

// Now reboots or powers off immediately.
func (b Bus) Now(ctx context.Context, action string) error {
	method := map[string]string{Reboot: "Reboot", PowerOff: "PowerOff"}[action]
	if method == "" {
		return errors.New("timehost: unknown power action")
	}
	return b.obj(login1, "/org/freedesktop/login1").CallWithContext(ctx, login1+".Manager."+method, 0, false).Err
}

// Cancel cancels a scheduled shutdown; false if none was pending.
func (b Bus) Cancel(ctx context.Context) (bool, error) {
	var ok bool
	err := b.obj(login1, "/org/freedesktop/login1").CallWithContext(ctx, login1+".Manager.CancelScheduledShutdown", 0).Store(&ok)
	return ok, err
}

var (
	labelRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	tzRE    = regexp.MustCompile(`^[A-Za-z0-9_+-]{1,40}(/[A-Za-z0-9_+-]{1,40}){0,2}$`)
)

// ValidHostname reports whether s is a static host name (one lowercase
// RFC 1123 label; the domain belongs into /etc/hosts or DNS).
func ValidHostname(s string) bool { return labelRE.MatchString(s) }

// ValidPretty reports whether s is a pretty host name (printable, ≤ 64 bytes).
func ValidPretty(s string) bool {
	return len(s) <= 64 && strings.IndexFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f }) < 0
}

// ValidTimezone checks the form of a time zone name (and that it is listed).
func ValidTimezone(tz string, list []string) bool {
	return tzRE.MatchString(tz) && !strings.Contains(tz, "..") && slices.Contains(list, tz)
}

// clip removes control characters and limits s to max bytes.
func clip(s string, max int) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	if len(s) > max {
		s = strings.ToValidUTF8(s[:max], "")
	}
	return s
}

// BootID returns the current boot ID (changes on every boot; the UI uses it
// to see that a reboot happened).
func BootID(procRoot string) string {
	b, _ := os.ReadFile(procRoot + "/sys/kernel/random/boot_id") //nolint:gosec // procfs
	return strings.TrimSpace(string(b))
}
