package capture

import (
	"bufio"
	"context"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/godbus/dbus/v5"
)

// Tcpdump is the capture program.
var Tcpdump = "/usr/bin/tcpdump"

// SystemdStarter runs tcpdump as a transient, strongly restricted service
// (SPEC §7.6 M1.5d): a dynamic unprivileged user with only CAP_NET_RAW
// (plus CAP_NET_ADMIN for promiscuous mode), read-only system, private /tmp,
// only packet and unix sockets, the system-service syscall set, a memory cap
// and a runtime cap. Its stdout is a pipe to the helper.
type SystemdStarter struct{ Conn *dbus.Conn }

const (
	capNetAdmin = 12
	capNetRaw   = 13
)

type property struct {
	Name  string
	Value dbus.Variant
}

type execCommand struct {
	Path          string
	Argv          []string
	IgnoreFailure bool
}

type boolList struct {
	Allow bool
	List  []string
}

func prop(name string, v any) property { return property{Name: name, Value: dbus.MakeVariant(v)} }

// unitProperties builds the sandboxed unit; out and errOut are the write
// ends of the stdout (pcap stream) and stderr (messages) pipes.
func unitProperties(args []string, spec Spec, out, errOut int) []property {
	caps := uint64(1) << capNetRaw
	if spec.Promisc {
		caps |= 1 << capNetAdmin
	}
	return []property{
		prop("Description", "Daemonica packet capture on "+spec.Iface),
		prop("ExecStart", []execCommand{{Path: Tcpdump, Argv: args}}),
		prop("DynamicUser", true),
		prop("AmbientCapabilities", caps),
		prop("CapabilityBoundingSet", caps),
		prop("NoNewPrivileges", true),
		prop("ProtectSystem", "strict"),
		prop("ProtectHome", "yes"),
		prop("PrivateTmp", true),
		prop("PrivateDevices", true),
		prop("ProtectKernelTunables", true),
		prop("ProtectKernelModules", true),
		prop("ProtectControlGroups", true),
		// The D-Bus property is the mask of allowed namespaces ("t"); 0 = none.
		prop("RestrictNamespaces", uint64(0)),
		prop("LockPersonality", true),
		prop("MemoryDenyWriteExecute", true),
		prop("RestrictAddressFamilies", boolList{Allow: true, List: []string{"AF_PACKET", "AF_UNIX"}}),
		prop("SystemCallFilter", boolList{Allow: true, List: []string{"@system-service"}}),
		prop("SystemCallArchitectures", []string{"native"}),
		prop("MemoryMax", uint64(256<<20)),
		prop("TasksMax", uint64(4)),
		prop("RuntimeMaxUSec", uint64((time.Duration(spec.DurationSec)*time.Second+30*time.Second)/time.Microsecond)), //nolint:gosec // duration validated (max. 30 min), positive
		prop("StandardInput", "null"),
		prop("StandardOutputFileDescriptor", dbus.UnixFD(out)), //nolint:gosec // fd fits
		// stderr gets its own pipe: tcpdump's messages must never mix into the
		// pcap stream, and the helper logs them with the capture.
		prop("StandardErrorFileDescriptor", dbus.UnixFD(errOut)), //nolint:gosec // fd fits
		prop("KillMode", "control-group"),
		prop("TimeoutStopUSec", uint64(5*time.Second/time.Microsecond)),
		prop("CollectMode", "inactive-or-failed"),
	}
}

func (s *SystemdStarter) mgr() dbus.BusObject {
	return s.Conn.Object("org.freedesktop.systemd1", "/org/freedesktop/systemd1")
}

// Start implements Starter.
func (s *SystemdStarter) Start(ctx context.Context, unit string, args []string, spec Spec) (io.ReadCloser, func(), error) {
	r, w, err := os.Pipe()
	if err != nil {
		return nil, nil, err
	}
	er, ew, err := os.Pipe()
	if err != nil {
		_ = r.Close()
		_ = w.Close()
		return nil, nil, err
	}
	var job dbus.ObjectPath
	err = s.mgr().CallWithContext(ctx, "org.freedesktop.systemd1.Manager.StartTransientUnit", 0, unit, "fail",
		unitProperties(args, spec, int(w.Fd()), int(ew.Fd())), []struct { //nolint:gosec // fd fits
			Name  string
			Props []property
		}{}).Store(&job)
	// systemd holds its own copies of the write ends now.
	_ = w.Close()
	_ = ew.Close()
	if err != nil {
		_ = r.Close()
		_ = er.Close()
		return nil, nil, err
	}
	go logStderr(unit, er)
	var once sync.Once
	stop := func() {
		once.Do(func() {
			sctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			_ = s.mgr().CallWithContext(sctx, "org.freedesktop.systemd1.Manager.StopUnit", 0, unit, "replace").Store(&job)
		})
	}
	return r, stop, nil
}

// logStderr logs tcpdump's messages (untrusted: control characters removed,
// lines and count bounded) until the unit closes its stderr.
func logStderr(unit string, r io.ReadCloser) {
	defer func() { _ = r.Close() }()
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 4096), 4096)
	for n := 0; sc.Scan(); n++ {
		if n < 50 {
			slog.Info("capture stderr", "unit", unit, "line", Clean(sc.Text(), 300))
		}
	}
	_, _ = io.Copy(io.Discard, r)
}

// Clean makes untrusted text printable and at most max bytes long.
func Clean(s string, max int) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || r == utf8.RuneError {
			return -1
		}
		return r
	}, s)
	if len(s) > max {
		s = strings.ToValidUTF8(s[:max], "")
	}
	return s
}

// Cleanup implements Starter.
func (s *SystemdStarter) Cleanup(ctx context.Context) {
	var units []struct {
		Name, Description, LoadState, ActiveState, SubState, Following string
		Path                                                           dbus.ObjectPath
		JobID                                                          uint32
		JobType                                                        string
		JobPath                                                        dbus.ObjectPath
	}
	if s.mgr().CallWithContext(ctx, "org.freedesktop.systemd1.Manager.ListUnitsByPatterns", 0, []string{}, []string{UnitPrefix + "*.service"}).Store(&units) != nil {
		return
	}
	for _, u := range units {
		var job dbus.ObjectPath
		_ = s.mgr().CallWithContext(ctx, "org.freedesktop.systemd1.Manager.StopUnit", 0, u.Name, "replace").Store(&job)
		_ = s.mgr().CallWithContext(ctx, "org.freedesktop.systemd1.Manager.ResetFailedUnit", 0, u.Name).Err
	}
}

// ConnectSystemd opens a system bus connection (with fd passing).
func ConnectSystemd() (*SystemdStarter, error) {
	c, err := dbus.ConnectSystemBus()
	if err != nil {
		return nil, err
	}
	return &SystemdStarter{Conn: c}, nil
}
