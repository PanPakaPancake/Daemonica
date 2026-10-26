//go:build integration

package integration

import (
	"context"
	"os"
	"slices"
	"testing"

	"github.com/godbus/dbus/v5"

	"github.com/PanPakaPancake/daemonica/internal/timehost"
)

// TestTimeHostOnHost (M1.7c, DEC-033): timedated, hostnamed and logind answer
// over D-Bus, the current zone is listed, the static name is valid and the
// hosts rename keeps an unchanged name as it is. Nothing is changed.
func TestTimeHostOnHost(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	conn, err := dbus.ConnectSystemBus()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	ctx := context.Background()
	b := timehost.Bus{Conn: conn}
	tm, err := b.Time(ctx)
	if err != nil || tm.Now.IsZero() {
		t.Fatalf("time: %v %+v", err, tm)
	}
	t.Logf("time %+v", tm)
	zs, err := b.Timezones(ctx)
	if err != nil || !slices.Contains(zs, tm.Timezone) || !timehost.ValidTimezone(tm.Timezone, zs) {
		t.Fatalf("zones: %v (%d), current %q", err, len(zs), tm.Timezone)
	}
	h, err := b.Host(ctx)
	if err != nil || h.Hostname == "" {
		t.Fatalf("host: %v %+v", err, h)
	}
	t.Logf("host %+v cloud-init resets %v", h, timehost.CloudInitResets(""))
	if h.Static != "" && !timehost.ValidHostname(h.Static) {
		t.Errorf("static name %q not accepted by ValidHostname", h.Static)
	}
	if s, err := b.Scheduled(ctx); err != nil || s != nil {
		t.Logf("scheduled: %v %+v", err, s)
	}
	in, err := b.Inhibitors(ctx)
	if err != nil {
		t.Fatalf("inhibitors: %v", err)
	}
	t.Logf("inhibitors %+v", in)
	if timehost.BootID("/proc") == "" {
		t.Error("no boot id")
	}
	text, err := os.ReadFile(timehost.HostsPath)
	if err != nil {
		t.Fatal(err)
	}
	name := h.Static
	if name == "" {
		name = h.Hostname
	}
	if got := timehost.RenameHosts(string(text), name, name); got != string(text) {
		t.Logf("hosts would gain a 127.0.1.1 line:\n%s", got)
	}
}
