package helper

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PanPakaPancake/daemonica/internal/policy"
	"github.com/PanPakaPancake/daemonica/internal/rpc"
	"github.com/PanPakaPancake/daemonica/internal/timehost"
)

type fakeTimeHost struct {
	t         timehost.Time
	h         timehost.Host
	sched     *timehost.Scheduled
	now       []string
	failHost  bool
	cancelled bool
}

func (f *fakeTimeHost) Time(context.Context) (timehost.Time, error) { return f.t, nil }
func (f *fakeTimeHost) Timezones(context.Context) ([]string, error) {
	return []string{"Etc/UTC", "Europe/Berlin"}, nil
}
func (f *fakeTimeHost) SetTimezone(_ context.Context, tz string) error { f.t.Timezone = tz; return nil }
func (f *fakeTimeHost) SetNTP(_ context.Context, on bool) error        { f.t.NTP = on; return nil }
func (f *fakeTimeHost) Host(context.Context) (timehost.Host, error)    { return f.h, nil }
func (f *fakeTimeHost) SetHostname(_ context.Context, s, p string) error {
	if f.failHost {
		return errors.New("hostnamed failed")
	}
	f.h.Static, f.h.Hostname, f.h.Pretty = s, s, p
	return nil
}
func (f *fakeTimeHost) Scheduled(context.Context) (*timehost.Scheduled, error) { return f.sched, nil }
func (f *fakeTimeHost) Inhibitors(context.Context) ([]timehost.Inhibitor, error) {
	return []timehost.Inhibitor{{What: "shutdown", Who: "apt", Why: "upgrade", Mode: "block"}}, nil
}
func (f *fakeTimeHost) Schedule(_ context.Context, a string, t time.Time) error {
	f.sched = &timehost.Scheduled{Type: a, At: t}
	return nil
}
func (f *fakeTimeHost) Now(_ context.Context, a string) error { f.now = append(f.now, a); return nil }
func (f *fakeTimeHost) Cancel(context.Context) (bool, error) {
	ok := f.sched != nil
	f.sched, f.cancelled = nil, ok
	return ok, nil
}

func TestTimeHostOpsRoles(t *testing.T) {
	dir := t.TempDir()
	hosts := filepath.Join(dir, "hosts")
	orig := "127.0.0.1 localhost\n127.0.1.1 srv1.example.org srv1\n"
	_ = os.WriteFile(hosts, []byte(orig), 0o644)
	proc := filepath.Join(dir, "proc")
	_ = os.MkdirAll(filepath.Join(proc, "sys/kernel/random"), 0o755)
	_ = os.WriteFile(filepath.Join(proc, "sys/kernel/random/boot_id"), []byte("boot-1\n"), 0o644)
	_ = os.MkdirAll(filepath.Join(dir, "etc/cloud"), 0o755)
	_ = os.WriteFile(filepath.Join(dir, "etc/cloud/cloud.cfg"), []byte("users: []\nmanage_etc_hosts: true\n"), 0o644)
	fb := &fakeTimeHost{t: timehost.Time{Timezone: "Etc/UTC", CanNTP: true, NTP: true}, h: timehost.Host{Hostname: "srv1", Static: "srv1"}}
	var deferred []func()
	now := time.Date(2026, 10, 26, 1, 2, 3, 0, time.UTC)
	e := newAuthEnv(t)
	g, sa, _ := setupAdmin(t, e)
	(&TimeHostOps{Bus: fb, HostsPath: hosts, Root: dir, ProcRoot: proc, Now: func() time.Time { return now },
		After: func(_ time.Duration, f func()) { deferred = append(deferred, f) }}).Register(e.web.Ops)
	const ip = "198.51.100.7"
	ro, _ := e.web.Grants.Issue(policy.Subject{AccountID: "ro", Role: policy.RoleReadOnly, LinuxUser: "carol", LinuxUID: 1002}, time.Now())

	r := e.callFrom(ip, "timehost.get", ro, nil)
	mustOK(t, r, "get")
	var st TimeHostState
	_ = json.Unmarshal(r.Result, &st)
	if st.BootID != "boot-1" || st.Host.Static != "srv1" || st.HostsLine != "127.0.1.1 srv1.example.org srv1" || !st.CloudInit || st.CloudHosts != timehost.HostsTemplate || len(st.Inhibitors) != 1 {
		t.Fatalf("get: %s", r.Result)
	}
	for _, op := range []string{"timehost.set_timezone", "timehost.set_ntp", "timehost.set_hostname", "power.schedule", "power.cancel"} {
		if c := code(e.callFrom(ip, op, ro, map[string]any{})); c != rpc.CodeForbidden {
			t.Fatalf("%s by read-only: %s", op, c)
		}
		if c := code(e.callFrom(ip, op, g, map[string]any{})); c != rpc.CodeStepUpNeeded {
			t.Fatalf("%s without step-up: %s", op, c)
		}
	}
	gs := stepUp(t, e, sa, g)

	if c := code(e.callFrom(ip, "timehost.set_timezone", gs, map[string]any{"timezone": "Mars/Olympus"})); c != rpc.CodeValidation {
		t.Fatalf("unknown zone: %s", c)
	}
	mustOK(t, e.callFrom(ip, "timehost.set_timezone", gs, map[string]any{"timezone": "Europe/Berlin"}), "tz")
	mustOK(t, e.callFrom(ip, "timehost.set_ntp", gs, map[string]any{"on": false}), "ntp")
	if fb.t.Timezone != "Europe/Berlin" || fb.t.NTP {
		t.Fatalf("time: %+v", fb.t)
	}

	// Host name: preview, invalid names, hostnamed failure restores hosts.
	if c := code(e.callFrom(ip, "timehost.hostname_plan", ro, map[string]any{"hostname": "Web_2"})); c != rpc.CodeValidation {
		t.Fatalf("invalid name: %s", c)
	}
	r = e.callFrom(ip, "timehost.hostname_plan", ro, map[string]any{"hostname": "web2"})
	mustOK(t, r, "plan")
	var hp HostnamePlan
	_ = json.Unmarshal(r.Result, &hp)
	if !hp.Changed || !strings.Contains(hp.Diff, "+127.0.1.1\tweb2.example.org web2") || !hp.CloudInit {
		t.Fatalf("plan: %s", r.Result)
	}
	fb.failHost = true
	if r := e.callFrom(ip, "timehost.set_hostname", gs, map[string]any{"hostname": "web2", "update_hosts": true}); r.Error == nil {
		t.Fatal("failure not reported")
	}
	if b, _ := os.ReadFile(hosts); string(b) != orig {
		t.Fatalf("hosts not restored: %q", b)
	}
	fb.failHost = false
	mustOK(t, e.callFrom(ip, "timehost.set_hostname", gs, map[string]any{"hostname": "web2", "pretty": "Web 2", "update_hosts": true}), "hostname")
	b, _ := os.ReadFile(hosts)
	bk, _ := os.ReadFile(hosts + ".daemonica-20261026-010203")
	if fb.h.Static != "web2" || fb.h.Pretty != "Web 2" || !strings.Contains(string(b), "127.0.1.1\tweb2.example.org web2") || string(bk) != orig {
		t.Fatalf("hostname: %+v %q %q", fb.h, b, bk)
	}

	// Power: typed name, delay range, schedule, cancel, immediate reboot after the answer.
	if c := code(e.callFrom(ip, "power.schedule", gs, map[string]any{"action": "reboot", "delay_min": 5, "confirm": "srv1"})); c != CodeConfirmMismatch {
		t.Fatalf("old name: %s", c)
	}
	if c := code(e.callFrom(ip, "power.schedule", gs, map[string]any{"action": "halt", "confirm": "web2"})); c != rpc.CodeValidation {
		t.Fatalf("halt: %s", c)
	}
	if c := code(e.callFrom(ip, "power.schedule", gs, map[string]any{"action": "reboot", "delay_min": 1441, "confirm": "web2"})); c != rpc.CodeValidation {
		t.Fatalf("delay: %s", c)
	}
	mustOK(t, e.callFrom(ip, "power.schedule", gs, map[string]any{"action": "poweroff", "delay_min": 10, "confirm": "web2"}), "schedule")
	if fb.sched == nil || fb.sched.Type != "poweroff" || !fb.sched.At.Equal(now.Add(10*time.Minute)) || len(fb.now) != 0 {
		t.Fatalf("scheduled: %+v", fb.sched)
	}
	r = e.callFrom(ip, "power.cancel", gs, nil)
	mustOK(t, r, "cancel")
	if !fb.cancelled || !strings.Contains(string(r.Result), "true") {
		t.Fatalf("cancel: %s", r.Result)
	}
	r = e.callFrom(ip, "power.schedule", gs, map[string]any{"action": "reboot", "delay_min": 0, "confirm": "web2"})
	mustOK(t, r, "reboot")
	if len(fb.now) != 0 || len(deferred) != 1 || !strings.Contains(string(r.Result), "boot-1") {
		t.Fatalf("reboot answered after acting: %v %s", fb.now, r.Result)
	}
	deferred[0]()
	if len(fb.now) != 1 || fb.now[0] != "reboot" {
		t.Fatalf("reboot: %v", fb.now)
	}
}
