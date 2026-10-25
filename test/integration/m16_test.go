//go:build integration

package integration

import (
	"context"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/PanPakaPancake/daemonica/internal/helper"
	"github.com/PanPakaPancake/daemonica/internal/jobs"
	"github.com/PanPakaPancake/daemonica/internal/netcfg"
	"github.com/PanPakaPancake/daemonica/internal/services"
)

// TestJobsOnHost is the M1.6 acceptance on a real systemd: a managed job
// whose arguments are injection payloads runs from its timer, receives
// exactly those arguments, shows up in the history with exit code and
// output, carries the hardening in `systemctl show`, and is removed again.
func TestJobsOnHost(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		t.Skip("needs systemd")
	}
	sd, err := services.Connect()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sd.Close() }()
	m := &jobs.Manager{Dir: t.TempDir(), UnitDir: "/etc/systemd/system", Systemd: helper.JobSystemd{C: sd},
		Run: netcfg.ExecRunner, LookupUser: helper.LookupLinuxUser}
	ctx := context.Background()
	payload := []string{";", "rm -rf /tmp/dmn-it16", "%n", "$HOME", "${PATH}", `"q"`, `back\slash`, "a b", "$(id)", "`id`"}
	j := jobs.Job{ID: "ittest", Description: "Daemonica integration test 100%", Mode: jobs.ModeExec, Program: "/usr/bin/printf",
		Args: append([]string{`[%s]\n`}, payload...), User: "nobody",
		Schedule: jobs.Schedule{Kind: jobs.KindCalendar, Calendar: "*:*:0/15"}, WritePaths: []string{"/var/tmp"}, MemoryMaxMiB: 64, TasksMax: 8, Enabled: true}
	_ = m.Delete(ctx, "ittest")
	t.Cleanup(func() { _ = m.Delete(context.Background(), "ittest") })
	if _, err := m.Save(ctx, j, true, "it"); err != nil {
		t.Fatalf("save: %v", err)
	}
	ts, err := sd.TimerState(ctx, j.Timer())
	if err != nil || ts.Active != "active" || ts.FileState != "enabled" || ts.Next.IsZero() {
		t.Fatalf("timer state: %+v %v", ts, err)
	}

	// The timer starts the job (AccuracySec defaults to 1 min).
	var runs []jobs.Run
	deadline := time.Now().Add(150 * time.Second)
	for time.Now().Before(deadline) {
		runs, _ = jobs.History(ctx, j.Service(), true)
		if len(runs) > 0 && runs[0].Result != "running" {
			break
		}
		time.Sleep(3 * time.Second)
	}
	if len(runs) == 0 {
		t.Fatal("the timer did not start the job")
	}
	r := runs[0]
	t.Logf("run: %+v", r)
	want := make([]string, len(payload))
	for i, p := range payload {
		want[i] = "[" + p + "]"
	}
	if r.Result != "success" || r.ExitCode == nil || *r.ExitCode != 0 || !slices.Equal(r.Excerpt, want) {
		t.Fatalf("run %+v\nwant output %q", r, want)
	}
	if _, err := os.Stat("/tmp/dmn-it16"); err == nil {
		t.Fatal("payload had an effect")
	}

	props, _ := exec.Command("systemctl", "show", j.Service(), "-p",
		"User,NoNewPrivileges,ProtectSystem,ProtectHome,PrivateTmp,PrivateDevices,RestrictSUIDSGID,ReadWritePaths,MemoryMax,TasksMax,Type").Output()
	t.Logf("unit properties:\n%s", props)
	for _, w := range []string{"User=nobody", "NoNewPrivileges=yes", "ProtectSystem=strict", "ProtectHome=read-only", "PrivateTmp=yes",
		"PrivateDevices=yes", "RestrictSUIDSGID=yes", "ReadWritePaths=/var/tmp", "MemoryMax=67108864", "TasksMax=8", "Type=oneshot"} {
		if !strings.Contains(string(props)+"\n", w+"\n") {
			t.Errorf("unit lacks %s", w)
		}
	}

	// Run now and a failing run: the history shows the exit code.
	j.Program = "/usr/bin/false"
	j.Args = nil
	j.Enabled = false
	if _, err := m.Save(ctx, j, false, "it"); err != nil {
		t.Fatal(err)
	}
	if ts, _ := sd.TimerState(ctx, j.Timer()); ts.Active == "active" {
		t.Fatalf("timer still active after disabling: %+v", ts)
	}
	if err := m.RunNow(ctx, "ittest"); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		runs, _ = jobs.History(ctx, j.Service(), true)
		if len(runs) > 1 && runs[0].Result != "running" {
			break
		}
		time.Sleep(time.Second)
	}
	if len(runs) < 2 || runs[0].Result != "exit-code" || runs[0].ExitCode == nil || *runs[0].ExitCode != 1 {
		t.Fatalf("failed run: %+v", runs)
	}

	if err := m.Delete(ctx, "ittest"); err != nil {
		t.Fatal(err)
	}
	for _, u := range []string{j.Service(), j.Timer()} {
		if _, err := os.Stat("/etc/systemd/system/" + u); err == nil {
			t.Errorf("%s left behind", u)
		}
	}
}

// TestCrontabOnHost edits a user crontab through crontab(1).
func TestCrontabOnHost(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	if _, err := os.Stat(jobs.CrontabBin); err != nil {
		t.Skip("cron not installed")
	}
	const u = "nobody"
	old, _ := jobs.ReadUserCrontab(u)
	t.Cleanup(func() { _ = jobs.WriteUserCrontab(context.Background(), u, string(old)) })
	ctx := context.Background()
	cur, _ := jobs.ReadUserCrontab(u)
	f := jobs.CrontabFromBytes(u, cur, time.Now())
	text, err := jobs.ApplyCronEdit(cur, jobs.CronEdit{User: u, Hash: f.Hash, Line: -1, Schedule: "17 3 * * *", Command: "/usr/bin/date +%F"})
	if err != nil {
		t.Fatal(err)
	}
	if err := jobs.WriteUserCrontab(ctx, u, text); err != nil {
		t.Fatal(err)
	}
	b, _ := jobs.ReadUserCrontab(u)
	if !strings.Contains(string(b), `17 3 * * * /usr/bin/date +\%F`) {
		t.Fatalf("crontab: %q", b)
	}
	st := jobs.Cron(time.Now())
	found := false
	for _, e := range st.Entries {
		if e.Source == "user:"+u && e.Schedule == "17 3 * * *" && len(e.Next) == 5 {
			found = true
		}
	}
	if !found {
		t.Fatalf("entry not in overview: %+v", st.Entries)
	}
	// crontab(1) rejects what our parser would let through by mistake.
	if err := jobs.WriteUserCrontab(ctx, u, "61 * * * * /bin/true\n"); err == nil {
		t.Fatal("crontab accepted an invalid line")
	}
}
