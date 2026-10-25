package jobs

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/PanPakaPancake/daemonica/internal/execx"
)

func baseJob() Job {
	return Job{ID: "backup", Mode: ModeExec, Program: "/usr/bin/true", User: "nobody",
		Schedule: Schedule{Kind: KindDaily, Time: "02:30"}, Enabled: true}
}

func TestNormalize(t *testing.T) {
	j, err := baseJob().Normalize()
	if err != nil {
		t.Fatal(err)
	}
	if j.TimeoutSec != DefaultTimeout || j.Hardening != HardenSafe || j.ProtectHome != "read-only" {
		t.Fatalf("defaults: %+v", j)
	}
	bad := map[string]func(*Job){
		"id upper":          func(j *Job) { j.ID = "Backup" },
		"id path":           func(j *Job) { j.ID = "../x" },
		"desc newline":      func(j *Job) { j.Description = "a\nExecStartPre=/bin/rm" },
		"desc backslash":    func(j *Job) { j.Description = `line\` },
		"user":              func(j *Job) { j.User = "root\n" },
		"program relative":  func(j *Job) { j.Program = "true" },
		"program space":     func(j *Job) { j.Program = "/usr/bin/x y" },
		"program percent":   func(j *Job) { j.Program = "/usr/bin/%n" },
		"program dotdot":    func(j *Job) { j.Program = "/usr/../bin/sh" },
		"arg newline":       func(j *Job) { j.Args = []string{"a\nExecStartPost=/bin/rm -rf /"} },
		"arg cr":            func(j *Job) { j.Args = []string{"a\rb"} },
		"arg nul":           func(j *Job) { j.Args = []string{"a\x00b"} },
		"mode":              func(j *Job) { j.Mode = "bash" },
		"interpreter":       func(j *Job) { j.Mode, j.Script, j.Interpreter = ModeScript, "/opt/x.sh", "/tmp/sh" },
		"shell newline":     func(j *Job) { j.Mode, j.Shell = ModeShell, "echo a\nrm -rf /" },
		"env name":          func(j *Job) { j.Env = []EnvVar{{Name: "A B", Value: "1"}} },
		"env dup":           func(j *Job) { j.Env = []EnvVar{{Name: "A", Value: "1"}, {Name: "A", Value: "2"}} },
		"env value newline": func(j *Job) { j.Env = []EnvVar{{Name: "A", Value: "1\n[Service]"}} },
		"workdir":           func(j *Job) { j.WorkDir = "relative" },
		"write path root":   func(j *Job) { j.WritePaths = []string{"/"} },
		"write path space":  func(j *Job) { j.WritePaths = []string{"/a b"} },
		"timeout":           func(j *Job) { j.TimeoutSec = -1 },
		"time":              func(j *Job) { j.Schedule.Time = "24:00" },
		"kind":              func(j *Job) { j.Schedule.Kind = "yearly" },
		"weekday": func(j *Job) {
			j.Schedule = Schedule{Kind: KindWeekly, Time: "01:00", Weekdays: []string{"Mon", "Funday"}}
		},
		"no weekday":       func(j *Job) { j.Schedule = Schedule{Kind: KindWeekly, Time: "01:00"} },
		"day":              func(j *Job) { j.Schedule = Schedule{Kind: KindMonthly, Time: "01:00", Day: 32} },
		"interval unit":    func(j *Job) { j.Schedule = Schedule{Kind: KindInterval, Every: 5, Unit: "s"} },
		"calendar newline": func(j *Job) { j.Schedule = Schedule{Kind: KindCalendar, Calendar: "daily\nExecStart=/bin/sh"} },
		"calendar percent": func(j *Job) { j.Schedule = Schedule{Kind: KindCalendar, Calendar: "%n"} },
		"calendar option":  func(j *Job) { j.Schedule = Schedule{Kind: KindCalendar, Calendar: "--help"} },
		"calendar semi":    func(j *Job) { j.Schedule = Schedule{Kind: KindCalendar, Calendar: "daily; rm"} },
		"timezone":         func(j *Job) { j.Schedule.Timezone = "../../etc/passwd" },
		"protect home":     func(j *Job) { j.ProtectHome = "tmpfs" },
	}
	for name, mut := range bad {
		j := baseJob()
		mut(&j)
		var ve *ErrValidation
		if _, err := j.Normalize(); !errors.As(err, &ve) {
			t.Errorf("%s: want validation error, got %v", name, err)
		}
	}
	w := baseJob()
	w.Schedule = Schedule{Kind: KindWeekly, Time: "01:00", Weekdays: []string{"Fri", "Mon", "Mon"}, Day: 4, Calendar: "x"}
	n, err := w.Normalize()
	if err != nil || !slices.Equal(n.Schedule.Weekdays, []string{"Mon", "Fri"}) || n.Schedule.Day != 0 || n.Schedule.Calendar != "" {
		t.Fatalf("weekly normalize: %+v %v", n.Schedule, err)
	}
}

func TestOnCalendar(t *testing.T) {
	for _, c := range []struct {
		s    Schedule
		want string
	}{
		{Schedule{Kind: KindHourly, Minute: 5}, "*-*-* *:05:00"},
		{Schedule{Kind: KindDaily, Time: "02:30"}, "*-*-* 02:30:00"},
		{Schedule{Kind: KindWeekly, Time: "02:30", Weekdays: []string{"Mon", "Wed"}, Timezone: "Europe/Berlin"}, "Mon,Wed *-*-* 02:30:00 Europe/Berlin"},
		{Schedule{Kind: KindMonthly, Time: "23:59", Day: 1}, "*-*-01 23:59:00"},
		{Schedule{Kind: KindCalendar, Calendar: "Sat *-*-1..7 04:00"}, "Sat *-*-1..7 04:00"},
		{Schedule{Kind: KindInterval, Every: 15, Unit: "min"}, ""},
	} {
		if got := c.s.OnCalendar(); got != c.want {
			t.Errorf("%+v: %q, want %q", c.s, got, c.want)
		}
	}
}

// TestUnitInjection: payloads in arguments, environment and description end
// up as quoted, escaped words; nothing starts a new line or a new setting.
func TestUnitInjection(t *testing.T) {
	j := baseJob()
	j.Description = "nightly 100% backup [Service] ExecStart=/bin/sh"
	j.Args = []string{";", "rm", "-rf", "/", "%n", "$HOME", "${PATH}", `"quoted"`, `back\slash`, "a b", "'single'", "`id`", "$(id)"}
	j.Env = []EnvVar{{Name: "TOKEN", Value: `a"b\c%d$e`}}
	j.WritePaths = []string{"/var/backups", "/srv/data"}
	j, err := j.Normalize()
	if err != nil {
		t.Fatal(err)
	}
	unit := j.ServiceUnit()
	want := `ExecStart="/usr/bin/true" ";" "rm" "-rf" "/" "%%n" "$$HOME" "$${PATH}" "\"quoted\"" "back\\slash" "a b" "'single'" "` + "`id`" + `" "$$(id)"`
	if !strings.Contains(unit, want+"\n") {
		t.Fatalf("ExecStart:\n%s\nwant line %s", unit, want)
	}
	for _, l := range []string{
		"Description=nightly 100%% backup [Service] ExecStart=/bin/sh",
		`Environment="TOKEN=a\"b\\c%%d$e"`,
		"User=nobody", "Type=oneshot", "NoNewPrivileges=yes", "ProtectSystem=strict", "ProtectHome=read-only",
		"ReadWritePaths=/var/backups /srv/data", "TimeoutStartSec=3600s", "SyslogIdentifier=daemonica-job-backup",
	} {
		if !strings.Contains(unit, "\n"+l+"\n") {
			t.Errorf("missing line %q in\n%s", l, unit)
		}
	}
	// Exactly one ExecStart and one [Service] section header.
	if strings.Count(unit, "\nExecStart=") != 1 || strings.Count(unit, "\n[Service]\n") != 1 {
		t.Fatalf("injected lines:\n%s", unit)
	}
	for _, l := range strings.Split(unit, "\n") {
		if strings.HasSuffix(l, `\`) {
			t.Fatalf("line continuation: %q", l)
		}
	}

	j.Hardening = HardenNone
	j, _ = j.Normalize()
	if u := j.ServiceUnit(); strings.Contains(u, "NoNewPrivileges") || strings.Contains(u, "ReadWritePaths") {
		t.Fatalf("hardening none still hardened:\n%s", u)
	}
}

func TestUnitModesAndTimer(t *testing.T) {
	j := baseJob()
	j.Mode, j.Script, j.Interpreter, j.Program = ModeScript, "/opt/backup.sh", "/bin/bash", ""
	j.Args = []string{"--full"}
	j.MemoryMaxMiB, j.CPUQuota, j.TasksMax = 512, 50, 64
	j.WorkDir = "/srv"
	j.Schedule = Schedule{Kind: KindDaily, Time: "02:30", Persistent: true, RandomDelaySec: 600, Timezone: "Europe/Berlin"}
	j, err := j.Normalize()
	if err != nil {
		t.Fatal(err)
	}
	u := j.ServiceUnit()
	for _, l := range []string{`ExecStart="/bin/bash" "/opt/backup.sh" "--full"`, "MemoryMax=512M", "CPUQuota=50%", "TasksMax=64", "WorkingDirectory=/srv"} {
		if !strings.Contains(u, "\n"+l+"\n") {
			t.Errorf("missing %q in\n%s", l, u)
		}
	}
	tu := j.TimerUnit()
	for _, l := range []string{"OnCalendar=*-*-* 02:30:00 Europe/Berlin", "Persistent=yes", "RandomizedDelaySec=600s", "Unit=daemonica-job-backup.service", "WantedBy=timers.target"} {
		if !strings.Contains(tu, "\n"+l+"\n") {
			t.Errorf("missing %q in\n%s", l, tu)
		}
	}
	j.Mode, j.Shell = ModeShell, `tar czf /backup/$(date +%F).tgz /etc && echo "ok"`
	j, _ = j.Normalize()
	if u := j.ServiceUnit(); !strings.Contains(u, `ExecStart="/bin/sh" "-c" "tar czf /backup/$$(date +%%F).tgz /etc && echo \"ok\""`+"\n") {
		t.Fatalf("shell:\n%s", u)
	}
	j.Schedule = Schedule{Kind: KindInterval, Every: 2, Unit: "h"}
	j, _ = j.Normalize()
	if tu := j.TimerUnit(); !strings.Contains(tu, "OnActiveSec=7200s\nOnUnitActiveSec=7200s\n") || strings.Contains(tu, "OnCalendar") {
		t.Fatalf("interval timer:\n%s", tu)
	}
}

func TestParseAnalyze(t *testing.T) {
	utcOut := `  Original form: daily
Normalized form: *-*-* 00:00:00
    Next elapse: Mon 2026-10-26 00:00:00 UTC
       From now: 4h 36min left
   Iteration #2: Tue 2026-10-27 00:00:00 UTC
       From now: 1 day 4h left
`
	p, err := parseAnalyze(utcOut)
	if err != nil || p.Normalized != "*-*-* 00:00:00" || len(p.Next) != 2 || !p.Next[1].Equal(time.Date(2026, 10, 27, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("utc: %+v %v", p, err)
	}
	localOut := `Normalized form: *-*-* 02:30:00
    Next elapse: Mon 2026-10-26 02:30:00 CET
       (in UTC): Mon 2026-10-26 01:30:00 UTC
       From now: 6h left
       Iter. #2: Tue 2026-10-27 02:30:00 CET
       (in UTC): Tue 2026-10-27 01:30:00 UTC
`
	p, err = parseAnalyze(localOut)
	if err != nil || len(p.Next) != 2 || !p.Next[0].Equal(time.Date(2026, 10, 26, 1, 30, 0, 0, time.UTC)) {
		t.Fatalf("local: %+v %v", p, err)
	}
	if p, err := parseAnalyze("Normalized form: 2020-01-01 00:00:00\n    Next elapse: never\n"); err != nil || len(p.Next) != 0 {
		t.Fatalf("never: %+v %v", p, err)
	}
	if _, err := parseAnalyze("garbage"); err == nil {
		t.Fatal("garbage accepted")
	}
}

func TestNextRunsRealSystemd(t *testing.T) {
	if _, err := os.Stat(SystemdAnalyze); err != nil {
		t.Skip("systemd-analyze not installed")
	}
	run := func(ctx context.Context, timeout time.Duration, path string, args ...string) (execx.Result, error) {
		return execx.Run(ctx, timeout, 64<<10, nil, path, args...)
	}
	s, _ := Schedule{Kind: KindWeekly, Time: "02:30", Weekdays: []string{"Mon", "Wed"}, Timezone: "Europe/Berlin"}.Normalize()
	p, err := NextRuns(context.Background(), run, s, 5, time.Now())
	if err != nil || len(p.Next) != 5 {
		t.Fatalf("%+v %v", p, err)
	}
	berlin, err := time.LoadLocation("Europe/Berlin")
	if err == nil {
		for _, n := range p.Next {
			l := n.In(berlin)
			if l.Hour() != 2 || l.Minute() != 30 || (l.Weekday() != time.Monday && l.Weekday() != time.Wednesday) {
				t.Errorf("run %v (%v) does not match", n, l)
			}
		}
	}
	if _, err := NextRuns(context.Background(), run, Schedule{Kind: KindCalendar, Calendar: "Funday 25:00"}, 5, time.Now()); err == nil {
		t.Fatal("bogus calendar accepted")
	}
	iv, _ := NextRuns(context.Background(), run, Schedule{Kind: KindInterval, Every: 15, Unit: "min"}, 3, time.Unix(0, 0))
	if !iv.Approx || len(iv.Next) != 3 || iv.Next[2].Unix() != 45*60 {
		t.Fatalf("interval: %+v", iv)
	}
}

func TestCronExpr(t *testing.T) {
	from := time.Date(2026, 10, 25, 18, 7, 30, 0, time.UTC) // Sunday
	for _, c := range []struct {
		expr string
		want []string
	}{
		{"*/15 * * * *", []string{"18:15", "18:30", "18:45"}},
		{"0 2 * * 1-5", []string{"Mon 02:00", "Tue 02:00", "Wed 02:00"}},
		{"30 4 1,15 * *", []string{"Nov 1 04:30", "Nov 15 04:30", "Dec 1 04:30"}},
		{"0 0 13 * fri", []string{"Fri 00:00", "Fri 00:00", "Fri 00:00"}}, // either field matches
		{"@daily", []string{"Oct 26 00:00", "Oct 27 00:00", "Oct 28 00:00"}},
		{"5 0 * jan,feb sun", []string{"Jan 3 00:05", "Jan 10 00:05", "Jan 17 00:05"}},
		{"0 12 * * 7", []string{"Nov 1 12:00", "Nov 8 12:00", "Nov 15 12:00"}},
	} {
		e, err := ParseCron(c.expr)
		if err != nil {
			t.Fatalf("%s: %v", c.expr, err)
		}
		got := e.Next(from, 3)
		if len(got) != 3 {
			t.Fatalf("%s: %v", c.expr, got)
		}
		for i, g := range got {
			var s string
			switch {
			case strings.HasPrefix(c.want[i], "Mon"), strings.HasPrefix(c.want[i], "Tue"), strings.HasPrefix(c.want[i], "Wed"), strings.HasPrefix(c.want[i], "Fri"):
				s = g.Format("Mon 15:04")
			case strings.Contains(c.want[i], " "):
				s = g.Format("Jan 2 15:04")
			default:
				s = g.Format("15:04")
			}
			if s != c.want[i] {
				t.Errorf("%s #%d: %s (%v), want %s", c.expr, i, s, g, c.want[i])
			}
		}
	}
	thirteenth, _ := ParseCron("0 0 13 * fri")
	runs := thirteenth.Next(from, 6)
	has13 := false
	for _, r := range runs {
		if r.Day() == 13 {
			has13 = true
		}
		if r.Day() != 13 && r.Weekday() != time.Friday {
			t.Errorf("unexpected %v", r)
		}
	}
	if !has13 {
		t.Errorf("13th never matched: %v", runs)
	}
	for _, bad := range []string{"* * * *", "60 * * * *", "* 24 * * *", "* * 0 * *", "* * * 13 *", "* * * * 8", "*/0 * * * *", "5-1 * * * *", "a * * * *", "@sometimes"} {
		if _, err := ParseCron(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if e, _ := ParseCron("@reboot"); !e.Reboot || e.Next(from, 1) != nil {
		t.Fatal("@reboot")
	}
}

func TestCronFiles(t *testing.T) {
	root := t.TempDir()
	CronRoot = root
	defer func() { CronRoot = "/" }()
	mk := func(p, content string, mode os.FileMode) {
		t.Helper()
		_ = os.MkdirAll(filepath.Dir(filepath.Join(root, p)), 0o755)
		if err := os.WriteFile(filepath.Join(root, p), []byte(content), mode); err != nil {
			t.Fatal(err)
		}
	}
	mk("etc/crontab", "SHELL=/bin/sh\n# comment\n17 *\t* * *\troot\tcd / && run-parts --report /etc/cron.hourly\n", 0o644)
	mk("etc/cron.d/e2scrub", "30 3 * * 0 root test -e /run/systemd/system || /usr/lib/x\n", 0o644)
	mk("etc/cron.d/skip.dpkg-old", "* * * * * root /bin/false\n", 0o644)
	mk("etc/cron.daily/logrotate", "#!/bin/sh\n", 0o755)
	mk("etc/cron.daily/README", "", 0o644)
	mk("var/spool/cron/crontabs/alice", "MAILTO=\"\"\n*/5 * * * * /home/alice/bin/poll \\% 50%\n@reboot /home/alice/start\nbogus line\n", 0o600)
	mk(CronDaemon[1:], "", 0o755)
	st := Cron(time.Date(2026, 10, 25, 18, 0, 0, 0, time.UTC))
	if !st.Installed || !slices.Equal(st.Users, []string{"alice"}) {
		t.Fatalf("%+v", st)
	}
	var sources []string
	for _, e := range st.Entries {
		sources = append(sources, e.Source+"|"+e.User+"|"+e.Schedule)
	}
	want := []string{"/etc/crontab|root|17 * * * *", "/etc/cron.d/e2scrub|root|30 3 * * 0", "/etc/cron.daily|root|@daily",
		"user:alice|alice|*/5 * * * *", "user:alice|alice|@reboot", "user:alice|alice|"}
	if !slices.Equal(sources, want) {
		t.Fatalf("entries:\n%v\nwant\n%v", sources, want)
	}
	if e := st.Entries[0]; e.Command != "cd / && run-parts --report /etc/cron.hourly" || len(e.Next) != 5 || e.Editable {
		t.Fatalf("crontab entry %+v", e)
	}
	if e := st.Entries[3]; e.Line != 1 || !e.Editable || e.Command != `/home/alice/bin/poll \% 50%` {
		t.Fatalf("user entry %+v", e)
	}
	if e := st.Entries[5]; e.Error == "" {
		t.Fatalf("bogus line not flagged %+v", e)
	}

	cur, _ := ReadUserCrontab("alice")
	f := CrontabFromBytes("alice", cur, time.Now())
	text, err := ApplyCronEdit(cur, CronEdit{User: "alice", Hash: f.Hash, Line: -1, Schedule: "0  3 * * *", Command: "/usr/bin/date +%F; rm -rf /tmp/x"})
	if err != nil || !strings.HasSuffix(text, "bogus line\n0 3 * * * /usr/bin/date +\\%F; rm -rf /tmp/x\n") {
		t.Fatalf("append: %q %v", text, err)
	}
	text, err = ApplyCronEdit(cur, CronEdit{User: "alice", Hash: f.Hash, Line: 1, Delete: true})
	if err != nil || strings.Contains(text, "poll") || !strings.HasPrefix(text, "MAILTO") {
		t.Fatalf("delete: %q %v", text, err)
	}
	for name, e := range map[string]CronEdit{
		"stale":        {Hash: "x", Line: -1, Schedule: "* * * * *", Command: "a"},
		"comment line": {Hash: f.Hash, Line: 0, Delete: true},
		"out of range": {Hash: f.Hash, Line: 99, Delete: true},
		"newline":      {Hash: f.Hash, Line: -1, Schedule: "* * * * *", Command: "a\n* * * * * rm -rf /"},
		"sched inject": {Hash: f.Hash, Line: -1, Schedule: "* * * * * rm", Command: "a"},
		"empty":        {Hash: f.Hash, Line: -1, Schedule: "* * * * *", Command: "  "},
	} {
		e.User = "alice"
		if _, err := ApplyCronEdit(cur, e); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if got := EscapeCronCommand(`a%b\%c%%`); got != `a\%b\%c\%\%` {
		t.Fatalf("escape: %s", got)
	}
}

func TestParseHistory(t *testing.T) {
	const u = "daemonica-job-backup.service"
	inv1, inv2 := strings.Repeat("a", 32), strings.Repeat("b", 32)
	lines := []string{
		`{"__REALTIME_TIMESTAMP":"1761400000000000","UNIT":"` + u + `","INVOCATION_ID":"` + inv1 + `","MESSAGE_ID":"7d4958e842da4a758f6c1cdc7b36dcc5","MESSAGE":"Starting..."}`,
		`{"__REALTIME_TIMESTAMP":"1761400000500000","_SYSTEMD_UNIT":"` + u + `","_SYSTEMD_INVOCATION_ID":"` + inv1 + `","MESSAGE":"hello \u001b[31mred"}`,
		`{"__REALTIME_TIMESTAMP":"1761400001000000","UNIT":"` + u + `","INVOCATION_ID":"` + inv1 + `","MESSAGE_ID":"7ad2d189f7e94e70a38c781354912448","MESSAGE":"Deactivated successfully."}`,
		`{"__REALTIME_TIMESTAMP":"1761403600000000","UNIT":"` + u + `","INVOCATION_ID":"` + inv2 + `","MESSAGE":"Starting..."}`,
		`{"__REALTIME_TIMESTAMP":"1761403600200000","_SYSTEMD_UNIT":"` + u + `","_SYSTEMD_INVOCATION_ID":"` + inv2 + `","MESSAGE":[102,97,105,108]}`,
		`{"__REALTIME_TIMESTAMP":"1761403601000000","UNIT":"` + u + `","INVOCATION_ID":"` + inv2 + `","MESSAGE_ID":"98e322203f7a4ed290d09fe03c09fe15","EXIT_CODE":"exited","EXIT_STATUS":"3"}`,
		`{"__REALTIME_TIMESTAMP":"1761403601100000","UNIT":"` + u + `","INVOCATION_ID":"` + inv2 + `","MESSAGE_ID":"d9b373ed55a64feb8242e02dbe79a49c","UNIT_RESULT":"exit-code"}`,
		`{"__REALTIME_TIMESTAMP":"1761407200000000","UNIT":"other.service","INVOCATION_ID":"` + strings.Repeat("c", 32) + `","MESSAGE":"x"}`,
		`not json`,
	}
	runs := ParseHistory([]byte(strings.Join(lines, "\n")), u, true)
	if len(runs) != 2 {
		t.Fatalf("%+v", runs)
	}
	r := runs[0]
	if r.Invocation != inv2 || r.Result != "exit-code" || r.ExitCode == nil || *r.ExitCode != 3 || r.DurationMS != 1100 || !slices.Equal(r.Excerpt, []string{"fail"}) {
		t.Fatalf("failed run %+v", r)
	}
	r = runs[1]
	if r.Result != "success" || r.ExitCode == nil || *r.ExitCode != 0 || len(r.Excerpt) != 1 || strings.ContainsRune(r.Excerpt[0], 0x1b) {
		t.Fatalf("ok run %+v", r)
	}
	if runs := ParseHistory([]byte(strings.Join(lines, "\n")), u, false); runs[0].Excerpt != nil {
		t.Fatal("excerpt without permission")
	}
}

func TestTrusted(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to create root-owned files")
	}
	dir := t.TempDir()
	_ = os.Chmod(dir, 0o755)
	f := filepath.Join(dir, "prog")
	_ = os.WriteFile(f, []byte("#!/bin/sh\n"), 0o755)
	if err := Trusted(f, 0); err != nil && !strings.Contains(err.Error(), "/tmp") {
		t.Fatalf("root file: %v", err)
	}
	_ = os.Chmod(f, 0o757)
	if err := Trusted(f, 0); err == nil {
		t.Fatal("world-writable accepted")
	}
	_ = os.Chmod(f, 0o755)
	_ = os.Chown(f, 1234, 1234)
	if err := Trusted(f, 0); err == nil {
		t.Fatal("foreign owner accepted for root job")
	}
	if err := Trusted(f, 1234); err != nil {
		t.Fatalf("own file rejected: %v", err)
	}
	_ = os.Chmod(dir, 0o777)
	if err := Trusted(f, 1234); err == nil {
		t.Fatal("writable parent accepted")
	}
	if err := Trusted("/usr/bin/true", 0); err != nil {
		t.Fatalf("/usr/bin/true: %v", err)
	}
}

type fakeSD struct {
	reloads int
	timers  map[string]bool
	started []string
	stopped []string
	reset   []string
}

func (f *fakeSD) DaemonReload(context.Context) error { f.reloads++; return nil }
func (f *fakeSD) EnableTimer(_ context.Context, t string, on bool) error {
	f.timers[t] = on
	return nil
}
func (f *fakeSD) StartNoWait(_ context.Context, u string) error {
	f.started = append(f.started, u)
	return nil
}
func (f *fakeSD) Stop(_ context.Context, u string) error {
	f.stopped = append(f.stopped, u)
	return nil
}
func (f *fakeSD) ResetFailed(_ context.Context, u string) error {
	f.reset = append(f.reset, u)
	return nil
}

func fakeAnalyze(_ context.Context, _ time.Duration, _ string, args ...string) (execx.Result, error) {
	if strings.Contains(args[len(args)-1], "Funday") {
		return execx.Result{ExitCode: 1}, nil
	}
	return execx.Result{Stdout: []byte("Normalized form: " + args[len(args)-1] + "\n    Next elapse: Mon 2026-10-26 02:30:00 UTC\n")}, nil
}

func newManager(t *testing.T) (*Manager, *fakeSD) {
	sd := &fakeSD{timers: map[string]bool{}}
	m := &Manager{Dir: t.TempDir(), UnitDir: t.TempDir(), Systemd: sd, Run: fakeAnalyze,
		LookupUser: func(n string) (Account, error) {
			switch n {
			case "root":
				return Account{UID: 0}, nil
			case "nobody":
				return Account{UID: 65534}, nil
			}
			return Account{}, errors.New("unknown")
		}}
	if err := m.Init(); err != nil {
		t.Fatal(err)
	}
	return m, sd
}

func TestManagerLifecycle(t *testing.T) {
	m, sd := newManager(t)
	ctx := context.Background()
	j := baseJob()
	if _, err := m.Save(ctx, j, false, "acc"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("update of missing job: %v", err)
	}
	saved, err := m.Save(ctx, j, true, "acc")
	if err != nil {
		t.Fatal(err)
	}
	if saved.CreatedBy != "acc" || saved.Created.IsZero() || !sd.timers[j.Timer()] || sd.reloads != 1 {
		t.Fatalf("save: %+v %+v", saved, sd)
	}
	for _, u := range []string{j.Service(), j.Timer()} {
		fi, err := os.Stat(filepath.Join(m.UnitDir, u))
		if err != nil || fi.Mode().Perm() != 0o644 {
			t.Fatalf("%s: %v %v", u, fi, err)
		}
	}
	if fi, _ := os.Stat(filepath.Join(m.Dir, "backup.json")); fi.Mode().Perm() != 0o600 {
		t.Fatalf("meta mode %v", fi.Mode())
	}
	if m.Drift(saved) {
		t.Fatal("drift right after save")
	}
	if _, err := m.Save(ctx, j, true, "acc"); !errors.Is(err, ErrExists) {
		t.Fatalf("duplicate create: %v", err)
	}
	j.Enabled = false
	j.Args = []string{"x"}
	upd, err := m.Save(ctx, j, false, "other")
	if err != nil || upd.CreatedBy != "acc" || sd.timers[j.Timer()] {
		t.Fatalf("update: %+v %v %+v", upd, err, sd)
	}
	if _, err := m.SetEnabled(ctx, "backup", true); err != nil || !sd.timers[j.Timer()] {
		t.Fatal("enable")
	}
	if l, _ := m.List(); len(l) != 1 || !l[0].Enabled {
		t.Fatalf("list %+v", l)
	}
	if err := m.RunNow(ctx, "backup"); err != nil || !slices.Equal(sd.started, []string{j.Service()}) {
		t.Fatal("run now")
	}
	_ = os.WriteFile(filepath.Join(m.UnitDir, j.Service()), []byte("edited"), 0o644)
	if !m.Drift(upd) {
		t.Fatal("drift not detected")
	}
	if err := m.Delete(ctx, "backup"); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(sd.reset, []string{j.Service(), j.Timer()}) {
		t.Fatalf("reset-failed: %v", sd.reset)
	}
	if _, err := os.Stat(filepath.Join(m.UnitDir, j.Timer())); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("timer left")
	}
	if _, err := m.Load("backup"); !errors.Is(err, ErrNotFound) {
		t.Fatal("meta left")
	}
	// A foreign unit with the same name is never overwritten.
	_ = os.WriteFile(filepath.Join(m.UnitDir, "daemonica-job-foreign.service"), []byte("x"), 0o644)
	f := baseJob()
	f.ID = "foreign"
	if _, err := m.Save(ctx, f, true, "acc"); !errors.Is(err, ErrExists) {
		t.Fatalf("foreign unit: %v", err)
	}
}

func TestManagerCheck(t *testing.T) {
	m, _ := newManager(t)
	ctx := context.Background()
	j := baseJob()
	j.User = "ghost"
	if _, _, _, err := m.Check(ctx, j); err == nil {
		t.Fatal("unknown user accepted")
	}
	j = baseJob()
	j.Program = "/nonexistent/prog"
	if _, _, _, err := m.Check(ctx, j); err == nil {
		t.Fatal("missing program accepted")
	}
	j = baseJob()
	j.Schedule = Schedule{Kind: KindCalendar, Calendar: "Funday 25:00"}
	if _, _, _, err := m.Check(ctx, j); err == nil {
		t.Fatal("bad calendar accepted")
	}
	j = baseJob()
	j.User, j.Mode, j.Shell = "root", ModeShell, "echo hi"
	j.Hardening = HardenNone
	_, p, warn, err := m.Check(ctx, j)
	if err != nil || len(p.Next) != 1 || !slices.Equal(warn, []string{"shell", "root", "no_hardening"}) {
		t.Fatalf("check: %+v %v %v", p, warn, err)
	}
}

func TestSince(t *testing.T) {
	created := time.Date(2026, 10, 25, 20, 58, 0, 0, time.UTC)
	runs := []Run{{Invocation: "new", Start: created.Add(time.Minute)}, {Invocation: "same", Start: created.Add(-500 * time.Millisecond)}, {Invocation: "old", Start: created.Add(-time.Hour)}}
	got := Since(runs, created)
	if len(got) != 2 || got[0].Invocation != "new" || got[1].Invocation != "same" {
		t.Fatalf("since: %+v", got)
	}
	if len(Since(runs, time.Time{})) != 3 {
		t.Fatal("zero time must keep all runs")
	}
}
