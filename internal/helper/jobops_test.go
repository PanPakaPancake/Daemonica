package helper

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/PanPakaPancake/daemonica/internal/execx"
	"github.com/PanPakaPancake/daemonica/internal/jobs"
	"github.com/PanPakaPancake/daemonica/internal/policy"
	"github.com/PanPakaPancake/daemonica/internal/rpc"
	"github.com/PanPakaPancake/daemonica/internal/services"
)

type jobSD struct{ started []string }

func (*jobSD) DaemonReload(context.Context) error              { return nil }
func (*jobSD) EnableTimer(context.Context, string, bool) error { return nil }
func (f *jobSD) StartNoWait(_ context.Context, u string) error {
	f.started = append(f.started, u)
	return nil
}
func (*jobSD) Stop(context.Context, string) error { return nil }

func TestJobOpsRoles(t *testing.T) {
	e := newAuthEnv(t)
	g, sa, _ := setupAdmin(t, e)
	sd := &jobSD{}
	m := &jobs.Manager{Dir: t.TempDir(), UnitDir: t.TempDir(), Systemd: sd,
		Run: func(_ context.Context, _ time.Duration, _ string, args ...string) (execx.Result, error) {
			return execx.Result{Stdout: []byte("Normalized form: " + args[len(args)-1] + "\n    Next elapse: Mon 2026-10-26 02:30:00 UTC\n")}, nil
		},
		LookupUser: func(n string) (jobs.Account, error) {
			switch n {
			case "root":
				return jobs.Account{UID: 0}, nil
			case "nobody", "alice":
				return jobs.Account{UID: 65534}, nil
			}
			return jobs.Account{}, errors.New("unknown")
		}}
	if err := m.Init(); err != nil {
		t.Fatal(err)
	}
	var excerpts []bool
	crontab := []byte("*/5 * * * * /bin/true\n")
	written := map[string]string{}
	ops := &JobOps{M: m,
		TimerState: func(_ context.Context, name string) (services.Timer, error) {
			return services.Timer{Name: name, Active: "active"}, nil
		},
		Timers: func(context.Context) ([]services.Timer, error) {
			return []services.Timer{{Name: "apt-daily.timer"}}, nil
		},
		History: func(_ context.Context, _ string, excerpt bool) ([]jobs.Run, error) {
			excerpts = append(excerpts, excerpt)
			return []jobs.Run{{Invocation: "x", Result: "success"}}, nil
		},
		Cron:      func(time.Time) jobs.CronStatus { return jobs.CronStatus{Installed: true} },
		ReadCron:  func(string) ([]byte, error) { return crontab, nil },
		WriteCron: func(_ context.Context, u, text string) error { written[u] = text; return nil },
	}
	ops.Register(e.web.Ops)
	const ip = "198.51.100.7"
	job := map[string]any{"id": "backup", "mode": "exec", "program": "/usr/bin/true", "args": []string{";", "%n"}, "user": "nobody",
		"schedule": map[string]any{"kind": "daily", "time": "02:30"}, "env": []map[string]string{{"name": "TOKEN", "value": "secret"}}, "enabled": true}

	// Admin without step-up: non-root jobs are fine, root jobs need step-up.
	r := e.callFrom(ip, "jobs.check", g, map[string]any{"job": job})
	mustOK(t, r, "check")
	var chk JobCheck
	_ = json.Unmarshal(r.Result, &chk)
	if len(chk.Preview.Next) != 1 || !strings.Contains(chk.ServiceUnit, `"%%n"`) {
		t.Fatalf("check: %+v", chk)
	}
	mustOK(t, e.callFrom(ip, "jobs.save", g, map[string]any{"job": job, "create": true}), "save")
	if c := code(e.callFrom(ip, "jobs.save", g, map[string]any{"job": job, "create": true})); c != rpc.CodeConflict {
		t.Fatalf("duplicate: %s", c)
	}
	rootJob := map[string]any{}
	for k, v := range job {
		rootJob[k] = v
	}
	rootJob["id"], rootJob["user"] = "rootjob", "root"
	if c := code(e.callFrom(ip, "jobs.save", g, map[string]any{"job": rootJob, "create": true})); c != rpc.CodeStepUpNeeded {
		t.Fatalf("root job without step-up: %s", c)
	}
	gs := stepUp(t, e, sa, g)
	// stepUp rotates g; a second admin session without step-up:
	g, _ = e.web.Grants.Issue(policy.Subject{AccountID: "adm2", Role: policy.RoleAdmin, LinuxUser: "dave", LinuxUID: 1003}, time.Now())
	mustOK(t, e.callFrom(ip, "jobs.save", gs, map[string]any{"job": rootJob, "create": true}), "save root")

	// Read-only: sees jobs with masked environment, no journal excerpt, no actions.
	ro, _ := e.web.Grants.Issue(policy.Subject{AccountID: "ro", Role: policy.RoleReadOnly, LinuxUser: "carol", LinuxUID: 1002}, time.Now())
	r = e.callFrom(ip, "jobs.overview", ro, nil)
	mustOK(t, r, "overview")
	var ov JobsOverview
	_ = json.Unmarshal(r.Result, &ov)
	if len(ov.Managed) != 2 || ov.Managed[0].Env[0].Value == "secret" || len(ov.Timers) != 1 || !ov.Cron.Installed || ov.Managed[0].State.Active != "active" {
		t.Fatalf("overview: %+v", ov)
	}
	r = e.callFrom(ip, "jobs.get", ro, map[string]any{"id": "backup"})
	mustOK(t, r, "get ro")
	var d JobDetail
	_ = json.Unmarshal(r.Result, &d)
	if strings.Contains(d.ServiceUnit, "secret") || len(d.History) != 1 || excerpts[len(excerpts)-1] {
		t.Fatalf("read-only detail leaks: %+v", d)
	}
	r = e.callFrom(ip, "jobs.get", g, map[string]any{"id": "backup"})
	_ = json.Unmarshal(r.Result, &d)
	if !strings.Contains(d.ServiceUnit, "secret") || !excerpts[len(excerpts)-1] {
		t.Fatalf("admin detail: %+v", d)
	}
	for _, o := range []string{"jobs.run", "jobs.enable", "jobs.save", "jobs.delete", "jobs.check", "cron.save"} {
		if c := code(e.callFrom(ip, o, ro, map[string]any{"id": "backup"})); c != rpc.CodeForbidden {
			t.Fatalf("read-only %s: %s", o, c)
		}
	}

	// Operator: run and enable/disable, nothing else.
	op, _ := e.web.Grants.Issue(policy.Subject{AccountID: "op", Role: policy.RoleOperator, LinuxUser: "bob", LinuxUID: 1001, StepUp: true}, time.Now())
	mustOK(t, e.callFrom(ip, "jobs.run", op, map[string]any{"id": "rootjob"}), "operator run")
	if len(sd.started) != 1 || sd.started[0] != "daemonica-job-rootjob.service" {
		t.Fatalf("started: %v", sd.started)
	}
	mustOK(t, e.callFrom(ip, "jobs.enable", op, map[string]any{"id": "backup", "enabled": false}), "operator disable")
	for _, o := range []string{"jobs.save", "jobs.delete", "jobs.check", "cron.save"} {
		if c := code(e.callFrom(ip, o, op, map[string]any{"id": "backup"})); c != rpc.CodeForbidden {
			t.Fatalf("operator %s: %s", o, c)
		}
	}
	if c := code(e.callFrom(ip, "jobs.run", op, map[string]any{"id": "../etc"})); c != rpc.CodeNotFound {
		t.Fatalf("run bad id: %s", c)
	}

	// Deleting a root job needs step-up as well.
	if c := code(e.callFrom(ip, "jobs.delete", g, map[string]any{"id": "rootjob"})); c != rpc.CodeStepUpNeeded {
		t.Fatalf("delete root job: %s", c)
	}
	mustOK(t, e.callFrom(ip, "jobs.delete", g, map[string]any{"id": "backup"}), "delete")

	// Cron edits: hash-checked, % escaped, root crontab needs step-up.
	r = e.callFrom(ip, "cron.get", g, map[string]any{"user": "alice"})
	mustOK(t, r, "cron.get")
	var cf jobs.CronFile
	_ = json.Unmarshal(r.Result, &cf)
	if len(cf.Entries) != 1 || !cf.Entries[0].Editable {
		t.Fatalf("cron file: %+v", cf)
	}
	edit := map[string]any{"user": "alice", "hash": cf.Hash, "line": -1, "schedule": "0 3 * * *", "command": "date +%F"}
	mustOK(t, e.callFrom(ip, "cron.save", g, edit), "cron.save")
	if written["alice"] != "*/5 * * * * /bin/true\n0 3 * * * date +\\%F\n" {
		t.Fatalf("written: %q", written["alice"])
	}
	edit["hash"] = "stale"
	if c := code(e.callFrom(ip, "cron.save", g, edit)); c != rpc.CodeConflict {
		t.Fatalf("stale: %s", c)
	}
	edit["user"], edit["hash"] = "root", cf.Hash
	if c := code(e.callFrom(ip, "cron.save", g, edit)); c != rpc.CodeStepUpNeeded {
		t.Fatalf("root crontab: %s", c)
	}
	edit["user"] = "ghost"
	if c := code(e.callFrom(ip, "cron.save", gs, edit)); c != rpc.CodeNotFound {
		t.Fatalf("unknown user: %s", c)
	}
}
