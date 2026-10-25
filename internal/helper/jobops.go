package helper

import (
	"context"
	"encoding/json"
	"errors"
	"os/user"
	"strconv"
	"strings"
	"time"

	"github.com/PanPakaPancake/daemonica/internal/jobs"
	"github.com/PanPakaPancake/daemonica/internal/policy"
	"github.com/PanPakaPancake/daemonica/internal/rpc"
	"github.com/PanPakaPancake/daemonica/internal/services"
)

// JobSystemd adapts the systemd D-Bus client to jobs.Systemd.
type JobSystemd struct{ C *services.Client }

// DaemonReload reloads unit files.
func (s JobSystemd) DaemonReload(ctx context.Context) error { return s.C.DaemonReload(ctx) }

// EnableTimer enables and starts, or stops and disables, a timer.
func (s JobSystemd) EnableTimer(ctx context.Context, timer string, on bool) error {
	if on {
		if err := s.C.Do(ctx, timer, services.ActEnable); err != nil {
			return err
		}
		return s.C.Do(ctx, timer, services.ActStart)
	}
	if err := s.C.Do(ctx, timer, services.ActStop); err != nil {
		return err
	}
	return s.C.Do(ctx, timer, services.ActDisable)
}

// StartNoWait queues a start job.
func (s JobSystemd) StartNoWait(ctx context.Context, unit string) error {
	return s.C.StartNoWait(ctx, unit)
}

// Stop stops a unit.
func (s JobSystemd) Stop(ctx context.Context, unit string) error {
	return s.C.Do(ctx, unit, services.ActStop)
}

// ResetFailed clears a unit's failed state.
func (s JobSystemd) ResetFailed(ctx context.Context, unit string) error {
	return s.C.ResetFailed(ctx, unit)
}

// LookupLinuxUser resolves a Linux user for jobs.Manager.
func LookupLinuxUser(name string) (jobs.Account, error) {
	u, err := user.Lookup(name)
	if err != nil {
		return jobs.Account{}, err
	}
	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return jobs.Account{}, err
	}
	return jobs.Account{UID: uint32(uid), Home: u.HomeDir}, nil
}

// JobOps exposes scheduled tasks (SPEC §7.7 M1.6).
type JobOps struct {
	M *jobs.Manager
	// Timers lists all timer units; TimerState reads one.
	Timers     func(ctx context.Context) ([]services.Timer, error)
	TimerState func(ctx context.Context, name string) (services.Timer, error)
	History    func(ctx context.Context, unit string, excerpt bool) ([]jobs.Run, error)
	// Cron, ReadCron and WriteCron default to the jobs package functions.
	Cron      func(now time.Time) jobs.CronStatus
	ReadCron  func(user string) ([]byte, error)
	WriteCron func(ctx context.Context, user, text string) error
	Now       func() time.Time
}

func (o *JobOps) now() time.Time {
	if o.Now != nil {
		return o.Now()
	}
	return time.Now()
}

// JobView is a managed job with its runtime state.
type JobView struct {
	jobs.Job
	State services.Timer `json:"state"`
	Drift bool           `json:"drift,omitempty"`
}

// JobDetail is the jobs.get result.
type JobDetail struct {
	JobView
	ServiceUnit string       `json:"service_unit"`
	TimerUnit   string       `json:"timer_unit"`
	Preview     jobs.Preview `json:"preview"`
	History     []jobs.Run   `json:"history"`
}

// JobsOverview is the jobs.overview result.
type JobsOverview struct {
	Managed []JobView        `json:"managed"`
	Timers  []services.Timer `json:"timers"`
	Cron    jobs.CronStatus  `json:"cron"`
}

// FieldError is a validation finding returned as data: the web layer only
// passes error codes, the wizard needs the field and the reason.
type FieldError struct {
	Field string `json:"field"`
	Code  string `json:"code"`
}

func fieldError(err error) (*FieldError, error) {
	var ve *jobs.ErrValidation
	if errors.As(err, &ve) {
		return &FieldError{Field: ve.Field, Code: ve.Code}, nil
	}
	return nil, err
}

// CalendarResult is the jobs.calendar and cron.preview result.
type CalendarResult struct {
	Preview jobs.Preview `json:"preview"`
	Error   *FieldError  `json:"error,omitempty"`
}

// JobCheck is the jobs.check result.
type JobCheck struct {
	Error       *FieldError  `json:"error,omitempty"`
	Job         jobs.Job     `json:"job"`
	Preview     jobs.Preview `json:"preview"`
	Warnings    []string     `json:"warnings"`
	ServiceUnit string       `json:"service_unit"`
	TimerUnit   string       `json:"timer_unit"`
}

type jobIDParams struct {
	ID string `json:"id"`
}

type jobEnableParams struct {
	ID      string `json:"id"`
	Enabled bool   `json:"enabled"`
}

type jobSaveParams struct {
	Job    jobs.Job `json:"job"`
	Create bool     `json:"create"`
}

type jobCalendarParams struct {
	Schedule jobs.Schedule `json:"schedule"`
}

type cronUserParams struct {
	User string `json:"user"`
}

func jobErr(err error) error {
	var ve *jobs.ErrValidation
	switch {
	case err == nil:
		return nil
	case errors.As(err, &ve):
		return Errf(rpc.CodeValidation, "%s: %s", ve.Field, ve.Msg)
	case errors.Is(err, jobs.ErrNotFound):
		return Errf(rpc.CodeNotFound, "")
	case errors.Is(err, jobs.ErrExists):
		return Errf(rpc.CodeConflict, "a job or unit with this name exists")
	case errors.Is(err, jobs.ErrStale):
		return Errf(rpc.CodeConflict, "stale")
	}
	return err
}

// decideFor checks an extra policy action inside a handler.
func decideFor(s *policy.Subject, a policy.Action) error {
	switch policy.Decide(*s, a, 0, false) {
	case policy.Deny:
		return Errf(rpc.CodeForbidden, "")
	case policy.NeedStepUp:
		return Errf(rpc.CodeStepUpNeeded, "")
	}
	return nil
}

// maskEnv hides environment values from roles that cannot edit jobs: they
// may hold credentials.
func maskEnv(s *policy.Subject, j jobs.Job) jobs.Job {
	if policy.Decide(*s, policy.ActJobsWrite, 0, false) == policy.Allow {
		return j
	}
	env := make([]jobs.EnvVar, len(j.Env))
	for i, e := range j.Env {
		env[i] = jobs.EnvVar{Name: e.Name, Value: "••••"}
	}
	j.Env = env
	return j
}

func (o *JobOps) view(ctx context.Context, s *policy.Subject, j jobs.Job) JobView {
	v := JobView{Job: maskEnv(s, j), Drift: o.M.Drift(j)}
	if o.TimerState != nil {
		v.State, _ = o.TimerState(ctx, j.Timer())
	}
	return v
}

func (o *JobOps) cron(now time.Time) jobs.CronStatus {
	if o.Cron != nil {
		return o.Cron(now)
	}
	return jobs.Cron(now)
}

func (o *JobOps) readCron(u string) ([]byte, error) {
	if o.ReadCron != nil {
		return o.ReadCron(u)
	}
	return jobs.ReadUserCrontab(u)
}

func (o *JobOps) writeCron(ctx context.Context, u, text string) error {
	if o.WriteCron != nil {
		return o.WriteCron(ctx, u, text)
	}
	return jobs.WriteUserCrontab(ctx, u, text)
}

// needsRoot reports whether writing j (or replacing a job that runs as
// root) needs the root rule (Annex A: root jobs admin + step-up).
func (o *JobOps) needsRoot(id, newUser string) bool {
	if newUser == "root" {
		return true
	}
	old, err := o.M.Load(id)
	return err == nil && old.User == "root"
}

func jobTarget(c Call) string {
	var p struct {
		ID  string   `json:"id"`
		Job jobs.Job `json:"job"`
	}
	_ = json.Unmarshal(c.Params, &p)
	if p.ID == "" {
		p.ID = p.Job.ID
	}
	return "job:" + p.ID
}

// Register installs jobs.* and cron.* operations.
func (o *JobOps) Register(ops map[string]*Op) {
	Register(ops, &Op{Name: "jobs.overview", Action: policy.ActJobsRead, NoAudit: true, Timeout: 30 * time.Second,
		Handle: func(ctx context.Context, c Call) (any, error) {
			list, err := o.M.List()
			if err != nil {
				return nil, err
			}
			res := JobsOverview{Managed: []JobView{}, Timers: []services.Timer{}, Cron: o.cron(o.now())}
			for _, j := range list {
				res.Managed = append(res.Managed, o.view(ctx, c.Subject, j))
			}
			if o.Timers != nil {
				if t, err := o.Timers(ctx); err == nil {
					res.Timers = t
				}
			}
			return res, nil
		}})

	Register(ops, &Op{Name: "jobs.get", Action: policy.ActJobsRead, NoAudit: true, Timeout: 30 * time.Second,
		Handle: func(ctx context.Context, c Call) (any, error) {
			var p jobIDParams
			if err := decode(c, &p); err != nil {
				return nil, err
			}
			j, err := o.M.Load(p.ID)
			if err != nil {
				return nil, jobErr(err)
			}
			d := JobDetail{JobView: o.view(ctx, c.Subject, j), TimerUnit: j.TimerUnit(), History: []jobs.Run{}}
			d.ServiceUnit = d.Job.ServiceUnit() // with masked environment values for read-only roles
			d.Preview, _ = jobs.NextRuns(ctx, o.M.Run, j.Schedule, 5, o.now())
			if o.History != nil {
				// The journal excerpt follows the logs rule (read-only sees no logs).
				excerpt := policy.Decide(*c.Subject, policy.ActLogsRead, 0, false) == policy.Allow
				if h, err := o.History(ctx, j.Service(), excerpt); err == nil {
					d.History = h
				}
			}
			return d, nil
		}})

	Register(ops, &Op{Name: "jobs.calendar", Action: policy.ActJobsRead, NoAudit: true, Timeout: 15 * time.Second,
		Handle: func(ctx context.Context, c Call) (any, error) {
			var p jobCalendarParams
			if err := decode(c, &p); err != nil {
				return nil, err
			}
			s, err := p.Schedule.Normalize()
			if err == nil {
				var pv jobs.Preview
				if pv, err = jobs.NextRuns(ctx, o.M.Run, s, 5, o.now()); err == nil {
					return CalendarResult{Preview: pv}, nil
				}
			}
			fe, err := fieldError(err)
			return CalendarResult{Error: fe}, err
		}})

	Register(ops, &Op{Name: "cron.preview", Action: policy.ActJobsRead, NoAudit: true,
		Handle: func(_ context.Context, c Call) (any, error) {
			var p struct {
				Schedule string `json:"schedule"`
			}
			if err := decode(c, &p); err != nil {
				return nil, err
			}
			e, err := jobs.ParseCron(p.Schedule)
			if err != nil || len(p.Schedule) > 200 {
				return CalendarResult{Error: &FieldError{Field: "schedule", Code: jobs.CodeInvalid}}, nil
			}
			pv := jobs.Preview{Normalized: strings.Join(strings.Fields(p.Schedule), " "), Next: e.Next(o.now(), 5)}
			if pv.Next == nil {
				pv.Next = []time.Time{}
			}
			return CalendarResult{Preview: pv}, nil
		}})

	Register(ops, &Op{Name: "jobs.check", Action: policy.ActJobsWrite, NoAudit: true, Timeout: 15 * time.Second,
		Handle: func(ctx context.Context, c Call) (any, error) {
			var p jobSaveParams
			if err := decode(c, &p); err != nil {
				return nil, err
			}
			j, pv, warn, err := o.M.Check(ctx, p.Job)
			if err != nil {
				fe, err := fieldError(err)
				return JobCheck{Error: fe}, err
			}
			if warn == nil {
				warn = []string{}
			}
			return JobCheck{Job: j, Preview: pv, Warnings: warn, ServiceUnit: j.ServiceUnit(), TimerUnit: j.TimerUnit()}, nil
		}})

	Register(ops, &Op{Name: "jobs.save", Action: policy.ActJobsWrite, Timeout: 2 * time.Minute, AuditTarget: jobTarget,
		Handle: func(ctx context.Context, c Call) (any, error) {
			var p jobSaveParams
			if err := decode(c, &p); err != nil {
				return nil, err
			}
			if o.needsRoot(p.Job.ID, p.Job.User) {
				if err := decideFor(c.Subject, policy.ActJobsWriteRoot); err != nil {
					return nil, err
				}
			}
			j, err := o.M.Save(ctx, p.Job, p.Create, c.Subject.AccountID)
			if err != nil {
				return nil, jobErr(err)
			}
			c.AuditKV["user"] = j.User
			c.AuditKV["mode"] = j.Mode
			c.AuditKV["enabled"] = strconv.FormatBool(j.Enabled)
			if p.Create {
				c.AuditKV["created"] = "true"
			}
			return o.view(ctx, c.Subject, j), nil
		}})

	Register(ops, &Op{Name: "jobs.delete", Action: policy.ActJobsWrite, Timeout: 2 * time.Minute, AuditTarget: jobTarget,
		Handle: func(ctx context.Context, c Call) (any, error) {
			var p jobIDParams
			if err := decode(c, &p); err != nil {
				return nil, err
			}
			if o.needsRoot(p.ID, "") {
				if err := decideFor(c.Subject, policy.ActJobsWriteRoot); err != nil {
					return nil, err
				}
			}
			return nil, jobErr(o.M.Delete(ctx, p.ID))
		}})

	Register(ops, &Op{Name: "jobs.run", Action: policy.ActJobsRun, Timeout: 30 * time.Second, AuditTarget: jobTarget,
		Handle: func(ctx context.Context, c Call) (any, error) {
			var p jobIDParams
			if err := decode(c, &p); err != nil {
				return nil, err
			}
			return nil, jobErr(o.M.RunNow(ctx, p.ID))
		}})

	Register(ops, &Op{Name: "jobs.stop", Action: policy.ActJobsRun, Timeout: 90 * time.Second, AuditTarget: jobTarget,
		Handle: func(ctx context.Context, c Call) (any, error) {
			var p jobIDParams
			if err := decode(c, &p); err != nil {
				return nil, err
			}
			return nil, jobErr(o.M.StopRun(ctx, p.ID))
		}})

	Register(ops, &Op{Name: "jobs.enable", Action: policy.ActJobsRun, Timeout: 2 * time.Minute, AuditTarget: jobTarget,
		Handle: func(ctx context.Context, c Call) (any, error) {
			var p jobEnableParams
			if err := decode(c, &p); err != nil {
				return nil, err
			}
			c.AuditKV["enabled"] = strconv.FormatBool(p.Enabled)
			j, err := o.M.SetEnabled(ctx, p.ID, p.Enabled)
			if err != nil {
				return nil, jobErr(err)
			}
			return o.view(ctx, c.Subject, j), nil
		}})

	Register(ops, &Op{Name: "cron.get", Action: policy.ActJobsRead, NoAudit: true,
		Handle: func(_ context.Context, c Call) (any, error) {
			var p cronUserParams
			if err := decode(c, &p); err != nil {
				return nil, err
			}
			if _, err := o.M.LookupUser(p.User); err != nil {
				return nil, Errf(rpc.CodeNotFound, "unknown user")
			}
			b, err := o.readCron(p.User)
			if err != nil {
				return nil, err
			}
			return jobs.CrontabFromBytes(p.User, b, o.now()), nil
		}})

	Register(ops, &Op{Name: "cron.save", Action: policy.ActJobsWrite, Timeout: 30 * time.Second,
		AuditTarget: func(c Call) string {
			var p jobs.CronEdit
			_ = json.Unmarshal(c.Params, &p)
			return "crontab:" + p.User
		},
		Handle: func(ctx context.Context, c Call) (any, error) {
			var p jobs.CronEdit
			if err := decode(c, &p); err != nil {
				return nil, err
			}
			if p.User == "root" {
				if err := decideFor(c.Subject, policy.ActJobsWriteRoot); err != nil {
					return nil, err
				}
			}
			if _, err := o.M.LookupUser(p.User); err != nil {
				return nil, Errf(rpc.CodeNotFound, "unknown user")
			}
			cur, err := o.readCron(p.User)
			if err != nil {
				return nil, err
			}
			text, err := jobs.ApplyCronEdit(cur, p)
			if err != nil {
				return nil, jobErr(err)
			}
			if err := o.writeCron(ctx, p.User, text); err != nil {
				return nil, jobErr(err)
			}
			c.AuditKV["line"] = strconv.Itoa(p.Line)
			c.AuditKV["delete"] = strconv.FormatBool(p.Delete)
			return jobs.CrontabFromBytes(p.User, []byte(text), o.now()), nil
		}})
}
