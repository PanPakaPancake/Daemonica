// Package jobs manages scheduled tasks (SPEC §7.7 M1.6): Daemonica's own jobs
// as systemd service + timer pairs named daemonica-job-<id>, the read-only
// overview of all systemd timers and cron, and edits of user crontabs.
//
// Nothing here runs through a shell: units are rendered from validated
// fields with every value quoted and escaped for systemd's parser, and
// external tools get argv arrays.
package jobs

import (
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/PanPakaPancake/daemonica/internal/validate"
)

// UnitPrefix is the name prefix of managed job units.
const UnitPrefix = "daemonica-job-"

// Modes of the command.
const (
	ModeExec   = "exec"   // program + argument list
	ModeScript = "script" // script path, optionally through an interpreter
	ModeShell  = "shell"  // /bin/sh -c (advanced, with warning)
)

// Schedule kinds.
const (
	KindHourly   = "hourly"
	KindDaily    = "daily"
	KindWeekly   = "weekly"
	KindMonthly  = "monthly"
	KindInterval = "interval"
	KindCalendar = "calendar"
)

// Hardening presets.
const (
	HardenSafe = "safe"
	HardenNone = "none"
)

// Limits.
const (
	MaxArgs        = 64
	MaxArgLen      = 4096
	MaxEnv         = 32
	MaxWritePaths  = 16
	MaxDescription = 200
	DefaultTimeout = 3600
	MaxTimeout     = 7 * 24 * 3600
)

// Interpreters allowed for script mode ("" runs the script directly).
var Interpreters = []string{"", "/bin/sh", "/bin/bash", "/usr/bin/python3", "/usr/bin/perl"}

// Weekdays in systemd's spelling.
var Weekdays = []string{"Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"}

// EnvVar is one environment variable of a job.
type EnvVar struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Schedule is the timer part of a job, as chosen in the schedule builder.
type Schedule struct {
	Kind     string   `json:"kind"`
	Minute   int      `json:"minute,omitempty"`   // hourly: minute of the hour
	Time     string   `json:"time,omitempty"`     // daily/weekly/monthly: HH:MM
	Weekdays []string `json:"weekdays,omitempty"` // weekly
	Day      int      `json:"day,omitempty"`      // monthly: 1-31
	Every    int      `json:"every,omitempty"`    // interval
	Unit     string   `json:"unit,omitempty"`     // interval: "min" or "h"
	Calendar string   `json:"calendar,omitempty"` // calendar: systemd.time expression
	Timezone string   `json:"timezone,omitempty"` // calendar kinds; "" = system time zone
	// Persistent catches up a run missed while the host was down (calendar kinds).
	Persistent     bool `json:"persistent,omitempty"`
	RandomDelaySec int  `json:"random_delay_sec,omitempty"`
}

// Job is a managed job (metadata stored by the helper).
type Job struct {
	ID          string   `json:"id"`
	Description string   `json:"description,omitempty"`
	Mode        string   `json:"mode"`
	Program     string   `json:"program,omitempty"`
	Args        []string `json:"args,omitempty"`
	Script      string   `json:"script,omitempty"`
	Interpreter string   `json:"interpreter,omitempty"`
	Shell       string   `json:"shell,omitempty"`
	User        string   `json:"user"`
	Schedule    Schedule `json:"schedule"`
	TimeoutSec  int      `json:"timeout_sec,omitempty"`
	Env         []EnvVar `json:"env,omitempty"`
	WorkDir     string   `json:"workdir,omitempty"`
	Hardening   string   `json:"hardening"`
	WritePaths  []string `json:"write_paths,omitempty"`
	// ProtectHome: "read-only" (default), "yes" or "no" under the safe preset.
	ProtectHome  string    `json:"protect_home,omitempty"`
	MemoryMaxMiB int       `json:"memory_max_mib,omitempty"`
	CPUQuota     int       `json:"cpu_quota,omitempty"` // percent of one CPU
	TasksMax     int       `json:"tasks_max,omitempty"`
	Enabled      bool      `json:"enabled"`
	Created      time.Time `json:"created,omitzero"`
	Updated      time.Time `json:"updated,omitzero"`
	CreatedBy    string    `json:"created_by,omitempty"`
}

// ErrValidation names the field and a stable reason code (translated by
// the UI) plus an English message for logs and tests.
type ErrValidation struct{ Field, Code, Msg string }

func (e *ErrValidation) Error() string { return e.Field + ": " + e.Msg }

// Reason codes besides the generic "invalid".
const (
	CodeInvalid       = "invalid"
	CodeUnknownUser   = "unknown_user"
	CodeMissing       = "missing"
	CodeNotExecutable = "not_executable"
	CodeUntrusted     = "untrusted"
	CodeRejected      = "rejected" // systemd does not accept the schedule
	CodeNever         = "never"    // the schedule never elapses
)

func invalid(field, format string, a ...any) error {
	return &ErrValidation{Field: field, Code: CodeInvalid, Msg: fmt.Sprintf(format, a...)}
}

func invalidCode(field, code, format string, a ...any) error {
	return &ErrValidation{Field: field, Code: code, Msg: fmt.Sprintf(format, a...)}
}

var (
	envNameRE  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}$`)
	pathRE     = regexp.MustCompile(`^/[A-Za-z0-9._/@+-]*$`)
	timeRE     = regexp.MustCompile(`^([01][0-9]|2[0-3]):[0-5][0-9]$`)
	calendarRE = regexp.MustCompile(`^[A-Za-z0-9*:,./~ +-]{1,200}$`)
	tzRE       = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_+-]*(/[A-Za-z0-9_+-]+){0,2}$`)
)

// UnitBase is "daemonica-job-<id>".
func (j Job) UnitBase() string { return UnitPrefix + j.ID }

// Service and Timer are the unit names.
func (j Job) Service() string { return j.UnitBase() + ".service" }

// Timer is the timer unit name.
func (j Job) Timer() string { return j.UnitBase() + ".timer" }

// IDFromUnit returns the job id of a managed unit name, or "".
func IDFromUnit(name string) string {
	base, ok := strings.CutPrefix(name, UnitPrefix)
	if !ok {
		return ""
	}
	base = strings.TrimSuffix(strings.TrimSuffix(base, ".service"), ".timer")
	if validate.JobName(base) != nil {
		return ""
	}
	return base
}

// CleanPath validates an absolute path that goes into a unit file unquoted.
func CleanPath(p string) bool {
	return len(p) <= 4096 && pathRE.MatchString(p) && filepath.Clean(p) == p && !strings.Contains(p, "/../")
}

// Normalize validates j and fills defaults. It checks syntax only; the host
// checks (user exists, program trusted, calendar accepted) are in Manager.
func (j Job) Normalize() (Job, error) {
	if validate.JobName(j.ID) != nil {
		return j, invalid("id", "lower-case letters, digits and '-', at most 48 characters")
	}
	if validate.NoControl(j.Description, MaxDescription) != nil || strings.Contains(j.Description, `\`) {
		return j, invalid("description", "no control characters or backslashes, at most %d characters", MaxDescription)
	}
	j.Description = strings.TrimSpace(j.Description)
	if validate.LinuxUser(j.User) != nil {
		return j, invalid("user", "invalid user name")
	}
	switch j.Mode {
	case ModeExec:
		if !CleanPath(j.Program) {
			return j, invalid("program", "absolute path without spaces or special characters")
		}
		j.Script, j.Interpreter, j.Shell = "", "", ""
	case ModeScript:
		if !CleanPath(j.Script) {
			return j, invalid("script", "absolute path without spaces or special characters")
		}
		if !slices.Contains(Interpreters, j.Interpreter) {
			return j, invalid("interpreter", "not allowed")
		}
		j.Program, j.Shell = "", ""
	case ModeShell:
		if strings.TrimSpace(j.Shell) == "" || validate.NoControl(j.Shell, MaxArgLen) != nil {
			return j, invalid("shell", "one line without control characters")
		}
		j.Program, j.Script, j.Interpreter, j.Args = "", "", "", nil
	default:
		return j, invalid("mode", "unknown mode")
	}
	if len(j.Args) > MaxArgs {
		return j, invalid("args", "at most %d arguments", MaxArgs)
	}
	for _, a := range j.Args {
		if validate.NoControl(a, MaxArgLen) != nil {
			return j, invalid("args", "arguments must not contain control characters or line breaks")
		}
	}
	if j.TimeoutSec == 0 {
		j.TimeoutSec = DefaultTimeout
	}
	if j.TimeoutSec < 1 || j.TimeoutSec > MaxTimeout {
		return j, invalid("timeout_sec", "1 s to 7 days")
	}
	if len(j.Env) > MaxEnv {
		return j, invalid("env", "at most %d variables", MaxEnv)
	}
	seen := map[string]bool{}
	for _, e := range j.Env {
		if !envNameRE.MatchString(e.Name) || seen[e.Name] {
			return j, invalid("env", "invalid or duplicate variable name %q", e.Name)
		}
		seen[e.Name] = true
		if validate.NoControl(e.Value, MaxArgLen) != nil {
			return j, invalid("env", "values must not contain control characters")
		}
	}
	if j.WorkDir != "" && !CleanPath(j.WorkDir) {
		return j, invalid("workdir", "absolute path without spaces or special characters")
	}
	switch j.Hardening {
	case "":
		j.Hardening = HardenSafe
	case HardenSafe, HardenNone:
	default:
		return j, invalid("hardening", "unknown preset")
	}
	if j.Hardening == HardenSafe {
		switch j.ProtectHome {
		case "":
			j.ProtectHome = "read-only"
		case "read-only", "yes", "no":
		default:
			return j, invalid("protect_home", "read-only, yes or no")
		}
	} else {
		j.ProtectHome, j.WritePaths = "", nil
	}
	if len(j.WritePaths) > MaxWritePaths {
		return j, invalid("write_paths", "at most %d paths", MaxWritePaths)
	}
	for _, p := range j.WritePaths {
		if !CleanPath(p) || p == "/" {
			return j, invalid("write_paths", "absolute paths without spaces or special characters")
		}
	}
	if j.MemoryMaxMiB < 0 || j.MemoryMaxMiB > 1<<20 || j.CPUQuota < 0 || j.CPUQuota > 10000 || j.TasksMax < 0 || j.TasksMax > 1<<20 {
		return j, invalid("limits", "out of range")
	}
	s, err := j.Schedule.Normalize()
	if err != nil {
		return j, err
	}
	j.Schedule = s
	return j, nil
}

// Normalize validates the schedule.
func (s Schedule) Normalize() (Schedule, error) {
	if s.RandomDelaySec < 0 || s.RandomDelaySec > 24*3600 {
		return s, invalid("random_delay_sec", "0 to 24 h")
	}
	if s.Timezone != "" && (!tzRE.MatchString(s.Timezone) || len(s.Timezone) > 64) {
		return s, invalid("timezone", "invalid time zone")
	}
	needTime := func() error {
		if !timeRE.MatchString(s.Time) {
			return invalid("time", "HH:MM")
		}
		return nil
	}
	clear := func(keep ...string) {
		k := func(f string) bool { return slices.Contains(keep, f) }
		if !k("minute") {
			s.Minute = 0
		}
		if !k("time") {
			s.Time = ""
		}
		if !k("weekdays") {
			s.Weekdays = nil
		}
		if !k("day") {
			s.Day = 0
		}
		if !k("every") {
			s.Every, s.Unit = 0, ""
		}
		if !k("calendar") {
			s.Calendar = ""
		}
	}
	switch s.Kind {
	case KindHourly:
		if s.Minute < 0 || s.Minute > 59 {
			return s, invalid("minute", "0-59")
		}
		clear("minute")
	case KindDaily:
		if err := needTime(); err != nil {
			return s, err
		}
		clear("time")
	case KindWeekly:
		if err := needTime(); err != nil {
			return s, err
		}
		if len(s.Weekdays) == 0 {
			return s, invalid("weekdays", "choose at least one day")
		}
		var days []string
		for _, d := range Weekdays {
			if slices.Contains(s.Weekdays, d) {
				days = append(days, d)
			}
		}
		if len(days) != len(slices.Compact(slices.Sorted(slices.Values(s.Weekdays)))) {
			return s, invalid("weekdays", "unknown day")
		}
		s.Weekdays = days
		clear("time", "weekdays")
	case KindMonthly:
		if err := needTime(); err != nil {
			return s, err
		}
		if s.Day < 1 || s.Day > 31 {
			return s, invalid("day", "1-31")
		}
		clear("time", "day")
	case KindInterval:
		switch s.Unit {
		case "min":
			if s.Every < 1 || s.Every > 7*24*60 {
				return s, invalid("every", "1 min to 7 days")
			}
		case "h":
			if s.Every < 1 || s.Every > 7*24 {
				return s, invalid("every", "1 h to 7 days")
			}
		default:
			return s, invalid("unit", "min or h")
		}
		s.Timezone, s.Persistent = "", false
		clear("every")
	case KindCalendar:
		c := strings.Join(strings.Fields(s.Calendar), " ")
		if !calendarRE.MatchString(c) || strings.HasPrefix(c, "-") {
			return s, invalid("calendar", "letters, digits, spaces and * : , . / ~ + - only")
		}
		s.Calendar = c
		clear("calendar")
	default:
		return s, invalid("kind", "unknown schedule")
	}
	return s, nil
}

// OnCalendar returns the calendar expression ("" for interval schedules).
func (s Schedule) OnCalendar() string {
	var e string
	switch s.Kind {
	case KindHourly:
		e = fmt.Sprintf("*-*-* *:%02d:00", s.Minute)
	case KindDaily:
		e = "*-*-* " + s.Time + ":00"
	case KindWeekly:
		e = strings.Join(s.Weekdays, ",") + " *-*-* " + s.Time + ":00"
	case KindMonthly:
		e = fmt.Sprintf("*-*-%02d %s:00", s.Day, s.Time)
	case KindCalendar:
		e = s.Calendar
	default:
		return ""
	}
	if s.Timezone != "" {
		e += " " + s.Timezone
	}
	return e
}

// Interval returns the interval of an interval schedule.
func (s Schedule) Interval() time.Duration {
	if s.Kind != KindInterval {
		return 0
	}
	if s.Unit == "h" {
		return time.Duration(s.Every) * time.Hour
	}
	return time.Duration(s.Every) * time.Minute
}

func seconds(d time.Duration) string { return strconv.FormatInt(int64(d/time.Second), 10) + "s" }

// ErrNotFound is returned for unknown jobs.
var ErrNotFound = errors.New("job not found")

// ErrExists is returned when creating a job whose id is taken.
var ErrExists = errors.New("job exists")
