package jobs

import (
	"fmt"
	"strconv"
	"strings"
)

// Marker is the first line of every managed unit file.
const Marker = "# Managed by Daemonica. Changes here are overwritten when the job is saved in the dashboard."

// QuoteArg quotes one word for a systemd command line (systemd.service
// "Command lines"): double quotes with C escapes for \ and ", "$$" so the
// manager does not substitute variables and "%%" so it does not expand
// specifiers. Control characters are rejected by Normalize; a quoted ";"
// is a literal argument, not a command separator.
func QuoteArg(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		case '$':
			b.WriteString("$$")
		case '%':
			b.WriteString("%%")
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// escapeSpec escapes specifiers in a plain (unquoted) setting value.
func escapeSpec(s string) string { return strings.ReplaceAll(s, "%", "%%") }

// quoteEnv quotes one Environment= assignment (specifiers and C escapes
// apply; variables are not expanded there).
func quoteEnv(e EnvVar) string {
	v := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "%", "%%").Replace(e.Value)
	return `"` + e.Name + "=" + v + `"`
}

// Argv is the command the service runs.
func (j Job) Argv() []string {
	switch j.Mode {
	case ModeExec:
		return append([]string{j.Program}, j.Args...)
	case ModeScript:
		if j.Interpreter == "" {
			return append([]string{j.Script}, j.Args...)
		}
		return append([]string{j.Interpreter, j.Script}, j.Args...)
	case ModeShell:
		return []string{"/bin/sh", "-c", j.Shell}
	}
	return nil
}

// SafeSettings is the "standard secure" hardening preset (without the
// configurable ProtectHome and ReadWritePaths).
var SafeSettings = [][2]string{
	{"NoNewPrivileges", "yes"},
	{"PrivateTmp", "yes"},
	{"PrivateDevices", "yes"},
	{"ProtectSystem", "strict"},
	{"ProtectKernelTunables", "yes"},
	{"ProtectKernelModules", "yes"},
	{"ProtectKernelLogs", "yes"},
	{"ProtectControlGroups", "yes"},
	{"ProtectClock", "yes"},
	{"ProtectHostname", "yes"},
	{"RestrictSUIDSGID", "yes"},
	{"RestrictRealtime", "yes"},
	{"RestrictNamespaces", "yes"},
	{"LockPersonality", "yes"},
}

// ServiceUnit renders the service unit. j must be normalized.
func (j Job) ServiceUnit() string {
	var b strings.Builder
	w := func(k, v string) { fmt.Fprintf(&b, "%s=%s\n", k, v) }
	b.WriteString(Marker + "\n[Unit]\n")
	desc := j.Description
	if desc == "" {
		desc = "Daemonica job " + j.ID
	}
	w("Description", escapeSpec(desc))
	w("Documentation", "https://github.com/PanPakaPancake/daemonica")
	b.WriteString("\n[Service]\n")
	w("Type", "oneshot")
	w("User", j.User)
	argv := j.Argv()
	q := make([]string, len(argv))
	for i, a := range argv {
		q[i] = QuoteArg(a)
	}
	w("ExecStart", strings.Join(q, " "))
	w("TimeoutStartSec", strconv.Itoa(j.TimeoutSec)+"s")
	w("SyslogIdentifier", j.UnitBase())
	if j.WorkDir != "" {
		w("WorkingDirectory", j.WorkDir)
	}
	for _, e := range j.Env {
		w("Environment", quoteEnv(e))
	}
	if j.Hardening == HardenSafe {
		for _, kv := range SafeSettings {
			w(kv[0], kv[1])
		}
		w("ProtectHome", j.ProtectHome)
		if len(j.WritePaths) > 0 {
			w("ReadWritePaths", strings.Join(j.WritePaths, " "))
		}
	}
	if j.MemoryMaxMiB > 0 {
		w("MemoryMax", strconv.Itoa(j.MemoryMaxMiB)+"M")
	}
	if j.CPUQuota > 0 {
		w("CPUQuota", strconv.Itoa(j.CPUQuota)+"%")
	}
	if j.TasksMax > 0 {
		w("TasksMax", strconv.Itoa(j.TasksMax))
	}
	return b.String()
}

// TimerUnit renders the timer unit. j must be normalized.
func (j Job) TimerUnit() string {
	var b strings.Builder
	w := func(k, v string) { fmt.Fprintf(&b, "%s=%s\n", k, v) }
	b.WriteString(Marker + "\n[Unit]\n")
	w("Description", "Timer for "+j.UnitBase())
	b.WriteString("\n[Timer]\n")
	s := j.Schedule
	if s.Kind == KindInterval {
		iv := seconds(s.Interval())
		w("OnActiveSec", iv)
		w("OnUnitActiveSec", iv)
	} else {
		w("OnCalendar", s.OnCalendar())
		if s.Persistent {
			w("Persistent", "yes")
		}
	}
	if s.RandomDelaySec > 0 {
		w("RandomizedDelaySec", strconv.Itoa(s.RandomDelaySec)+"s")
	}
	w("Unit", j.Service())
	b.WriteString("\n[Install]\nWantedBy=timers.target\n")
	return b.String()
}
