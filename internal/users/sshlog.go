package users

import (
	"context"
	"regexp"
	"sort"
	"time"
)

// LogLine is one journal entry of the SSH daemon (adapted by the caller, so
// this package does not depend on the journal reader).
type LogLine struct {
	Time    time.Time
	PID     int
	Message string
}

var (
	acceptedRE     = regexp.MustCompile(`^Accepted (\S+) for (\S+) from (\S+) port \d+`)
	disconnectedRE = regexp.MustCompile(`^Disconnected from user (\S+) `)
)

// SSHLogins rebuilds SSH sessions from sshd's journal lines, newest first:
// "Accepted <method> for <user> from <addr> port <n>" starts a session, the
// same process's "Disconnected from user <user> …" ends it. A session whose
// process is gone without a disconnect line counts as ended at its start
// (end time unknown). alive reports whether a PID still runs.
//
// Fallback for hosts where neither wtmpdb nor lastlog2 records logins (e.g.
// Ubuntu 26.04 without pam_wtmpdb): sshd always logs to the journal.
func SSHLogins(lines []LogLine, alive func(pid int) bool) []Login {
	open := map[int]int{} // PID → index in out
	out := []Login{}
	sorted := append([]LogLine(nil), lines...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Time.Before(sorted[j].Time) })
	for _, l := range sorted {
		if m := acceptedRE.FindStringSubmatch(l.Message); m != nil {
			out = append(out, Login{User: m[2], From: m[3], TTY: "ssh", Service: "sshd (" + m[1] + ")", Time: l.Time.UTC()})
			if l.PID > 0 {
				open[l.PID] = len(out) - 1
			}
			continue
		}
		if m := disconnectedRE.FindStringSubmatch(l.Message); m != nil {
			if i, ok := open[l.PID]; ok && out[i].User == m[1] {
				out[i].End = l.Time.UTC()
				delete(open, l.PID)
			}
		}
	}
	for pid, i := range open {
		if alive == nil || !alive(pid) {
			out[i].End = out[i].Time
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Time.After(out[j].Time) })
	return out
}

// journalLogins reads the SSH sessions from the journal, if a reader is set.
func (l LoginDB) journalLogins(ctx context.Context) []Login {
	if l.Journal == nil {
		return nil
	}
	lines, err := l.Journal(ctx)
	if err != nil {
		return nil
	}
	return SSHLogins(lines, l.Alive)
}
