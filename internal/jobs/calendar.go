package jobs

import (
	"context"
	"errors"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/PanPakaPancake/daemonica/internal/execx"
)

// SystemdAnalyze is the binary path.
var SystemdAnalyze = "/usr/bin/systemd-analyze"

// Runner runs a program (argv only).
type Runner func(ctx context.Context, timeout time.Duration, path string, args ...string) (execx.Result, error)

// Preview is the next runs of a schedule.
type Preview struct {
	Normalized string      `json:"normalized,omitempty"`
	Next       []time.Time `json:"next"`
	// Approx marks interval schedules: the runs count from the timer's start.
	Approx bool `json:"approx,omitempty"`
}

var (
	normRE = regexp.MustCompile(`^\s*Normalized form:\s*(.+)$`)
	iterRE = regexp.MustCompile(`^\s*(Next elapse|Iter(?:ation|\.) #\d+):\s*(.+)$`)
	utcRE  = regexp.MustCompile(`^\s*\(in UTC\):\s*(.+)$`)
)

// parseAnalyze reads `systemd-analyze calendar --iterations=N` output. With
// a non-UTC system time zone every elapse line is followed by an "(in UTC)"
// line; those are used then, otherwise the elapse lines are UTC already.
func parseAnalyze(out string) (Preview, error) {
	var p Preview
	var local, utc []string
	for _, l := range strings.Split(out, "\n") {
		if m := normRE.FindStringSubmatch(l); m != nil {
			p.Normalized = strings.TrimSpace(m[1])
		} else if m := iterRE.FindStringSubmatch(l); m != nil {
			local = append(local, strings.TrimSpace(m[2]))
		} else if m := utcRE.FindStringSubmatch(l); m != nil {
			utc = append(utc, strings.TrimSpace(m[1]))
		}
	}
	src := local
	if len(utc) > 0 {
		src = utc
	}
	for _, s := range src {
		if s == "never" {
			continue
		}
		t, err := time.Parse("Mon 2006-01-02 15:04:05 MST", s)
		if err != nil || !strings.HasSuffix(s, " UTC") {
			return p, errors.New("unexpected systemd-analyze output")
		}
		p.Next = append(p.Next, t.UTC())
	}
	if p.Normalized == "" {
		return p, errors.New("unexpected systemd-analyze output")
	}
	return p, nil
}

// NextRuns validates the schedule with systemd and returns its next n runs.
func NextRuns(ctx context.Context, run Runner, s Schedule, n int, now time.Time) (Preview, error) {
	if s.Kind == KindInterval {
		p := Preview{Approx: true}
		for i := 1; i <= n; i++ {
			p.Next = append(p.Next, now.Add(time.Duration(i)*s.Interval()).UTC().Truncate(time.Second))
		}
		return p, nil
	}
	expr := s.OnCalendar()
	res, err := run(ctx, 10*time.Second, SystemdAnalyze, "calendar", "--iterations="+itoa(n), "--", expr)
	if err != nil || res.ExitCode != 0 {
		return Preview{}, invalidCode("calendar", CodeRejected, "systemd does not accept this schedule")
	}
	p, err := parseAnalyze(string(res.Stdout))
	if err != nil {
		return Preview{}, err
	}
	if len(p.Next) == 0 {
		return p, invalidCode("calendar", CodeNever, "this schedule never elapses")
	}
	return p, nil
}

func itoa(n int) string { return strconv.Itoa(min(max(n, 1), 20)) }
