package jobs

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/PanPakaPancake/daemonica/internal/execx"
	"github.com/PanPakaPancake/daemonica/internal/sysinfo"
	"github.com/PanPakaPancake/daemonica/internal/validate"
)

// Journalctl is the binary path.
var Journalctl = "/usr/bin/journalctl"

// History limits.
const (
	MaxRuns      = 20
	ExcerptLines = 30
	historyScan  = 5000
)

// systemd catalog message IDs (sd-messages.h).
const (
	msgUnitSuccess = "7ad2d189f7e94e70a38c781354912448"
	msgUnitFailed  = "d9b373ed55a64feb8242e02dbe79a49c"
	msgProcessExit = "98e322203f7a4ed290d09fe03c09fe15"
)

// Run is one execution of a job's service.
type Run struct {
	Invocation string    `json:"invocation"`
	Start      time.Time `json:"start"`
	End        time.Time `json:"end,omitzero"`
	DurationMS int64     `json:"duration_ms,omitempty"`
	// Result: "running", "success", or systemd's failure result
	// (exit-code, timeout, signal, core-dump, ...).
	Result   string   `json:"result"`
	ExitCode *int     `json:"exit_code,omitempty"`
	Excerpt  []string `json:"excerpt,omitempty"`
}

type jentry map[string]json.RawMessage

func (e jentry) str(k string) string {
	v, ok := e[k]
	if !ok {
		return ""
	}
	var s string
	if json.Unmarshal(v, &s) == nil {
		return s
	}
	var ints []int
	if json.Unmarshal(v, &ints) == nil {
		b := make([]byte, 0, len(ints))
		for _, i := range ints {
			if i >= 0 && i < 256 {
				b = append(b, byte(i))
			}
		}
		return string(b)
	}
	return ""
}

var hexID = func(s string) bool {
	if len(s) != 32 {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// ParseHistory groups journal entries of a unit by invocation: the
// manager's messages carry INVOCATION_ID, the job's own output
// _SYSTEMD_INVOCATION_ID. Newest run first, at most MaxRuns.
func ParseHistory(data []byte, unit string, excerpt bool) []Run {
	runs := map[string]*Run{}
	var order []string
	get := func(id string, t time.Time) *Run {
		r, ok := runs[id]
		if !ok {
			r = &Run{Invocation: id, Start: t, Result: "running"}
			runs[id] = r
			order = append(order, id)
		}
		if !t.IsZero() && (r.Start.IsZero() || t.Before(r.Start)) {
			r.Start = t
		}
		return r
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	for sc.Scan() {
		var e jentry
		if json.Unmarshal(sc.Bytes(), &e) != nil {
			continue
		}
		var t time.Time
		if us, err := strconv.ParseInt(e.str("__REALTIME_TIMESTAMP"), 10, 64); err == nil {
			t = time.UnixMicro(us).UTC()
		}
		if id := e.str("INVOCATION_ID"); hexID(id) && e.str("UNIT") == unit {
			r := get(id, t)
			switch e.str("MESSAGE_ID") {
			case msgUnitSuccess:
				r.End, r.Result = t, "success"
				if r.ExitCode == nil {
					zero := 0
					r.ExitCode = &zero
				}
			case msgUnitFailed:
				r.End = t
				r.Result = sysinfo.SanitizeText(e.str("UNIT_RESULT"), 32)
				if r.Result == "" {
					r.Result = "failed"
				}
			case msgProcessExit:
				if e.str("EXIT_CODE") == "exited" {
					if n, err := strconv.Atoi(e.str("EXIT_STATUS")); err == nil {
						r.ExitCode = &n
					}
				}
			}
			continue
		}
		if id := e.str("_SYSTEMD_INVOCATION_ID"); hexID(id) && e.str("_SYSTEMD_UNIT") == unit {
			r := get(id, t)
			if excerpt {
				r.Excerpt = append(r.Excerpt, sysinfo.SanitizeText(strings.TrimRight(e.str("MESSAGE"), "\n"), 1024))
				if len(r.Excerpt) > ExcerptLines {
					r.Excerpt = r.Excerpt[len(r.Excerpt)-ExcerptLines:]
				}
			}
		}
	}
	out := make([]Run, 0, len(order))
	for _, id := range order {
		r := runs[id]
		if !r.End.IsZero() {
			r.DurationMS = r.End.Sub(r.Start).Milliseconds()
		}
		out = append(out, *r)
	}
	slices.SortStableFunc(out, func(a, b Run) int { return b.Start.Compare(a.Start) })
	if len(out) > MaxRuns {
		out = out[:MaxRuns]
	}
	return out
}

// History reads the last runs of a unit from the journal.
func History(ctx context.Context, unit string, excerpt bool) ([]Run, error) {
	if validate.Unit(unit) != nil {
		return nil, errors.New("invalid unit")
	}
	res, err := execx.Run(ctx, 20*time.Second, 32<<20, nil, Journalctl,
		"--no-pager", "--output=json", "--quiet", "--utc", "--unit="+unit, "--lines="+strconv.Itoa(historyScan))
	if err != nil && !errors.Is(err, execx.ErrTruncated) {
		return nil, err
	}
	return ParseHistory(res.Stdout, unit, excerpt), nil
}

// Since drops runs that started before t: a job created again under a name
// used before must not show the runs of its predecessor. A zero t keeps all.
func Since(runs []Run, t time.Time) []Run {
	if t.IsZero() {
		return runs
	}
	out := runs[:0:0]
	for _, r := range runs {
		// The journal's clock and the metadata's agree to the second.
		if !r.Start.Before(t.Add(-time.Second)) {
			out = append(out, r)
		}
	}
	return out
}
