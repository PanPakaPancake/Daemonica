// Package journal queries journald through journalctl's JSON export, invoked
// with an argv array only (SPEC §3.2 rule 7). All fields are untrusted and are
// sanitised before they leave the helper (SPEC §3.5 log injection).
package journal

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/PanPakaPancake/daemonica/internal/execx"
	"github.com/PanPakaPancake/daemonica/internal/sysinfo"
	"github.com/PanPakaPancake/daemonica/internal/validate"
)

// Journalctl is the binary path.
var Journalctl = "/usr/bin/journalctl"

// Limits.
const (
	MaxLines      = 5000
	DefaultLines  = 500
	MaxGrep       = 200
	MaxMessageLen = 4096
	// MaxResultBytes keeps one result well below the 1 MiB RPC frame limit.
	MaxResultBytes = 640 << 10
)

// Query describes a journal query.
type Query struct {
	Unit     string    `json:"unit,omitempty"`
	Priority *int      `json:"priority,omitempty"` // 0 (emerg) … 7 (debug): show this level and more severe
	Since    time.Time `json:"since,omitempty"`
	Until    time.Time `json:"until,omitempty"`
	Boot     string    `json:"boot,omitempty"` // "", "0", "-1", or a 32-hex boot ID
	Grep     string    `json:"grep,omitempty"` // server-side substring (case-insensitive)
	After    string    `json:"after,omitempty"`
	Lines    int       `json:"lines,omitempty"`
	// Identifier filters by SYSLOG_IDENTIFIER (e.g. kernel, sshd).
	Identifier string `json:"identifier,omitempty"`
}

// Entry is one sanitised journal entry.
type Entry struct {
	Time       time.Time `json:"time"`
	Priority   int       `json:"priority"`
	Unit       string    `json:"unit,omitempty"`
	Identifier string    `json:"identifier,omitempty"`
	PID        int       `json:"pid,omitempty"`
	Message    string    `json:"message"`
	Cursor     string    `json:"-"`
}

// Result of a query.
type Result struct {
	Entries   []Entry `json:"entries"`
	Cursor    string  `json:"cursor,omitempty"` // pass as After to continue (follow)
	Truncated bool    `json:"truncated"`
}

var (
	bootRE   = regexp.MustCompile(`^(0|-[1-9][0-9]?|[0-9a-f]{32})$`)
	cursorRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9=;_\-]{0,511}$`)
	identRE  = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.@:\-]{0,63}$`)
)

// Args validates q and builds the journalctl argv. Every value is passed as
// its own element (or after "="), never interpreted by a shell; values that
// could be mistaken for options are rejected.
func (q Query) Args() ([]string, error) {
	args := []string{"--no-pager", "--output=json", "--quiet", "--utc"}
	if q.Unit != "" {
		if validate.Unit(q.Unit) != nil {
			return nil, errors.New("invalid unit")
		}
		args = append(args, "--unit="+q.Unit)
	}
	if q.Identifier != "" {
		if !identRE.MatchString(q.Identifier) {
			return nil, errors.New("invalid identifier")
		}
		args = append(args, "--identifier="+q.Identifier)
	}
	if q.Priority != nil {
		if *q.Priority < 0 || *q.Priority > 7 {
			return nil, errors.New("invalid priority")
		}
		args = append(args, "--priority="+strconv.Itoa(*q.Priority))
	}
	if !q.Since.IsZero() {
		args = append(args, "--since="+q.Since.UTC().Format("2006-01-02 15:04:05"))
	}
	if !q.Until.IsZero() {
		args = append(args, "--until="+q.Until.UTC().Format("2006-01-02 15:04:05"))
	}
	if q.Boot != "" {
		if !bootRE.MatchString(q.Boot) {
			return nil, errors.New("invalid boot")
		}
		args = append(args, "--boot="+q.Boot)
	}
	if q.Grep != "" {
		if len(q.Grep) > MaxGrep || validate.NoControl(q.Grep, MaxGrep) != nil {
			return nil, errors.New("invalid search text")
		}
		// Plain substring: escape PCRE2 metacharacters so the text is not a regex.
		args = append(args, "--case-sensitive=false", "--grep="+regexp.QuoteMeta(q.Grep))
	}
	if q.After != "" {
		// Follow mode: everything after the cursor; the count is capped in Parse.
		if !cursorRE.MatchString(q.After) {
			return nil, errors.New("invalid cursor")
		}
		args = append(args, "--after-cursor="+q.After)
	} else {
		args = append(args, "--lines="+strconv.Itoa(q.limit()))
	}
	return args, nil
}

func (q Query) limit() int {
	switch {
	case q.Lines <= 0:
		return DefaultLines
	case q.Lines > MaxLines:
		return MaxLines
	}
	return q.Lines
}

// Run executes the query.
func Run(ctx context.Context, q Query) (Result, error) {
	args, err := q.Args()
	if err != nil {
		return Result{}, err
	}
	n := q.limit()
	res, err := execx.Run(ctx, 20*time.Second, 32<<20, nil, Journalctl, args...)
	if err != nil && !errors.Is(err, execx.ErrTruncated) {
		return Result{}, err
	}
	out := Parse(res.Stdout, n)
	if errors.Is(err, execx.ErrTruncated) {
		out.Truncated = true
	}
	return out, nil
}

type rawEntry map[string]json.RawMessage

// field decodes a journal field that may be a string or a byte array.
func field(r rawEntry, k string) string {
	v, ok := r[k]
	if !ok {
		return ""
	}
	var s string
	if json.Unmarshal(v, &s) == nil {
		return s
	}
	var b []byte
	var ints []int
	if json.Unmarshal(v, &ints) == nil {
		b = make([]byte, 0, len(ints))
		for _, i := range ints {
			if i >= 0 && i < 256 {
				b = append(b, byte(i))
			}
		}
		return string(b)
	}
	return ""
}

// Parse converts journalctl JSON lines into sanitised entries (at most max).
func Parse(data []byte, max int) Result {
	var res Result
	budget := MaxResultBytes
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	for sc.Scan() {
		var r rawEntry
		if json.Unmarshal(sc.Bytes(), &r) != nil {
			continue
		}
		e := Entry{Cursor: field(r, "__CURSOR")}
		if us, err := strconv.ParseInt(field(r, "__REALTIME_TIMESTAMP"), 10, 64); err == nil {
			e.Time = time.UnixMicro(us).UTC()
		}
		e.Priority = 6
		if p, err := strconv.Atoi(field(r, "PRIORITY")); err == nil && p >= 0 && p <= 7 {
			e.Priority = p
		}
		e.Unit = sysinfo.SanitizeText(field(r, "_SYSTEMD_UNIT"), 256)
		e.Identifier = sysinfo.SanitizeText(field(r, "SYSLOG_IDENTIFIER"), 64)
		e.PID, _ = strconv.Atoi(field(r, "_PID"))
		e.Message = sysinfo.SanitizeText(strings.TrimRight(field(r, "MESSAGE"), "\n"), MaxMessageLen)
		budget -= len(e.Message) + len(e.Unit) + len(e.Identifier) + 96
		if budget < 0 {
			res.Truncated = true
			break
		}
		res.Entries = append(res.Entries, e)
		if e.Cursor != "" {
			res.Cursor = e.Cursor
		}
		if len(res.Entries) >= max {
			res.Truncated = true
			break
		}
	}
	return res
}
