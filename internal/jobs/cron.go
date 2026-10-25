package jobs

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/bits"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/PanPakaPancake/daemonica/internal/execx"
	"github.com/PanPakaPancake/daemonica/internal/sysinfo"
	"github.com/PanPakaPancake/daemonica/internal/validate"
)

// Cron paths (Debian/Ubuntu layout).
var (
	CronRoot     = "/"
	CrontabBin   = "/usr/bin/crontab"
	CronDaemon   = "/usr/sbin/cron"
	cronSpool    = "var/spool/cron/crontabs"
	cronPeriodic = []string{"hourly", "daily", "weekly", "monthly"}
)

// MaxCronCommand bounds a command written to a user crontab.
const MaxCronCommand = 1000

// CronExpr is a parsed five-field cron schedule (or an @-shortcut).
type CronExpr struct {
	minute, hour, dom, month, dow uint64
	domStar, dowStar              bool
	Reboot                        bool
}

var cronNames = map[string]int{
	"jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6, "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12,
	"sun": 0, "mon": 1, "tue": 2, "wed": 3, "thu": 4, "fri": 5, "sat": 6,
}

var cronShortcuts = map[string]string{
	"@yearly": "0 0 1 1 *", "@annually": "0 0 1 1 *", "@monthly": "0 0 1 * *", "@weekly": "0 0 * * 0",
	"@daily": "0 0 * * *", "@midnight": "0 0 * * *", "@hourly": "0 * * * *",
}

func cronValue(s string, lo, hi int, names bool) (int, error) {
	if names {
		if v, ok := cronNames[strings.ToLower(s)]; ok {
			return v, nil
		}
	}
	v, err := strconv.Atoi(s)
	if err != nil || v < lo || v > hi {
		return 0, fmt.Errorf("value %q out of range %d-%d", s, lo, hi)
	}
	return v, nil
}

func cronField(f string, lo, hi int, names bool) (uint64, error) {
	var set uint64
	for _, part := range strings.Split(f, ",") {
		rng, stepS, hasStep := strings.Cut(part, "/")
		step := 1
		if hasStep {
			n, err := strconv.Atoi(stepS)
			if err != nil || n < 1 || n > hi {
				return 0, fmt.Errorf("invalid step %q", stepS)
			}
			step = n
		}
		a, b := lo, hi
		switch {
		case rng == "*":
		case strings.Contains(rng, "-"):
			x, y, _ := strings.Cut(rng, "-")
			var err error
			if a, err = cronValue(x, lo, hi, names); err != nil {
				return 0, err
			}
			if b, err = cronValue(y, lo, hi, names); err != nil {
				return 0, err
			}
			if b < a {
				return 0, fmt.Errorf("invalid range %q", rng)
			}
		default:
			v, err := cronValue(rng, lo, hi, names)
			if err != nil {
				return 0, err
			}
			a, b = v, v
			if hasStep {
				b = hi
			}
		}
		for v := a; v <= b; v += step {
			set |= 1 << uint(v)
		}
	}
	return set, nil
}

// ParseCron parses a five-field schedule or an @-shortcut.
func ParseCron(s string) (CronExpr, error) {
	s = strings.TrimSpace(s)
	if s == "@reboot" {
		return CronExpr{Reboot: true}, nil
	}
	if v, ok := cronShortcuts[strings.ToLower(s)]; ok {
		s = v
	}
	f := strings.Fields(s)
	if len(f) != 5 {
		return CronExpr{}, errors.New("five fields expected: minute hour day month weekday")
	}
	var e CronExpr
	var err error
	if e.minute, err = cronField(f[0], 0, 59, false); err != nil {
		return e, fmt.Errorf("minute: %w", err)
	}
	if e.hour, err = cronField(f[1], 0, 23, false); err != nil {
		return e, fmt.Errorf("hour: %w", err)
	}
	if e.dom, err = cronField(f[2], 1, 31, false); err != nil {
		return e, fmt.Errorf("day of month: %w", err)
	}
	if e.month, err = cronField(f[3], 1, 12, true); err != nil {
		return e, fmt.Errorf("month: %w", err)
	}
	if e.dow, err = cronField(f[4], 0, 7, true); err != nil {
		return e, fmt.Errorf("weekday: %w", err)
	}
	if e.dow&(1<<7) != 0 {
		e.dow |= 1
	}
	e.domStar, e.dowStar = strings.HasPrefix(f[2], "*"), strings.HasPrefix(f[4], "*")
	return e, nil
}

func (e CronExpr) dayMatches(t time.Time) bool {
	d := e.dom&(1<<uint(t.Day())) != 0
	w := e.dow&(1<<uint(t.Weekday())) != 0
	// Vixie cron: when both day fields are restricted, either may match.
	if !e.domStar && !e.dowStar {
		return d || w
	}
	return d && w
}

// Next returns the next n times after from (in from's location).
func (e CronExpr) Next(from time.Time, n int) []time.Time {
	if e.Reboot || e.minute == 0 || e.hour == 0 || e.month == 0 {
		return nil
	}
	var out []time.Time
	t := from.Truncate(time.Minute).Add(time.Minute)
	limit := from.AddDate(5, 0, 0)
	for len(out) < n && t.Before(limit) {
		switch {
		case e.month&(1<<uint(t.Month())) == 0:
			t = time.Date(t.Year(), t.Month()+1, 1, 0, 0, 0, 0, t.Location())
		case !e.dayMatches(t):
			t = time.Date(t.Year(), t.Month(), t.Day()+1, 0, 0, 0, 0, t.Location())
		case e.hour&(1<<uint(t.Hour())) == 0:
			t = time.Date(t.Year(), t.Month(), t.Day(), t.Hour()+1, 0, 0, 0, t.Location())
		case e.minute&(1<<uint(t.Minute())) == 0:
			// jump to the next set minute bit in this hour, if any
			rest := e.minute >> uint(t.Minute()+1) << uint(t.Minute()+1)
			if rest == 0 {
				t = time.Date(t.Year(), t.Month(), t.Day(), t.Hour()+1, 0, 0, 0, t.Location())
			} else {
				t = time.Date(t.Year(), t.Month(), t.Day(), t.Hour(), bits.TrailingZeros64(rest), 0, 0, t.Location())
			}
		default:
			out = append(out, t)
			t = t.Add(time.Minute)
		}
	}
	return out
}

// CronEntry is one scheduled cron line (or a periodic script).
type CronEntry struct {
	Source   string      `json:"source"`         // file path or "user:<name>"
	Line     int         `json:"line"`           // 0-based line index, -1 for periodic scripts
	User     string      `json:"user,omitempty"` // user the command runs as
	Schedule string      `json:"schedule"`
	Command  string      `json:"command"`
	Next     []time.Time `json:"next,omitempty"`
	Reboot   bool        `json:"reboot,omitempty"`
	Editable bool        `json:"editable,omitempty"`
	Error    string      `json:"error,omitempty"`
}

// CronFile is a user crontab as read for editing.
type CronFile struct {
	User    string      `json:"user"`
	Hash    string      `json:"hash"`
	Entries []CronEntry `json:"entries"`
}

// CronStatus is the cron part of the overview.
type CronStatus struct {
	Installed bool        `json:"installed"`
	Entries   []CronEntry `json:"entries"`
	// Users with a crontab (editable through cron.save).
	Users []string `json:"users"`
}

func hashOf(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

// splitFields returns the first n whitespace-separated fields and the rest
// of the line with its inner spacing kept.
func splitFields(line string, n int) ([]string, string, bool) {
	var f []string
	rest := strings.TrimLeft(line, " \t")
	for range n {
		i := strings.IndexAny(rest, " \t")
		if i < 0 {
			return nil, "", false
		}
		f = append(f, rest[:i])
		rest = strings.TrimLeft(rest[i:], " \t")
	}
	return f, rest, rest != ""
}

var envLineRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*\s*=`)

// parseCrontab parses crontab text; withUser for /etc/crontab and cron.d.
func parseCrontab(text, source, user string, withUser bool, now time.Time) []CronEntry {
	var out []CronEntry
	for i, raw := range strings.Split(text, "\n") {
		l := strings.TrimSpace(raw)
		if l == "" || strings.HasPrefix(l, "#") || envLineRE.MatchString(l) {
			continue
		}
		e := CronEntry{Source: source, Line: i, User: user}
		n := 5
		if strings.HasPrefix(l, "@") {
			n = 1
		}
		if withUser {
			n++
		}
		f, rest, ok := splitFields(l, n)
		if !ok {
			e.Error = "incomplete line"
			e.Command = sysinfo.SanitizeText(l, 512)
			out = append(out, e)
			continue
		}
		if withUser {
			e.User = sysinfo.SanitizeText(f[len(f)-1], 32)
			f = f[:len(f)-1]
		}
		e.Schedule = strings.Join(f, " ")
		e.Command = sysinfo.SanitizeText(rest, 1024)
		x, err := ParseCron(e.Schedule)
		switch {
		case err != nil:
			e.Error = err.Error()
		case x.Reboot:
			e.Reboot = true
		default:
			e.Next = x.Next(now, 5)
		}
		out = append(out, e)
	}
	return out
}

// runPartsRE is the file name rule of run-parts (others are skipped by cron).
var runPartsRE = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

func readSmall(p string) ([]byte, error) {
	fi, err := os.Lstat(p)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() || fi.Size() > 1<<20 {
		return nil, errors.New("not a regular file")
	}
	return os.ReadFile(p) //nolint:gosec // fixed cron locations
}

// Cron reads the system and user crontabs.
func Cron(now time.Time) CronStatus {
	st := CronStatus{Entries: []CronEntry{}, Users: []string{}}
	if _, err := os.Stat(filepath.Join(CronRoot, CronDaemon)); err == nil {
		st.Installed = true
	}
	root := func(p string) string { return filepath.Join(CronRoot, p) }
	if b, err := readSmall(root("etc/crontab")); err == nil {
		st.Entries = append(st.Entries, parseCrontab(string(b), "/etc/crontab", "", true, now)...)
	}
	if ents, err := os.ReadDir(root("etc/cron.d")); err == nil {
		for _, d := range ents {
			if !runPartsRE.MatchString(d.Name()) {
				continue
			}
			if b, err := readSmall(root("etc/cron.d/" + d.Name())); err == nil {
				st.Entries = append(st.Entries, parseCrontab(string(b), "/etc/cron.d/"+d.Name(), "", true, now)...)
			}
		}
	}
	for _, p := range cronPeriodic {
		dir := "etc/cron." + p
		ents, err := os.ReadDir(root(dir))
		if err != nil {
			continue
		}
		for _, d := range ents {
			fi, err := d.Info()
			if err != nil || !runPartsRE.MatchString(d.Name()) || !fi.Mode().IsRegular() || fi.Mode()&0o111 == 0 {
				continue
			}
			st.Entries = append(st.Entries, CronEntry{Source: "/" + dir, Line: -1, User: "root", Schedule: "@" + p,
				Command: "/" + dir + "/" + d.Name()})
		}
	}
	if ents, err := os.ReadDir(root(cronSpool)); err == nil {
		for _, d := range ents {
			u := d.Name()
			if validate.LinuxUser(u) != nil {
				continue
			}
			b, err := readSmall(root(cronSpool + "/" + u))
			if err != nil {
				continue
			}
			st.Users = append(st.Users, u)
			es := parseCrontab(string(b), "user:"+u, u, false, now)
			for i := range es {
				es[i].Editable = true
			}
			st.Entries = append(st.Entries, es...)
		}
	}
	return st
}

// ReadUserCrontab returns a user's crontab ("" when the user has none).
func ReadUserCrontab(user string) ([]byte, error) {
	if validate.LinuxUser(user) != nil {
		return nil, errors.New("invalid user")
	}
	b, err := readSmall(filepath.Join(CronRoot, cronSpool, user))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	return b, err
}

// CrontabFromBytes returns the editable view of a user's crontab text.
func CrontabFromBytes(user string, b []byte, now time.Time) CronFile {
	es := parseCrontab(string(b), "user:"+user, user, false, now)
	for i := range es {
		es[i].Editable = true
	}
	if es == nil {
		es = []CronEntry{}
	}
	return CronFile{User: user, Hash: hashOf(b), Entries: es}
}

// EscapeCronCommand makes every % literal: in a crontab an unescaped %
// ends the command and starts its standard input.
func EscapeCronCommand(s string) string {
	var b strings.Builder
	esc := false
	for _, r := range s {
		if r == '%' && !esc {
			b.WriteString(`\%`)
			continue
		}
		esc = r == '\\' && !esc
		b.WriteRune(r)
	}
	return b.String()
}

// CronEdit changes one line of a user crontab.
type CronEdit struct {
	User     string `json:"user"`
	Hash     string `json:"hash"`
	Line     int    `json:"line"` // -1 appends
	Delete   bool   `json:"delete,omitempty"`
	Schedule string `json:"schedule,omitempty"`
	Command  string `json:"command,omitempty"`
}

// ErrStale is returned when the crontab changed since it was read.
var ErrStale = errors.New("crontab changed")

// ApplyCronEdit computes the new crontab text for e.
func ApplyCronEdit(cur []byte, e CronEdit) (string, error) {
	if hashOf(cur) != e.Hash {
		return "", ErrStale
	}
	lines := strings.Split(strings.TrimSuffix(string(cur), "\n"), "\n")
	if len(cur) == 0 {
		lines = nil
	}
	var newLine string
	if !e.Delete {
		sched := strings.Join(strings.Fields(e.Schedule), " ")
		if validate.NoControl(sched, 200) != nil {
			return "", invalid("schedule", "invalid")
		}
		if _, err := ParseCron(sched); err != nil {
			return "", invalid("schedule", "%s", err.Error())
		}
		cmd := strings.TrimSpace(e.Command)
		if cmd == "" || validate.NoControl(cmd, MaxCronCommand) != nil {
			return "", invalid("command", "one line without control characters, at most %d characters", MaxCronCommand)
		}
		newLine = sched + " " + EscapeCronCommand(cmd)
	}
	switch {
	case e.Line == -1 && !e.Delete:
		lines = append(lines, newLine)
	case e.Line >= 0 && e.Line < len(lines):
		l := strings.TrimSpace(lines[e.Line])
		if l == "" || strings.HasPrefix(l, "#") || envLineRE.MatchString(l) {
			return "", invalid("line", "not a schedule line")
		}
		if e.Delete {
			lines = slices.Delete(lines, e.Line, e.Line+1)
		} else {
			lines[e.Line] = newLine
		}
	default:
		return "", invalid("line", "no such line")
	}
	if len(lines) == 0 {
		return "", nil
	}
	return strings.Join(lines, "\n") + "\n", nil
}

// WriteUserCrontab installs text as the user's crontab with crontab(1),
// which checks the syntax again and signals cron.
func WriteUserCrontab(ctx context.Context, user, text string) error {
	if validate.LinuxUser(user) != nil {
		return errors.New("invalid user")
	}
	args := []string{"-u", user, "-"}
	var stdin *strings.Reader
	if text == "" {
		args = []string{"-u", user, "-r"}
	} else {
		stdin = strings.NewReader(text)
	}
	var res execx.Result
	var err error
	if stdin != nil {
		res, err = execx.Run(ctx, 20*time.Second, 64<<10, stdin, CrontabBin, args...)
	} else {
		res, err = execx.Run(ctx, 20*time.Second, 64<<10, nil, CrontabBin, args...)
	}
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return invalid("crontab", "%s", sysinfo.SanitizeText(strings.TrimSpace(string(res.Stderr)), 300))
	}
	return nil
}
