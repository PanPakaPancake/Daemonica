package apt

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Kind is a package job.
type Kind string

// Job kinds.
const (
	KindUpdate     Kind = "update"     // apt-get update
	KindUpgrade    Kind = "upgrade"    // everything upgradable (with new dependencies)
	KindSelected   Kind = "selected"   // only the named packages (security or a selection)
	KindInstall    Kind = "install"    // install the named packages
	KindRemove     Kind = "remove"     // remove the named packages
	KindPurge      Kind = "purge"      // remove including configuration
	KindAutoremove Kind = "autoremove" // remove unneeded dependencies
	KindDryRun     Kind = "dry-run"    // unattended-upgrade --dry-run --debug
)

// Kinds lists the valid kinds.
var Kinds = []Kind{KindUpdate, KindUpgrade, KindSelected, KindInstall, KindRemove, KindPurge, KindAutoremove, KindDryRun}

// NeedsPackages reports whether a kind takes package names.
func (k Kind) NeedsPackages() bool {
	return k == KindSelected || k == KindInstall || k == KindRemove || k == KindPurge
}

// Job states.
const (
	StateRunning   = "running"
	StateSucceeded = "succeeded"
	StateFailed    = "failed"
	// StateUnknown: the unit ended without a result line (e.g. a reboot).
	StateUnknown = "unknown"
)

// Job is a package job and its progress.
type Job struct {
	ID       string     `json:"id"`
	Kind     Kind       `json:"kind"`
	Packages []string   `json:"packages"`
	Account  string     `json:"account"`
	Started  time.Time  `json:"started"`
	Ended    *time.Time `json:"ended,omitempty"`
	State    string     `json:"state"`
	// Result is systemd's service result ("success", "exit-code", …).
	Result string `json:"result,omitempty"`
	Exit   int    `json:"exit"`
	// Phase is "lock" (waiting for the dpkg lock), "download" or "install".
	Phase   string  `json:"phase,omitempty"`
	Percent float64 `json:"percent"`
	Current string  `json:"current,omitempty"`
	// Issues are apt's warnings and errors (W:, E:, Err:), Conffiles the
	// configuration files kept although the package ships a new version.
	Issues    []string `json:"issues"`
	Conffiles []string `json:"conffiles"`
	// RestoreAuto are packages marked automatic again afterwards (apt-get
	// install marks the packages it is given as manual).
	RestoreAuto []string `json:"restore_auto,omitempty"`
}

// Unit is how a job is run: a transient oneshot service.
type Unit struct {
	Name string
	// Exec are the commands, run in order (the next one only if the previous succeeded).
	Exec [][]string
	// Post runs at the end in any case; its output marks the result.
	Post []string
	Env  []string
	Log  string
}

// Units starts transient units and tells whether one still exists.
type Units interface {
	Start(ctx context.Context, u Unit) error
	Exists(ctx context.Context, unit string) bool
}

// UnitPrefix names the transient units of package jobs.
const UnitPrefix = "daemonica-apt-"

// ResultMarker starts the line the unit's last command writes.
const ResultMarker = "@@daemonica-result"

// Env is the environment of package jobs: no prompts, keep changed
// configuration files, needrestart only lists.
var Env = []string{
	"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8", "LC_ALL=C.UTF-8",
	"DEBIAN_FRONTEND=noninteractive", "APT_LISTCHANGES_FRONTEND=none", "NEEDRESTART_MODE=l", "UCF_FORCE_CONFFOLD=1",
}

// aptOpts are the options of every changing apt-get call.
var aptOpts = []string{
	"-q", "-y", "-o", "APT::Status-Fd=1", "-o", "APT::Color=0", "-o", "Dpkg::Use-Pty=0",
	"-o", "DPkg::Lock::Timeout=600", "-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold",
}

// Commands returns the unit's commands for a job.
func Commands(k Kind, pkgs, restoreAuto []string) [][]string {
	ag := func(args ...string) []string { return append(append([]string{AptGet}, aptOpts...), args...) }
	var cmds [][]string
	switch k {
	case KindUpdate:
		cmds = [][]string{{AptGet, "-q", "-o", "APT::Status-Fd=1", "-o", "DPkg::Lock::Timeout=600", "update"}}
	case KindUpgrade:
		cmds = [][]string{ag("--with-new-pkgs", "upgrade")}
	case KindSelected:
		cmds = [][]string{ag(append([]string{"install", "--only-upgrade"}, pkgs...)...)}
	case KindInstall:
		cmds = [][]string{ag(append([]string{"install"}, pkgs...)...)}
	case KindRemove:
		cmds = [][]string{ag(append([]string{"remove"}, pkgs...)...)}
	case KindPurge:
		cmds = [][]string{ag(append([]string{"purge"}, pkgs...)...)}
	case KindAutoremove:
		cmds = [][]string{ag("autoremove")}
	case KindDryRun:
		cmds = [][]string{{UnattendedBin, "--dry-run", "--debug"}}
	}
	if len(restoreAuto) > 0 {
		cmds = append(cmds, append([]string{AptMark, "auto"}, restoreAuto...))
	}
	return cmds
}

// Runner runs package jobs one at a time and keeps their state and logs in
// Dir (<id>.json, <id>.log). Jobs survive a helper restart: the unit runs
// on and its result line ends up in the log.
type Runner struct {
	Dir   string
	Units Units
	Now   func() time.Time
	// Keep is the number of finished jobs kept (default 30).
	Keep int

	mu sync.Mutex
}

// Errors.
var (
	ErrBusy     = errors.New("apt: a package job is running")
	ErrNotFound = errors.New("apt: no such job")
)

var idRE = regexp.MustCompile(`^[0-9]{8}-[0-9]{6}-[0-9a-f]{6}$`)

func (r *Runner) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// Init creates the directory.
func (r *Runner) Init() error { return os.MkdirAll(r.Dir, 0o700) }

func (r *Runner) path(id, ext string) string { return filepath.Join(r.Dir, id+ext) }

func (r *Runner) save(j Job) error {
	b, err := json.Marshal(j)
	if err != nil {
		return err
	}
	tmp := r.path(j.ID, ".json.tmp")
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, r.path(j.ID, ".json"))
}

func (r *Runner) load(id string) (Job, error) {
	var j Job
	if !idRE.MatchString(id) {
		return j, ErrNotFound
	}
	b, err := os.ReadFile(r.path(id, ".json"))
	if errors.Is(err, os.ErrNotExist) {
		return j, ErrNotFound
	}
	if err != nil {
		return j, err
	}
	return j, json.Unmarshal(b, &j)
}

func (r *Runner) ids() []string {
	ents, _ := os.ReadDir(r.Dir)
	var ids []string
	for _, e := range ents {
		if id, ok := strings.CutSuffix(e.Name(), ".json"); ok && idRE.MatchString(id) {
			ids = append(ids, id)
		}
	}
	slices.Sort(ids) // ids start with the time
	return ids
}

// Start starts a job unless one is running.
func (r *Runner) Start(ctx context.Context, k Kind, pkgs, restoreAuto []string, account string) (Job, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, id := range r.ids() {
		if j, err := r.refresh(ctx, id); err == nil && j.State == StateRunning {
			return Job{}, ErrBusy
		}
	}
	var rb [3]byte
	_, _ = rand.Read(rb[:])
	now := r.now().UTC()
	j := Job{ID: now.Format("20060102-150405") + "-" + hex.EncodeToString(rb[:]), Kind: k, Packages: pkgs, Account: account,
		Started: now, State: StateRunning, Issues: []string{}, Conffiles: []string{}, RestoreAuto: restoreAuto}
	if j.Packages == nil {
		j.Packages = []string{}
	}
	logPath := r.path(j.ID, ".log")
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return Job{}, err
	}
	_ = f.Close()
	if err := r.save(j); err != nil {
		return Job{}, err
	}
	u := Unit{Name: UnitPrefix + j.ID + ".service", Exec: Commands(k, pkgs, restoreAuto), Env: Env, Log: logPath,
		Post: []string{"/bin/sh", "-c", `echo "` + ResultMarker + ` $SERVICE_RESULT $EXIT_CODE $EXIT_STATUS"`}}
	if err := r.Units.Start(ctx, u); err != nil {
		end := r.now().UTC()
		j.State, j.Ended, j.Result = StateFailed, &end, "start-failed"
		_ = r.save(j)
		return j, err
	}
	r.prune()
	return j, nil
}

func (r *Runner) prune() {
	keep := r.Keep
	if keep <= 0 {
		keep = 30
	}
	ids := r.ids()
	for len(ids) > keep {
		_ = os.Remove(r.path(ids[0], ".json"))
		_ = os.Remove(r.path(ids[0], ".log"))
		ids = ids[1:]
	}
}

// Get returns a job with its current progress.
func (r *Runner) Get(ctx context.Context, id string) (Job, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.refresh(ctx, id)
}

// List returns the jobs, newest first.
func (r *Runner) List(ctx context.Context) []Job {
	r.mu.Lock()
	defer r.mu.Unlock()
	ids := r.ids()
	out := make([]Job, 0, len(ids))
	for i := len(ids) - 1; i >= 0; i-- {
		if j, err := r.refresh(ctx, ids[i]); err == nil {
			out = append(out, j)
		}
	}
	return out
}

// tailBytes is how much of the log end is read for progress.
const tailBytes = 64 << 10

// maxScan bounds the full log scan at the end of a job.
const maxScan = 16 << 20

func (r *Runner) refresh(ctx context.Context, id string) (Job, error) {
	j, err := r.load(id)
	if err != nil || j.State != StateRunning {
		return j, err
	}
	logPath := r.path(id, ".log")
	tail := Tail(logPath, tailBytes)
	res, ok := resultLine(tail)
	if !ok {
		if r.Units.Exists(ctx, UnitPrefix+id+".service") {
			Progress(&j, tail)
			return j, nil
		}
		// Gone without a result: look once more (the line may just have been written).
		if res, ok = resultLine(Tail(logPath, tailBytes)); !ok {
			end := r.now().UTC()
			j.State, j.Ended, j.Phase = StateUnknown, &end, ""
			Summarize(&j, logPath)
			return j, r.save(j)
		}
	}
	end := r.now().UTC()
	j.Ended, j.Result, j.Exit, j.Phase = &end, res.result, res.exit, ""
	j.State = StateFailed
	if res.result == "success" {
		j.State, j.Percent = StateSucceeded, 100
	}
	Summarize(&j, logPath)
	return j, r.save(j)
}

type result struct {
	result string
	exit   int
}

func resultLine(tail string) (result, bool) {
	i := strings.LastIndex(tail, ResultMarker+" ")
	if i < 0 {
		return result{}, false
	}
	line, _, _ := strings.Cut(tail[i+len(ResultMarker)+1:], "\n")
	f := strings.Fields(line)
	if len(f) == 0 {
		return result{}, false
	}
	res := result{result: clip(f[0], 40)}
	if len(f) >= 3 {
		res.exit, _ = strconv.Atoi(f[2])
	}
	return res, true
}

// Progress sets phase, percentage and current step from the log tail
// (APT::Status-Fd lines "dlstatus:…:pct:msg", "pmstatus:pkg:pct:msg").
func Progress(j *Job, tail string) {
	lines := strings.Split(tail, "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		l := strings.TrimRight(lines[i], "\r")
		if strings.Contains(l, "Waiting for cache lock") || strings.Contains(l, "Could not get lock") {
			j.Phase, j.Current = "lock", clip(l, 300)
			return
		}
		kind, rest, ok := strings.Cut(l, ":")
		if !ok || (kind != "dlstatus" && kind != "pmstatus") {
			continue
		}
		f := strings.SplitN(rest, ":", 3)
		if len(f) != 3 {
			continue
		}
		pct, err := strconv.ParseFloat(f[1], 64)
		if err != nil || pct < 0 || pct > 100 {
			continue
		}
		j.Phase, j.Percent, j.Current = "install", pct, clip(f[2], 200)
		if kind == "dlstatus" {
			j.Phase = "download"
		}
		return
	}
}

var conffileRE = regexp.MustCompile(`^Configuration file '([^']{1,300})'`)

// Summarize collects apt's warnings and errors and the kept configuration
// files from the whole log.
func Summarize(j *Job, logPath string) {
	f, err := os.Open(logPath) //nolint:gosec // job directory
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()
	j.Issues, j.Conffiles = []string{}, []string{}
	sc := bufio.NewScanner(io.LimitReader(f, maxScan))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		l := strings.TrimRight(sc.Text(), "\r")
		switch {
		case strings.HasPrefix(l, "W: "), strings.HasPrefix(l, "E: "), strings.HasPrefix(l, "Err:"):
			if len(j.Issues) < 50 && !slices.Contains(j.Issues, clip(l, 400)) {
				j.Issues = append(j.Issues, clip(l, 400))
			}
		case strings.HasPrefix(l, "pmerror:"):
			if len(j.Issues) < 50 {
				j.Issues = append(j.Issues, clip("E: "+strings.TrimPrefix(l, "pmerror:"), 400))
			}
		}
		if m := conffileRE.FindStringSubmatch(l); m != nil && len(j.Conffiles) < 50 && !slices.Contains(j.Conffiles, m[1]) {
			j.Conffiles = append(j.Conffiles, clip(m[1], 300))
		}
	}
}

// MaxChunk bounds one log read.
const MaxChunk = 256 << 10

// Log returns the log from offset up to the last complete line (at most
// MaxChunk), without the status and result lines, and the next offset.
func (r *Runner) Log(id string, offset int64) (string, int64, error) {
	if !idRE.MatchString(id) {
		return "", 0, ErrNotFound
	}
	f, err := os.Open(r.path(id, ".log"))
	if errors.Is(err, os.ErrNotExist) {
		return "", 0, ErrNotFound
	}
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil {
		return "", 0, err
	}
	if offset < 0 || offset > st.Size() {
		offset = 0
	}
	buf := make([]byte, min(st.Size()-offset, MaxChunk))
	n, _ := f.ReadAt(buf, offset)
	buf = buf[:n]
	if i := strings.LastIndexByte(string(buf), '\n'); i >= 0 {
		buf = buf[:i+1]
	} else if len(buf) < MaxChunk {
		buf = buf[:0] // wait for the line to complete
	}
	var b strings.Builder
	for l := range strings.SplitSeq(strings.TrimSuffix(string(buf), "\n"), "\n") {
		if len(buf) == 0 || strings.HasPrefix(l, "dlstatus:") || strings.HasPrefix(l, "pmstatus:") ||
			strings.HasPrefix(l, "pmconffile:") || strings.HasPrefix(l, ResultMarker) {
			continue
		}
		b.WriteString(strings.ToValidUTF8(l, "") + "\n")
	}
	return b.String(), offset + int64(len(buf)), nil
}
