package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/PanPakaPancake/daemonica/internal/validate"
)

// Systemd is what the manager needs from systemd (D-Bus in production).
type Systemd interface {
	DaemonReload(ctx context.Context) error
	// EnableTimer enables and starts (true) or stops and disables (false) a timer.
	EnableTimer(ctx context.Context, timer string, on bool) error
	// StartNoWait queues a start job without waiting for it.
	StartNoWait(ctx context.Context, unit string) error
	Stop(ctx context.Context, unit string) error
}

// Account is the host view of a Linux user.
type Account struct {
	UID  uint32
	Home string
}

// Manager stores managed jobs and writes their units.
type Manager struct {
	// Dir holds <id>.json metadata (helper state, 0700).
	Dir string
	// UnitDir is /etc/systemd/system.
	UnitDir string
	Systemd Systemd
	Run     Runner
	// LookupUser resolves a Linux user.
	LookupUser func(name string) (Account, error)
	Now        func() time.Time

	mu sync.Mutex
}

func (m *Manager) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

func (m *Manager) metaPath(id string) string { return filepath.Join(m.Dir, id+".json") }

// Init creates the metadata directory.
func (m *Manager) Init() error { return os.MkdirAll(m.Dir, 0o700) }

// Load returns a stored job.
func (m *Manager) Load(id string) (Job, error) {
	if validate.JobName(id) != nil {
		return Job{}, ErrNotFound
	}
	b, err := os.ReadFile(m.metaPath(id))
	if errors.Is(err, fs.ErrNotExist) {
		return Job{}, ErrNotFound
	}
	if err != nil {
		return Job{}, err
	}
	var j Job
	if err := json.Unmarshal(b, &j); err != nil {
		return Job{}, err
	}
	return j, nil
}

// List returns all stored jobs sorted by id.
func (m *Manager) List() ([]Job, error) {
	ents, err := os.ReadDir(m.Dir)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	out := []Job{}
	for _, e := range ents {
		id, ok := strings.CutSuffix(e.Name(), ".json")
		if !ok {
			continue
		}
		if j, err := m.Load(id); err == nil {
			out = append(out, j)
		}
	}
	slices.SortFunc(out, func(a, b Job) int { return strings.Compare(a.ID, b.ID) })
	return out, nil
}

func writeAtomic(p string, b []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(p), ".daemonica-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), p)
}

// Trusted reports whether path (after resolving symlinks) and every parent
// directory are owned by root or uid and not writable by anyone else
// (sticky directories excepted). A root job must not run a program another
// user could replace.
func Trusted(path string, uid uint32) error {
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		return errors.New("does not exist")
	}
	for p := real; ; p = filepath.Dir(p) {
		fi, err := os.Lstat(p)
		if err != nil {
			return err
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok {
			return errors.New("cannot check owner")
		}
		if st.Uid != 0 && st.Uid != uid {
			return fmt.Errorf("%s belongs to another user", p)
		}
		perm := fi.Mode().Perm()
		sticky := fi.IsDir() && fi.Mode()&fs.ModeSticky != 0
		if perm&0o022 != 0 && !sticky {
			return fmt.Errorf("%s is writable by other users", p)
		}
		if p == "/" {
			return nil
		}
	}
}

// Check validates j against the host: the user exists, the program or
// script is a trusted file, the schedule is accepted by systemd. It returns
// the normalized job and the next runs.
func (m *Manager) Check(ctx context.Context, j Job) (Job, Preview, []string, error) {
	j, err := j.Normalize()
	if err != nil {
		return j, Preview{}, nil, err
	}
	var warnings []string
	acct, err := m.LookupUser(j.User)
	if err != nil {
		return j, Preview{}, nil, invalid("user", "unknown user")
	}
	file := j.Program
	switch j.Mode {
	case ModeScript:
		file = j.Script
		if j.Interpreter != "" {
			if err := Trusted(j.Interpreter, 0); err != nil {
				return j, Preview{}, nil, invalid("interpreter", "%s", err.Error())
			}
		}
	case ModeShell:
		file = "/bin/sh"
		warnings = append(warnings, "shell")
	}
	if err := Trusted(file, acct.UID); err != nil {
		return j, Preview{}, nil, invalid(map[string]string{ModeExec: "program", ModeScript: "script", ModeShell: "shell"}[j.Mode], "%s", err.Error())
	}
	fi, err := os.Stat(file)
	switch {
	case err != nil || !fi.Mode().IsRegular():
		return j, Preview{}, nil, invalid("program", "not a regular file")
	case (j.Mode == ModeExec || j.Interpreter == "") && fi.Mode()&0o111 == 0:
		return j, Preview{}, nil, invalid("program", "not executable")
	}
	if j.WorkDir != "" {
		if fi, err := os.Stat(j.WorkDir); err != nil || !fi.IsDir() {
			return j, Preview{}, nil, invalid("workdir", "directory does not exist")
		}
	}
	for _, p := range j.WritePaths {
		if _, err := os.Stat(p); err != nil {
			return j, Preview{}, nil, invalid("write_paths", "%s does not exist", p)
		}
	}
	if j.User == "root" {
		warnings = append(warnings, "root")
	}
	if j.Hardening == HardenNone {
		warnings = append(warnings, "no_hardening")
	}
	if j.Schedule.Kind == KindMonthly && j.Schedule.Day > 28 {
		warnings = append(warnings, "short_months")
	}
	p, err := NextRuns(ctx, m.Run, j.Schedule, 5, m.now())
	if err != nil {
		return j, Preview{}, nil, err
	}
	return j, p, warnings, nil
}

// Save creates (create=true) or replaces a job: metadata, unit files,
// daemon-reload and the timer state.
func (m *Manager) Save(ctx context.Context, j Job, create bool, by string) (Job, error) {
	j, _, _, err := m.Check(ctx, j)
	if err != nil {
		return j, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	old, err := m.Load(j.ID)
	switch {
	case create && err == nil:
		return j, ErrExists
	case create && errors.Is(err, ErrNotFound):
		if _, serr := os.Lstat(filepath.Join(m.UnitDir, j.Service())); serr == nil {
			return j, ErrExists // a unit of that name exists outside Daemonica
		}
		j.Created, j.CreatedBy = m.now().UTC(), by
	case !create && err != nil:
		return j, ErrNotFound
	default:
		j.Created, j.CreatedBy = old.Created, old.CreatedBy
	}
	j.Updated = m.now().UTC()
	meta, err := json.MarshalIndent(j, "", "  ")
	if err != nil {
		return j, err
	}
	if err := writeAtomic(filepath.Join(m.UnitDir, j.Service()), []byte(j.ServiceUnit()), 0o644); err != nil {
		return j, err
	}
	if err := writeAtomic(filepath.Join(m.UnitDir, j.Timer()), []byte(j.TimerUnit()), 0o644); err != nil {
		return j, err
	}
	if err := writeAtomic(m.metaPath(j.ID), meta, 0o600); err != nil {
		return j, err
	}
	if err := m.Systemd.DaemonReload(ctx); err != nil {
		return j, err
	}
	// Re-arm the timer so a changed schedule takes effect.
	if err := m.Systemd.EnableTimer(ctx, j.Timer(), false); err != nil && j.Enabled {
		return j, err
	}
	if j.Enabled {
		if err := m.Systemd.EnableTimer(ctx, j.Timer(), true); err != nil {
			return j, err
		}
	}
	return j, nil
}

// SetEnabled enables or disables a job's timer.
func (m *Manager) SetEnabled(ctx context.Context, id string, on bool) (Job, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	j, err := m.Load(id)
	if err != nil {
		return j, err
	}
	if err := m.Systemd.EnableTimer(ctx, j.Timer(), on); err != nil {
		return j, err
	}
	j.Enabled, j.Updated = on, m.now().UTC()
	meta, _ := json.MarshalIndent(j, "", "  ")
	return j, writeAtomic(m.metaPath(j.ID), meta, 0o600)
}

// RunNow starts the job's service once.
func (m *Manager) RunNow(ctx context.Context, id string) error {
	j, err := m.Load(id)
	if err != nil {
		return err
	}
	return m.Systemd.StartNoWait(ctx, j.Service())
}

// StopRun stops a running execution.
func (m *Manager) StopRun(ctx context.Context, id string) error {
	j, err := m.Load(id)
	if err != nil {
		return err
	}
	return m.Systemd.Stop(ctx, j.Service())
}

// Delete stops and removes a job and its units.
func (m *Manager) Delete(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	j, err := m.Load(id)
	if err != nil {
		return err
	}
	_ = m.Systemd.EnableTimer(ctx, j.Timer(), false)
	_ = m.Systemd.Stop(ctx, j.Service())
	for _, u := range []string{j.Timer(), j.Service()} {
		if err := os.Remove(filepath.Join(m.UnitDir, u)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	if err := m.Systemd.DaemonReload(ctx); err != nil {
		return err
	}
	return os.Remove(m.metaPath(id))
}

// Drift reports whether the unit files differ from what Daemonica wrote
// (edited outside the dashboard, or missing).
func (m *Manager) Drift(j Job) bool {
	for name, want := range map[string]string{j.Service(): j.ServiceUnit(), j.Timer(): j.TimerUnit()} {
		b, err := os.ReadFile(filepath.Join(m.UnitDir, name)) //nolint:gosec // fixed directory, validated name
		if err != nil || string(b) != want {
			return true
		}
	}
	return false
}
