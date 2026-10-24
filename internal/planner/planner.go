// Package planner implements the Plan → Apply → Confirm pattern for risky
// changes (SPEC §3.2 rule 10). It runs inside daemonia-helper so the rollback
// timer is independent of the browser and of the web process.
//
// Crash safety: before a change is applied, a journal record is written. If
// the helper restarts while a change is unconfirmed, Recover() rolls it back.
package planner

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// DefaultConfirmWindow is the default confirmation timeout (90 s).
const DefaultConfirmWindow = 90 * time.Second

// State of a change.
type State string

// States.
const (
	StatePlanned    State = "planned"
	StateApplied    State = "applied" // waiting for confirmation
	StateConfirmed  State = "confirmed"
	StateRolledBack State = "rolled_back"
	StateFailed     State = "failed"
	StateDiscarded  State = "discarded"
)

// Handler applies and rolls back one kind of change (network, firewall, allowlist…).
// Payload is an opaque, already-validated description produced by Plan.
type Handler interface {
	Kind() string
	// Apply performs the change. It must leave a backup that Rollback can use.
	Apply(ctx context.Context, payload json.RawMessage) error
	// Rollback restores the pre-change state. Must be idempotent.
	Rollback(ctx context.Context, payload json.RawMessage) error
}

// Change is the public view of a planned change.
type Change struct {
	ID        string          `json:"id"`
	Kind      string          `json:"kind"`
	Summary   string          `json:"summary"`
	Diff      string          `json:"diff"`
	Risk      string          `json:"risk"` // low|medium|high (lockout risk)
	State     State           `json:"state"`
	Owner     string          `json:"owner"` // account ID that planned it
	Payload   json.RawMessage `json:"payload"`
	Deadline  time.Time       `json:"deadline,omitempty"`
	CreatedAt time.Time       `json:"created_at"`
	Error     string          `json:"error,omitempty"`
}

// Errors.
var (
	ErrNotFound    = errors.New("planner: change not found")
	ErrWrongState  = errors.New("planner: change is not in the required state")
	ErrBusy        = errors.New("planner: another change of this kind is pending")
	ErrUnknownKind = errors.New("planner: unknown change kind")
	ErrNotOwner    = errors.New("planner: change belongs to another account")
)

// Manager coordinates changes. One pending change per kind at a time (locks
// concurrent modifications, SPEC §3.2 rule 8).
type Manager struct {
	mu         sync.Mutex
	handlers   map[string]Handler
	changes    map[string]*Change
	timers     map[string]*time.Timer
	journalDir string
	window     time.Duration
	now        func() time.Time
	// OnEvent is called for audit purposes (kind, id, event, error).
	OnEvent func(c Change, event string, err error)
}

// New creates a Manager persisting its journal in journalDir (0700).
func New(journalDir string, window time.Duration) (*Manager, error) {
	if window <= 0 {
		window = DefaultConfirmWindow
	}
	if err := os.MkdirAll(journalDir, 0o700); err != nil {
		return nil, err
	}
	return &Manager{
		handlers: map[string]Handler{}, changes: map[string]*Change{}, timers: map[string]*time.Timer{},
		journalDir: journalDir, window: window, now: time.Now,
	}, nil
}

// Register adds a handler.
func (m *Manager) Register(h Handler) { m.mu.Lock(); m.handlers[h.Kind()] = h; m.mu.Unlock() }

func newID() string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// Plan records a change proposal. Nothing is modified on the system.
func (m *Manager) Plan(kind, owner, summary, diff, risk string, payload json.RawMessage) (Change, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.handlers[kind]; !ok {
		return Change{}, ErrUnknownKind
	}
	c := &Change{ID: newID(), Kind: kind, Summary: summary, Diff: diff, Risk: risk, State: StatePlanned,
		Owner: owner, Payload: payload, CreatedAt: m.now().UTC()}
	m.changes[c.ID] = c
	m.emit(*c, "planned", nil)
	return *c, nil
}

// Get returns a change.
func (m *Manager) Get(id string) (Change, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.changes[id]
	if !ok {
		return Change{}, ErrNotFound
	}
	return *c, nil
}

// Apply executes a planned change and arms the rollback timer.
func (m *Manager) Apply(ctx context.Context, id, owner string) (Change, error) {
	m.mu.Lock()
	c, ok := m.changes[id]
	if !ok {
		m.mu.Unlock()
		return Change{}, ErrNotFound
	}
	if c.Owner != owner {
		m.mu.Unlock()
		return Change{}, ErrNotOwner
	}
	if c.State != StatePlanned {
		m.mu.Unlock()
		return Change{}, ErrWrongState
	}
	for _, o := range m.changes {
		if o.Kind == c.Kind && o.State == StateApplied {
			m.mu.Unlock()
			return Change{}, ErrBusy
		}
	}
	h := m.handlers[c.Kind]
	c.State = StateApplied
	c.Deadline = m.now().UTC().Add(m.window)
	if err := m.writeJournal(c); err != nil {
		c.State = StateFailed
		c.Error = "journal write failed"
		m.mu.Unlock()
		return *c, err
	}
	m.mu.Unlock()

	if err := h.Apply(ctx, c.Payload); err != nil {
		// Apply failed: roll back whatever was partially done.
		rbErr := h.Rollback(context.WithoutCancel(ctx), c.Payload)
		m.mu.Lock()
		c.State = StateFailed
		c.Error = "apply failed"
		m.removeJournal(c.ID)
		cc := *c
		m.mu.Unlock()
		m.emit(cc, "apply_failed", errors.Join(err, rbErr))
		return cc, err
	}

	m.mu.Lock()
	m.timers[c.ID] = time.AfterFunc(m.window, func() { m.expire(c.ID) })
	cc := *c
	m.mu.Unlock()
	m.emit(cc, "applied", nil)
	return cc, nil
}

// Confirm keeps an applied change. For lockout-relevant changes the caller
// must invoke Confirm from a NEW connection (enforced in the web layer).
func (m *Manager) Confirm(id, owner string) (Change, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.changes[id]
	if !ok {
		return Change{}, ErrNotFound
	}
	if c.Owner != owner {
		return Change{}, ErrNotOwner
	}
	if c.State != StateApplied || !m.now().Before(c.Deadline) {
		return Change{}, ErrWrongState
	}
	if t := m.timers[id]; t != nil {
		t.Stop()
		delete(m.timers, id)
	}
	c.State = StateConfirmed
	m.removeJournal(id)
	m.emit(*c, "confirmed", nil)
	return *c, nil
}

// Rollback reverts an applied change immediately (user-initiated).
func (m *Manager) Rollback(id, owner string) (Change, error) {
	m.mu.Lock()
	c, ok := m.changes[id]
	if !ok {
		m.mu.Unlock()
		return Change{}, ErrNotFound
	}
	if c.Owner != owner {
		m.mu.Unlock()
		return Change{}, ErrNotOwner
	}
	m.mu.Unlock()
	return m.doRollback(id, "rolled_back_by_user")
}

func (m *Manager) expire(id string) { _, _ = m.doRollback(id, "rolled_back_timeout") }

func (m *Manager) doRollback(id, event string) (Change, error) {
	m.mu.Lock()
	c, ok := m.changes[id]
	if !ok || c.State != StateApplied {
		m.mu.Unlock()
		return Change{}, ErrWrongState
	}
	if t := m.timers[id]; t != nil {
		t.Stop()
		delete(m.timers, id)
	}
	h := m.handlers[c.Kind]
	payload := c.Payload
	m.mu.Unlock()

	err := h.Rollback(context.Background(), payload)

	m.mu.Lock()
	defer m.mu.Unlock()
	if err != nil {
		c.State = StateFailed
		c.Error = "rollback failed"
	} else {
		c.State = StateRolledBack
		m.removeJournal(id)
	}
	m.emit(*c, event, err)
	return *c, err
}

// Recover rolls back every change left unconfirmed in the journal (e.g. after
// a helper crash or host reboot during the confirmation window).
func (m *Manager) Recover(ctx context.Context) []error {
	entries, err := os.ReadDir(m.journalDir)
	if err != nil {
		return []error{err}
	}
	var errs []error
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		p := filepath.Join(m.journalDir, e.Name())
		data, err := os.ReadFile(p) //nolint:gosec // helper-owned journal dir
		if err != nil {
			errs = append(errs, err)
			continue
		}
		var c Change
		if err := json.Unmarshal(data, &c); err != nil {
			errs = append(errs, fmt.Errorf("planner: corrupt journal %s: %w", e.Name(), err))
			continue
		}
		h, ok := m.handlers[c.Kind]
		if !ok {
			errs = append(errs, fmt.Errorf("planner: no handler for %s", c.Kind))
			continue
		}
		if err := h.Rollback(ctx, c.Payload); err != nil {
			errs = append(errs, err)
			continue
		}
		_ = os.Remove(p)
		c.State = StateRolledBack
		m.emit(c, "rolled_back_recovery", nil)
	}
	return errs
}

func (m *Manager) writeJournal(c *Change) error {
	data, err := json.Marshal(c)
	if err != nil {
		return err
	}
	p := filepath.Join(m.journalDir, c.ID+".json")
	tmp := p + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600) //nolint:gosec // helper-owned dir
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

func (m *Manager) removeJournal(id string) { _ = os.Remove(filepath.Join(m.journalDir, id+".json")) }

func (m *Manager) emit(c Change, event string, err error) {
	if m.OnEvent != nil {
		m.OnEvent(c, event, err)
	}
}
