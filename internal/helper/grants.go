package helper

import (
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/PanPakaPancake/daemonica/internal/auth"
	"github.com/PanPakaPancake/daemonica/internal/policy"
)

// Session lifetime bounds (SPEC §3.5).
const (
	DefaultIdle     = 30 * time.Minute
	DefaultAbsolute = 12 * time.Hour
	MinIdle         = 5 * time.Minute
	MaxIdle         = 60 * time.Minute
	MinAbsolute     = 1 * time.Hour
	MaxAbsolute     = 24 * time.Hour
	// touchInterval limits how often last-use times are written to disk.
	touchInterval = time.Minute
)

// ErrGrantInvalid covers unknown, expired and revoked grants.
var ErrGrantInvalid = errors.New("grant invalid")

// GrantRecord is the persisted form of a grant (token hash only, never the token).
type GrantRecord struct {
	Hash        string
	Subject     policy.Subject
	Created     time.Time
	LastUsed    time.Time
	StepUpUntil time.Time
	SourceIP    string
}

// GrantPersistence stores grants so sessions survive helper restarts.
type GrantPersistence interface {
	SaveGrant(GrantRecord) error
	DeleteGrant(hash string) error
	DeleteAccountGrants(accountID string) error
	LoadGrants() ([]GrantRecord, error)
	TouchGrant(hash string, lastUsed time.Time) error
}

type grant struct {
	rec       GrantRecord
	lastWrite time.Time
}

// SessionInfo is the public view of a session (no token, no full hash).
type SessionInfo struct {
	ID          string    `json:"id"` // first 16 hex chars of the token hash
	AccountID   string    `json:"account_id"`
	Role        string    `json:"role"`
	LinuxUser   string    `json:"linux_user"`
	Created     time.Time `json:"created"`
	LastUsed    time.Time `json:"last_used"`
	SourceIP    string    `json:"source_ip,omitempty"`
	StepUp      bool      `json:"step_up"`
	Current     bool      `json:"current"`
	AccountName string    `json:"account_name,omitempty"`
}

// GrantStore holds helper-issued grants. The browser cookie carries the opaque
// grant token; the helper keeps only its SHA-256 hash (memory + optional DB).
type GrantStore struct {
	mu       sync.Mutex
	grants   map[string]*grant // key: token hash
	idle     time.Duration
	absolute time.Duration
	persist  GrantPersistence
}

// NewGrantStore creates an in-memory store with clamped lifetimes.
func NewGrantStore(idle, absolute time.Duration) *GrantStore {
	return &GrantStore{grants: map[string]*grant{}, idle: clamp(idle, MinIdle, MaxIdle, DefaultIdle),
		absolute: clamp(absolute, MinAbsolute, MaxAbsolute, DefaultAbsolute)}
}

// WithPersistence attaches a backend and loads non-expired grants from it.
func (g *GrantStore) WithPersistence(p GrantPersistence, now time.Time) error {
	recs, err := p.LoadGrants()
	if err != nil {
		return err
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.persist = p
	for _, r := range recs {
		if g.expired(r, now) {
			_ = p.DeleteGrant(r.Hash)
			continue
		}
		r := r
		g.grants[r.Hash] = &grant{rec: r, lastWrite: r.LastUsed}
	}
	return nil
}

func clamp(v, lo, hi, def time.Duration) time.Duration {
	if v == 0 {
		return def
	}
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func (g *GrantStore) expired(r GrantRecord, now time.Time) bool {
	return now.Sub(r.LastUsed) >= g.idle || now.Sub(r.Created) >= g.absolute
}

// Issue creates a grant for a freshly authenticated subject (called only after
// the helper itself verified a WebAuthn assertion). UID 0 mappings are refused.
func (g *GrantStore) Issue(s policy.Subject, now time.Time) (string, error) {
	return g.IssueFrom(s, now, "")
}

// IssueFrom is Issue with the client's source IP recorded for the session list.
func (g *GrantStore) IssueFrom(s policy.Subject, now time.Time, ip string) (string, error) {
	if s.LinuxUID == 0 || !policy.ValidRole(s.Role) || s.AccountID == "" {
		return "", errors.New("grant: refusing invalid subject")
	}
	s.StepUp = false
	return g.insert(GrantRecord{Subject: s, Created: now, LastUsed: now, SourceIP: ip})
}

func (g *GrantStore) insert(r GrantRecord) (string, error) {
	tok, err := auth.NewToken("grant")
	if err != nil {
		return "", err
	}
	r.Hash = auth.Hash(tok)
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.persist != nil {
		if err := g.persist.SaveGrant(r); err != nil {
			return "", err
		}
	}
	g.grants[r.Hash] = &grant{rec: r, lastWrite: r.LastUsed}
	return tok, nil
}

// Resolve validates a grant and returns the subject with current step-up state.
// It also slides the idle timeout.
func (g *GrantStore) Resolve(tok string, now time.Time) (policy.Subject, string, error) {
	if tok == "" || len(tok) > 128 {
		return policy.Subject{}, "", ErrGrantInvalid
	}
	h := auth.Hash(tok)
	g.mu.Lock()
	defer g.mu.Unlock()
	gr, ok := g.grants[h]
	if !ok {
		return policy.Subject{}, "", ErrGrantInvalid
	}
	if g.expired(gr.rec, now) {
		g.deleteLocked(h)
		return policy.Subject{}, "", ErrGrantInvalid
	}
	gr.rec.LastUsed = now
	if g.persist != nil && now.Sub(gr.lastWrite) >= touchInterval {
		if g.persist.TouchGrant(h, now) == nil {
			gr.lastWrite = now
		}
	}
	s := gr.rec.Subject
	s.StepUp = now.Before(gr.rec.StepUpUntil)
	return s, "sha256:" + h[:16], nil
}

// RotateWithStepUp replaces the grant by a new token carrying a fresh step-up
// (5 min) and revokes the old token (session rotation, SPEC §3.5).
func (g *GrantStore) RotateWithStepUp(tok string, now time.Time) (string, error) {
	h := auth.Hash(tok)
	g.mu.Lock()
	gr, ok := g.grants[h]
	if !ok || g.expired(gr.rec, now) {
		g.mu.Unlock()
		return "", ErrGrantInvalid
	}
	rec := gr.rec
	g.deleteLocked(h)
	g.mu.Unlock()
	rec.LastUsed, rec.StepUpUntil = now, now.Add(auth.StepUpTTL)
	return g.insert(rec)
}

// MarkStepUp records a fresh step-up on an existing grant without rotation (tests, internal use).
func (g *GrantStore) MarkStepUp(tok string, now time.Time) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	gr, ok := g.grants[auth.Hash(tok)]
	if !ok {
		return ErrGrantInvalid
	}
	gr.rec.StepUpUntil = now.Add(auth.StepUpTTL)
	if g.persist != nil {
		_ = g.persist.SaveGrant(gr.rec)
	}
	return nil
}

func (g *GrantStore) deleteLocked(h string) {
	delete(g.grants, h)
	if g.persist != nil {
		_ = g.persist.DeleteGrant(h)
	}
}

// Revoke ends one grant.
func (g *GrantStore) Revoke(tok string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.deleteLocked(auth.Hash(tok))
}

// RevokeByID ends the session with public id. If accountID is non-empty, only
// a session of that account may be revoked (own sessions).
func (g *GrantStore) RevokeByID(id, accountID string) bool {
	if len(id) != 16 {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	for h, gr := range g.grants {
		if h[:16] == id && (accountID == "" || gr.rec.Subject.AccountID == accountID) {
			g.deleteLocked(h)
			return true
		}
	}
	return false
}

// RevokeAccount ends all grants of an account (recovery, deactivation, role change).
func (g *GrantStore) RevokeAccount(accountID string) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	n := 0
	for k, gr := range g.grants {
		if gr.rec.Subject.AccountID == accountID {
			delete(g.grants, k)
			n++
		}
	}
	if g.persist != nil {
		_ = g.persist.DeleteAccountGrants(accountID)
	}
	return n
}

// List returns live sessions (of accountID, or all when empty), newest first.
// currentID marks the caller's own session.
func (g *GrantStore) List(accountID, currentID string, now time.Time) []SessionInfo {
	g.mu.Lock()
	defer g.mu.Unlock()
	var out []SessionInfo
	for h, gr := range g.grants {
		r := gr.rec
		if g.expired(r, now) || (accountID != "" && r.Subject.AccountID != accountID) {
			continue
		}
		out = append(out, SessionInfo{ID: h[:16], AccountID: r.Subject.AccountID, Role: string(r.Subject.Role),
			LinuxUser: r.Subject.LinuxUser, Created: r.Created, LastUsed: r.LastUsed, SourceIP: r.SourceIP,
			StepUp: now.Before(r.StepUpUntil), Current: "sha256:"+h[:16] == currentID})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastUsed.After(out[j].LastUsed) })
	return out
}

// Count returns the number of live grants.
func (g *GrantStore) Count() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.grants)
}
