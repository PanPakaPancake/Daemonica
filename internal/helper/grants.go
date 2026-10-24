package helper

import (
	"errors"
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
)

// ErrGrantInvalid covers unknown, expired and revoked grants.
var ErrGrantInvalid = errors.New("grant invalid")

type grant struct {
	subject     policy.Subject
	created     time.Time
	lastUsed    time.Time
	stepUpUntil time.Time
}

// GrantStore holds helper-issued grants. The web process only ever sees the
// opaque token; the helper keeps the SHA-256 hash. Grants are bound to an
// account; revoking an account's grants ends all its sessions.
type GrantStore struct {
	mu       sync.Mutex
	grants   map[string]*grant // key: token hash
	idle     time.Duration
	absolute time.Duration
}

// NewGrantStore creates a store with clamped lifetimes.
func NewGrantStore(idle, absolute time.Duration) *GrantStore {
	return &GrantStore{grants: map[string]*grant{}, idle: clamp(idle, MinIdle, MaxIdle, DefaultIdle),
		absolute: clamp(absolute, MinAbsolute, MaxAbsolute, DefaultAbsolute)}
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

// Issue creates a grant for a freshly authenticated subject (called only after
// the helper itself verified a WebAuthn assertion). UID 0 mappings are refused.
func (g *GrantStore) Issue(s policy.Subject, now time.Time) (string, error) {
	if s.LinuxUID == 0 || !policy.ValidRole(s.Role) || s.AccountID == "" {
		return "", errors.New("grant: refusing invalid subject")
	}
	s.StepUp = false
	tok, err := auth.NewToken("grant")
	if err != nil {
		return "", err
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.grants[auth.Hash(tok)] = &grant{subject: s, created: now, lastUsed: now}
	return tok, nil
}

// Resolve validates a grant and returns the subject with current step-up state.
// It also slides the idle timeout.
func (g *GrantStore) Resolve(tok string, now time.Time) (policy.Subject, string, error) {
	if tok == "" {
		return policy.Subject{}, "", ErrGrantInvalid
	}
	h := auth.Hash(tok)
	g.mu.Lock()
	defer g.mu.Unlock()
	gr, ok := g.grants[h]
	if !ok {
		return policy.Subject{}, "", ErrGrantInvalid
	}
	if now.Sub(gr.lastUsed) >= g.idle || now.Sub(gr.created) >= g.absolute {
		delete(g.grants, h)
		return policy.Subject{}, "", ErrGrantInvalid
	}
	gr.lastUsed = now
	s := gr.subject
	s.StepUp = now.Before(gr.stepUpUntil)
	return s, "sha256:" + h[:16], nil
}

// MarkStepUp records a fresh, helper-verified step-up for the grant (5 min).
func (g *GrantStore) MarkStepUp(tok string, now time.Time) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	gr, ok := g.grants[auth.Hash(tok)]
	if !ok {
		return ErrGrantInvalid
	}
	gr.stepUpUntil = now.Add(auth.StepUpTTL)
	return nil
}

// Revoke ends one grant.
func (g *GrantStore) Revoke(tok string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.grants, auth.Hash(tok))
}

// RevokeAccount ends all grants of an account (recovery, deactivation, role change).
func (g *GrantStore) RevokeAccount(accountID string) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	n := 0
	for k, gr := range g.grants {
		if gr.subject.AccountID == accountID {
			delete(g.grants, k)
			n++
		}
	}
	return n
}

// Count returns the number of live grants.
func (g *GrantStore) Count() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.grants)
}
