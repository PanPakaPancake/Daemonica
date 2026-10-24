// Package auth contains authentication primitives shared by the helper:
// one-time tokens (bootstrap, recovery, invitations), session token hashing
// and the step-up state model. WebAuthn ceremonies are verified in the helper
// (SPEC §3.2 rule 5) using these primitives.
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"time"
)

// TokenBytes is the entropy of all one-time and session tokens (256 bit).
const TokenBytes = 32

// Token purposes.
const (
	PurposeBootstrap = "bootstrap"
	PurposeRecovery  = "recovery"
	PurposeInvite    = "invite"
)

// Default lifetimes (SPEC §3.3, §7.1).
const (
	BootstrapTTL = 60 * time.Minute
	RecoveryTTL  = 30 * time.Minute
	InviteTTL    = 60 * time.Minute
	StepUpTTL    = 5 * time.Minute
	ChallengeTTL = 120 * time.Second
)

// ErrTokenInvalid is returned for unknown, expired, consumed or mismatching tokens.
// Callers MUST NOT distinguish these cases toward the client.
var ErrTokenInvalid = errors.New("token invalid")

// NewToken returns a new random token in URL-safe base64 (no padding) with a
// purpose prefix, e.g. "dmn_bootstrap_...".
func NewToken(purpose string) (string, error) {
	b := make([]byte, TokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "dmn_" + purpose + "_" + base64.RawURLEncoding.EncodeToString(b), nil
}

// Hash returns the storage form of a token (SHA-256, hex). Tokens are never stored in clear.
func Hash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// OneTimeToken is the stored form.
type OneTimeToken struct {
	Purpose   string
	Hash      string
	Subject   string // e.g. account ID for recovery/invite; empty for bootstrap
	ExpiresAt time.Time
	Used      bool
	Meta      map[string]string
}

// TokenStore persists one-time tokens. Implementations must make Consume atomic.
type TokenStore interface {
	Put(t OneTimeToken) error
	// Consume marks the token as used and returns it if it is valid for purpose.
	Consume(purpose, presented string, now time.Time) (OneTimeToken, error)
	// Peek validates without consuming (used to show the setup wizard after token entry).
	Peek(purpose, presented string, now time.Time) (OneTimeToken, error)
	// RevokePurpose invalidates all tokens of a purpose (and subject, if non-empty).
	RevokePurpose(purpose, subject string) error
}

// MemTokenStore is an in-memory TokenStore (tests and as a building block).
type MemTokenStore struct {
	mu     sync.Mutex
	tokens map[string]*OneTimeToken
}

// NewMemTokenStore creates an empty store.
func NewMemTokenStore() *MemTokenStore {
	return &MemTokenStore{tokens: map[string]*OneTimeToken{}}
}

// Put stores a token (by hash).
func (s *MemTokenStore) Put(t OneTimeToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := t
	s.tokens[t.Hash] = &cp
	return nil
}

func (s *MemTokenStore) find(purpose, presented string, now time.Time) (*OneTimeToken, error) {
	if !strings.HasPrefix(presented, "dmn_"+purpose+"_") {
		return nil, ErrTokenInvalid
	}
	h := Hash(presented)
	var match *OneTimeToken
	// Constant-time comparison against all candidates to avoid timing side channels.
	for k, t := range s.tokens {
		if subtle.ConstantTimeCompare([]byte(k), []byte(h)) == 1 {
			match = t
		}
	}
	if match == nil || match.Purpose != purpose || match.Used || !now.Before(match.ExpiresAt) {
		return nil, ErrTokenInvalid
	}
	return match, nil
}

// Consume validates and marks a token as used.
func (s *MemTokenStore) Consume(purpose, presented string, now time.Time) (OneTimeToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, err := s.find(purpose, presented, now)
	if err != nil {
		return OneTimeToken{}, err
	}
	t.Used = true
	return *t, nil
}

// Peek validates without consuming.
func (s *MemTokenStore) Peek(purpose, presented string, now time.Time) (OneTimeToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, err := s.find(purpose, presented, now)
	if err != nil {
		return OneTimeToken{}, err
	}
	return *t, nil
}

// RevokePurpose marks matching tokens as used.
func (s *MemTokenStore) RevokePurpose(purpose, subject string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, t := range s.tokens {
		if t.Purpose == purpose && (subject == "" || t.Subject == subject) {
			t.Used = true
		}
	}
	return nil
}

// Issue creates a token, stores its hash and returns the clear token exactly once.
// Issuing a new bootstrap/recovery token revokes earlier unused ones of the same scope.
func Issue(store TokenStore, purpose, subject string, ttl time.Duration, now time.Time) (string, error) {
	if err := store.RevokePurpose(purpose, subject); err != nil {
		return "", err
	}
	tok, err := NewToken(purpose)
	if err != nil {
		return "", err
	}
	err = store.Put(OneTimeToken{Purpose: purpose, Hash: Hash(tok), Subject: subject, ExpiresAt: now.Add(ttl)})
	if err != nil {
		return "", err
	}
	return tok, nil
}
