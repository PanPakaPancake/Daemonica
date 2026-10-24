package auth

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestTokenOneTimeUse(t *testing.T) {
	s := NewMemTokenStore()
	now := time.Now()
	tok, err := Issue(s, PurposeBootstrap, "", BootstrapTTL, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(tok) < 40 || !strings.HasPrefix(tok, "dmn_bootstrap_") {
		t.Fatalf("unexpected token shape %q", tok)
	}
	if _, err := s.Peek(PurposeBootstrap, tok, now); err != nil {
		t.Fatal("peek failed")
	}
	if _, err := s.Consume(PurposeBootstrap, tok, now); err != nil {
		t.Fatal("first consume failed")
	}
	if _, err := s.Consume(PurposeBootstrap, tok, now); !errors.Is(err, ErrTokenInvalid) {
		t.Fatal("token usable twice")
	}
}

func TestTokenExpiryAndPurpose(t *testing.T) {
	s := NewMemTokenStore()
	now := time.Now()
	tok, _ := Issue(s, PurposeRecovery, "acc1", RecoveryTTL, now)
	if _, err := s.Consume(PurposeBootstrap, tok, now); err == nil {
		t.Fatal("wrong purpose accepted")
	}
	if _, err := s.Consume(PurposeRecovery, tok, now.Add(RecoveryTTL)); err == nil {
		t.Fatal("expired token accepted")
	}
}

func TestReissueRevokesPrevious(t *testing.T) {
	s := NewMemTokenStore()
	now := time.Now()
	old, _ := Issue(s, PurposeBootstrap, "", BootstrapTTL, now)
	newer, _ := Issue(s, PurposeBootstrap, "", BootstrapTTL, now)
	if _, err := s.Consume(PurposeBootstrap, old, now); err == nil {
		t.Fatal("old token still valid after reissue")
	}
	if _, err := s.Consume(PurposeBootstrap, newer, now); err != nil {
		t.Fatal("new token invalid")
	}
}

func TestHashIsNotToken(t *testing.T) {
	tok, _ := NewToken(PurposeInvite)
	if Hash(tok) == tok || len(Hash(tok)) != 64 {
		t.Fatal("hash shape wrong")
	}
}
