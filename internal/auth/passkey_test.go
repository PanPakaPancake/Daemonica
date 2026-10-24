package auth

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/PanPakaPancake/daemonica/internal/testutil/softauthn"
)

const (
	rp     = "dash.example.org"
	origin = "https://dash.example.org:8443"
)

func newPK(t *testing.T) *Passkeys {
	t.Helper()
	p, err := NewPasskeys(rp, []string{origin})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func register(t *testing.T, p *Passkeys, sa *softauthn.Authenticator, u *User) *webauthn.Credential {
	t.Helper()
	id, opts, err := p.BeginRegistration("acc", u)
	if err != nil {
		t.Fatal(err)
	}
	var o map[string]map[string]any
	_ = json.Unmarshal(opts, &o)
	sel, _ := o["publicKey"]["authenticatorSelection"].(map[string]any)
	if sel["userVerification"] != "required" || sel["residentKey"] != "required" {
		t.Fatalf("registration options must require UV and resident keys: %v", sel)
	}
	if att, ok := o["publicKey"]["attestation"]; ok && att != "none" {
		t.Fatalf("attestation must be none, got %v", att)
	}
	resp, _, err := sa.Create(opts, origin)
	if err != nil {
		t.Fatal(err)
	}
	cred, err := p.FinishRegistration(id, "acc", u, resp)
	if err != nil {
		t.Fatalf("registration failed: %v", err)
	}
	u.Credentials = append(u.Credentials, *cred)
	return cred
}

func TestRegisterLoginStepUp(t *testing.T) {
	p := newPK(t)
	sa := softauthn.New()
	u := &User{Handle: []byte("0123456789abcdef0123456789abcdef"), Name: "alice", DisplayName: "Alice"}
	register(t, p, sa, u)

	id, opts, err := p.BeginLogin()
	if err != nil {
		t.Fatal(err)
	}
	resp, _ := sa.Get(opts, origin, nil)
	handle, cred, err := p.FinishLogin(id, resp, func(h []byte) (*User, error) {
		if string(h) != string(u.Handle) {
			return nil, errors.New("unknown")
		}
		return u, nil
	})
	if err != nil || string(handle) != string(u.Handle) || cred == nil {
		t.Fatalf("login failed: %v", err)
	}
	// Single use: replaying the ceremony fails.
	if _, _, err := p.FinishLogin(id, resp, func([]byte) (*User, error) { return u, nil }); !errors.Is(err, ErrCeremony) {
		t.Fatal("ceremony reuse accepted")
	}

	sid, sopts, err := p.BeginStepUp("acc", u)
	if err != nil {
		t.Fatal(err)
	}
	sresp, _ := sa.Get(sopts, origin, nil)
	if _, err := p.FinishStepUp(sid, "other-account", u, sresp); err == nil {
		t.Fatal("step-up accepted for a different account binding")
	}
	sid, sopts, _ = p.BeginStepUp("acc", u)
	sresp, _ = sa.Get(sopts, origin, nil)
	if _, err := p.FinishStepUp(sid, "acc", u, sresp); err != nil {
		t.Fatalf("step-up failed: %v", err)
	}
}

func TestRegistrationRejections(t *testing.T) {
	p := newPK(t)
	u := &User{Handle: []byte("0123456789abcdef0123456789abcdef"), Name: "bob", DisplayName: "Bob"}

	// Wrong origin.
	id, opts, _ := p.BeginRegistration("acc", u)
	resp, _, _ := softauthn.New().Create(opts, "https://evil.example.org")
	if _, err := p.FinishRegistration(id, "acc", u, resp); err == nil {
		t.Fatal("foreign origin accepted")
	}
	// No user verification.
	sa := softauthn.New()
	sa.Flags = softauthn.FlagUP
	id, opts, _ = p.BeginRegistration("acc", u)
	resp, _, _ = sa.Create(opts, origin)
	if _, err := p.FinishRegistration(id, "acc", u, resp); err == nil {
		t.Fatal("registration without UV accepted")
	}
	// Binding mismatch and garbage.
	id, opts, _ = p.BeginRegistration("acc", u)
	resp, _, _ = softauthn.New().Create(opts, origin)
	if _, err := p.FinishRegistration(id, "acc2", u, resp); err == nil {
		t.Fatal("binding mismatch accepted")
	}
	id, _, _ = p.BeginRegistration("acc", u)
	if _, err := p.FinishRegistration(id, "acc", u, []byte(`{"garbage":true}`)); err == nil {
		t.Fatal("garbage accepted")
	}
	if _, err := p.FinishRegistration("unknown", "acc", u, resp); !errors.Is(err, ErrCeremony) {
		t.Fatal("unknown ceremony accepted")
	}
}

func TestCeremonyExpiry(t *testing.T) {
	p := newPK(t)
	now := time.Now()
	p.now = func() time.Time { return now }
	id, _, _ := p.BeginLogin()
	now = now.Add(ChallengeTTL + time.Second)
	if _, _, err := p.FinishLogin(id, []byte(`{}`), func([]byte) (*User, error) { return nil, errors.New("x") }); !errors.Is(err, ErrCeremony) {
		t.Fatal("expired ceremony accepted")
	}
}

func TestCeremonyLimit(t *testing.T) {
	p := newPK(t)
	for i := 0; i < MaxCeremonies; i++ {
		if _, _, err := p.BeginLogin(); err != nil {
			t.Fatalf("ceremony %d refused early", i)
		}
	}
	if _, _, err := p.BeginLogin(); err == nil {
		t.Fatal("ceremony limit not enforced")
	}
}

func TestNewPasskeysRequiresConfig(t *testing.T) {
	if _, err := NewPasskeys("", nil); err == nil {
		t.Fatal("empty config accepted")
	}
}

func TestMemTokenStorePeekAndRevoke(t *testing.T) {
	s := NewMemTokenStore()
	tok, _ := Issue(s, PurposeRecovery, "a1", time.Hour, time.Now())
	if _, err := s.Peek(PurposeRecovery, "dmn_recovery_x", time.Now()); err == nil {
		t.Fatal("bogus token accepted")
	}
	_ = s.RevokePurpose(PurposeRecovery, "a1")
	if _, err := s.Peek(PurposeRecovery, tok, time.Now()); err == nil {
		t.Fatal("revoked token still valid")
	}
}
