package auth

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// Ceremony kinds.
const (
	CeremonyRegister = "register"
	CeremonyLogin    = "login"
	CeremonyStepUp   = "stepup"
)

// MaxCeremonies bounds pending ceremonies (DoS protection; SPEC §6.5 SA-11).
const MaxCeremonies = 1000

// ErrCeremony is returned for unknown, expired, reused or mismatching ceremonies
// and for any verification failure. Callers must not reveal which case occurred.
var ErrCeremony = errors.New("passkey verification failed")

// User adapts an account to webauthn.User.
type User struct {
	Handle      []byte
	Name        string
	DisplayName string
	Credentials []webauthn.Credential
}

// WebAuthnID implements webauthn.User.
func (u *User) WebAuthnID() []byte { return u.Handle }

// WebAuthnName implements webauthn.User.
func (u *User) WebAuthnName() string { return u.Name }

// WebAuthnDisplayName implements webauthn.User.
func (u *User) WebAuthnDisplayName() string { return u.DisplayName }

// WebAuthnCredentials implements webauthn.User.
func (u *User) WebAuthnCredentials() []webauthn.Credential { return u.Credentials }

type ceremony struct {
	kind    string
	session webauthn.SessionData
	binding string // account ID (register/step-up) or "" (login)
	expires time.Time
}

// Passkeys performs WebAuthn ceremonies with the SPEC §3.3 profile:
// user verification required, resident (discoverable) keys required,
// attestation none, exact RP ID and origins, one-time 120 s challenges.
type Passkeys struct {
	wa  *webauthn.WebAuthn
	mu  sync.Mutex
	cer map[string]*ceremony
	now func() time.Time
}

// NewPasskeys builds the verifier for rpID (the dashboard domain) and its exact origins.
func NewPasskeys(rpID string, origins []string) (*Passkeys, error) {
	if rpID == "" || len(origins) == 0 {
		return nil, errors.New("passkeys: RP ID and origins required")
	}
	cfg := &webauthn.Config{
		RPID:                  rpID,
		RPDisplayName:         "Daemonia",
		RPOrigins:             origins,
		AttestationPreference: protocol.PreferNoAttestation,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			ResidentKey:        protocol.ResidentKeyRequirementRequired,
			RequireResidentKey: protocol.ResidentKeyRequired(),
			UserVerification:   protocol.VerificationRequired,
		},
		Timeouts: webauthn.TimeoutsConfig{
			Login:        webauthn.TimeoutConfig{Enforce: true, Timeout: ChallengeTTL, TimeoutUVD: ChallengeTTL},
			Registration: webauthn.TimeoutConfig{Enforce: true, Timeout: ChallengeTTL, TimeoutUVD: ChallengeTTL},
		},
	}
	wa, err := webauthn.New(cfg)
	if err != nil {
		return nil, err
	}
	return &Passkeys{wa: wa, cer: map[string]*ceremony{}, now: time.Now}, nil
}

func (p *Passkeys) put(kind, binding string, s *webauthn.SessionData) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	for k, c := range p.cer {
		if now.After(c.expires) {
			delete(p.cer, k)
		}
	}
	if len(p.cer) >= MaxCeremonies {
		return "", errors.New("passkeys: too many pending ceremonies")
	}
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	id := hex.EncodeToString(b)
	p.cer[id] = &ceremony{kind: kind, session: *s, binding: binding, expires: now.Add(ChallengeTTL)}
	return id, nil
}

// take removes and returns a ceremony (single use), checking kind, binding and expiry.
func (p *Passkeys) take(id, kind, binding string) (*ceremony, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	c, ok := p.cer[id]
	if !ok {
		return nil, ErrCeremony
	}
	delete(p.cer, id)
	if c.kind != kind || c.binding != binding || p.now().After(c.expires) {
		return nil, ErrCeremony
	}
	return c, nil
}

// BeginRegistration starts enrolling a new passkey for u (bound to accountID).
func (p *Passkeys) BeginRegistration(accountID string, u *User) (string, json.RawMessage, error) {
	excl := webauthn.Credentials(u.Credentials).CredentialDescriptors()
	opts, sess, err := p.wa.BeginRegistration(u,
		webauthn.WithExclusions(excl),
		webauthn.WithConveyancePreference(protocol.PreferNoAttestation),
		webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired),
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			ResidentKey:        protocol.ResidentKeyRequirementRequired,
			RequireResidentKey: protocol.ResidentKeyRequired(),
			UserVerification:   protocol.VerificationRequired,
		}),
	)
	if err != nil {
		return "", nil, err
	}
	id, err := p.put(CeremonyRegister, accountID, sess)
	if err != nil {
		return "", nil, err
	}
	raw, err := json.Marshal(opts)
	return id, raw, err
}

// FinishRegistration verifies the attestation response and returns the new credential.
func (p *Passkeys) FinishRegistration(ceremonyID, accountID string, u *User, response []byte) (*webauthn.Credential, error) {
	c, err := p.take(ceremonyID, CeremonyRegister, accountID)
	if err != nil {
		return nil, err
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(response)
	if err != nil {
		return nil, ErrCeremony
	}
	cred, err := p.wa.CreateCredential(u, c.session, parsed)
	if err != nil || !cred.Flags.UserVerified {
		return nil, ErrCeremony
	}
	return cred, nil
}

// BeginLogin starts a username-less (discoverable) login.
func (p *Passkeys) BeginLogin() (string, json.RawMessage, error) {
	opts, sess, err := p.wa.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		return "", nil, err
	}
	id, err := p.put(CeremonyLogin, "", sess)
	if err != nil {
		return "", nil, err
	}
	raw, err := json.Marshal(opts)
	return id, raw, err
}

// FinishLogin verifies a discoverable assertion. lookup resolves the user handle
// to a user with its stored credentials. Returns the user handle and the updated credential.
func (p *Passkeys) FinishLogin(ceremonyID string, response []byte, lookup func(handle []byte) (*User, error)) ([]byte, *webauthn.Credential, error) {
	c, err := p.take(ceremonyID, CeremonyLogin, "")
	if err != nil {
		return nil, nil, err
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(response)
	if err != nil {
		return nil, nil, ErrCeremony
	}
	var handle []byte
	handler := func(rawID, userHandle []byte) (webauthn.User, error) {
		u, err := lookup(userHandle)
		if err != nil {
			return nil, err
		}
		handle = userHandle
		return u, nil
	}
	_, cred, err := p.wa.ValidatePasskeyLogin(handler, c.session, parsed)
	if err != nil || cred == nil || !cred.Flags.UserVerified || cred.Authenticator.CloneWarning {
		return nil, nil, ErrCeremony
	}
	return handle, cred, nil
}

// BeginStepUp starts a re-verification for an already authenticated user.
func (p *Passkeys) BeginStepUp(accountID string, u *User) (string, json.RawMessage, error) {
	opts, sess, err := p.wa.BeginLogin(u, webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		return "", nil, err
	}
	id, err := p.put(CeremonyStepUp, accountID, sess)
	if err != nil {
		return "", nil, err
	}
	raw, err := json.Marshal(opts)
	return id, raw, err
}

// FinishStepUp verifies the step-up assertion for the same account.
func (p *Passkeys) FinishStepUp(ceremonyID, accountID string, u *User, response []byte) (*webauthn.Credential, error) {
	c, err := p.take(ceremonyID, CeremonyStepUp, accountID)
	if err != nil {
		return nil, err
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(response)
	if err != nil {
		return nil, ErrCeremony
	}
	if !bytes.Equal(parsed.Response.UserHandle, nil) && !bytes.Equal(parsed.Response.UserHandle, u.Handle) {
		return nil, ErrCeremony
	}
	cred, err := p.wa.ValidateLogin(u, c.session, parsed)
	if err != nil || !cred.Flags.UserVerified || cred.Authenticator.CloneWarning {
		return nil, ErrCeremony
	}
	return cred, nil
}
