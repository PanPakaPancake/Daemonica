// Package softauthn is a minimal software WebAuthn authenticator for tests.
// It produces "none" attestation registrations and ES256 assertions with
// user presence + user verification, discoverable credentials (user handle
// returned in assertions), and an incrementing signature counter.
// It is used only from tests; it never ships in production code paths.
package softauthn

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"

	"github.com/fxamacker/cbor/v2"
)

var b64 = base64.RawURLEncoding

// Flags.
const (
	FlagUP = 0x01
	FlagUV = 0x04
	FlagBE = 0x08
	FlagBS = 0x10
	FlagAT = 0x40
)

// Credential is a credential held by the authenticator.
type Credential struct {
	ID         []byte
	Key        *ecdsa.PrivateKey
	RPID       string
	UserHandle []byte
	Counter    uint32
}

// Authenticator holds credentials.
type Authenticator struct {
	Creds []*Credential
	// Flags controls UP/UV/BE/BS bits (default UP|UV).
	Flags byte
	// CounterStep is added to the counter per assertion (0 = counter not used).
	CounterStep uint32
}

// New returns an authenticator with UP|UV and a counter step of 1.
func New() *Authenticator { return &Authenticator{Flags: FlagUP | FlagUV, CounterStep: 1} }

type creationOptions struct {
	PublicKey struct {
		Challenge string `json:"challenge"`
		RP        struct {
			ID string `json:"id"`
		} `json:"rp"`
		User struct {
			ID string `json:"id"`
		} `json:"user"`
	} `json:"publicKey"`
}

type requestOptions struct {
	PublicKey struct {
		Challenge string `json:"challenge"`
		RPID      string `json:"rpId"`
	} `json:"publicKey"`
}

func clientData(typ, challenge, origin string) []byte {
	b, _ := json.Marshal(map[string]any{"type": typ, "challenge": challenge, "origin": origin, "crossOrigin": false})
	return b
}

func authData(rpID string, flags byte, counter uint32, attested []byte) []byte {
	h := sha256.Sum256([]byte(rpID))
	out := append([]byte{}, h[:]...)
	out = append(out, flags)
	var c [4]byte
	binary.BigEndian.PutUint32(c[:], counter)
	out = append(out, c[:]...)
	return append(out, attested...)
}

func coseKey(pub *ecdsa.PublicKey) []byte {
	pt, _ := pub.Bytes() // 0x04 || X || Y
	x, y := pt[1:33], pt[33:65]
	b, _ := cbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: x, -3: y})
	return b
}

// Create answers navigator.credentials.create() options (JSON as produced by the server).
// origin is the page origin the browser would report.
func (a *Authenticator) Create(optionsJSON []byte, origin string) ([]byte, *Credential, error) {
	var o creationOptions
	if err := json.Unmarshal(optionsJSON, &o); err != nil {
		return nil, nil, err
	}
	uh, err := b64.DecodeString(o.PublicKey.User.ID)
	if err != nil {
		return nil, nil, errors.New("softauthn: bad user id")
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	id := make([]byte, 32)
	_, _ = rand.Read(id)
	cred := &Credential{ID: id, Key: key, RPID: o.PublicKey.RP.ID, UserHandle: uh}

	attested := make([]byte, 16) // AAGUID zero
	var l [2]byte
	binary.BigEndian.PutUint16(l[:], uint16(len(id))) //nolint:gosec // credential IDs are 16 bytes
	attested = append(attested, l[:]...)
	attested = append(attested, id...)
	attested = append(attested, coseKey(&key.PublicKey)...)
	ad := authData(cred.RPID, a.Flags|FlagAT, 0, attested)
	att, _ := cbor.Marshal(map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": ad})
	cd := clientData("webauthn.create", o.PublicKey.Challenge, origin)
	resp, _ := json.Marshal(map[string]any{
		"id": b64.EncodeToString(id), "rawId": b64.EncodeToString(id), "type": "public-key",
		"response":                map[string]any{"clientDataJSON": b64.EncodeToString(cd), "attestationObject": b64.EncodeToString(att), "transports": []string{"internal"}},
		"clientExtensionResults":  map[string]any{},
		"authenticatorAttachment": "platform",
	})
	a.Creds = append(a.Creds, cred)
	return resp, cred, nil
}

// Get answers navigator.credentials.get() options using cred (or the first matching credential).
func (a *Authenticator) Get(optionsJSON []byte, origin string, cred *Credential) ([]byte, error) {
	var o requestOptions
	if err := json.Unmarshal(optionsJSON, &o); err != nil {
		return nil, err
	}
	if cred == nil {
		for _, c := range a.Creds {
			if c.RPID == o.PublicKey.RPID {
				cred = c
				break
			}
		}
	}
	if cred == nil {
		return nil, errors.New("softauthn: no credential for RP")
	}
	cred.Counter += a.CounterStep
	ad := authData(cred.RPID, a.Flags, cred.Counter, nil)
	cd := clientData("webauthn.get", o.PublicKey.Challenge, origin)
	h := sha256.Sum256(cd)
	sig, err := ecdsa.SignASN1(rand.Reader, cred.Key, sha256Sum(append(append([]byte{}, ad...), h[:]...)))
	if err != nil {
		return nil, err
	}
	return json.Marshal(map[string]any{
		"id": b64.EncodeToString(cred.ID), "rawId": b64.EncodeToString(cred.ID), "type": "public-key",
		"response": map[string]any{
			"clientDataJSON": b64.EncodeToString(cd), "authenticatorData": b64.EncodeToString(ad),
			"signature": b64.EncodeToString(sig), "userHandle": b64.EncodeToString(cred.UserHandle),
		},
		"clientExtensionResults": map[string]any{},
	})
}

func sha256Sum(b []byte) []byte { h := sha256.Sum256(b); return h[:] }
