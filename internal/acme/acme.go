// Package acme is the reusable ACME client used for the dashboard certificate
// (SPEC §3.6) and, in Phase 3, for nginx sites. It wraps lego with the
// project's constraints: ECDSA P-256 keys, explicit CA choice (staging is the
// default for tests), HTTP-01/TLS-ALPN-01 only in a short-lived "ACME window",
// DNS-01 guided: the operator creates the TXT record by hand (SPEC §3.6 b).
package acme

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/challenge/http01"
	"github.com/go-acme/lego/v4/challenge/tlsalpn01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
)

// CA directory URLs.
const (
	Staging    = lego.LEDirectoryStaging
	Production = lego.LEDirectoryProduction
)

// Method is the challenge type.
type Method string

// Supported methods.
const (
	HTTP01    Method = "http-01"
	TLSALPN01 Method = "tls-alpn-01"
	DNS01     Method = "dns-01"
)

// DNSTimeout is how long a guided DNS-01 challenge waits for the operator
// and for the record to reach all authoritative name servers.
const DNSTimeout = 30 * time.Minute

// Guide connects a guided DNS-01 challenge with the operator.
type Guide struct {
	// Record is called with the TXT record to create (name without trailing dot).
	Record func(name, value string)
	// Confirmed reports whether the operator says the record is in place;
	// until then the record is not checked.
	Confirmed func() bool
	// Checked receives every propagation check (authoritative name servers).
	Checked func(ok bool, err error)
}

// guided is the lego DNS provider for Guide: it presents nothing itself.
type guided struct{ g *Guide }

func (m guided) Present(domain, _, keyAuth string) error {
	i := dns01.GetChallengeInfo(domain, keyAuth)
	m.g.Record(dns01.UnFqdn(i.EffectiveFQDN), i.Value)
	return nil
}

func (guided) CleanUp(string, string, string) error { return nil }

func (guided) Timeout() (time.Duration, time.Duration) { return DNSTimeout, 10 * time.Second }

// Request describes one issuance.
type Request struct {
	Domain   string
	Method   Method
	CA       string // Staging or Production
	StateDir string // holds the ACME account key (0600)
	// AgreeTOS must be true: the operator accepted the CA's terms in the UI.
	AgreeTOS bool
	// Guide is required for DNS01.
	Guide *Guide
}

// Result carries PEM-encoded certificate chain and private key.
type Result struct {
	CertPEM  []byte
	KeyPEM   []byte
	NotAfter time.Time
}

type acmeUser struct {
	key crypto.PrivateKey
	reg *registration.Resource
}

func (u *acmeUser) GetEmail() string                        { return "" }
func (u *acmeUser) GetRegistration() *registration.Resource { return u.reg }
func (u *acmeUser) GetPrivateKey() crypto.PrivateKey        { return u.key }

// PortFree reports whether a TCP port can be bound on all addresses (preflight).
func PortFree(port string) bool {
	l, err := net.Listen("tcp", ":"+port)
	if err != nil {
		return false
	}
	_ = l.Close()
	return true
}

func accountKey(dir, ca string) (crypto.PrivateKey, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	name := "account-staging.key"
	if ca == Production {
		name = "account-production.key"
	}
	p := filepath.Join(dir, name)
	if b, err := os.ReadFile(p); err == nil { //nolint:gosec // helper state dir
		blk, _ := pem.Decode(b)
		if blk == nil {
			return nil, errors.New("acme: corrupt account key")
		}
		return x509.ParseECPrivateKey(blk.Bytes)
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		return nil, err
	}
	return k, nil
}

// Obtain issues a certificate. The caller is responsible for opening and
// closing firewall access to port 80/443 around this call (ACME window).
func Obtain(ctx context.Context, r Request) (*Result, error) {
	if !r.AgreeTOS {
		return nil, errors.New("acme: terms of service not accepted")
	}
	if r.CA != Staging && r.CA != Production {
		return nil, errors.New("acme: unknown CA")
	}
	key, err := accountKey(r.StateDir, r.CA)
	if err != nil {
		return nil, err
	}
	u := &acmeUser{key: key}
	cfg := lego.NewConfig(u)
	cfg.CADirURL = r.CA
	cfg.Certificate.KeyType = certcrypto.EC256
	cfg.UserAgent = "daemonica"
	client, err := lego.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("acme: client: %w", err)
	}
	switch r.Method {
	case HTTP01:
		if !PortFree("80") {
			return nil, errors.New("acme: port 80 is in use")
		}
		if err := client.Challenge.SetHTTP01Provider(http01.NewProviderServer("", "80")); err != nil {
			return nil, err
		}
	case TLSALPN01:
		if !PortFree("443") {
			return nil, errors.New("acme: port 443 is in use")
		}
		if err := client.Challenge.SetTLSALPN01Provider(tlsalpn01.NewProviderServer("", "443")); err != nil {
			return nil, err
		}
	case DNS01:
		if r.Guide == nil {
			return nil, errors.New("acme: dns-01 needs a guide")
		}
		g := r.Guide
		err := client.Challenge.SetDNS01Provider(guided{g}, dns01.WrapPreCheck(func(_, fqdn, value string, check dns01.PreCheckFunc) (bool, error) {
			if ctx.Err() != nil {
				return true, ctx.Err() // ends lego's wait loop
			}
			if !g.Confirmed() {
				return false, nil
			}
			ok, err := check(fqdn, value)
			g.Checked(ok, err)
			return ok, nil
		}))
		if err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("acme: unsupported method")
	}
	reg, err := client.Registration.ResolveAccountByKey()
	if err != nil {
		reg, err = client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			return nil, fmt.Errorf("acme: registration: %w", err)
		}
	}
	u.reg = reg

	type out struct {
		res *certificate.Resource
		err error
	}
	ch := make(chan out, 1)
	go func() {
		res, err := client.Certificate.Obtain(certificate.ObtainRequest{Domains: []string{r.Domain}, Bundle: true})
		ch <- out{res, err}
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case o := <-ch:
		if o.err != nil {
			return nil, fmt.Errorf("acme: obtain: %w", o.err)
		}
		certs, err := certcrypto.ParsePEMBundle(o.res.Certificate)
		if err != nil || len(certs) == 0 {
			return nil, errors.New("acme: invalid certificate returned")
		}
		return &Result{CertPEM: o.res.Certificate, KeyPEM: o.res.PrivateKey, NotAfter: certs[0].NotAfter}, nil
	}
}
