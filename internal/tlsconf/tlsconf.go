// Package tlsconf provides the dashboard's TLS configuration (SPEC §3.6):
// TLS 1.3 only, ECDSA P-256 certificates, hot-swappable certificate.
package tlsconf

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"sync/atomic"
	"time"
)

// Holder stores the active certificate and allows atomic replacement
// (e.g. after ACME renewal) without restarting the listener.
type Holder struct {
	cert atomic.Pointer[tls.Certificate]
}

// Set replaces the active certificate.
func (h *Holder) Set(c *tls.Certificate) { h.cert.Store(c) }

// Get returns the active certificate.
func (h *Holder) Get() *tls.Certificate { return h.cert.Load() }

// Config returns a TLS 1.3-only server config backed by h.
func Config(h *Holder) *tls.Config {
	return &tls.Config{
		MinVersion:       tls.VersionTLS13,
		MaxVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256},
		NextProtos:       []string{"h2", "http/1.1"},
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			c := h.Get()
			if c == nil {
				return nil, errors.New("tls: no certificate configured")
			}
			return c, nil
		},
	}
}

// SelfSignedSetup creates an ephemeral ECDSA P-256 certificate for setup
// mode on loopback. It is never persisted and never used once a real
// certificate is configured. The key lives only in memory.
func SelfSignedSetup(names []string, ips []net.IP, validity time.Duration) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "daemonia-setup"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(validity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              names,
		IPAddresses:           ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, nil
}

// CheckCertificate validates an operator-supplied certificate (PEM) and key:
// key must be ECDSA P-256 (SPEC §3.6), chain must cover the domain and be currently valid.
func CheckCertificate(certPEM, keyPEM []byte, domain string, now time.Time) (*tls.Certificate, error) {
	c, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, errors.New("certificate and key do not form a valid pair")
	}
	leaf, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		return nil, errors.New("unparseable certificate")
	}
	pk, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || pk.Curve != elliptic.P256() {
		return nil, errors.New("certificate key must be ECDSA P-256")
	}
	if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
		return nil, errors.New("certificate is not currently valid")
	}
	if err := leaf.VerifyHostname(domain); err != nil {
		return nil, errors.New("certificate does not cover the configured domain")
	}
	c.Leaf = leaf
	return &c, nil
}

// DaysLeft returns the remaining validity in whole days (negative if expired).
func DaysLeft(c *tls.Certificate, now time.Time) int {
	if c == nil || c.Leaf == nil {
		return -1
	}
	return int(c.Leaf.NotAfter.Sub(now).Hours() / 24)
}
