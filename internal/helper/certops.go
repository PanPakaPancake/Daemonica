package helper

import (
	"context"
	"os"
	"path/filepath"
	"time"

	"github.com/PanPakaPancake/daemonica/internal/acme"
	"github.com/PanPakaPancake/daemonica/internal/rpc"
	"github.com/PanPakaPancake/daemonica/internal/tlsconf"
)

// CertOps installs the dashboard certificate (SPEC §3.6): own PEM upload or
// Let's Encrypt via HTTP-01 / TLS-ALPN-01. Files are written for the web
// process only: <TLSDir>/fullchain.pem and privkey.pem, owner daemonica-web, 0600.
type CertOps struct {
	Config   *ConfigStore
	Guard    func(token string) error // setup guard (bootstrap token + setup mode)
	TLSDir   string
	StateDir string // ACME account keys
	WebUID   int
	WebGID   int
	Now      func() time.Time
}

type acmeParams struct {
	Token    string `json:"token"`
	Method   string `json:"method"`
	CA       string `json:"ca"` // "staging" | "production"
	AgreeTOS bool   `json:"agree_tos"`
}

type pemParams struct {
	Token   string `json:"token"`
	CertPEM string `json:"cert_pem"`
	KeyPEM  string `json:"key_pem"`
}

// CertInfo summarises the installed certificate.
type CertInfo struct {
	Domain   string    `json:"domain"`
	NotAfter time.Time `json:"not_after"`
	DaysLeft int       `json:"days_left"`
	Source   string    `json:"source"`
}

func (c *CertOps) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c *CertOps) install(certPEM, keyPEM []byte) error {
	if err := os.MkdirAll(c.TLSDir, 0o700); err != nil {
		return err
	}
	_ = os.Chown(c.TLSDir, c.WebUID, c.WebGID)
	for name, data := range map[string][]byte{"privkey.pem": keyPEM, "fullchain.pem": certPEM} {
		p := filepath.Join(c.TLSDir, name)
		if err := WriteFileAtomic(p, data, 0o600); err != nil {
			return err
		}
		if err := os.Chown(p, c.WebUID, c.WebGID); err != nil {
			return err
		}
	}
	return nil
}

// Register installs the certificate operations.
func (c *CertOps) Register(ops map[string]*Op) {
	Register(ops, &Op{Name: "setup.acme_issue", PreAuth: true, Timeout: 4 * time.Minute,
		Handle: func(ctx context.Context, call Call) (any, error) {
			var p acmeParams
			if err := decode(call, &p); err != nil {
				return nil, err
			}
			if err := c.Guard(p.Token); err != nil {
				return nil, err
			}
			cfg := c.Config.Get()
			if cfg.Domain == "" {
				return nil, Errf(rpc.CodeValidation, "set the domain first")
			}
			ca := acme.Staging
			if p.CA == "production" {
				ca = acme.Production
			} else if p.CA != "staging" {
				return nil, Errf(rpc.CodeValidation, "ca must be staging or production")
			}
			if !p.AgreeTOS {
				return nil, Errf(rpc.CodeValidation, "terms of service must be accepted")
			}
			m := acme.Method(p.Method)
			if m != acme.HTTP01 && m != acme.TLSALPN01 {
				return nil, Errf(rpc.CodeValidation, "method must be http-01 or tls-alpn-01")
			}
			res, err := acme.Obtain(ctx, acme.Request{Domain: cfg.Domain, Method: m, CA: ca, StateDir: filepath.Join(c.StateDir, "acme"), AgreeTOS: true})
			if err != nil {
				return nil, Errf(rpc.CodeUnavailable, "%s", err.Error())
			}
			if err := c.install(res.CertPEM, res.KeyPEM); err != nil {
				return nil, err
			}
			src := "acme-" + p.CA
			if _, err := c.Config.Update(func(cf *Config) error { cf.TLSSource = src; return nil }); err != nil {
				return nil, err
			}
			return CertInfo{Domain: cfg.Domain, NotAfter: res.NotAfter, DaysLeft: int(time.Until(res.NotAfter).Hours() / 24), Source: src}, nil
		}})

	Register(ops, &Op{Name: "setup.upload_cert", PreAuth: true,
		Handle: func(_ context.Context, call Call) (any, error) {
			var p pemParams
			if err := decode(call, &p); err != nil {
				return nil, err
			}
			if err := c.Guard(p.Token); err != nil {
				return nil, err
			}
			cfg := c.Config.Get()
			if cfg.Domain == "" {
				return nil, Errf(rpc.CodeValidation, "set the domain first")
			}
			cert, err := tlsconf.CheckCertificate([]byte(p.CertPEM), []byte(p.KeyPEM), cfg.Domain, c.now())
			if err != nil {
				return nil, Errf(rpc.CodeValidation, "%s", err.Error())
			}
			if err := c.install([]byte(p.CertPEM), []byte(p.KeyPEM)); err != nil {
				return nil, err
			}
			if _, err := c.Config.Update(func(cf *Config) error { cf.TLSSource = "own"; return nil }); err != nil {
				return nil, err
			}
			return CertInfo{Domain: cfg.Domain, NotAfter: cert.Leaf.NotAfter, DaysLeft: tlsconf.DaysLeft(cert, c.now()), Source: "own"}, nil
		}})
}
