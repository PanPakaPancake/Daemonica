package helper

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/PanPakaPancake/daemonica/internal/acme"
	"github.com/PanPakaPancake/daemonica/internal/audit"
	"github.com/PanPakaPancake/daemonica/internal/policy"
	"github.com/PanPakaPancake/daemonica/internal/rpc"
	"github.com/PanPakaPancake/daemonica/internal/tlsconf"
)

// CertOps installs the dashboard certificate (SPEC §3.6): own PEM upload or
// Let's Encrypt via HTTP-01 / TLS-ALPN-01 or guided DNS-01, from the setup
// wizard and from the settings, and renews ACME certificates (DEC-034).
// Files are written for the web process only: <TLSDir>/fullchain.pem and
// privkey.pem, owner daemonica-web, 0600; the web process reloads them.
type CertOps struct {
	Config   *ConfigStore
	Guard    func(token string) error // setup guard (bootstrap token + setup mode)
	TLSDir   string
	StateDir string // ACME account keys
	WebUID   int
	WebGID   int
	Now      func() time.Time
	// Window opens the firewall for an ACME challenge on port and returns
	// the function that closes it (SPEC §3.6 "ACME-Fenster"; nil = none).
	Window func(ctx context.Context, port int) (func(context.Context) error, error)
	// Obtain and PortFree are acme.Obtain and acme.PortFree (replaced in tests).
	Obtain   func(context.Context, acme.Request) (*acme.Result, error)
	PortFree func(port string) bool
	Audit    *audit.Logger

	mu        sync.Mutex
	cur       *Issuance
	cancel    context.CancelFunc
	confirmed bool
	wg        sync.WaitGroup
}

// RenewDays is the remaining validity below which ACME certificates are
// renewed automatically (HTTP-01/TLS-ALPN-01) and the UI warns (SPEC §3.6).
const RenewDays = 30

// Issuance states.
const (
	IssueRunning  = "running"
	IssueDNSWait  = "dns_wait" // TXT record shown, waiting for the operator
	IssueDNSCheck = "dns_check"
	IssueDone     = "done"
	IssueFailed   = "failed"
	IssueCanceled = "canceled"
)

// TXTRecord is the record a guided DNS-01 challenge needs.
type TXTRecord struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Issuance is the current or last ACME issuance (one at a time).
type Issuance struct {
	Method  string     `json:"method"`
	CA      string     `json:"ca"` // staging | production
	State   string     `json:"state"`
	Renewal bool       `json:"renewal,omitempty"`
	Record  *TXTRecord `json:"record,omitempty"`
	// Check is the last DNS propagation result: "" not checked yet, "ok",
	// "pending" (not on all authoritative name servers yet) or an error.
	Check    string    `json:"check,omitempty"`
	Checks   int       `json:"checks,omitempty"`
	Error    string    `json:"error,omitempty"`
	Started  time.Time `json:"started"`
	Finished time.Time `json:"finished,omitzero"`
	Cert     *CertInfo `json:"cert,omitempty"`
}

func (i *Issuance) running() bool {
	return i != nil && (i.State == IssueRunning || i.State == IssueDNSWait || i.State == IssueDNSCheck)
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

// CertInfo summarises a certificate.
type CertInfo struct {
	Domain   string    `json:"domain"`
	Names    []string  `json:"names,omitempty"`
	Issuer   string    `json:"issuer,omitempty"`
	NotAfter time.Time `json:"not_after"`
	DaysLeft int       `json:"days_left"`
	Source   string    `json:"source"`
}

// CertView is the settings view of the dashboard certificate.
type CertView struct {
	Domain string    `json:"domain"`
	Cert   *CertInfo `json:"cert,omitempty"`
	Source string    `json:"source,omitempty"` // own | acme-staging | acme-production
	Method string    `json:"method,omitempty"`
	// AutoRenew: renewed without the operator (ACME over HTTP-01/TLS-ALPN-01).
	AutoRenew bool      `json:"auto_renew"`
	RenewDays int       `json:"renew_days"`
	Issuance  *Issuance `json:"issuance,omitempty"`
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
	// The key first: the web process reloads when fullchain.pem changes.
	for _, f := range []struct {
		name string
		data []byte
	}{{"privkey.pem", keyPEM}, {"fullchain.pem", certPEM}} {
		p := filepath.Join(c.TLSDir, f.name)
		if err := WriteFileAtomic(p, f.data, 0o600); err != nil {
			return err
		}
		if err := os.Chown(p, c.WebUID, c.WebGID); err != nil {
			return err
		}
	}
	return nil
}

// Installed reads the installed certificate (nil if there is none).
func (c *CertOps) Installed() *CertInfo {
	b, err := os.ReadFile(filepath.Join(c.TLSDir, "fullchain.pem")) //nolint:gosec // fixed path
	if err != nil {
		return nil
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil
	}
	leaf, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return nil
	}
	cfg := c.Config.Get()
	return &CertInfo{Domain: cfg.Domain, Names: leaf.DNSNames, Issuer: leaf.Issuer.CommonName, NotAfter: leaf.NotAfter,
		DaysLeft: int(leaf.NotAfter.Sub(c.now()).Hours() / 24), Source: cfg.TLSSource}
}

// autoRenew reports whether the configured certificate renews by itself.
func autoRenew(cfg Config) bool {
	return (cfg.TLSSource == "acme-staging" || cfg.TLSSource == "acme-production") &&
		(cfg.TLSMethod == string(acme.HTTP01) || cfg.TLSMethod == string(acme.TLSALPN01))
}

func (c *CertOps) snapshot() *Issuance {
	if c.cur == nil {
		return nil
	}
	i := *c.cur
	if i.Record != nil {
		r := *i.Record
		i.Record = &r
	}
	return &i
}

// Current returns the current or last issuance.
func (c *CertOps) Current() *Issuance {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.snapshot()
}

func (c *CertOps) update(f func(*Issuance)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	f(c.cur)
}

func checkACME(p acmeParams) (acme.Method, error) {
	if p.CA != "staging" && p.CA != "production" {
		return "", Errf(rpc.CodeValidation, "ca must be staging or production")
	}
	if !p.AgreeTOS {
		return "", Errf(rpc.CodeValidation, "terms of service must be accepted")
	}
	m := acme.Method(p.Method)
	if m != acme.HTTP01 && m != acme.TLSALPN01 && m != acme.DNS01 {
		return "", Errf(rpc.CodeValidation, "method must be http-01, tls-alpn-01 or dns-01")
	}
	return m, nil
}

// Start begins an ACME issuance in the background and returns its state.
func (c *CertOps) Start(m acme.Method, ca string, renewal bool, actor audit.Actor) (*Issuance, error) {
	cfg := c.Config.Get()
	if cfg.Domain == "" {
		return nil, Errf(rpc.CodeValidation, "set the domain first")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cur.running() {
		return nil, Errf(rpc.CodeConflict, "an issuance is already running")
	}
	timeout := 5 * time.Minute
	if m == acme.DNS01 {
		timeout = acme.DNSTimeout + 5*time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	c.cur = &Issuance{Method: string(m), CA: ca, State: IssueRunning, Renewal: renewal, Started: c.now()}
	c.cancel, c.confirmed = cancel, false
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		defer cancel()
		c.run(ctx, cfg.Domain, m, ca, renewal, actor)
	}()
	return c.snapshot(), nil
}

func (c *CertOps) run(ctx context.Context, domain string, m acme.Method, ca string, renewal bool, actor audit.Actor) {
	info, err := c.issue(ctx, domain, m, ca)
	state, msg := IssueDone, ""
	switch {
	case errors.Is(err, context.Canceled):
		state = IssueCanceled
	case err != nil:
		state, msg = IssueFailed, clipMsg(err.Error(), 500)
	}
	c.update(func(i *Issuance) {
		i.State, i.Error, i.Finished, i.Cert = state, msg, c.now(), info
	})
	if c.Audit != nil {
		ev := audit.Event{Action: "cert.issued", Target: "cert:" + domain, Result: audit.ResultOK, Actor: actor,
			Params: map[string]string{"method": string(m), "ca": ca, "renewal": strconv.FormatBool(renewal)}}
		if state != IssueDone {
			ev.Result, ev.Reason = audit.ResultError, state
			if msg != "" {
				ev.Reason = clipMsg(msg, 200)
			}
		}
		_, _ = c.Audit.Append(ev)
	}
}

func (c *CertOps) issue(ctx context.Context, domain string, m acme.Method, ca string) (*CertInfo, error) {
	req := acme.Request{Domain: domain, Method: m, CA: acme.Staging, StateDir: filepath.Join(c.StateDir, "acme"), AgreeTOS: true}
	if ca == "production" {
		req.CA = acme.Production
	}
	port := map[acme.Method]int{acme.HTTP01: 80, acme.TLSALPN01: 443}[m]
	if port != 0 {
		free := c.PortFree
		if free == nil {
			free = acme.PortFree
		}
		if !free(strconv.Itoa(port)) {
			return nil, errors.New("port " + strconv.Itoa(port) + " is in use")
		}
		if c.Window != nil {
			closeFn, err := c.Window(ctx, port)
			if err != nil {
				return nil, errors.New("cannot open the firewall for the ACME challenge: " + err.Error())
			}
			defer func() { _ = closeFn(context.WithoutCancel(ctx)) }()
		}
	}
	if m == acme.DNS01 {
		req.Guide = &acme.Guide{
			Record: func(name, value string) {
				c.update(func(i *Issuance) { i.State, i.Record = IssueDNSWait, &TXTRecord{Name: name, Value: value} })
			},
			Confirmed: func() bool {
				c.mu.Lock()
				defer c.mu.Unlock()
				return c.confirmed
			},
			Checked: func(ok bool, err error) {
				c.update(func(i *Issuance) {
					i.Checks++
					switch {
					case ok:
						i.Check = "ok"
					case err != nil:
						i.Check = clipMsg(err.Error(), 300)
					default:
						i.Check = "pending" // not yet on all authoritative name servers
					}
				})
			},
		}
	}
	obtain := c.Obtain
	if obtain == nil {
		obtain = acme.Obtain
	}
	res, err := obtain(ctx, req)
	if err != nil {
		if ctx.Err() != nil && errors.Is(ctx.Err(), context.Canceled) {
			return nil, context.Canceled
		}
		return nil, err
	}
	if err := c.install(res.CertPEM, res.KeyPEM); err != nil {
		return nil, err
	}
	src := "acme-" + ca
	if _, err := c.Config.Update(func(cf *Config) error { cf.TLSSource, cf.TLSMethod = src, string(m); return nil }); err != nil {
		return nil, err
	}
	return &CertInfo{Domain: domain, NotAfter: res.NotAfter, DaysLeft: int(res.NotAfter.Sub(c.now()).Hours() / 24), Source: src}, nil
}

// Confirm tells a guided DNS-01 issuance that the TXT record is in place.
func (c *CertOps) Confirm() (*Issuance, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cur == nil || c.cur.State != IssueDNSWait {
		return nil, Errf(rpc.CodeConflict, "no DNS-01 challenge is waiting")
	}
	c.confirmed, c.cur.State = true, IssueDNSCheck
	return c.snapshot(), nil
}

// Cancel stops a running issuance.
func (c *CertOps) Cancel() (*Issuance, error) {
	c.mu.Lock()
	if !c.cur.running() {
		c.mu.Unlock()
		return nil, Errf(rpc.CodeConflict, "no issuance is running")
	}
	c.cancel()
	c.mu.Unlock()
	return c.Current(), nil
}

// clipMsg limits an error message for state and audit (ACME errors can
// carry long server problem documents).
func clipMsg(s string, max int) string {
	if len(s) > max {
		return strings.ToValidUTF8(s[:max], "") + "…"
	}
	return s
}

// Wait waits for the background issuance (tests, shutdown).
func (c *CertOps) Wait() { c.wg.Wait() }

func (c *CertOps) upload(certPEM, keyPEM string) (*CertInfo, error) {
	cfg := c.Config.Get()
	if cfg.Domain == "" {
		return nil, Errf(rpc.CodeValidation, "set the domain first")
	}
	if c.Current().running() {
		return nil, Errf(rpc.CodeConflict, "an issuance is running")
	}
	cert, err := tlsconf.CheckCertificate([]byte(certPEM), []byte(keyPEM), cfg.Domain, c.now())
	if err != nil {
		return nil, Errf(rpc.CodeValidation, "%s", err.Error())
	}
	if err := c.install([]byte(certPEM), []byte(keyPEM)); err != nil {
		return nil, err
	}
	if _, err := c.Config.Update(func(cf *Config) error { cf.TLSSource, cf.TLSMethod = "own", ""; return nil }); err != nil {
		return nil, err
	}
	return &CertInfo{Domain: cfg.Domain, Names: cert.Leaf.DNSNames, Issuer: cert.Leaf.Issuer.CommonName, NotAfter: cert.Leaf.NotAfter,
		DaysLeft: tlsconf.DaysLeft(cert, c.now()), Source: "own"}, nil
}

// RenewDue starts a renewal when the certificate renews by itself and has
// fewer than RenewDays left; it reports whether it started one.
func (c *CertOps) RenewDue() bool {
	cfg := c.Config.Get()
	if !cfg.SetupDone || !autoRenew(cfg) {
		return false
	}
	if info := c.Installed(); info == nil || info.DaysLeft >= RenewDays {
		return false
	}
	ca := "staging"
	if cfg.TLSSource == "acme-production" {
		ca = "production"
	}
	_, err := c.Start(acme.Method(cfg.TLSMethod), ca, true, audit.Actor{})
	return err == nil
}

// RenewLoop checks for due renewals shortly after start and then every
// interval (a failed renewal is retried at the next check).
func (c *CertOps) RenewLoop(ctx context.Context, first, interval time.Duration) {
	t := time.NewTimer(first)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c.RenewDue()
			t.Reset(interval)
		}
	}
}

// Register installs the certificate operations.
func (c *CertOps) Register(ops map[string]*Op) {
	guarded := func(call Call) (acmeParams, error) {
		var p acmeParams
		if err := decode(call, &p); err != nil {
			return p, err
		}
		return p, c.Guard(p.Token)
	}

	// --- setup wizard (bootstrap token) ---
	Register(ops, &Op{Name: "setup.acme_issue", PreAuth: true,
		Handle: func(_ context.Context, call Call) (any, error) {
			p, err := guarded(call)
			if err != nil {
				return nil, err
			}
			m, err := checkACME(p)
			if err != nil {
				return nil, err
			}
			return c.Start(m, p.CA, false, audit.Actor{})
		}})
	Register(ops, &Op{Name: "setup.cert_status", PreAuth: true, NoAudit: true,
		Handle: func(_ context.Context, call Call) (any, error) {
			if _, err := guarded(call); err != nil {
				return nil, err
			}
			return CertView{Domain: c.Config.Get().Domain, Cert: c.Installed(), Issuance: c.Current(), RenewDays: RenewDays}, nil
		}})
	Register(ops, &Op{Name: "setup.cert_dns_confirm", PreAuth: true,
		Handle: func(_ context.Context, call Call) (any, error) {
			if _, err := guarded(call); err != nil {
				return nil, err
			}
			return c.Confirm()
		}})
	Register(ops, &Op{Name: "setup.cert_cancel", PreAuth: true,
		Handle: func(_ context.Context, call Call) (any, error) {
			if _, err := guarded(call); err != nil {
				return nil, err
			}
			return c.Cancel()
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
			return c.upload(p.CertPEM, p.KeyPEM)
		}})

	// --- daemonica-admin (root console): the way back when the browser cannot
	// do passkey ceremonies any more (expired or untrusted certificate) ---
	root := audit.Actor{Name: "root (daemonica-admin)", LinuxUser: "root"}
	Register(ops, &Op{Name: "admin.cert_status", AdminChannel: true, NoAudit: true,
		Handle: func(context.Context, Call) (any, error) {
			cfg := c.Config.Get()
			return CertView{Domain: cfg.Domain, Cert: c.Installed(), Source: cfg.TLSSource, Method: cfg.TLSMethod,
				AutoRenew: autoRenew(cfg), RenewDays: RenewDays, Issuance: c.Current()}, nil
		}})
	Register(ops, &Op{Name: "admin.cert_issue", AdminChannel: true,
		Handle: func(_ context.Context, call Call) (any, error) {
			var p acmeParams
			if err := decode(call, &p); err != nil {
				return nil, err
			}
			m, err := checkACME(p)
			if err != nil {
				return nil, err
			}
			call.AuditKV["method"], call.AuditKV["ca"] = p.Method, p.CA
			return c.Start(m, p.CA, false, root)
		}})
	Register(ops, &Op{Name: "admin.cert_dns_confirm", AdminChannel: true,
		Handle: func(context.Context, Call) (any, error) { return c.Confirm() }})
	Register(ops, &Op{Name: "admin.cert_cancel", AdminChannel: true,
		Handle: func(context.Context, Call) (any, error) { return c.Cancel() }})
	Register(ops, &Op{Name: "admin.cert_upload", AdminChannel: true,
		Handle: func(_ context.Context, call Call) (any, error) {
			var p pemParams
			if err := decode(call, &p); err != nil {
				return nil, err
			}
			return c.upload(p.CertPEM, p.KeyPEM)
		}})

	// --- settings (admin; changes need step-up) ---
	Register(ops, &Op{Name: "cert.get", Action: policy.ActSettingsRead, NoAudit: true,
		Handle: func(context.Context, Call) (any, error) {
			cfg := c.Config.Get()
			return CertView{Domain: cfg.Domain, Cert: c.Installed(), Source: cfg.TLSSource, Method: cfg.TLSMethod,
				AutoRenew: autoRenew(cfg), RenewDays: RenewDays, Issuance: c.Current()}, nil
		}})
	Register(ops, &Op{Name: "cert.acme_issue", Action: policy.ActSettingsWrite,
		Handle: func(_ context.Context, call Call) (any, error) {
			var p acmeParams
			if err := decode(call, &p); err != nil {
				return nil, err
			}
			m, err := checkACME(p)
			if err != nil {
				return nil, err
			}
			call.AuditKV["method"], call.AuditKV["ca"] = p.Method, p.CA
			return c.Start(m, p.CA, false, audit.Actor{AccountID: call.Subject.AccountID})
		}})
	Register(ops, &Op{Name: "cert.dns_confirm", Action: policy.ActSettingsWrite,
		Handle: func(context.Context, Call) (any, error) { return c.Confirm() }})
	Register(ops, &Op{Name: "cert.cancel", Action: policy.ActSettingsWrite,
		Handle: func(context.Context, Call) (any, error) { return c.Cancel() }})
	Register(ops, &Op{Name: "cert.upload", Action: policy.ActSettingsWrite,
		Handle: func(_ context.Context, call Call) (any, error) {
			var p pemParams
			if err := decode(call, &p); err != nil {
				return nil, err
			}
			return c.upload(p.CertPEM, p.KeyPEM)
		}})
}
