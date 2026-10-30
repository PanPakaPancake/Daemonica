package helper

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/PanPakaPancake/daemonica/internal/acme"
	"github.com/PanPakaPancake/daemonica/internal/audit"
)

const certDomain = "dash.example.org"

func testCertPEM(t *testing.T, notAfter time.Time) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: certDomain}, Issuer: pkix.Name{CommonName: "(STAGING) Test"},
		DNSNames: []string{certDomain}, NotBefore: time.Now().Add(-time.Hour), NotAfter: notAfter}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kd, _ := x509.MarshalECPrivateKey(key)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd})
}

func certFixture(t *testing.T) *CertOps {
	t.Helper()
	dir := t.TempDir()
	cfg, err := OpenConfig(filepath.Join(dir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cfg.Update(func(c *Config) error { c.Domain = certDomain; return nil }); err != nil {
		t.Fatal(err)
	}
	return &CertOps{Config: cfg, TLSDir: filepath.Join(dir, "tls"), StateDir: dir, WebUID: os.Getuid(), WebGID: os.Getgid(),
		Guard: func(string) error { return nil }, PortFree: func(string) bool { return true }}
}

func waitState(t *testing.T, c *CertOps, want string) *Issuance {
	t.Helper()
	for range 200 {
		if i := c.Current(); i != nil && i.State == want {
			return i
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("state %q not reached, have %+v", want, c.Current())
	return nil
}

func TestCertDNSGuided(t *testing.T) {
	c := certFixture(t)
	certPEM, keyPEM := testCertPEM(t, time.Now().Add(90*24*time.Hour))
	c.Obtain = func(ctx context.Context, r acme.Request) (*acme.Result, error) {
		if r.Method != acme.DNS01 || r.CA != acme.Staging || r.Guide == nil || r.Domain != certDomain {
			t.Errorf("request %+v", r)
		}
		r.Guide.Record("_acme-challenge."+certDomain, "abc")
		for !r.Guide.Confirmed() {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(2 * time.Millisecond):
			}
		}
		r.Guide.Checked(false, nil)
		r.Guide.Checked(true, nil)
		return &acme.Result{CertPEM: certPEM, KeyPEM: keyPEM, NotAfter: time.Now().Add(90 * 24 * time.Hour)}, nil
	}
	if _, err := c.Confirm(); err == nil {
		t.Fatal("confirm without issuance")
	}
	if _, err := c.Start(acme.DNS01, "staging", false, auditActor()); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Start(acme.HTTP01, "staging", false, auditActor()); err == nil {
		t.Fatal("second issuance started")
	}
	i := waitState(t, c, IssueDNSWait)
	if i.Record == nil || i.Record.Value != "abc" {
		t.Fatalf("record %+v", i.Record)
	}
	if _, err := c.Confirm(); err != nil {
		t.Fatal(err)
	}
	c.Wait()
	i = c.Current()
	if i.State != IssueDone || i.Checks != 2 || i.Check != "ok" || i.Cert == nil {
		t.Fatalf("issuance %+v", i)
	}
	cfg := c.Config.Get()
	if cfg.TLSSource != "acme-staging" || cfg.TLSMethod != "dns-01" || autoRenew(cfg) {
		t.Fatalf("config %+v", cfg)
	}
	if got := c.Installed(); got == nil || got.Domain != certDomain || got.DaysLeft < 88 {
		t.Fatalf("installed %+v", got)
	}
	for _, f := range []string{"fullchain.pem", "privkey.pem"} {
		if fi, err := os.Stat(filepath.Join(c.TLSDir, f)); err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("%s: %v %v", f, fi, err)
		}
	}
}

func TestCertCancelAndWindow(t *testing.T) {
	c := certFixture(t)
	var opened, closed int
	c.Window = func(_ context.Context, port int) (func(context.Context) error, error) {
		if port != 80 {
			t.Errorf("port %d", port)
		}
		opened++
		return func(context.Context) error { closed++; return nil }, nil
	}
	c.Obtain = func(ctx context.Context, _ acme.Request) (*acme.Result, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if _, err := c.Start(acme.HTTP01, "staging", false, auditActor()); err != nil {
		t.Fatal(err)
	}
	waitState(t, c, IssueRunning)
	if _, err := c.Cancel(); err != nil {
		t.Fatal(err)
	}
	c.Wait()
	if i := c.Current(); i.State != IssueCanceled || opened != 1 || closed != 1 {
		t.Fatalf("state %+v opened %d closed %d", i, opened, closed)
	}
	if _, err := c.Cancel(); err == nil {
		t.Fatal("cancel without issuance")
	}

	// Port in use: fails before talking to the CA.
	c.PortFree = func(string) bool { return false }
	if _, err := c.Start(acme.HTTP01, "staging", false, auditActor()); err != nil {
		t.Fatal(err)
	}
	c.Wait()
	if i := c.Current(); i.State != IssueFailed || i.Error == "" || opened != 1 {
		t.Fatalf("state %+v", i)
	}
}

func TestCertRenewDue(t *testing.T) {
	c := certFixture(t)
	var calls int
	fresh, freshKey := testCertPEM(t, time.Now().Add(90*24*time.Hour))
	c.Obtain = func(_ context.Context, r acme.Request) (*acme.Result, error) {
		calls++
		if r.Method != acme.HTTP01 || r.CA != acme.Production {
			t.Errorf("request %+v", r)
		}
		return &acme.Result{CertPEM: fresh, KeyPEM: freshKey, NotAfter: time.Now().Add(90 * 24 * time.Hour)}, nil
	}
	old, oldKey := testCertPEM(t, time.Now().Add(10*24*time.Hour))
	if err := c.install(old, oldKey); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Config.Update(func(cf *Config) error {
		cf.SetupDone, cf.TLSSource, cf.TLSMethod = true, "acme-production", "dns-01"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if c.RenewDue() {
		t.Fatal("dns-01 renewed without the operator")
	}
	// Installations from before M1.8 have no method recorded: their wizard only offered HTTP-01.
	_, _ = c.Config.Update(func(cf *Config) error { cf.TLSMethod = ""; return nil })
	if !c.RenewDue() {
		t.Fatal("due renewal not started")
	}
	c.Wait()
	if i := c.Current(); i.State != IssueDone || !i.Renewal || calls != 1 {
		t.Fatalf("issuance %+v calls %d", i, calls)
	}
	if c.RenewDue() || calls != 1 {
		t.Fatal("renewed a fresh certificate")
	}
}

func TestCertUpload(t *testing.T) {
	c := certFixture(t)
	certPEM, keyPEM := testCertPEM(t, time.Now().Add(30*24*time.Hour))
	if _, err := c.upload(string(certPEM), "garbage"); err == nil {
		t.Fatal("bad key accepted")
	}
	info, err := c.upload(string(certPEM), string(keyPEM))
	if err != nil {
		t.Fatal(err)
	}
	if info.Source != "own" || c.Config.Get().TLSSource != "own" || c.Config.Get().TLSMethod != "" {
		t.Fatalf("info %+v", info)
	}
}

func auditActor() audit.Actor { return audit.Actor{AccountID: "acc-test"} }

// TestCertAdminChannel: the root console can replace the certificate without a
// browser session (way back after an expired or untrusted certificate); the
// web channel cannot reach these operations.
func TestCertAdminChannel(t *testing.T) {
	e := newAuthEnv(t)
	c := certFixture(t)
	c.Config = e.cfg
	if _, err := e.cfg.Update(func(cf *Config) error { cf.Domain = certDomain; return nil }); err != nil {
		t.Fatal(err)
	}
	c.Register(e.web.Ops)
	certPEM, keyPEM := testCertPEM(t, time.Now().Add(30*24*time.Hour))
	params := map[string]string{"cert_pem": string(certPEM), "key_pem": string(keyPEM)}
	if r, _ := e.call(t, e.web, "admin.cert_upload", "", params); r.OK {
		t.Fatal("admin op reachable on the web channel")
	}
	r, _ := e.call(t, e.admin, "admin.cert_upload", "", params)
	mustOK(t, r, "admin.cert_upload")
	r, res := e.call(t, e.admin, "admin.cert_status", "", nil)
	mustOK(t, r, "admin.cert_status")
	var v CertView
	_ = json.Unmarshal(res, &v)
	if v.Cert == nil || v.Source != "own" {
		t.Fatalf("status %+v", v)
	}
	if r, _ := e.call(t, e.admin, "admin.cert_issue", "", map[string]any{"method": "http-01", "ca": "staging"}); r.OK {
		t.Fatal("issuance without accepted terms")
	}
}
