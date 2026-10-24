package web

import (
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/PanPakaPancake/daemonica/internal/rpc"
)

// fakeHelper answers RPCs over a Unix socket.
func fakeHelper(t *testing.T, handle func(*rpc.Request) *rpc.Response) string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "h.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				req, err := rpc.ReadRequest(c)
				if err != nil {
					return
				}
				_ = rpc.WriteFrame(c, handle(req))
			}()
		}
	}()
	return sock
}

const okOrigin = "https://dash.example.org:8443"

func newAuthServer(t *testing.T, handle func(*rpc.Request) *rpc.Response) http.Handler {
	s := &Server{
		Helper:   &rpc.Client{Socket: fakeHelper(t, handle)},
		Log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		UI:       fstest.MapFS{"index.html": {Data: []byte("x")}},
		Origins:  func() []string { return []string{okOrigin} },
		Limiter:  NewRateLimiter(100, 100, 100, 100),
		Sessions: NewSessions(),
	}
	return s.Handler()
}

func post(h http.Handler, path, body string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	r.Header.Set("Origin", okOrigin)
	r.Header.Set(CSRFHeader, "1")
	r.RemoteAddr = "198.51.100.7:5555"
	for _, c := range cookies {
		r.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

func get(h http.Handler, path string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, path, nil)
	r.RemoteAddr = "198.51.100.7:5555"
	for _, c := range cookies {
		r.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

func sessionCookie(rec *httptest.ResponseRecorder) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == SessionCookie {
			return c
		}
	}
	return nil
}

func TestLoginCreatesHardenedSessionWithoutLeakingGrant(t *testing.T) {
	g1 := "dmn_grant_" + strings.Repeat("A", 43)
	g2 := "dmn_grant_" + strings.Repeat("B", 43)
	valid := map[string]bool{}
	h := newAuthServer(t, func(r *rpc.Request) *rpc.Response {
		switch r.Op {
		case "auth.finish_login":
			valid[g1] = true
			resp, _ := rpc.Succeed(r.ID, map[string]any{"grant": g1, "account": map[string]string{"name": "Pancake"}})
			return resp
		case "session.whoami":
			if !valid[r.Grant] {
				return rpc.Fail(r.ID, rpc.CodeUnauthorized, "")
			}
			resp, _ := rpc.Succeed(r.ID, map[string]any{"role": "admin"})
			return resp
		case "auth.finish_stepup":
			if !valid[r.Grant] {
				return rpc.Fail(r.ID, rpc.CodeUnauthorized, "")
			}
			delete(valid, r.Grant)
			valid[g2] = true
			resp, _ := rpc.Succeed(r.ID, map[string]any{"grant": g2})
			return resp
		case "auth.logout":
			delete(valid, r.Grant)
			return &rpc.Response{V: rpc.Version, ID: r.ID, OK: true}
		}
		return rpc.Fail(r.ID, rpc.CodeUnknownOp, "")
	})

	if rec := get(h, "/api/v1/session"); rec.Code != 401 {
		t.Fatalf("no cookie: %d", rec.Code)
	}
	rec := post(h, "/api/v1/auth/login/finish", `{"ceremony_id":"x","response":{}}`)
	if rec.Code != 200 {
		t.Fatalf("login: %d %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "dmn_grant_") {
		t.Fatal("grant leaked into the response body (readable by scripts)")
	}
	c := sessionCookie(rec)
	if c == nil || !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteStrictMode || c.Path != "/" || c.Domain != "" || c.Value != g1 {
		t.Fatalf("cookie flags wrong: %+v", c)
	}
	if rec := get(h, "/api/v1/session", c); rec.Code != 200 {
		t.Fatalf("session lookup: %d", rec.Code)
	}

	// Step-up rotates the token; the old cookie stops working.
	rec = post(h, "/api/v1/auth/stepup/finish", `{"ceremony_id":"y","response":{}}`, c)
	c2 := sessionCookie(rec)
	if rec.Code != 204 || c2 == nil || c2.Value != g2 || strings.Contains(rec.Body.String(), "dmn_grant_") {
		t.Fatalf("step-up did not rotate cookie: %d %+v", rec.Code, c2)
	}
	if rec := get(h, "/api/v1/session", c); rec.Code != 401 {
		t.Fatal("old cookie valid after rotation (fixation)")
	}

	// Logout clears the session.
	rec = post(h, "/api/v1/auth/logout", ``, c2)
	if rec.Code != 204 || sessionCookie(rec) == nil || sessionCookie(rec).MaxAge >= 0 {
		t.Fatal("logout did not clear cookie")
	}
	if rec := get(h, "/api/v1/session", c2); rec.Code != 401 {
		t.Fatal("session valid after logout")
	}
	// Malformed cookies never reach the helper as grants.
	if rec := get(h, "/api/v1/session", &http.Cookie{Name: SessionCookie, Value: "x' OR 1=1"}); rec.Code != 401 {
		t.Fatal("malformed cookie accepted")
	}
}

func TestHelperCodesMapToHTTP(t *testing.T) {
	handler := func(r *rpc.Request) *rpc.Response {
		var p map[string]string
		_ = json.Unmarshal(r.Params, &p)
		return rpc.Fail(r.ID, p["want"], "internal detail must not leak")
	}
	cases := map[string]int{
		rpc.CodeTokenInvalid: 401, rpc.CodeValidation: 400, rpc.CodeSetupComplete: 409,
		rpc.CodeLockout: 409, rpc.CodeUnavailable: 503, "weird": 500,
	}
	for code, status := range cases {
		// Fresh server per case: token failures legitimately trigger per-IP backoff.
		h := newAuthServer(t, handler)
		rec := post(h, "/api/v1/setup/domain", `{"want":"`+code+`"}`)
		if rec.Code != status || strings.Contains(rec.Body.String(), "internal detail") {
			t.Errorf("%s → %d %s", code, rec.Code, rec.Body.String())
		}
	}
	if rec := post(newAuthServer(t, handler), "/api/v1/setup/domain", `not json`); rec.Code != 400 {
		t.Fatalf("invalid json: %d", rec.Code)
	}
}

func TestSessionEndpointsRequireCookieAndCSRF(t *testing.T) {
	called := false
	h := newAuthServer(t, func(r *rpc.Request) *rpc.Response { called = true; return rpc.Fail(r.ID, rpc.CodeInternal, "") })
	for _, p := range []string{"/api/v1/auth/stepup/begin", "/api/v1/passkeys/begin", "/api/v1/auth/logout"} {
		if rec := post(h, p, `{}`); rec.Code != 401 {
			t.Errorf("%s without cookie: %d", p, rec.Code)
		}
	}
	r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login/begin", nil)
	r.Header.Set("Origin", "https://evil.example")
	r.Header.Set(CSRFHeader, "1")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != 403 || called {
		t.Fatal("cross-origin request reached the helper")
	}
}

func TestTokenFailuresTriggerBackoff(t *testing.T) {
	h := newAuthServer(t, func(r *rpc.Request) *rpc.Response { return rpc.Fail(r.ID, rpc.CodeTokenInvalid, "") })
	if rec := post(h, "/api/v1/setup/domain", `{}`); rec.Code != 401 {
		t.Fatalf("first: %d", rec.Code)
	}
	if rec := post(h, "/api/v1/setup/domain", `{}`); rec.Code != 429 {
		t.Fatalf("second attempt must be throttled, got %d", rec.Code)
	}
}
