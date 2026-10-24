package web

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/PanPakaPancake/daemonica/internal/rpc"
)

func testServer() http.Handler {
	s := &Server{
		Helper:   &rpc.Client{Socket: "/nonexistent.sock"},
		Log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		UI:       fstest.MapFS{"index.html": {Data: []byte("<html>shell</html>")}, "assets/app.js": {Data: []byte("x")}},
		Origins:  func() []string { return []string{"https://example.org:8443"} },
		Limiter:  NewRateLimiter(1, 5, 10, 10),
		Sessions: NewSessions(),
	}
	return s.Handler()
}

func TestRoutingBeforeLogin(t *testing.T) {
	h := testServer()
	cases := []struct {
		method, path string
		want         int
		body         string
	}{
		{"GET", "/", 200, "shell"},
		{"GET", "/users/alice", 200, "shell"}, // SPA fallback
		{"GET", "/assets/app.js", 200, "x"},
		{"GET", "/assets/missing.js", 404, ""},
		{"GET", "/api/v1/system/overview", 401, "unauthorized"},
		{"GET", "/api/v1/debug/pprof", 401, ""},
		{"GET", "/debug/pprof/", 200, "shell"}, // no pprof handler exists; falls back to UI shell
		{"POST", "/", 403, "csrf_failed"},
		{"GET", "/api/v1/setup/state", 503, "helper_unavailable"},
	}
	for _, c := range cases {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(c.method, c.path, nil))
		if rec.Code != c.want || !strings.Contains(rec.Body.String(), c.body) {
			t.Errorf("%s %s: got %d %q", c.method, c.path, rec.Code, rec.Body.String())
		}
		if rec.Header().Get("Content-Security-Policy") == "" {
			t.Errorf("%s %s: missing CSP", c.method, c.path)
		}
	}
}

func TestStaticRejectsWritesEvenWithCSRF(t *testing.T) {
	h := testServer()
	r := httptest.NewRequest("PUT", "/index.html", nil)
	r.Header.Set(CSRFHeader, "1")
	r.Header.Set("Origin", "https://example.org:8443")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != 405 {
		t.Fatalf("got %d", rec.Code)
	}
}

func TestIndexGetsFreshStyleNonce(t *testing.T) {
	s := &Server{
		Helper:   &rpc.Client{Socket: "/nonexistent.sock"},
		Log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		UI:       fstest.MapFS{"index.html": {Data: []byte(`<meta name="style-nonce" content="__STYLE_NONCE__">`)}},
		Origins:  func() []string { return nil },
		Limiter:  NewRateLimiter(1, 5, 10, 10),
		Sessions: NewSessions(),
	}
	h := s.Handler()
	get := func(p string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", p, nil))
		return rec
	}
	a, b := get("/"), get("/users")
	if strings.Contains(a.Body.String(), "__STYLE_NONCE__") {
		t.Fatal("placeholder not replaced")
	}
	csp := a.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "style-src 'self' 'nonce-") || strings.Contains(csp, "script-src 'self' 'nonce") || strings.Contains(csp, "unsafe") {
		t.Fatalf("csp %q", csp)
	}
	if a.Body.String() == b.Body.String() {
		t.Fatal("nonce must differ per response")
	}
	n := strings.TrimSuffix(strings.TrimPrefix(a.Body.String(), `<meta name="style-nonce" content="`), `">`)
	if !strings.Contains(csp, "'nonce-"+n+"'") {
		t.Fatal("nonce in page and header differ")
	}
	if get("/api/v1/x").Header().Get("Content-Security-Policy") != CSP {
		t.Fatal("API responses must keep the static CSP")
	}
}
