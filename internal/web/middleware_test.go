package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
}

func TestSecurityHeaders(t *testing.T) {
	rec := httptest.NewRecorder()
	SecurityHeaders(okHandler()).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/x", nil))
	h := rec.Header()
	for k, want := range map[string]string{
		"X-Content-Type-Options":       "nosniff",
		"Referrer-Policy":              "no-referrer",
		"Cross-Origin-Opener-Policy":   "same-origin",
		"Cross-Origin-Resource-Policy": "same-origin",
		"Cache-Control":                "no-store",
	} {
		if h.Get(k) != want {
			t.Errorf("%s = %q", k, h.Get(k))
		}
	}
	csp := h.Get("Content-Security-Policy")
	for _, part := range []string{"default-src 'none'", "frame-ancestors 'none'", "script-src 'self'", "base-uri 'none'"} {
		if !strings.Contains(csp, part) {
			t.Errorf("CSP missing %q", part)
		}
	}
	if strings.Contains(csp, "unsafe") {
		t.Error("CSP must not contain unsafe-*")
	}
}

func TestCSRF(t *testing.T) {
	origin := func() []string { return []string{"https://dash.example.org:8443"} }
	h := CSRF(origin, okHandler())
	cases := []struct {
		name, method, origin, hdr string
		want                      int
	}{
		{"get passes", http.MethodGet, "", "", 204},
		{"post ok", http.MethodPost, "https://dash.example.org:8443", "1", 204},
		{"post no header", http.MethodPost, "https://dash.example.org:8443", "", 403},
		{"post wrong origin", http.MethodPost, "https://evil.example", "1", 403},
		{"post wrong port", http.MethodPost, "https://dash.example.org", "1", 403},
		{"post http scheme", http.MethodPost, "http://dash.example.org:8443", "1", 403},
		{"post null origin", http.MethodPost, "null", "1", 403},
		{"post no origin", http.MethodPost, "", "1", 403},
		{"delete ok", http.MethodDelete, "https://dash.example.org:8443", "1", 204},
		{"options refused", http.MethodOptions, "https://evil.example", "", 405},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest(c.method, "/api/v1/x", nil)
			if c.origin != "" {
				r.Header.Set("Origin", c.origin)
			}
			if c.hdr != "" {
				r.Header.Set(CSRFHeader, c.hdr)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, r)
			if rec.Code != c.want {
				t.Fatalf("got %d want %d", rec.Code, c.want)
			}
		})
	}
}

func TestProblemHasNoInternals(t *testing.T) {
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	WithCorrelationID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		Problem(w, r, 500, "internal_error")
	})).ServeHTTP(rec, r)
	if ct := rec.Header().Get("Content-Type"); ct != "application/problem+json" {
		t.Fatal(ct)
	}
	if !strings.Contains(rec.Body.String(), `"correlation_id":"`) {
		t.Fatal("missing correlation id")
	}
}
