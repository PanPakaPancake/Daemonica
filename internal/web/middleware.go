// Package web implements the unprivileged HTTPS front end (daemonia-web).
package web

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
)

// CSP is the strict Content-Security-Policy from SPEC §3.5.
const CSP = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; " +
	"connect-src 'self'; font-src 'self'; frame-ancestors 'none'; base-uri 'none'; " +
	"form-action 'self'; require-trusted-types-for 'script'"

// CSRFHeader must be present on every state-changing request.
const CSRFHeader = "X-Daemonia-CSRF"

type ctxKey int

const correlationKey ctxKey = 1

// CorrelationID returns the request's correlation ID.
func CorrelationID(ctx context.Context) string {
	v, _ := ctx.Value(correlationKey).(string)
	return v
}

// WithCorrelationID assigns a random correlation ID to each request.
func WithCorrelationID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b := make([]byte, 8)
		_, _ = rand.Read(b)
		id := hex.EncodeToString(b)
		w.Header().Set("X-Correlation-ID", id)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), correlationKey, id)))
	})
}

// SecurityHeaders sets the mandatory response headers (SPEC §3.5).
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", CSP)
		h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Cross-Origin-Embedder-Policy", "require-corp")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Permissions-Policy", "accelerometer=(), camera=(), geolocation=(), gyroscope=(), "+
			"magnetometer=(), microphone=(), payment=(), usb=(), interest-cohort=(), "+
			"publickey-credentials-get=(self), publickey-credentials-create=(self), clipboard-write=(self)")
		if strings.HasPrefix(r.URL.Path, "/api/") {
			h.Set("Cache-Control", "no-store")
		}
		// No Server/version banner (SPEC §3.1).
		h.Del("Server")
		next.ServeHTTP(w, r)
	})
}

func isSafeMethod(m string) bool {
	return m == http.MethodGet || m == http.MethodHead || m == http.MethodOptions
}

// CSRF enforces SameSite=Strict cookies plus a mandatory custom header and an
// exact Origin match on state-changing requests (SPEC §3.5). expectedOrigins
// returns e.g. ["https://dash.example.org:8443"] (several only in setup mode,
// where loopback can be addressed as localhost, 127.0.0.1 or [::1]).
// CORS is never enabled.
func CSRF(expectedOrigins func() []string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			// No CORS: preflights are refused.
			Problem(w, r, http.StatusMethodNotAllowed, "method_not_allowed")
			return
		}
		if isSafeMethod(r.Method) {
			next.ServeHTTP(w, r)
			return
		}
		if r.Header.Get(CSRFHeader) != "1" {
			Problem(w, r, http.StatusForbidden, "csrf_failed")
			return
		}
		ok := false
		for _, o := range expectedOrigins() {
			if SameOrigin(r.Header.Get("Origin"), o) {
				ok = true
				break
			}
		}
		if !ok {
			Problem(w, r, http.StatusForbidden, "origin_mismatch")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// SameOrigin compares an Origin header to the expected origin exactly
// (scheme, host and port). An absent or "null" origin is rejected.
func SameOrigin(got, want string) bool {
	if got == "" || got == "null" || want == "" {
		return false
	}
	gu, err1 := url.Parse(got)
	wu, err2 := url.Parse(want)
	if err1 != nil || err2 != nil {
		return false
	}
	return gu.Scheme == wu.Scheme && strings.EqualFold(gu.Host, wu.Host) && gu.Path == "" && gu.User == nil
}

// LimitBody caps request bodies per route.
func LimitBody(max int64, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, max)
		next.ServeHTTP(w, r)
	})
}

// problemDoc is an RFC 9457 problem document. Detail never carries internal information.
type problemDoc struct {
	Type          string `json:"type"`
	Title         string `json:"title"`
	Status        int    `json:"status"`
	Code          string `json:"code"`
	CorrelationID string `json:"correlation_id"`
}

// Problem writes an application/problem+json error with a stable code.
// The frontend translates codes; no internal details are leaked.
func Problem(w http.ResponseWriter, r *http.Request, status int, code string) {
	doc := problemDoc{
		Type:          "about:blank",
		Title:         http.StatusText(status),
		Status:        status,
		Code:          code,
		CorrelationID: CorrelationID(r.Context()),
	}
	w.Header().Set("Content-Type", "application/problem+json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(doc)
}

// Recover converts panics into a generic 500 without leaking details.
func Recover(log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				if v == http.ErrAbortHandler { //nolint:errorlint // sentinel comparison as documented
					panic(v)
				}
				log.Error("panic in handler", "correlation_id", CorrelationID(r.Context()), "path", r.URL.Path)
				Problem(w, r, http.StatusInternalServerError, "internal_error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}
