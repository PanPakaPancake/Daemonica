package web

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"path"
	"strings"
	"time"

	"github.com/PanPakaPancake/daemonica/internal/netallow"
	"github.com/PanPakaPancake/daemonica/internal/rpc"
)

// Server holds the HTTP handlers of daemonica-web.
type Server struct {
	Helper   *rpc.Client
	Log      *slog.Logger
	UI       fs.FS
	Origins  func() []string
	Limiter  *RateLimiter
	Sessions *Sessions
	// Allow, if set, is re-checked on every request so connections opened
	// before an allowlist was tightened cannot keep using the dashboard.
	Allow *netallow.Allowlist
	// ReloadConfig asks the process to re-read the helper config now.
	ReloadConfig func()
}

type connKey struct{}

// ConnAccepted is used as http.Server.ConnContext: it records when the TCP
// connection was accepted (Plan→Apply→Confirm needs proof of a new connection).
func ConnAccepted(ctx context.Context, _ net.Conn) context.Context {
	return context.WithValue(ctx, connKey{}, time.Now().UTC())
}

func connSince(r *http.Request) time.Time {
	t, _ := r.Context().Value(connKey{}).(time.Time)
	return t
}

// AllowCheck rejects requests whose peer is no longer in the allowlist.
func AllowCheck(a *netallow.Allowlist, next http.Handler) http.Handler {
	if a == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ip := clientIP(r); !ip.IsValid() || !a.Contains(ip) {
			w.Header().Set("Connection", "close")
			http.Error(w, "", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Handler builds the full middleware chain. Before login only the UI shell,
// static assets and the setup/login endpoints are reachable (SPEC §3.1).
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /api/v1/setup/state", LimitBody(0, http.HandlerFunc(s.setupState)))
	mux.Handle("POST /api/v1/setup/token", LimitBody(4<<10, http.HandlerFunc(s.setupToken)))
	s.registerAuthRoutes(mux)
	s.registerFileRoutes(mux)
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		// Unknown API routes: never reveal whether a route exists to anonymous clients.
		Problem(w, r, http.StatusUnauthorized, "unauthorized")
	})
	mux.Handle("/", s.static())

	var h http.Handler = mux
	h = CSRF(s.Origins, h)
	h = SecurityHeaders(h)
	h = WithCorrelationID(h)
	h = AllowCheck(s.Allow, h)
	h = Recover(s.Log, h)
	return h
}

func clientIP(r *http.Request) netip.Addr {
	a, _ := netallow.RemoteAddr(r.RemoteAddr)
	return a
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) setupState(w http.ResponseWriter, r *http.Request) {
	var out map[string]any
	if err := s.Helper.Call(r.Context(), "setup.state", "", clientIP(r).String(), nil, &out); err != nil {
		Problem(w, r, http.StatusServiceUnavailable, "helper_unavailable")
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) setupToken(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if !s.Limiter.Allow(ip) {
		Problem(w, r, http.StatusTooManyRequests, "rate_limited")
		return
	}
	var body struct {
		Token string `json:"token"`
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		Problem(w, r, http.StatusBadRequest, "bad_request")
		return
	}
	err := s.Helper.Call(r.Context(), "setup.check_token", "", ip.String(), map[string]string{"token": body.Token}, nil)
	switch code := rpc.ErrorCode(err); {
	case err == nil:
		s.Limiter.Success(ip)
		writeJSON(w, http.StatusOK, map[string]bool{"valid": true})
	case code == rpc.CodeSetupComplete:
		Problem(w, r, http.StatusConflict, "setup_complete")
	case code == rpc.CodeTokenInvalid || code == rpc.CodeBadRequest:
		s.Limiter.Fail(ip)
		Problem(w, r, http.StatusUnauthorized, "token_invalid")
	default:
		var re *rpc.Error
		if errors.As(err, &re) && re.Code == rpc.CodeUnavailable {
			Problem(w, r, http.StatusServiceUnavailable, "helper_unavailable")
			return
		}
		Problem(w, r, http.StatusInternalServerError, "internal_error")
	}
}

// static serves the embedded UI. Unknown non-asset paths fall back to
// index.html (client-side routing). Directory listings are never produced.
// NoncePlaceholder in index.html is replaced by a fresh per-response nonce.
const NoncePlaceholder = "__STYLE_NONCE__"

// serveIndex renders index.html with a fresh style nonce and the matching CSP.
// The nonce only authorises <style> elements created by UI libraries (Radix
// scroll lock); scripts remain restricted to 'self' (DEC-018).
func (s *Server) serveIndex(w http.ResponseWriter, r *http.Request) {
	b, err := fs.ReadFile(s.UI, "index.html")
	if err != nil {
		http.NotFound(w, r)
		return
	}
	nb := make([]byte, 16)
	_, _ = rand.Read(nb)
	nonce := base64.RawURLEncoding.EncodeToString(nb)
	w.Header().Set("Content-Security-Policy", strings.Replace(CSP, "style-src 'self'", "style-src 'self' 'nonce-"+nonce+"'", 1))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write(bytes.ReplaceAll(b, []byte(NoncePlaceholder), []byte(nonce)))
}

// static serves the embedded UI. Unknown non-asset paths fall back to
// index.html (client-side routing). Directory listings are never produced.
func (s *Server) static() http.Handler {
	fileServer := http.FileServerFS(s.UI)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			Problem(w, r, http.StatusMethodNotAllowed, "method_not_allowed")
			return
		}
		p := path.Clean("/" + r.URL.Path)
		name := strings.TrimPrefix(p, "/")
		if name == "" || name == "index.html" {
			s.serveIndex(w, r)
			return
		}
		if fi, err := fs.Stat(s.UI, name); err != nil || fi.IsDir() {
			if strings.HasPrefix(name, "assets/") || strings.Contains(path.Base(name), ".") {
				http.NotFound(w, r)
				return
			}
			s.serveIndex(w, r)
			return
		}
		if strings.HasPrefix(name, "assets/") {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			w.Header().Set("Cache-Control", "no-cache")
		}
		fileServer.ServeHTTP(w, r)
	})
}
