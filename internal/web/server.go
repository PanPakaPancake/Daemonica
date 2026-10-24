package web

import (
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"net/http"
	"net/netip"
	"path"
	"strings"

	"github.com/PanPakaPancake/daemonica/internal/netallow"
	"github.com/PanPakaPancake/daemonica/internal/rpc"
)

// Server holds the HTTP handlers of daemonia-web.
type Server struct {
	Helper  *rpc.Client
	Log     *slog.Logger
	UI      fs.FS
	Origins  func() []string
	Limiter  *RateLimiter
	Sessions *Sessions
}

// Handler builds the full middleware chain. Before login only the UI shell,
// static assets and the setup/login endpoints are reachable (SPEC §3.1).
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /api/v1/setup/state", LimitBody(0, http.HandlerFunc(s.setupState)))
	mux.Handle("POST /api/v1/setup/token", LimitBody(4<<10, http.HandlerFunc(s.setupToken)))
	s.registerAuthRoutes(mux)
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		// Unknown API routes: never reveal whether a route exists to anonymous clients.
		Problem(w, r, http.StatusUnauthorized, "unauthorized")
	})
	mux.Handle("/", s.static())

	var h http.Handler = mux
	h = CSRF(s.Origins, h)
	h = SecurityHeaders(h)
	h = WithCorrelationID(h)
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
func (s *Server) static() http.Handler {
	fileServer := http.FileServerFS(s.UI)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			Problem(w, r, http.StatusMethodNotAllowed, "method_not_allowed")
			return
		}
		p := path.Clean("/" + r.URL.Path)
		name := strings.TrimPrefix(p, "/")
		if name == "" {
			name = "index.html"
		}
		if fi, err := fs.Stat(s.UI, name); err != nil || fi.IsDir() {
			if strings.HasPrefix(name, "assets/") || strings.Contains(path.Base(name), ".") {
				http.NotFound(w, r)
				return
			}
			r2 := r.Clone(r.Context())
			r2.URL.Path = "/"
			fileServer.ServeHTTP(w, r2)
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
