package web

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/PanPakaPancake/daemonica/internal/auth"
	"github.com/PanPakaPancake/daemonica/internal/rpc"
)

// SessionCookie is the session cookie name (SPEC §3.5). The __Host- prefix
// forces Secure, Path=/ and no Domain attribute.
const SessionCookie = "__Host-daemonia_session"

// Sessions maps browser session cookies to helper grants. Only SHA-256 hashes
// of cookie values are kept. Authorization state (role, step-up, expiry) lives
// in the helper; this table only binds a cookie to a grant.
type Sessions struct {
	mu sync.Mutex
	m  map[string]*websession
}

type websession struct {
	grant    string
	created  time.Time
	lastSeen time.Time
	ip       string
}

// NewSessions creates an empty session table.
func NewSessions() *Sessions { return &Sessions{m: map[string]*websession{}} }

func newCookieValue() string {
	b := make([]byte, auth.TokenBytes)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// Create stores a new session for grant and sets the cookie. Any session
// presented with the request is destroyed (rotation, no fixation).
func (s *Sessions) Create(w http.ResponseWriter, r *http.Request, grant string) {
	s.drop(r)
	v := newCookieValue()
	now := time.Now()
	s.mu.Lock()
	s.m[auth.Hash(v)] = &websession{grant: grant, created: now, lastSeen: now, ip: clientIP(r).String()}
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: SessionCookie, Value: v, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
}

// Rotate issues a new cookie value for the same grant (after step-up).
func (s *Sessions) Rotate(w http.ResponseWriter, r *http.Request) {
	if g := s.Grant(r); g != "" {
		s.Create(w, r, g)
	}
}

// Grant returns the grant bound to the request's cookie ("" if none).
func (s *Sessions) Grant(r *http.Request) string {
	c, err := r.Cookie(SessionCookie)
	if err != nil || len(c.Value) > 64 {
		return ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ws, ok := s.m[auth.Hash(c.Value)]
	if !ok {
		return ""
	}
	ws.lastSeen = time.Now()
	return ws.grant
}

// drop removes the request's session server-side only.
func (s *Sessions) drop(r *http.Request) {
	if c, err := r.Cookie(SessionCookie); err == nil {
		s.mu.Lock()
		delete(s.m, auth.Hash(c.Value))
		s.mu.Unlock()
	}
}

// Destroy removes the request's session and clears the cookie.
func (s *Sessions) Destroy(w http.ResponseWriter, r *http.Request) {
	s.drop(r)
	http.SetCookie(w, &http.Cookie{Name: SessionCookie, Value: "", Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: -1})
}

// Prune drops sessions not seen within maxIdle (the helper enforces the real timeout).
func (s *Sessions) Prune(maxIdle time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, v := range s.m {
		if time.Since(v.lastSeen) > maxIdle {
			delete(s.m, k)
		}
	}
}

// httpStatus maps stable helper codes to HTTP status codes.
func httpStatus(code string) int {
	switch code {
	case rpc.CodeBadRequest, rpc.CodeValidation:
		return http.StatusBadRequest
	case rpc.CodeUnauthorized, rpc.CodeTokenInvalid:
		return http.StatusUnauthorized
	case rpc.CodeForbidden, rpc.CodeStepUpNeeded:
		return http.StatusForbidden
	case rpc.CodeNotFound, rpc.CodeUnknownOp:
		return http.StatusNotFound
	case rpc.CodeConflict, rpc.CodeSetupComplete, rpc.CodeLockout:
		return http.StatusConflict
	case rpc.CodeRateLimited:
		return http.StatusTooManyRequests
	case rpc.CodeUnavailable:
		return http.StatusServiceUnavailable
	case rpc.CodeTimeout:
		return http.StatusGatewayTimeout
	case rpc.CodeNotSupported:
		return http.StatusNotImplemented
	default:
		return http.StatusInternalServerError
	}
}

// readParams reads the (size-limited) JSON body as raw params. Empty body → nil.
func readParams(r *http.Request) (json.RawMessage, error) {
	b, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	if len(b) == 0 {
		return nil, nil
	}
	if !json.Valid(b) {
		return nil, io.ErrUnexpectedEOF
	}
	return json.RawMessage(b), nil
}

// endpoint describes a JSON API route forwarded to a helper operation.
type endpoint struct {
	op       string
	session  bool  // requires a valid session cookie
	preauth  bool  // rate-limited pre-auth endpoint
	maxBody  int64 // request body limit
	setGrant bool  // response carries a grant → create session, strip grant
	stepUp   bool  // successful call upgrades the session (rotate cookie)
	logout   bool  // destroy session after the call
}

func (s *Server) forward(e endpoint) http.Handler {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := clientIP(r)
		if e.preauth && !s.Limiter.Allow(ip) {
			Problem(w, r, http.StatusTooManyRequests, "rate_limited")
			return
		}
		grant := ""
		if e.session {
			if grant = s.Sessions.Grant(r); grant == "" {
				Problem(w, r, http.StatusUnauthorized, "unauthorized")
				return
			}
		}
		params, err := readParams(r)
		if err != nil {
			Problem(w, r, http.StatusBadRequest, "bad_request")
			return
		}
		// Path parameters are merged into the params object by the caller via pathParam.
		if pv := r.PathValue("id"); pv != "" {
			params = mergeID(params, pv)
		}
		var out json.RawMessage
		err = s.Helper.Call(r.Context(), e.op, grant, ip.String(), params, &out)
		if err != nil {
			code := rpc.ErrorCode(err)
			if code == "" {
				code = rpc.CodeInternal
			}
			if e.preauth && (code == rpc.CodeUnauthorized || code == rpc.CodeTokenInvalid) {
				s.Limiter.Fail(ip)
			}
			if e.session && code == rpc.CodeUnauthorized {
				s.Sessions.Destroy(w, r)
			}
			Problem(w, r, httpStatus(code), code)
			return
		}
		if e.preauth {
			s.Limiter.Success(ip)
		}
		switch {
		case e.setGrant:
			var gr struct {
				Grant   string          `json:"grant"`
				Account json.RawMessage `json:"account"`
			}
			if json.Unmarshal(out, &gr) != nil || gr.Grant == "" {
				Problem(w, r, http.StatusInternalServerError, "internal_error")
				return
			}
			s.Sessions.Create(w, r, gr.Grant)
			writeJSON(w, http.StatusOK, map[string]json.RawMessage{"account": gr.Account})
			return
		case e.stepUp:
			s.Sessions.Rotate(w, r)
		case e.logout:
			s.Sessions.Destroy(w, r)
		}
		if len(out) == 0 || string(out) == "null" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(out)
	})
	max := e.maxBody
	if max == 0 {
		max = 16 << 10
	}
	return LimitBody(max, h)
}

func mergeID(params json.RawMessage, id string) json.RawMessage {
	m := map[string]any{}
	if len(params) > 0 {
		_ = json.Unmarshal(params, &m)
	}
	m["id"] = id
	b, _ := json.Marshal(m)
	return b
}

// registerAuthRoutes installs setup, login, step-up, passkey and recovery endpoints.
func (s *Server) registerAuthRoutes(mux *http.ServeMux) {
	pre := func(op string) http.Handler { return s.forward(endpoint{op: op, preauth: true}) }
	sess := func(op string) http.Handler { return s.forward(endpoint{op: op, session: true}) }

	// Setup mode (helper rejects these once setup is complete).
	mux.Handle("POST /api/v1/setup/domain", pre("setup.set_domain"))
	mux.Handle("POST /api/v1/setup/allowlist", pre("setup.set_allowlist"))
	mux.Handle("POST /api/v1/setup/linux-users", pre("setup.linux_users"))
	mux.Handle("POST /api/v1/setup/certificate/acme", pre("setup.acme_issue"))
	mux.Handle("POST /api/v1/setup/certificate/upload", s.forward(endpoint{op: "setup.upload_cert", preauth: true, maxBody: 64 << 10}))
	mux.Handle("POST /api/v1/setup/register/begin", pre("setup.begin_register"))
	mux.Handle("POST /api/v1/setup/register/finish", s.forward(endpoint{op: "setup.finish_register", preauth: true, setGrant: true, maxBody: 64 << 10}))

	// Login (username-less passkey).
	mux.Handle("POST /api/v1/auth/login/begin", pre("auth.begin_login"))
	mux.Handle("POST /api/v1/auth/login/finish", s.forward(endpoint{op: "auth.finish_login", preauth: true, setGrant: true, maxBody: 64 << 10}))

	// Recovery (token from `daemonia-admin recover`).
	mux.Handle("POST /api/v1/recovery/begin", pre("recovery.begin_register"))
	mux.Handle("POST /api/v1/recovery/finish", s.forward(endpoint{op: "recovery.finish_register", preauth: true, setGrant: true, maxBody: 64 << 10}))

	// Authenticated session.
	mux.Handle("GET /api/v1/session", sess("session.whoami"))
	mux.Handle("POST /api/v1/auth/stepup/begin", sess("auth.begin_stepup"))
	mux.Handle("POST /api/v1/auth/stepup/finish", s.forward(endpoint{op: "auth.finish_stepup", session: true, stepUp: true, maxBody: 64 << 10}))
	mux.Handle("POST /api/v1/auth/logout", s.forward(endpoint{op: "auth.logout", session: true, logout: true}))
	mux.Handle("GET /api/v1/passkeys", sess("passkeys.list"))
	mux.Handle("POST /api/v1/passkeys/begin", sess("passkeys.begin_add"))
	mux.Handle("POST /api/v1/passkeys/finish", s.forward(endpoint{op: "passkeys.finish_add", session: true, maxBody: 64 << 10}))
	mux.Handle("PATCH /api/v1/passkeys/{id}", sess("passkeys.rename"))
	mux.Handle("DELETE /api/v1/passkeys/{id}", sess("passkeys.remove"))
}
