package web

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/PanPakaPancake/daemonica/internal/rpc"
)

// SessionCookie is the session cookie name (SPEC §3.5). The __Host- prefix
// forces Secure, Path=/ and no Domain attribute.
const SessionCookie = "__Host-daemonica_session"

// Sessions binds the browser to a helper grant. The cookie value IS the opaque
// grant token (256 bit); the helper stores only its SHA-256 hash and owns all
// session state (expiry, step-up, revocation), so sessions survive restarts of
// both processes and nothing session-related is kept in the web process.
type Sessions struct{}

// NewSessions returns the cookie binder.
func NewSessions() *Sessions { return &Sessions{} }

func setCookie(w http.ResponseWriter, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{Name: SessionCookie, Value: value, Path: "/", Secure: true, HttpOnly: true,
		SameSite: http.SameSiteStrictMode, MaxAge: maxAge})
}

// Create sets the session cookie for grant (replacing any previous cookie).
func (s *Sessions) Create(w http.ResponseWriter, _ *http.Request, grant string) {
	setCookie(w, grant, 0)
}

// Grant returns the grant presented by the request ("" if none or malformed).
func (s *Sessions) Grant(r *http.Request) string {
	c, err := r.Cookie(SessionCookie)
	if err != nil || len(c.Value) > 96 || !strings.HasPrefix(c.Value, "dmn_grant_") {
		return ""
	}
	return c.Value
}

// Destroy clears the cookie.
func (s *Sessions) Destroy(w http.ResponseWriter, _ *http.Request) { setCookie(w, "", -1) }

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
	// File manager (M1.3).
	case "permission_denied", "path_blocked", "protected_path", "root_mode_required":
		return http.StatusForbidden
	case "sensitive_path", "already_exists", "not_empty", "symlink_refused", "virtual_fs", "busy", "mount_point",
		"not_regular_file", "is_a_directory", "not_a_directory", "read_only_fs", "limit_exceeded", "no_login_shell":
		return http.StatusConflict
	case "no_space":
		return http.StatusInsufficientStorage
	case "too_large":
		return http.StatusRequestEntityTooLarge
	case "range_not_satisfiable":
		return http.StatusRequestedRangeNotSatisfiable
	case "aborted":
		return http.StatusBadRequest
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
	// newConn: the response closes the connection (HTTP/1.1 close, HTTP/2
	// GOAWAY) and the config is reloaded, so the next request must pass the
	// new allowlist on a fresh connection.
	newConn bool
	// connSince adds the connection accept time as "connection_since".
	connSince bool
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
			params = mergeField(params, "id", pv)
		}
		if e.connSince {
			params = mergeField(params, "connection_since", connSince(r).Format(time.RFC3339Nano))
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
		if e.newConn {
			w.Header().Set("Connection", "close")
			if s.ReloadConfig != nil {
				s.ReloadConfig()
			}
		}
		switch {
		case e.setGrant || e.stepUp:
			var gr struct {
				Grant   string          `json:"grant"`
				Account json.RawMessage `json:"account"`
			}
			if json.Unmarshal(out, &gr) != nil || gr.Grant == "" {
				Problem(w, r, http.StatusInternalServerError, "internal_error")
				return
			}
			s.Sessions.Create(w, r, gr.Grant)
			if e.stepUp {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			writeJSON(w, http.StatusOK, map[string]json.RawMessage{"account": gr.Account})
			return
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

func mergeField(params json.RawMessage, key, val string) json.RawMessage {
	m := map[string]any{}
	if len(params) > 0 {
		_ = json.Unmarshal(params, &m)
	}
	m[key] = val
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

	// Recovery (token from `daemonica-admin recover`).
	mux.Handle("POST /api/v1/recovery/begin", pre("recovery.begin_register"))
	mux.Handle("POST /api/v1/recovery/finish", s.forward(endpoint{op: "recovery.finish_register", preauth: true, setGrant: true, maxBody: 64 << 10}))

	// Authenticated session.
	mux.Handle("GET /api/v1/session", sess("session.whoami"))
	mux.Handle("POST /api/v1/auth/stepup/begin", sess("auth.begin_stepup"))
	mux.Handle("POST /api/v1/auth/stepup/finish", s.forward(endpoint{op: "auth.finish_stepup", session: true, stepUp: true, maxBody: 64 << 10}))
	mux.Handle("POST /api/v1/auth/logout", s.forward(endpoint{op: "auth.logout", session: true, logout: true}))
	mux.Handle("GET /api/v1/sessions", sess("sessions.list"))
	mux.Handle("POST /api/v1/sessions/list", sess("sessions.list"))
	mux.Handle("DELETE /api/v1/sessions/{id}", sess("sessions.revoke"))
	mux.Handle("GET /api/v1/passkeys", sess("passkeys.list"))
	mux.Handle("POST /api/v1/passkeys/begin", sess("passkeys.begin_add"))
	mux.Handle("POST /api/v1/passkeys/finish", s.forward(endpoint{op: "passkeys.finish_add", session: true, maxBody: 64 << 10}))
	mux.Handle("PATCH /api/v1/passkeys/{id}", sess("passkeys.rename"))
	mux.Handle("DELETE /api/v1/passkeys/{id}", sess("passkeys.remove"))

	// Invitations (token from an admin, SPEC §7.1).
	mux.Handle("POST /api/v1/invite/begin", pre("invite.begin_register"))
	mux.Handle("POST /api/v1/invite/finish", s.forward(endpoint{op: "invite.finish_register", preauth: true, setGrant: true, maxBody: 64 << 10}))

	// Account administration (admin; changes need step-up, enforced by the helper).
	mux.Handle("GET /api/v1/accounts", sess("accounts.list"))
	mux.Handle("GET /api/v1/accounts/linux-users", sess("accounts.linux_users"))
	mux.Handle("POST /api/v1/accounts", sess("accounts.invite"))
	mux.Handle("POST /api/v1/accounts/{id}/reinvite", sess("accounts.reinvite"))
	mux.Handle("PATCH /api/v1/accounts/{id}/role", sess("accounts.set_role"))
	mux.Handle("PATCH /api/v1/accounts/{id}/disabled", sess("accounts.set_disabled"))
	mux.Handle("DELETE /api/v1/accounts/{id}", sess("accounts.delete"))

	// Audit log (admin).
	mux.Handle("POST /api/v1/audit/query", sess("audit.query"))
	mux.Handle("POST /api/v1/audit/verify", sess("audit.verify"))

	// Settings with Plan → Apply → Confirm (SPEC §3.2 rule 10).
	// M1.1: overview, processes, services, journal.
	mux.Handle("GET /api/v1/system/overview", sess("sysinfo.overview"))
	mux.Handle("GET /api/v1/processes", s.forward(endpoint{op: "proc.list", session: true}))
	mux.Handle("POST /api/v1/processes/signal", sess("proc.signal"))
	mux.Handle("GET /api/v1/services", sess("services.list"))
	mux.Handle("POST /api/v1/services/get", sess("services.get"))
	mux.Handle("POST /api/v1/services/action", sess("services.action"))
	mux.Handle("POST /api/v1/journal/query", sess("journal.query"))

	// M1.2: Linux users/groups and SSH keys.
	mux.Handle("POST /api/v1/users/list", sess("users.list"))
	for _, op := range []string{"create", "update", "set_locked", "set_sudo", "delete"} {
		mux.Handle("POST /api/v1/users/"+op, sess("users."+op))
	}
	mux.Handle("POST /api/v1/users/set_password", s.forward(endpoint{op: "users.set_password", session: true, maxBody: 4 << 10}))
	for _, op := range []string{"create", "set_members", "delete"} {
		mux.Handle("POST /api/v1/users/groups/"+op, sess("groups."+op))
	}
	mux.Handle("GET /api/v1/ssh-keys/server", sess("sshkeys.server"))
	for _, op := range []string{"list", "add", "remove", "set_options", "fix_permissions"} {
		mux.Handle("POST /api/v1/ssh-keys/"+op, sess("sshkeys."+op))
	}

	// M1.5a: network.
	mux.Handle("GET /api/v1/network", sess("net.get"))
	mux.Handle("GET /api/v1/network/ports", sess("net.ports"))
	mux.Handle("POST /api/v1/network/config", sess("net.config"))
	mux.Handle("POST /api/v1/network/plan", sess("net.plan"))

	// M1.5b: firewall.
	mux.Handle("GET /api/v1/firewall", sess("firewall.get"))
	mux.Handle("GET /api/v1/firewall/raw", sess("firewall.raw"))
	mux.Handle("POST /api/v1/firewall/plan", sess("firewall.plan"))
	mux.Handle("POST /api/v1/firewall/install", sess("firewall.install"))
	mux.Handle("POST /api/v1/firewall/logs", sess("firewall.logs"))

	// M1.5d: packet capture.
	mux.Handle("GET /api/v1/captures", sess("capture.status"))
	for _, op := range []string{"start", "stop", "lines", "delete", "delete_all", "settings", "download_token", "install"} {
		mux.Handle("POST /api/v1/captures/"+op, sess("capture."+op))
	}
	mux.Handle("GET /api/v1/captures/download/{token}", http.HandlerFunc(s.captureDownload))

	// M1.6: scheduled tasks.
	mux.Handle("GET /api/v1/jobs", sess("jobs.overview"))
	for _, op := range []string{"get", "calendar", "check", "save", "delete", "run", "stop", "enable"} {
		mux.Handle("POST /api/v1/jobs/"+op, sess("jobs."+op))
	}
	mux.Handle("POST /api/v1/cron/get", sess("cron.get"))
	mux.Handle("POST /api/v1/cron/save", sess("cron.save"))
	mux.Handle("POST /api/v1/cron/preview", sess("cron.preview"))
	mux.Handle("GET /api/v1/scripts", sess("scripts.list"))
	for _, op := range []string{"read", "preview", "check", "add", "update", "remove", "delete"} {
		mux.Handle("POST /api/v1/scripts/"+op, sess("scripts."+op))
	}
	mux.Handle("POST /api/v1/scripts/save", s.forward(endpoint{op: "scripts.save", session: true, maxBody: 1 << 20}))

	mux.Handle("GET /api/v1/settings", sess("settings.get"))
	mux.Handle("POST /api/v1/settings/allowlist/plan", sess("settings.allowlist_plan"))
	mux.Handle("GET /api/v1/changes/{id}", sess("settings.change_get"))
	mux.Handle("POST /api/v1/changes/{id}/apply", s.forward(endpoint{op: "settings.change_apply", session: true, newConn: true}))
	mux.Handle("POST /api/v1/changes/{id}/confirm", s.forward(endpoint{op: "settings.change_confirm", session: true, connSince: true}))
	mux.Handle("POST /api/v1/changes/{id}/rollback", s.forward(endpoint{op: "settings.change_rollback", session: true, newConn: true}))
}
