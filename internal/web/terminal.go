package web

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"sync"
	"time"

	"github.com/coder/websocket"

	"github.com/PanPakaPancake/daemonica/internal/rpc"
)

// Web terminal transport (SPEC §7.5). The browser first asks for a ticket
// with a normal CSRF-protected POST (the helper checks role, step-up and the
// terminal limit there), then opens the WebSocket with that ticket. A ticket
// is single-use, valid for 30 s and bound to the session cookie and the
// client address; the upgrade also requires the exact dashboard origin.
//
// Frames: browser → server binary messages are passed to the helper as they
// are ('d' + input or 'r' + cols/rows, the helper validates them); server →
// browser binary messages are terminal output. When the session ends the
// server closes the socket with code 4000 and the end reason as text.

const (
	ticketTTL      = 30 * time.Second
	maxTickets     = 64
	termReadLimit  = 64<<10 + 1
	termCheckEvery = 2 * time.Second
	// CloseTerminalEnded is the WebSocket close code carrying the end reason.
	CloseTerminalEnded websocket.StatusCode = 4000
)

type termTicket struct {
	grant   string
	ip      netip.Addr
	params  json.RawMessage
	op      string // follow tickets: the followed query
	expires time.Time
}

// terminalTickets holds the issued, unused tickets (in memory only).
type terminalTickets struct {
	mu sync.Mutex
	m  map[string]termTicket
}

func (tt *terminalTickets) issue(t termTicket) (string, bool) {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	id := base64.RawURLEncoding.EncodeToString(b)
	tt.mu.Lock()
	defer tt.mu.Unlock()
	if tt.m == nil {
		tt.m = map[string]termTicket{}
	}
	now := time.Now()
	for k, v := range tt.m {
		if now.After(v.expires) {
			delete(tt.m, k)
		}
	}
	if len(tt.m) >= maxTickets {
		return "", false
	}
	t.expires = now.Add(ticketTTL)
	tt.m[id] = t
	return id, true
}

// take removes and returns a valid ticket.
func (tt *terminalTickets) take(id string) (termTicket, bool) {
	tt.mu.Lock()
	defer tt.mu.Unlock()
	t, ok := tt.m[id]
	delete(tt.m, id)
	return t, ok && time.Now().Before(t.expires)
}

func (s *Server) registerTerminalRoutes(mux *http.ServeMux) {
	mux.Handle("POST /api/v1/terminal/ticket", LimitBody(1<<10, http.HandlerFunc(s.terminalTicket)))
	mux.Handle("GET /api/v1/terminal/ws", http.HandlerFunc(s.terminalSocket))
}

func (s *Server) terminalTicket(w http.ResponseWriter, r *http.Request) {
	grant := s.Sessions.Grant(r)
	if grant == "" {
		Problem(w, r, http.StatusUnauthorized, "unauthorized")
		return
	}
	var p struct {
		Mode string `json:"mode"`
		Cols uint16 `json:"cols"`
		Rows uint16 `json:"rows"`
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		Problem(w, r, http.StatusBadRequest, "bad_request")
		return
	}
	ip := clientIP(r)
	var info json.RawMessage
	if err := s.Helper.Call(r.Context(), "pty.check", grant, ip.String(), map[string]string{"mode": p.Mode}, &info); err != nil {
		s.rpcFail(w, r, err)
		return
	}
	params, _ := json.Marshal(p)
	id, ok := s.tickets.issue(termTicket{grant: grant, ip: ip, params: params})
	if !ok {
		Problem(w, r, http.StatusTooManyRequests, "rate_limited")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ticket": id, "info": info})
}

func (s *Server) originAllowed(r *http.Request) bool {
	for _, o := range s.Origins() {
		if SameOrigin(r.Header.Get("Origin"), o) {
			return true
		}
	}
	return false
}

func (s *Server) terminalSocket(w http.ResponseWriter, r *http.Request) {
	if !s.originAllowed(r) {
		Problem(w, r, http.StatusForbidden, "origin_mismatch")
		return
	}
	grant := s.Sessions.Grant(r)
	ip := clientIP(r)
	t, ok := s.tickets.take(r.URL.Query().Get("ticket"))
	if grant == "" || !ok || t.grant != grant || t.ip != ip {
		Problem(w, r, http.StatusUnauthorized, "unauthorized")
		return
	}
	// The server's read/write timeouts must not cut a long terminal session.
	rc := http.NewResponseController(w)
	_ = rc.SetReadDeadline(time.Time{})
	_ = rc.SetWriteDeadline(time.Time{})
	// The origin was checked exactly above; the library's own check (Origin
	// host = Host header) gets the same hosts.
	var hosts []string
	for _, o := range s.Origins() {
		if u, err := url.Parse(o); err == nil {
			hosts = append(hosts, u.Host)
		}
	}
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{CompressionMode: websocket.CompressionDisabled, OriginPatterns: hosts})
	if err != nil {
		return // Accept has answered
	}
	defer func() { _ = conn.CloseNow() }()
	conn.SetReadLimit(termReadLimit)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d, err := s.Helper.OpenDuplex(ctx, "pty.open", grant, ip.String(), t.params, nil)
	if err != nil {
		code := rpc.ErrorCode(err)
		if code == "" {
			code = rpc.CodeInternal
		}
		_ = conn.Close(CloseTerminalEnded, "error:"+code)
		return
	}
	defer func() { _ = d.Close() }()

	// Browser → helper.
	go func() {
		defer cancel()
		for {
			typ, b, err := conn.Read(ctx)
			if err != nil || typ != websocket.MessageBinary || len(b) == 0 {
				return
			}
			if d.Send(b) != nil {
				return
			}
		}
	}()

	// The allowlist may change while the terminal is open.
	if s.Allow != nil {
		go func() {
			tick := time.NewTicker(termCheckEvery)
			defer tick.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-tick.C:
					if !s.Allow.Contains(ip) {
						_ = conn.Close(CloseTerminalEnded, "allowlist")
						cancel()
						return
					}
				}
			}
		}()
	}

	// Helper → browser.
	buf := make([]byte, rpc.MaxChunk)
	for {
		n, err := d.Read(buf)
		if n > 0 {
			wctx, wcancel := context.WithTimeout(ctx, 30*time.Second)
			werr := conn.Write(wctx, websocket.MessageBinary, buf[:n])
			wcancel()
			if werr != nil {
				return
			}
		}
		if errors.Is(err, io.EOF) {
			var end struct {
				Reason string `json:"reason"`
			}
			reason := "exit"
			if d.Finish(&end) == nil && end.Reason != "" {
				reason = end.Reason
			}
			_ = conn.Close(CloseTerminalEnded, reason)
			return
		}
		if err != nil {
			if ctx.Err() == nil {
				_ = conn.Close(CloseTerminalEnded, "error")
			}
			return
		}
	}
}
