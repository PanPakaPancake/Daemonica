package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"time"

	"github.com/coder/websocket"

	"github.com/PanPakaPancake/daemonica/internal/rpc"
)

// Live follow of log queries (SPEC §7.2 logs, §7.6 M1.5c firewall logs).
// Like the terminal, the browser gets a single-use ticket with a normal
// CSRF-protected POST (the helper checks the role with a first query), then
// opens a WebSocket. The web process repeats the query with the last cursor
// once per second and pushes new entries as JSON text messages
// {"entries": [...], "skipped": n}. At most followRate entries per second are
// sent; the rest are counted in "skipped" (rate limit against log floods).

const (
	followEvery = time.Second
	followRate  = 100
	// CloseFollowEnded carries the reason ("allowlist", "error:<code>") when the server ends a follow.
	CloseFollowEnded websocket.StatusCode = 4000
)

// followOps are the queries that may be followed; each takes an "after" cursor.
var followOps = map[string]bool{"journal.query": true, "firewall.logs": true}

func (s *Server) registerFollowRoutes(mux *http.ServeMux) {
	mux.Handle("POST /api/v1/follow/ticket", LimitBody(4<<10, http.HandlerFunc(s.followTicket)))
	mux.Handle("GET /api/v1/follow/ws", http.HandlerFunc(s.followSocket))
}

type followPage struct {
	Entries   []json.RawMessage `json:"entries"`
	Cursor    string            `json:"cursor"`
	Truncated bool              `json:"truncated"`
}

func (s *Server) followTicket(w http.ResponseWriter, r *http.Request) {
	grant := s.Sessions.Grant(r)
	if grant == "" {
		Problem(w, r, http.StatusUnauthorized, "unauthorized")
		return
	}
	var p struct {
		Op     string         `json:"op"`
		Params map[string]any `json:"params"`
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil || !followOps[p.Op] {
		Problem(w, r, http.StatusBadRequest, "bad_request")
		return
	}
	if p.Params == nil {
		p.Params = map[string]any{}
	}
	ip := clientIP(r)
	// The first query checks role and parameters and yields the start cursor
	// unless the browser continues from its own.
	if _, ok := p.Params["after"].(string); !ok {
		var first followPage
		q := map[string]any{}
		for k, v := range p.Params {
			q[k] = v
		}
		q["lines"] = 1
		if err := s.Helper.Call(r.Context(), p.Op, grant, ip.String(), q, &first); err != nil {
			s.rpcFail(w, r, err)
			return
		}
		if first.Cursor != "" {
			p.Params["after"] = first.Cursor
		}
	} else if err := s.Helper.Call(r.Context(), p.Op, grant, ip.String(), p.Params, &followPage{}); err != nil {
		s.rpcFail(w, r, err)
		return
	}
	params, _ := json.Marshal(p.Params)
	id, ok := s.follows.issue(termTicket{grant: grant, ip: ip, params: params, op: p.Op})
	if !ok {
		Problem(w, r, http.StatusTooManyRequests, "rate_limited")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ticket": id})
}

func (s *Server) followSocket(w http.ResponseWriter, r *http.Request) {
	if !s.originAllowed(r) {
		Problem(w, r, http.StatusForbidden, "origin_mismatch")
		return
	}
	grant := s.Sessions.Grant(r)
	ip := clientIP(r)
	t, ok := s.follows.take(r.URL.Query().Get("ticket"))
	if grant == "" || !ok || t.grant != grant || t.ip != ip || !followOps[t.op] {
		Problem(w, r, http.StatusUnauthorized, "unauthorized")
		return
	}
	rc := http.NewResponseController(w)
	_ = rc.SetReadDeadline(time.Time{})
	_ = rc.SetWriteDeadline(time.Time{})
	var hosts []string
	for _, o := range s.Origins() {
		if u, err := url.Parse(o); err == nil {
			hosts = append(hosts, u.Host)
		}
	}
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{CompressionMode: websocket.CompressionDisabled, OriginPatterns: hosts})
	if err != nil {
		return
	}
	defer func() { _ = conn.CloseNow() }()
	conn.SetReadLimit(1 << 10)
	// The browser sends nothing; CloseRead ends ctx when it goes away.
	ctx := conn.CloseRead(context.Background())

	var params map[string]any
	_ = json.Unmarshal(t.params, &params)
	tick := time.NewTicker(followEvery)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		if s.Allow != nil && !s.Allow.Contains(ip) {
			_ = conn.Close(CloseFollowEnded, "allowlist")
			return
		}
		var page followPage
		cctx, cancel := context.WithTimeout(ctx, 25*time.Second)
		err := s.Helper.Call(cctx, t.op, grant, ip.String(), params, &page)
		cancel()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			code := rpc.ErrorCode(err)
			if code == "" {
				code = rpc.CodeInternal
			}
			_ = conn.Close(CloseFollowEnded, "error:"+code)
			return
		}
		if page.Cursor != "" {
			params["after"] = page.Cursor
		}
		if len(page.Entries) == 0 {
			continue
		}
		msg := struct {
			Entries []json.RawMessage `json:"entries"`
			Skipped int               `json:"skipped"`
		}{Entries: page.Entries}
		if n := len(page.Entries); n > followRate {
			msg.Entries, msg.Skipped = page.Entries[n-followRate:], n-followRate
		}
		b, _ := json.Marshal(msg)
		wctx, wcancel := context.WithTimeout(ctx, 30*time.Second)
		werr := conn.Write(wctx, websocket.MessageText, b)
		wcancel()
		if werr != nil {
			return
		}
	}
}
