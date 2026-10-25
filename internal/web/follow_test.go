package web

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/coder/websocket"

	"github.com/PanPakaPancake/daemonica/internal/rpc"
)

// fakeFollowHelper serves firewall.logs: no cursor → start cursor c0; after
// c0 → 150 entries and c1; after c1 → forbidden (e.g. the role changed).
func fakeFollowHelper(t *testing.T) string {
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
				var p map[string]any
				_ = json.Unmarshal(req.Params, &p)
				var resp *rpc.Response
				switch p["after"] {
				case nil:
					resp, _ = rpc.Succeed(req.ID, map[string]any{"entries": []any{}, "cursor": "c0"})
				case "c0":
					es := make([]map[string]int, 150)
					for i := range es {
						es[i] = map[string]int{"n": i}
					}
					resp, _ = rpc.Succeed(req.ID, map[string]any{"entries": es, "cursor": "c1"})
				default:
					resp = rpc.Fail(req.ID, rpc.CodeForbidden, "")
				}
				_ = rpc.WriteFrame(c, resp)
			}()
		}
	}()
	return sock
}

func TestFollowSocket(t *testing.T) {
	s := &Server{
		Helper:   &rpc.Client{Socket: fakeFollowHelper(t)},
		Log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		UI:       fstest.MapFS{"index.html": {Data: []byte("x")}},
		Limiter:  NewRateLimiter(100, 100, 100, 100),
		Sessions: NewSessions(),
	}
	ts := httptest.NewServer(nil)
	s.Origins = func() []string { return []string{ts.URL} }
	ts.Config.Handler = s.Handler()
	t.Cleanup(ts.Close)

	post := func(body string) (*http.Response, string) {
		req, _ := http.NewRequest("POST", ts.URL+"/api/v1/follow/ticket", strings.NewReader(body))
		req.Header.Set(CSRFHeader, "1")
		req.Header.Set("Origin", ts.URL)
		req.AddCookie(&http.Cookie{Name: SessionCookie, Value: testGrant})
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		var out struct {
			Ticket string `json:"ticket"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp, out.Ticket
	}
	if r, _ := post(`{"op":"pty.open","params":{}}`); r.StatusCode != http.StatusBadRequest {
		t.Fatalf("op outside the follow list: %d", r.StatusCode)
	}
	r, tk := post(`{"op":"firewall.logs","params":{"filter":{"action":"block"}}}`)
	if r.StatusCode != http.StatusOK || tk == "" {
		t.Fatalf("ticket: %d", r.StatusCode)
	}
	// A follow ticket does not open a terminal.
	if _, r, err := dial(ts, tk, ts.URL, testGrant); err == nil || r == nil || r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("terminal with follow ticket: %v", err)
	}
	_, tk = post(`{"op":"firewall.logs","params":{"filter":{"action":"block"}}}`)
	h := http.Header{}
	h.Set("Origin", ts.URL)
	h.Set("Cookie", SessionCookie+"="+testGrant)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(ts.URL, "http")+"/api/v1/follow/ws?ticket="+tk, &websocket.DialOptions{HTTPHeader: h})
	if err != nil {
		t.Fatal(err)
	}
	_, b, err := c.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var msg struct {
		Entries []map[string]int `json:"entries"`
		Skipped int              `json:"skipped"`
	}
	_ = json.Unmarshal(b, &msg)
	if len(msg.Entries) != followRate || msg.Skipped != 50 || msg.Entries[0]["n"] != 50 {
		t.Fatalf("first page: %d entries, %d skipped", len(msg.Entries), msg.Skipped)
	}
	_, _, err = c.Read(ctx)
	var ce websocket.CloseError
	if !errors.As(err, &ce) || ce.Code != CloseFollowEnded || ce.Reason != "error:forbidden" {
		t.Fatalf("close: %v", err)
	}
}
