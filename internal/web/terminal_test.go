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

// fakeTerminalHelper answers pty.check and runs an echo "terminal" for pty.open
// (input "exit" ends it with reason "exit").
func fakeTerminalHelper(t *testing.T, checkCode string) string {
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
				if checkCode != "" {
					_ = rpc.WriteFrame(c, rpc.Fail(req.ID, checkCode, ""))
					return
				}
				ok, _ := rpc.Succeed(req.ID, map[string]string{"mode": "standard"})
				_ = rpc.WriteFrame(c, ok)
				if req.Op != "pty.open" {
					return
				}
				for {
					b, err := rpc.ReadChunk(c)
					if err != nil {
						return
					}
					if b[0] == 'd' && string(b[1:]) == "exit" {
						_ = rpc.WriteChunk(c, nil)
						end, _ := rpc.Succeed(req.ID, map[string]any{"reason": "exit", "exit_code": 0})
						_ = rpc.WriteFrame(c, end)
						return
					}
					_ = rpc.WriteChunk(c, append([]byte("echo:"), b...))
				}
			}()
		}
	}()
	return sock
}

const testGrant = "dmn_grant_test"

func terminalServer(t *testing.T, checkCode string) *httptest.Server {
	t.Helper()
	s := &Server{
		Helper:   &rpc.Client{Socket: fakeTerminalHelper(t, checkCode)},
		Log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		UI:       fstest.MapFS{"index.html": {Data: []byte("x")}},
		Limiter:  NewRateLimiter(100, 100, 100, 100),
		Sessions: NewSessions(),
	}
	ts := httptest.NewServer(nil)
	origin := "http://" + ts.Listener.Addr().String()
	s.Origins = func() []string { return []string{origin} }
	ts.Config.Handler = s.Handler()
	t.Cleanup(ts.Close)
	return ts
}

func ticket(t *testing.T, ts *httptest.Server, grant string) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest("POST", ts.URL+"/api/v1/terminal/ticket", strings.NewReader(`{"mode":"standard","cols":80,"rows":24}`))
	req.Header.Set(CSRFHeader, "1")
	req.Header.Set("Origin", ts.URL)
	req.AddCookie(&http.Cookie{Name: SessionCookie, Value: grant})
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

func dial(ts *httptest.Server, tk, origin, grant string) (*websocket.Conn, *http.Response, error) {
	h := http.Header{}
	h.Set("Origin", origin)
	h.Set("Cookie", SessionCookie+"="+grant)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return websocket.Dial(ctx, "ws"+strings.TrimPrefix(ts.URL, "http")+"/api/v1/terminal/ws?ticket="+tk, &websocket.DialOptions{HTTPHeader: h})
}

func TestTerminalSocketRoundTrip(t *testing.T) {
	ts := terminalServer(t, "")
	resp, tk := ticket(t, ts, testGrant)
	if resp.StatusCode != http.StatusOK || tk == "" {
		t.Fatalf("ticket: %d", resp.StatusCode)
	}
	c, _, err := dial(ts, tk, ts.URL, testGrant)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	_ = c.Write(ctx, websocket.MessageBinary, []byte("dls"))
	_, b, err := c.Read(ctx)
	if err != nil || string(b) != "echo:dls" {
		t.Fatalf("echo: %q %v", b, err)
	}
	_ = c.Write(ctx, websocket.MessageBinary, []byte("dexit"))
	_, _, err = c.Read(ctx)
	var ce websocket.CloseError
	if !errors.As(err, &ce) || ce.Code != CloseTerminalEnded || ce.Reason != "exit" {
		t.Fatalf("close: %v", err)
	}
	// A ticket is single-use.
	if _, r, err := dial(ts, tk, ts.URL, testGrant); err == nil || r == nil || r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("reused ticket: %v", err)
	}
}

func TestTerminalSocketRejectsForeignOriginAndSession(t *testing.T) {
	ts := terminalServer(t, "")
	_, tk := ticket(t, ts, testGrant)
	if _, r, err := dial(ts, tk, "https://evil.example", testGrant); err == nil || r == nil || r.StatusCode != http.StatusForbidden {
		t.Fatalf("foreign origin: %v", err)
	}
	_, tk = ticket(t, ts, testGrant)
	if _, r, err := dial(ts, tk, ts.URL, "dmn_grant_other"); err == nil || r == nil || r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("other session: %v", err)
	}
	if _, r, err := dial(ts, "nope", ts.URL, testGrant); err == nil || r == nil || r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unknown ticket: %v", err)
	}
}

func TestTerminalTicketPassesHelperVerdict(t *testing.T) {
	ts := terminalServer(t, rpc.CodeStepUpNeeded)
	if resp, tk := ticket(t, ts, testGrant); resp.StatusCode != http.StatusForbidden || tk != "" {
		t.Fatalf("step-up: %d %q", resp.StatusCode, tk)
	}
	if resp, _ := ticket(t, ts, ""); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no session: %d", resp.StatusCode)
	}
}
