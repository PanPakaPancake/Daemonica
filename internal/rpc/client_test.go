package rpc

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"path/filepath"
	"testing"
)

// fakeServer answers each request with handler(req).
func fakeServer(t *testing.T, handler func(*Request) any) string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "s.sock")
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
				req, err := ReadRequest(c)
				if err != nil {
					return
				}
				_ = WriteFrame(c, handler(req))
			}()
		}
	}()
	return sock
}

func TestClientSuccessAndError(t *testing.T) {
	sock := fakeServer(t, func(r *Request) any {
		if r.Op == "x.ok" {
			resp, _ := Succeed(r.ID, map[string]string{"grant": r.Grant, "ip": r.SourceIP})
			return resp
		}
		if r.Op == "x.badid" {
			resp, _ := Succeed(r.ID+1, nil)
			return resp
		}
		if r.Op == "x.noerr" {
			return &Response{V: Version, ID: r.ID}
		}
		return Fail(r.ID, CodeForbidden, "")
	})
	c := &Client{Socket: sock}
	var out map[string]string
	if err := c.Call(context.Background(), "x.ok", "g1", "10.0.0.1", map[string]int{"a": 1}, &out); err != nil {
		t.Fatal(err)
	}
	if out["grant"] != "g1" || out["ip"] != "10.0.0.1" {
		t.Fatalf("unexpected %v", out)
	}
	err := c.Call(context.Background(), "x.deny", "", "", nil, nil)
	if ErrorCode(err) != CodeForbidden {
		t.Fatalf("want forbidden, got %v", err)
	}
	if err := c.Call(context.Background(), "x.badid", "", "", nil, nil); err == nil {
		t.Fatal("id mismatch not detected")
	}
	if ErrorCode(c.Call(context.Background(), "x.noerr", "", "", nil, nil)) != CodeInternal {
		t.Fatal("missing error object must map to internal")
	}
	if ErrorCode(errors.New("plain")) != "" {
		t.Fatal("plain error has no code")
	}
	var e *Error
	if !errors.As(err, &e) || e.Error() == "" {
		t.Fatal("Error() empty")
	}
}

func TestClientUnavailable(t *testing.T) {
	c := &Client{Socket: filepath.Join(t.TempDir(), "missing.sock")}
	if ErrorCode(c.Call(context.Background(), "x.y", "", "", nil, nil)) != CodeUnavailable {
		t.Fatal("expected unavailable")
	}
}

func TestWriteFrameTooLarge(t *testing.T) {
	big := make([]byte, MaxFrameSize)
	for i := range big {
		big[i] = 'a'
	}
	err := WriteFrame(&discard{}, map[string]string{"x": string(big)})
	if !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("got %v", err)
	}
	if err := WriteFrame(&discard{}, func() {}); err == nil {
		t.Fatal("unmarshalable value accepted")
	}
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }

func TestReadResponseValidation(t *testing.T) {
	if _, err := ReadResponse(frame(`{"v":9,"id":1,"ok":true}`)); !errors.Is(err, ErrVersionMismatch) {
		t.Fatal("version mismatch accepted")
	}
	if _, err := ReadResponse(frame(`{"v":1,"id":1,"ok":true,"x":1}`)); err == nil {
		t.Fatal("unknown field accepted")
	}
	raw, _ := json.Marshal(Response{V: 1, ID: 3, OK: true})
	if r, err := ReadResponse(frame(string(raw))); err != nil || r.ID != 3 {
		t.Fatal("valid response rejected")
	}
}
