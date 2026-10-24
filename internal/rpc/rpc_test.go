package rpc

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	req := Request{V: Version, ID: 7, Op: "systemd.restart", Grant: "g", Params: json.RawMessage(`{"unit":"nginx.service"}`)}
	if err := WriteFrame(&buf, req); err != nil {
		t.Fatal(err)
	}
	got, err := ReadRequest(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if got.Op != req.Op || got.ID != 7 || string(got.Params) != string(req.Params) {
		t.Fatalf("mismatch: %+v", got)
	}
}

func TestRejectsOversizedHeaderWithoutAllocating(t *testing.T) {
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], MaxFrameSize+1)
	_, err := ReadFrame(bytes.NewReader(hdr[:]))
	if !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("want ErrFrameTooLarge, got %v", err)
	}
}

func TestRejectsEmptyFrame(t *testing.T) {
	_, err := ReadFrame(bytes.NewReader([]byte{0, 0, 0, 0}))
	if !errors.Is(err, ErrEmptyFrame) {
		t.Fatalf("got %v", err)
	}
}

func frame(payload string) *bytes.Reader {
	var b bytes.Buffer
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(payload)))
	b.Write(hdr[:])
	b.WriteString(payload)
	return bytes.NewReader(b.Bytes())
}

func TestRequestValidation(t *testing.T) {
	cases := map[string]string{
		"wrong version": `{"v":2,"id":1,"op":"a.b"}`,
		"unknown field": `{"v":1,"id":1,"op":"a.b","role":"admin"}`,
		"bad op":        `{"v":1,"id":1,"op":"exec"}`,
		"op injection":  `{"v":1,"id":1,"op":"a.b; rm -rf /"}`,
		"trailing data": `{"v":1,"id":1,"op":"a.b"} {}`,
		"op uppercase":  `{"v":1,"id":1,"op":"A.b"}`,
		"op too deep":   `{"v":1,"id":1,"op":"a.b.c.d.e"}`,
		"not json":      `nope`,
	}
	for name, payload := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ReadRequest(frame(payload)); err == nil {
				t.Fatalf("expected rejection of %s", payload)
			}
		})
	}
}

func TestValidOpName(t *testing.T) {
	for _, ok := range []string{"auth.login", "firewall.logs.query", "fs.list", "pty.open"} {
		if !ValidOpName(ok) {
			t.Errorf("%q should be valid", ok)
		}
	}
	for _, bad := range []string{"", "auth", ".x", "a..b", "a.B", "a.b\n", "a-b.c"} {
		if ValidOpName(bad) {
			t.Errorf("%q should be invalid", bad)
		}
	}
}

func FuzzReadRequest(f *testing.F) {
	f.Add([]byte{0, 0, 0, 2, '{', '}'})
	f.Add([]byte{0, 0, 0, 30, '{', '"', 'v', '"', ':', '1'})
	f.Fuzz(func(t *testing.T, data []byte) {
		req, err := ReadRequest(bytes.NewReader(data))
		if err == nil {
			if req.V != Version || !ValidOpName(req.Op) {
				t.Fatalf("accepted invalid request %+v", req)
			}
		}
	})
}
