package helper

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PanPakaPancake/daemonica/internal/capture"
	"github.com/PanPakaPancake/daemonica/internal/execx"
	"github.com/PanPakaPancake/daemonica/internal/policy"
	"github.com/PanPakaPancake/daemonica/internal/rpc"
)

// capStarter feeds a pcap stream with n records and then ends.
type capStarter struct {
	n    int
	args []string
}

func (f *capStarter) Start(_ context.Context, _ string, args []string, _ capture.Spec) (io.ReadCloser, func(), error) {
	f.args = args
	b := make([]byte, 24)
	binary.LittleEndian.PutUint32(b[0:], 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(b[4:], 2)
	binary.LittleEndian.PutUint16(b[6:], 4)
	binary.LittleEndian.PutUint32(b[16:], 96)
	binary.LittleEndian.PutUint32(b[20:], 101) // raw IP
	for i := 0; i < f.n; i++ {
		pkt := make([]byte, 20)
		pkt[0], pkt[8], pkt[9] = 0x45, 64, 17
		binary.BigEndian.PutUint16(pkt[2:], 20)
		copy(pkt[12:], []byte{10, 0, 0, 1, 10, 0, 0, 2})
		h := make([]byte, 16)
		binary.LittleEndian.PutUint32(h[0:], uint32(1000+i)) //nolint:gosec // test
		binary.LittleEndian.PutUint32(h[8:], 20)
		binary.LittleEndian.PutUint32(h[12:], 20)
		b = append(append(b, h...), pkt...)
	}
	return io.NopCloser(strings.NewReader(string(b))), func() {}, nil
}

func (f *capStarter) Cleanup(context.Context) {}

func TestCaptureOps(t *testing.T) {
	e := newAuthEnv(t)
	g, sa, _ := setupAdmin(t, e)
	td := filepath.Join(t.TempDir(), "tcpdump")
	if err := os.WriteFile(td, nil, 0o755); err != nil { //nolint:gosec // test binary stand-in
		t.Fatal(err)
	}
	old := capture.Tcpdump
	capture.Tcpdump = td
	t.Cleanup(func() { capture.Tcpdump = old })

	var compiled []string
	run := func(_ context.Context, _ time.Duration, path string, args ...string) (execx.Result, error) {
		compiled = append(compiled, path+" "+strings.Join(args, " "))
		if strings.Contains(strings.Join(args, " "), "bogus") {
			return execx.Result{ExitCode: 1}, nil
		}
		return execx.Result{}, nil
	}
	st := &capStarter{n: 3}
	m := &capture.Manager{Dir: filepath.Join(e.dir, "captures"), Starter: st, Free: func(string) (uint64, uint64, error) { return 50, 100, nil }}
	if err := m.Init(context.Background()); err != nil {
		t.Fatal(err)
	}
	ops := &CaptureOps{M: m, Config: e.cfg, Run: run, Ifaces: func() ([]string, error) { return []string{"lo", "eth0"}, nil }}
	ops.Register(e.web.Ops)
	const me = "198.51.100.7"

	r := e.callFrom(me, "capture.status", g, nil)
	mustOK(t, r, "status")
	var s CaptureStatus
	_ = json.Unmarshal(r.Result, &s)
	if !s.Available || len(s.Ifaces) != 2 || s.DashboardPort != 8443 || len(s.Captures) != 0 || s.RetentionHours != 24 {
		t.Fatalf("status: %+v", s)
	}

	spec := map[string]any{"iface": "eth0", "accept_warning": true, "builder": map[string]any{"proto": "udp"}}
	if code(e.callFrom(me, "capture.start", g, spec)) != rpc.CodeStepUpNeeded {
		t.Fatal("start without step-up")
	}
	g = stepUp(t, e, sa, g)
	bad := []struct {
		p    map[string]any
		code string
	}{
		{map[string]any{"iface": "eth0"}, rpc.CodeValidation},                                          // no warning acknowledged
		{map[string]any{"iface": "wlan9", "accept_warning": true}, rpc.CodeValidation},                 // unknown interface
		{map[string]any{"iface": "eth0", "accept_warning": true, "expr": "bogus"}, rpc.CodeValidation}, // does not compile
	}
	for _, b := range bad {
		if c := code(e.callFrom(me, "capture.start", g, b.p)); c != b.code {
			t.Fatalf("start %v: %s", b.p, c)
		}
	}
	r = e.callFrom(me, "capture.start", g, spec)
	mustOK(t, r, "start")
	var meta capture.Meta
	_ = json.Unmarshal(r.Result, &meta)
	if !capture.ValidID(meta.ID) || meta.Iface != "eth0" || !strings.Contains(meta.Filter, "not (tcp port 8443)") {
		t.Fatalf("meta: %+v", meta)
	}
	if last := compiled[len(compiled)-1]; !strings.HasPrefix(last, td+" -d -i eth0") {
		t.Fatalf("compile check: %s", last)
	}

	// The stream ends after three packets.
	var lines capture.Lines
	for i := 0; i < 100; i++ {
		r = e.callFrom(me, "capture.lines", g, map[string]any{"id": meta.ID})
		mustOK(t, r, "lines")
		lines = capture.Lines{}
		_ = json.Unmarshal(r.Result, &lines)
		if !lines.Running && len(lines.Entries) == 3 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if len(lines.Entries) != 3 || lines.Running || lines.Entries[0].Src != "10.0.0.1" {
		t.Fatalf("lines: %+v", lines)
	}
	r = e.callFrom(me, "capture.lines", g, map[string]any{"id": meta.ID, "after": lines.Cursor})
	mustOK(t, r, "lines after")
	lines = capture.Lines{}
	_ = json.Unmarshal(r.Result, &lines)
	if len(lines.Entries) != 0 {
		t.Fatalf("lines after cursor: %+v", lines)
	}

	// Download token: one-time, bound to the session.
	r = e.callFrom(me, "capture.download_token", g, map[string]any{"id": meta.ID})
	mustOK(t, r, "download_token")
	var tok struct {
		Token string `json:"token"`
	}
	_ = json.Unmarshal(r.Result, &tok)
	call := Call{SessionKey: e.web.Grants.SessionKey(g)}
	if _, ok := ops.takeToken(Call{SessionKey: "other"}, tok.Token); ok {
		t.Fatal("token accepted for another session")
	}
	r = e.callFrom(me, "capture.download_token", g, map[string]any{"id": meta.ID})
	_ = json.Unmarshal(r.Result, &tok)
	if id, ok := ops.takeToken(call, tok.Token); !ok || id != meta.ID {
		t.Fatal("token not accepted")
	}
	if _, ok := ops.takeToken(call, tok.Token); ok {
		t.Fatal("token reused")
	}
	r = e.callFrom(me, "capture.download_token", g, map[string]any{"id": meta.ID})
	_ = json.Unmarshal(r.Result, &tok)
	ops.Now = func() time.Time { return time.Now().Add(2 * CaptureTokenTTL) }
	if _, ok := ops.takeToken(call, tok.Token); ok {
		t.Fatal("expired token accepted")
	}
	ops.Now = nil

	// Operators cannot capture or download.
	op, _ := e.web.Grants.Issue(policy.Subject{AccountID: "op", Role: policy.RoleOperator, LinuxUser: "bob", LinuxUID: 1001, StepUp: true}, time.Now())
	for _, o := range []string{"capture.status", "capture.start", "capture.download_token", "capture.delete"} {
		if c := code(e.callFrom(me, o, op, spec)); c != rpc.CodeForbidden {
			t.Fatalf("operator %s: %s", o, c)
		}
	}

	if code(e.callFrom(me, "capture.settings", g, map[string]any{"retention_hours": 0})) != rpc.CodeValidation {
		t.Fatal("retention 0 accepted")
	}
	mustOK(t, e.callFrom(me, "capture.settings", g, map[string]any{"retention_hours": 48}), "settings")
	if ops.Retention() != 48*time.Hour {
		t.Fatalf("retention: %v", ops.Retention())
	}
	mustOK(t, e.callFrom(me, "capture.delete", g, map[string]any{"id": meta.ID}), "delete")
	if code(e.callFrom(me, "capture.delete", g, map[string]any{"id": meta.ID})) != rpc.CodeNotFound {
		t.Fatal("delete twice")
	}
}
