package netallow

import (
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestDefaultIsLoopback(t *testing.T) {
	a := New(nil)
	if !a.Contains(netip.MustParseAddr("127.0.0.1")) || !a.Contains(netip.MustParseAddr("::1")) {
		t.Fatal("loopback must be allowed by default")
	}
	if a.Contains(netip.MustParseAddr("203.0.113.5")) {
		t.Fatal("public address must be denied by default")
	}
	if !a.Contains(netip.MustParseAddr("::ffff:127.0.0.1")) {
		t.Fatal("v4-mapped loopback must match")
	}
}

func TestParseList(t *testing.T) {
	got, err := ParseList([]string{"192.168.1.7/24", "2001:db8::1", "192.168.1.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("dedupe/mask failed: %v", got)
	}
	for _, bad := range []string{"", "300.1.1.1", "10.0.0.0/33", "fe80::1%eth0", "x", "1.2.3.4/24;rm"} {
		if _, err := ParseList([]string{bad}); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestIsPublic(t *testing.T) {
	p, _ := ParseList([]string{"0.0.0.0/0"})
	if !IsPublic(p) {
		t.Fatal("0.0.0.0/0 is public")
	}
	p, _ = ParseList([]string{"10.0.0.0/8", "fd00::/8"})
	if IsPublic(p) {
		t.Fatal("private ranges are not public")
	}
}

func TestListenerDropsDisallowed(t *testing.T) {
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	a := New([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}) // loopback NOT allowed
	rejected := make(chan netip.Addr, 1)
	a.OnReject = func(addr netip.Addr) { rejected <- addr }
	l := &Listener{Listener: inner, Allow: a}
	defer func() { _ = l.Close() }()

	accepted := make(chan struct{}, 1)
	go func() {
		if c, err := l.Accept(); err == nil {
			_ = c.Close()
			accepted <- struct{}{}
		}
	}()
	// The peer may see the reset during or right after the handshake.
	c, dialErr := net.Dial("tcp", inner.Addr().String())
	if dialErr == nil {
		defer func() { _ = c.Close() }()
	}
	select {
	case addr := <-rejected:
		if !addr.IsLoopback() {
			t.Fatalf("unexpected addr %v", addr)
		}
	case <-accepted:
		t.Fatal("disallowed connection was accepted")
	case <-time.After(2 * time.Second):
		t.Fatal("timeout")
	}
	// Peer observes closed connection.
	if dialErr == nil {
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := c.Read(make([]byte, 1)); err == nil {
			t.Fatal("expected closed connection")
		}
	}

	// Now allow loopback: next connection accepted.
	a.Set(Loopback)
	c2, err := net.Dial("tcp", inner.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c2.Close() }()
	select {
	case <-accepted:
	case <-time.After(2 * time.Second):
		t.Fatal("allowed connection not accepted")
	}
}
