package tlsconf

import (
	"crypto/tls"
	"net"
	"testing"
	"time"
)

func TestTLS13Only(t *testing.T) {
	h := &Holder{}
	c, err := SelfSignedSetup([]string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	h.Set(c)
	cfg := Config(h)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.(*tls.Conn).Handshake()
			_ = conn.Close()
		}
	}()

	// TLS 1.2 client must fail.
	_, err = tls.Dial("tcp", ln.Addr().String(), &tls.Config{MaxVersion: tls.VersionTLS12, InsecureSkipVerify: true}) //nolint:gosec // test
	if err == nil {
		t.Fatal("TLS 1.2 handshake succeeded")
	}
	conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // test
	if err != nil {
		t.Fatal(err)
	}
	if conn.ConnectionState().Version != tls.VersionTLS13 {
		t.Fatal("not TLS 1.3")
	}
	_ = conn.Close()
}

func TestDaysLeft(t *testing.T) {
	c, _ := SelfSignedSetup([]string{"x"}, nil, 48*time.Hour)
	if d := DaysLeft(c, time.Now()); d < 1 || d > 2 {
		t.Fatalf("days left %d", d)
	}
}
