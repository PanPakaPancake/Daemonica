package web

import (
	"net/netip"
	"testing"
	"time"
)

func TestRateLimiterBurstAndBackoff(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	l := NewRateLimiter(1, 3, 100, 100)
	l.now = func() time.Time { return now }
	ip := netip.MustParseAddr("198.51.100.1")
	for i := 0; i < 3; i++ {
		if !l.Allow(ip) {
			t.Fatalf("burst request %d refused", i)
		}
	}
	if l.Allow(ip) {
		t.Fatal("burst exceeded")
	}
	now = now.Add(2 * time.Second)
	if !l.Allow(ip) {
		t.Fatal("refill failed")
	}
	other := netip.MustParseAddr("198.51.100.2")
	if !l.Allow(other) {
		t.Fatal("independent IP throttled (no global lockout expected)")
	}
	l.Fail(ip)
	l.Fail(ip)
	now = now.Add(time.Second)
	if l.Allow(ip) {
		t.Fatal("backoff not applied")
	}
	now = now.Add(5 * time.Second)
	if !l.Allow(ip) {
		t.Fatal("backoff did not expire")
	}
}

func TestGlobalLimit(t *testing.T) {
	l := NewRateLimiter(100, 100, 0, 2)
	a, b, c := netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2"), netip.MustParseAddr("10.0.0.3")
	if !l.Allow(a) || !l.Allow(b) {
		t.Fatal("unexpected refusal")
	}
	if l.Allow(c) {
		t.Fatal("global limit not enforced")
	}
}

func TestRateLimiterIPv6Prefix(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	l := NewRateLimiter(0.001, 2, 100, 100)
	l.now = func() time.Time { return now }
	// Rotating addresses inside one /64 shares the bucket.
	for i, a := range []string{"2001:db8:1:2::1", "2001:db8:1:2::2"} {
		if !l.Allow(netip.MustParseAddr(a)) {
			t.Fatalf("request %d refused", i)
		}
	}
	if l.Allow(netip.MustParseAddr("2001:db8:1:2:ffff::9")) {
		t.Fatal("same /64 escaped the per-IP limit")
	}
	if !l.Allow(netip.MustParseAddr("2001:db8:1:3::1")) {
		t.Fatal("other /64 throttled")
	}
	// IPv4-mapped addresses count as the IPv4 address.
	l.Fail(netip.MustParseAddr("::ffff:198.51.100.7"))
	if l.Allow(netip.MustParseAddr("198.51.100.7")) {
		t.Fatal("mapped address escaped the backoff")
	}
}
