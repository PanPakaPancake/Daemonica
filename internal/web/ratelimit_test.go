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
