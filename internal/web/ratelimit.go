package web

import (
	"net/netip"
	"sync"
	"time"
)

// RateLimiter is a token bucket per client IP plus a global bucket, with
// exponential backoff per IP after repeated failures (SPEC §3.3 login
// hardening: no account lockout, only per-IP and global limits).
type RateLimiter struct {
	mu     sync.Mutex
	perIP  map[netip.Addr]*bucket
	global bucket
	rate   float64 // tokens per second per IP
	burst  float64
	gRate  float64
	gBurst float64
	maxIPs int
	now    func() time.Time
}

type bucket struct {
	tokens   float64
	last     time.Time
	failures int
	blockTil time.Time
}

// NewRateLimiter creates a limiter. Example: NewRateLimiter(0.2, 5, 5, 50).
func NewRateLimiter(perIPRate, perIPBurst, globalRate, globalBurst float64) *RateLimiter {
	return &RateLimiter{perIP: map[netip.Addr]*bucket{}, rate: perIPRate, burst: perIPBurst,
		gRate: globalRate, gBurst: globalBurst, maxIPs: 10000, now: time.Now,
		global: bucket{tokens: globalBurst}}
}

func refill(b *bucket, now time.Time, rate, burst float64) {
	if b.last.IsZero() {
		b.tokens, b.last = burst, now
		return
	}
	b.tokens += now.Sub(b.last).Seconds() * rate
	if b.tokens > burst {
		b.tokens = burst
	}
	b.last = now
}

// Allow consumes one token for ip; false means "429".
func (l *RateLimiter) Allow(ip netip.Addr) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	b, ok := l.perIP[ip]
	if !ok {
		if len(l.perIP) >= l.maxIPs {
			l.gc(now)
		}
		b = &bucket{}
		l.perIP[ip] = b
	}
	if now.Before(b.blockTil) {
		return false
	}
	refill(b, now, l.rate, l.burst)
	refill(&l.global, now, l.gRate, l.gBurst)
	if b.tokens < 1 || l.global.tokens < 1 {
		return false
	}
	b.tokens--
	l.global.tokens--
	return true
}

// Fail records a failed attempt and applies exponential backoff (1s … 15 min).
func (l *RateLimiter) Fail(ip netip.Addr) {
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.perIP[ip]
	if !ok {
		b = &bucket{}
		l.perIP[ip] = b
	}
	b.failures++
	d := time.Second << min(b.failures-1, 10)
	if d > 15*time.Minute {
		d = 15 * time.Minute
	}
	b.blockTil = l.now().Add(d)
}

// Success resets the backoff for ip.
func (l *RateLimiter) Success(ip netip.Addr) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if b, ok := l.perIP[ip]; ok {
		b.failures = 0
		b.blockTil = time.Time{}
	}
}

func (l *RateLimiter) gc(now time.Time) {
	for ip, b := range l.perIP {
		if now.After(b.blockTil) && now.Sub(b.last) > time.Hour {
			delete(l.perIP, ip)
		}
	}
}
