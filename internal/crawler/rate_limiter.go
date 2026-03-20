package crawler

import (
	"context"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// RateLimiter manages per-WHOIS-server rate limiting using token buckets.
type RateLimiter struct {
	mu       sync.RWMutex
	limiters map[string]*serverLimiter

	defaultQPS   float64
	defaultBurst int
}

type serverLimiter struct {
	limiter      *rate.Limiter
	backoffUntil time.Time
}

func NewRateLimiter(defaultQPS float64, defaultBurst int) *RateLimiter {
	if defaultQPS <= 0 {
		defaultQPS = 1.0
	}
	if defaultBurst <= 0 {
		defaultBurst = 3
	}
	return &RateLimiter{
		limiters:     make(map[string]*serverLimiter),
		defaultQPS:   defaultQPS,
		defaultBurst: defaultBurst,
	}
}

// Wait blocks until the rate limiter allows a query to the given server.
// Returns an error if the server is in backoff.
func (rl *RateLimiter) Wait(server string) error {
	sl := rl.getOrCreate(server)

	// Check backoff
	if !sl.backoffUntil.IsZero() && time.Now().Before(sl.backoffUntil) {
		waitTime := time.Until(sl.backoffUntil)
		time.Sleep(waitTime)
	}

	// Use the token bucket
	return sl.limiter.Wait(context.Background())
}

// Allow checks if a query to the server is allowed without blocking.
func (rl *RateLimiter) Allow(server string) bool {
	sl := rl.getOrCreate(server)

	if !sl.backoffUntil.IsZero() && time.Now().Before(sl.backoffUntil) {
		return false
	}

	return sl.limiter.Allow()
}

// Backoff sets a backoff period for a server (e.g., after rate limit detection).
func (rl *RateLimiter) Backoff(server string, duration time.Duration) {
	sl := rl.getOrCreate(server)

	rl.mu.Lock()
	defer rl.mu.Unlock()
	sl.backoffUntil = time.Now().Add(duration)
}

// ExponentialBackoff applies increasing backoff based on consecutive failures.
func (rl *RateLimiter) ExponentialBackoff(server string, failures int) {
	// 1s, 2s, 4s, 8s, 16s, 32s, 64s, 128s, 256s, max 300s
	seconds := 1 << failures
	if seconds > 300 {
		seconds = 300
	}
	rl.Backoff(server, time.Duration(seconds)*time.Second)
}

// SetRate updates the rate limit for a specific server.
func (rl *RateLimiter) SetRate(server string, qps float64, burst int) {
	sl := rl.getOrCreate(server)

	rl.mu.Lock()
	defer rl.mu.Unlock()
	sl.limiter.SetLimit(rate.Limit(qps))
	sl.limiter.SetBurst(burst)
}

// IsBackedOff returns whether a server is currently in a backoff period.
func (rl *RateLimiter) IsBackedOff(server string) bool {
	rl.mu.RLock()
	sl, ok := rl.limiters[server]
	rl.mu.RUnlock()

	if !ok {
		return false
	}
	return !sl.backoffUntil.IsZero() && time.Now().Before(sl.backoffUntil)
}

func (rl *RateLimiter) getOrCreate(server string) *serverLimiter {
	rl.mu.RLock()
	sl, ok := rl.limiters[server]
	rl.mu.RUnlock()

	if ok {
		return sl
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()

	// Double-check after acquiring write lock
	if sl, ok := rl.limiters[server]; ok {
		return sl
	}

	sl = &serverLimiter{
		limiter: rate.NewLimiter(rate.Limit(rl.defaultQPS), rl.defaultBurst),
	}
	rl.limiters[server] = sl
	return sl
}
