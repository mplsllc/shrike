package middleware

import (
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
)

// RateLimitConfig holds rate limit settings per tier.
type RateLimitConfig struct {
	AnonymousPerMin   int
	FreeKeyPerMin     int
	ContributorPerMin int
}

type clientLimiter struct {
	limiter    *rate.Limiter
	lastSeen   time.Time
	violations int       // consecutive rate limit hits
	bannedUntil time.Time // progressive ban
}

// APIRateLimiter provides per-IP and per-key rate limiting with progressive bans.
// After 3 violations in an hour, the client gets a 1-hour cooldown.
// After 10 violations, 24-hour ban.
type APIRateLimiter struct {
	mu       sync.Mutex
	clients  map[string]*clientLimiter
	config   RateLimitConfig
}

func NewAPIRateLimiter(config RateLimitConfig) *APIRateLimiter {
	rl := &APIRateLimiter{
		clients: make(map[string]*clientLimiter),
		config:  config,
	}
	go rl.cleanupLoop()
	return rl
}

// Middleware returns a Gin middleware that enforces rate limits with progressive bans.
func (rl *APIRateLimiter) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Exempt web UI pages, static files, health, and metrics from rate limiting
		path := c.Request.URL.Path
		if !strings.HasPrefix(path, "/api/") {
			c.Next()
			return
		}

		var limitKey string
		var perMin int

		// Check if authenticated
		tier, exists := c.Get("api_tier")
		if exists {
			keyID, _ := c.Get("api_key_id")
			switch tier.(string) {
			case "contributor":
				perMin = rl.config.ContributorPerMin
			case "free":
				perMin = rl.config.FreeKeyPerMin
			default:
				perMin = rl.config.FreeKeyPerMin
			}
			limitKey = "key:" + keyID.(string)
		} else {
			perMin = rl.config.AnonymousPerMin
			limitKey = "ip:" + c.ClientIP()
		}

		cl := rl.getOrCreate(limitKey, perMin)

		// Check if banned
		if !cl.bannedUntil.IsZero() && time.Now().Before(cl.bannedUntil) {
			remaining := int(time.Until(cl.bannedUntil).Seconds())
			c.Header("Retry-After", strings.TrimRight(strings.TrimRight(
				time.Until(cl.bannedUntil).String(), "0"), "."))
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":       "temporarily banned due to excessive requests",
				"retry_after": remaining,
			})
			c.Abort()
			return
		}

		if !cl.limiter.Allow() {
			rl.mu.Lock()
			cl.violations++
			v := cl.violations

			// Progressive bans — aggressive early lockout
			switch {
			case v >= 5:
				cl.bannedUntil = time.Now().Add(24 * time.Hour)
			case v >= 3:
				cl.bannedUntil = time.Now().Add(1 * time.Hour)
			case v >= 2:
				cl.bannedUntil = time.Now().Add(10 * time.Minute)
			}
			rl.mu.Unlock()

			retryAfter := 60
			if !cl.bannedUntil.IsZero() {
				retryAfter = int(time.Until(cl.bannedUntil).Seconds())
			}

			c.Header("Retry-After", "60")
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":       "rate limit exceeded",
				"retry_after": retryAfter,
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// BotProtection returns middleware that blocks obvious bots and scrapers.
// Exempts health/metrics endpoints for monitoring tools.
func BotProtection() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Exempt non-API paths (web UI, health, metrics, static)
		path := c.Request.URL.Path
		if !strings.HasPrefix(path, "/api/") {
			c.Next()
			return
		}

		ua := c.GetHeader("User-Agent")

		// Block empty user agents (most legitimate clients send one)
		if ua == "" {
			c.JSON(http.StatusForbidden, gin.H{"error": "User-Agent header required"})
			c.Abort()
			return
		}

		// Block known scraping tools
		uaLower := strings.ToLower(ua)
		blocked := []string{
			"scrapy", "python-requests/", "go-http-client/",
			"wget/", "curl/", "libwww-perl",
			"httpclient", "java/", "okhttp/",
			"masscan", "zgrab", "censys",
		}
		for _, b := range blocked {
			if strings.Contains(uaLower, b) {
				// Allow if they have a valid API key
				if _, exists := c.Get("api_tier"); exists {
					break
				}
				c.JSON(http.StatusForbidden, gin.H{
					"error":   "automated access requires an API key",
					"signup":  "/api/v1/keys/signup",
					"message": "API keys are free. Sign up to use the API programmatically.",
				})
				c.Abort()
				return
			}
		}

		c.Next()
	}
}

// RequestSizeLimit limits the maximum request body size.
func RequestSizeLimit(maxBytes int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.ContentLength > maxBytes {
			c.JSON(http.StatusRequestEntityTooLarge, gin.H{
				"error": "request body too large",
			})
			c.Abort()
			return
		}
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxBytes)
		c.Next()
	}
}

func (rl *APIRateLimiter) getOrCreate(key string, perMin int) *clientLimiter {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	cl, ok := rl.clients[key]
	if ok {
		cl.lastSeen = time.Now()
		return cl
	}

	rps := float64(perMin) / 60.0
	burst := perMin / 6
	if burst < 1 {
		burst = 1
	}

	cl = &clientLimiter{
		limiter:  rate.NewLimiter(rate.Limit(rps), burst),
		lastSeen: time.Now(),
	}
	rl.clients[key] = cl
	return cl
}

// cleanupLoop removes stale entries and resets violation counts periodically.
func (rl *APIRateLimiter) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		rl.mu.Lock()
		cutoff := time.Now().Add(-10 * time.Minute)
		for k, cl := range rl.clients {
			// Remove clients not seen in 10 minutes (unless banned)
			if cl.lastSeen.Before(cutoff) && (cl.bannedUntil.IsZero() || time.Now().After(cl.bannedUntil)) {
				delete(rl.clients, k)
			}
		}
		rl.mu.Unlock()
	}
}
