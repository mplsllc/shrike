package middleware

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// cachedKey holds an API key's metadata in memory.
type cachedKey struct {
	id        int64
	tier      string
	loadedAt  time.Time
}

// ApiKeyAuth validates API keys and sets tier info on the context.
// Keys are cached in memory to avoid hitting the DB on every request.
// Anonymous requests (no key) pass through — the rate limiter handles them.
type ApiKeyAuth struct {
	mu    sync.RWMutex
	keys  map[string]*cachedKey // key_hash_hex → cached metadata
	pool  *pgxpool.Pool
	ttl   time.Duration
}

func NewApiKeyAuth(pool *pgxpool.Pool) *ApiKeyAuth {
	return &ApiKeyAuth{
		keys: make(map[string]*cachedKey),
		pool: pool,
		ttl:  5 * time.Minute,
	}
}

// Middleware returns a Gin middleware that extracts and validates API keys.
// Sets "api_tier" and "api_key_id" on the context if a valid key is found.
// Anonymous requests pass through without error.
func (a *ApiKeyAuth) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		key := extractAPIKey(c)
		if key == "" {
			// Anonymous — pass through
			c.Next()
			return
		}

		// Hash the key
		hash := sha256.Sum256([]byte(key))
		hashHex := hex.EncodeToString(hash[:])

		// Check in-memory cache
		cached := a.getCached(hashHex)
		if cached == nil {
			// Cache miss — query DB
			var err error
			cached, err = a.loadFromDB(c.Request.Context(), hash[:])
			if err != nil || cached == nil {
				// Invalid key — treat as anonymous
				c.Next()
				return
			}
			a.setCached(hashHex, cached)
		}

		// Set tier info on context
		c.Set("api_tier", cached.tier)
		c.Set("api_key_id", fmt.Sprintf("%d", cached.id))

		c.Next()
	}
}

func extractAPIKey(c *gin.Context) string {
	// Check Authorization header: "Bearer <key>"
	auth := c.GetHeader("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimPrefix(auth, "Bearer ")
	}

	// Check query parameter
	if key := c.Query("api_key"); key != "" {
		return key
	}

	// Check X-API-Key header
	return c.GetHeader("X-API-Key")
}

func (a *ApiKeyAuth) getCached(hashHex string) *cachedKey {
	a.mu.RLock()
	defer a.mu.RUnlock()

	ck, ok := a.keys[hashHex]
	if !ok {
		return nil
	}
	if time.Since(ck.loadedAt) > a.ttl {
		return nil // Expired
	}
	return ck
}

func (a *ApiKeyAuth) setCached(hashHex string, ck *cachedKey) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.keys[hashHex] = ck
}

func (a *ApiKeyAuth) loadFromDB(ctx context.Context, keyHash []byte) (*cachedKey, error) {
	var id int64
	var tier string
	err := a.pool.QueryRow(ctx,
		`SELECT id, tier FROM api_keys WHERE key_hash = $1 AND revoked_at IS NULL`,
		keyHash).Scan(&id, &tier)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &cachedKey{id: id, tier: tier, loadedAt: time.Now()}, nil
}
