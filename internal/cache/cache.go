package cache

import (
	"fmt"
	"sync"
	"time"

	"git.mp.ls/mpls/shrike/internal/metrics"
	"git.mp.ls/mpls/shrike/internal/models"
)

// entry holds a cached value with expiration.
type entry struct {
	value     interface{}
	expiresAt time.Time
}

func (e *entry) isExpired() bool {
	return time.Now().After(e.expiresAt)
}

// Cache is an in-process LRU-style cache with TTLs per entity type.
// Size-bounded with configurable max entries. Thread-safe.
type Cache struct {
	mu      sync.RWMutex
	data    map[string]*entry
	maxSize int

	// TTLs per entity type
	domainTTL  time.Duration
	ipTTL      time.Duration
	asnTTL     time.Duration
	dnsTTL     time.Duration
	defaultTTL time.Duration
}

func New(maxSize int, defaultTTL time.Duration) *Cache {
	c := &Cache{
		data:       make(map[string]*entry, maxSize),
		maxSize:    maxSize,
		domainTTL:  15 * time.Minute,
		ipTTL:      15 * time.Minute,
		asnTTL:     15 * time.Minute,
		dnsTTL:     5 * time.Minute,
		defaultTTL: defaultTTL,
	}

	// Start background eviction
	go c.evictLoop()

	return c
}

// GetDomain returns a cached domain + snapshot, or nil if not found/expired.
func (c *Cache) GetDomain(name string) (*models.Domain, *models.DomainSnapshot) {
	c.mu.RLock()
	e, ok := c.data["domain:"+name]
	c.mu.RUnlock()

	if !ok || e.isExpired() {
		metrics.CacheMisses.Inc()
		return nil, nil
	}

	metrics.CacheHits.Inc()
	pair := e.value.(*domainCacheEntry)
	return pair.domain, pair.snapshot
}

// WarmDomain stores a domain + snapshot in the cache.
// Called after a live lookup or crawl completes.
func (c *Cache) WarmDomain(domain *models.Domain, snapshot *models.DomainSnapshot) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.evictIfFull()
	c.data["domain:"+domain.Name] = &entry{
		value:     &domainCacheEntry{domain: domain, snapshot: snapshot},
		expiresAt: time.Now().Add(c.domainTTL),
	}
}

// GetIP returns a cached IP block + snapshot.
func (c *Cache) GetIP(cidr string) (*models.IPBlock, *models.IPSnapshot) {
	c.mu.RLock()
	e, ok := c.data["ip:"+cidr]
	c.mu.RUnlock()

	if !ok || e.isExpired() {
		metrics.CacheMisses.Inc()
		return nil, nil
	}

	metrics.CacheHits.Inc()
	pair := e.value.(*ipCacheEntry)
	return pair.block, pair.snapshot
}

// WarmIP stores an IP block + snapshot.
func (c *Cache) WarmIP(block *models.IPBlock, snapshot *models.IPSnapshot) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.evictIfFull()
	c.data["ip:"+block.CIDR] = &entry{
		value:     &ipCacheEntry{block: block, snapshot: snapshot},
		expiresAt: time.Now().Add(c.ipTTL),
	}
}

// GetASN returns a cached ASN + snapshot.
func (c *Cache) GetASN(number int) (*models.ASN, *models.ASNSnapshot) {
	c.mu.RLock()
	key := asnKey(number)
	e, ok := c.data[key]
	c.mu.RUnlock()

	if !ok || e.isExpired() {
		metrics.CacheMisses.Inc()
		return nil, nil
	}

	metrics.CacheHits.Inc()
	pair := e.value.(*asnCacheEntry)
	return pair.asn, pair.snapshot
}

// WarmASN stores an ASN + snapshot.
func (c *Cache) WarmASN(asn *models.ASN, snapshot *models.ASNSnapshot) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.evictIfFull()
	c.data[asnKey(asn.Number)] = &entry{
		value:     &asnCacheEntry{asn: asn, snapshot: snapshot},
		expiresAt: time.Now().Add(c.asnTTL),
	}
}

// Invalidate removes a specific key from the cache.
func (c *Cache) Invalidate(key string) {
	c.mu.Lock()
	delete(c.data, key)
	c.mu.Unlock()
}

// Size returns the current number of entries.
func (c *Cache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.data)
}

// evictIfFull removes expired entries first, then oldest if still at capacity.
func (c *Cache) evictIfFull() {
	if len(c.data) < c.maxSize {
		return
	}

	// First pass: remove expired entries
	now := time.Now()
	for k, e := range c.data {
		if now.After(e.expiresAt) {
			delete(c.data, k)
		}
	}

	// If still at capacity, remove ~10% of entries (random eviction via map iteration)
	if len(c.data) >= c.maxSize {
		toRemove := c.maxSize / 10
		if toRemove < 1 {
			toRemove = 1
		}
		removed := 0
		for k := range c.data {
			delete(c.data, k)
			removed++
			if removed >= toRemove {
				break
			}
		}
	}
}

// evictLoop periodically removes expired entries.
func (c *Cache) evictLoop() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		c.mu.Lock()
		now := time.Now()
		for k, e := range c.data {
			if now.After(e.expiresAt) {
				delete(c.data, k)
			}
		}
		c.mu.Unlock()
	}
}

// Cache entry types
type domainCacheEntry struct {
	domain   *models.Domain
	snapshot *models.DomainSnapshot
}

type ipCacheEntry struct {
	block    *models.IPBlock
	snapshot *models.IPSnapshot
}

type asnCacheEntry struct {
	asn      *models.ASN
	snapshot *models.ASNSnapshot
}

func asnKey(number int) string {
	return fmt.Sprintf("asn:%d", number)
}
