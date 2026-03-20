package services

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"git.mp.ls/mpls/shrike/internal/models"
)

const (
	lookupTimeout = 15 * time.Second
)

// LookupResult holds the outcome of a real-time lookup.
type LookupResult struct {
	Domain   *models.Domain
	Snapshot *models.DomainSnapshot
	DNS      []models.DNSRecord
	Err      error
}

// LookupStatus represents the state of an in-flight lookup.
type LookupStatus string

const (
	StatusFetching LookupStatus = "fetching"
	StatusReady    LookupStatus = "ready"
	StatusError    LookupStatus = "error"
	StatusUnknown  LookupStatus = "unknown"
)

// DomainStore abstracts domain persistence (breaks import cycle with repository).
type DomainStore interface {
	GetByName(ctx context.Context, name string) (*models.Domain, error)
	Upsert(ctx context.Context, name, tld string) (int64, error)
	GetLatestSnapshot(ctx context.Context, domainID int64) (*models.DomainSnapshot, error)
	InsertSnapshotIfChanged(ctx context.Context, snap *models.DomainSnapshot) (bool, error)
}

// WhoisFetcher abstracts the WHOIS/RDAP lookup (breaks import cycle with crawler).
type WhoisFetcher interface {
	FetchDomain(ctx context.Context, domain, tld string, domainID int64, now time.Time) (*models.DomainSnapshot, error)
}

// DNSFetcher abstracts DNS resolution (breaks import cycle with crawler).
type DNSFetcher interface {
	ResolveAll(ctx context.Context, domain string, domainID int64) ([]models.DNSRecord, error)
}

// DNSStore abstracts DNS record persistence.
type DNSStore interface {
	InsertBatch(ctx context.Context, records []models.DNSRecord) (int, error)
}

// CacheWarmer is called after a successful lookup to warm the LRU cache.
type CacheWarmer interface {
	WarmDomain(domain *models.Domain, snapshot *models.DomainSnapshot)
}

// TLDExtractor extracts the TLD from a domain name.
type TLDExtractor func(domain string) string

// inflight tracks a single in-flight lookup.
type inflight struct {
	ch     chan struct{} // closed when lookup completes
	result *LookupResult
}

// LookupService handles real-time domain lookups with in-flight dedup.
type LookupService struct {
	mu        sync.Mutex
	inflights map[string]*inflight

	store      DomainStore
	dnsStore   DNSStore
	fetcher    WhoisFetcher
	dns        DNSFetcher
	cache      CacheWarmer
	extractTLD TLDExtractor
}

func NewLookupService(
	store DomainStore,
	dnsStore DNSStore,
	fetcher WhoisFetcher,
	dns DNSFetcher,
	cache CacheWarmer,
	extractTLD TLDExtractor,
) *LookupService {
	return &LookupService{
		inflights:  make(map[string]*inflight),
		store:      store,
		dnsStore:   dnsStore,
		fetcher:    fetcher,
		dns:        dns,
		cache:      cache,
		extractTLD: extractTLD,
	}
}

// Lookup retrieves domain data. Returns immediately if cached/stored.
// If unknown, triggers a live crawl with in-flight dedup.
// When wait=true, blocks until the crawl completes (up to 15s).
// When wait=false, returns nil result if an async crawl was started.
func (ls *LookupService) Lookup(ctx context.Context, domainName string, wait bool) (*LookupResult, bool, error) {
	domainName = strings.ToLower(domainName)

	// Fast path: check DB
	domain, err := ls.store.GetByName(ctx, domainName)
	if err != nil {
		return nil, false, fmt.Errorf("checking domain: %w", err)
	}
	if domain != nil {
		snap, err := ls.store.GetLatestSnapshot(ctx, domain.ID)
		if err != nil {
			return nil, false, fmt.Errorf("getting snapshot: %w", err)
		}
		if snap != nil {
			return &LookupResult{Domain: domain, Snapshot: snap}, false, nil
		}
	}

	// Domain unknown or no snapshot — start or subscribe to live lookup
	ls.mu.Lock()
	if inf, ok := ls.inflights[domainName]; ok {
		ls.mu.Unlock()

		if !wait {
			return nil, true, nil
		}

		select {
		case <-inf.ch:
			return inf.result, false, nil
		case <-ctx.Done():
			return nil, false, ctx.Err()
		}
	}

	inf := &inflight{ch: make(chan struct{})}
	ls.inflights[domainName] = inf
	ls.mu.Unlock()

	go ls.runLookup(domainName, inf)

	if !wait {
		return nil, true, nil
	}

	select {
	case <-inf.ch:
		return inf.result, false, nil
	case <-ctx.Done():
		return nil, false, ctx.Err()
	}
}

// GetInflightStatus returns the status of an in-flight lookup.
func (ls *LookupService) GetInflightStatus(domainName string) LookupStatus {
	domainName = strings.ToLower(domainName)

	ls.mu.Lock()
	inf, ok := ls.inflights[domainName]
	ls.mu.Unlock()

	if !ok {
		return StatusUnknown
	}

	select {
	case <-inf.ch:
		if inf.result != nil && inf.result.Err != nil {
			return StatusError
		}
		return StatusReady
	default:
		return StatusFetching
	}
}

func (ls *LookupService) runLookup(domainName string, inf *inflight) {
	ctx, cancel := context.WithTimeout(context.Background(), lookupTimeout)
	defer cancel()
	defer func() {
		close(inf.ch)
		go func() {
			time.Sleep(30 * time.Second)
			ls.mu.Lock()
			delete(ls.inflights, domainName)
			ls.mu.Unlock()
		}()
	}()

	result := &LookupResult{}
	inf.result = result

	tld := ls.extractTLD(domainName)
	now := time.Now().UTC()

	domainID, err := ls.store.Upsert(ctx, domainName, tld)
	if err != nil {
		result.Err = fmt.Errorf("upserting domain: %w", err)
		return
	}
	result.Domain = &models.Domain{ID: domainID, Name: domainName, TLD: tld}

	// Run WHOIS and DNS in parallel
	var wg sync.WaitGroup
	var snap *models.DomainSnapshot
	var dnsRecords []models.DNSRecord
	var whoisErr, dnsErr error

	wg.Add(1)
	go func() {
		defer wg.Done()
		snap, whoisErr = ls.fetcher.FetchDomain(ctx, domainName, tld, domainID, now)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		dnsRecords, dnsErr = ls.dns.ResolveAll(ctx, domainName, domainID)
	}()

	wg.Wait()

	if whoisErr != nil {
		log.Printf("WHOIS lookup failed for %s: %v", domainName, whoisErr)
		result.Err = whoisErr
		return
	}

	if snap != nil {
		stored, err := ls.store.InsertSnapshotIfChanged(ctx, snap)
		if err != nil {
			result.Err = fmt.Errorf("storing snapshot: %w", err)
			return
		}
		result.Snapshot = snap
		if stored && ls.cache != nil {
			ls.cache.WarmDomain(result.Domain, snap)
		}
	}

	if dnsErr != nil {
		log.Printf("DNS resolution failed for %s: %v", domainName, dnsErr)
	} else if len(dnsRecords) > 0 {
		result.DNS = dnsRecords
		// Persist DNS records with dedup
		if ls.dnsStore != nil {
			if _, err := ls.dnsStore.InsertBatch(ctx, dnsRecords); err != nil {
				log.Printf("Failed to persist DNS records for %s: %v", domainName, err)
			}
		}
	}
}
