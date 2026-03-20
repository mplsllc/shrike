package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"git.mp.ls/mpls/shrike/internal/api"
	"git.mp.ls/mpls/shrike/internal/cache"
	"git.mp.ls/mpls/shrike/internal/config"
	"git.mp.ls/mpls/shrike/internal/crawler"
	"git.mp.ls/mpls/shrike/internal/db"
	"git.mp.ls/mpls/shrike/internal/metrics"
	"git.mp.ls/mpls/shrike/internal/middleware"
	"git.mp.ls/mpls/shrike/internal/models"
	"git.mp.ls/mpls/shrike/internal/repository"
	"git.mp.ls/mpls/shrike/internal/services"
	"git.mp.ls/mpls/shrike/internal/version"
)

func main() {
	log.Printf("Shrike server %s starting", version.Version)

	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pool, err := db.Connect(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer pool.Close()

	metrics.Register()

	// Initialize server discovery for real-time lookups
	discovery := crawler.NewServerDiscovery(nil)
	if err := discovery.LoadRDAPBootstrap(ctx); err != nil {
		log.Printf("Warning: RDAP bootstrap failed: %v", err)
	}

	// Initialize crawler components for real-time lookups
	rateLimiter := crawler.NewRateLimiter(1.0, 3)
	rdapClient := crawler.NewRDAPClient(discovery)
	whoisClient := crawler.NewWhoisClient()
	dnsResolver := crawler.NewDNSResolver()

	likexianParser := crawler.NewLikexianParser()
	registry := crawler.NewParserRegistry(likexianParser)

	// Initialize cache and repos
	appCache := cache.New(cfg.CacheSize, cfg.CacheTTL)
	domainRepo := repository.NewDomainRepository(pool)

	// Create the WhoisFetcher adapter (bridges crawler → services interface)
	fetcher := &whoisFetcherAdapter{
		discovery:   discovery,
		rateLimiter: rateLimiter,
		rdapClient:  rdapClient,
		whoisClient: whoisClient,
		registry:    registry,
	}

	dnsRepo := repository.NewDNSRepository(pool)
	ipRepo := repository.NewIPRepository(pool)
	asnRepo := repository.NewASNRepository(pool)

	// Create lookup service
	lookupService := services.NewLookupService(
		domainRepo,
		dnsRepo,
		fetcher,
		dnsResolver,
		appCache,
		crawler.TLDFromDomain,
	)

	router := api.NewRouter(api.RouterDeps{
		Pool:          pool,
		DomainRepo:    domainRepo,
		IPRepo:        ipRepo,
		ASNRepo:       asnRepo,
		LookupService: lookupService,
		Cache:         appCache,
		RateLimitCfg: middleware.RateLimitConfig{
			AnonymousPerMin:   cfg.RateLimitAnonymous,
			FreeKeyPerMin:     cfg.RateLimitFree,
			ContributorPerMin: cfg.RateLimitContributor,
		},
		TemplateDir: "web/templates",
	})

	go func() {
		log.Printf("Listening on %s", cfg.ListenAddr())
		if err := router.Run(cfg.ListenAddr()); err != nil {
			log.Fatalf("Server failed: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down...")
	cancel()
}

// whoisFetcherAdapter bridges the crawler package to the services.WhoisFetcher interface.
type whoisFetcherAdapter struct {
	discovery   *crawler.ServerDiscovery
	rateLimiter *crawler.RateLimiter
	rdapClient  *crawler.RDAPClient
	whoisClient *crawler.WhoisClient
	registry    *crawler.ParserRegistry
}

func (a *whoisFetcherAdapter) FetchDomain(ctx context.Context, domain, tld string, domainID int64, now time.Time) (*models.DomainSnapshot, error) {
	// Try RDAP first
	if a.discovery.HasRDAP(tld) {
		server := a.discovery.RDAPServer(tld)
		a.rateLimiter.Wait(server)

		rdapResp, err := a.rdapClient.QueryDomain(ctx, domain)
		if err == nil {
			return crawler.NormalizeRDAPResponse(rdapResp, domainID, now), nil
		}
	}

	// Raw WHOIS fallback
	whoisServer, err := a.discovery.WhoisServer(ctx, tld)
	if err != nil {
		return nil, err
	}
	a.rateLimiter.Wait(whoisServer)

	rawResp, _, err := a.whoisClient.QueryWithReferral(ctx, whoisServer, domain)
	if err != nil {
		return nil, err
	}
	if crawler.IsRateLimited(rawResp) {
		return nil, fmt.Errorf("rate limited by %s", whoisServer)
	}

	snap, _, err := a.registry.Parse(rawResp, tld, domainID, now)
	return snap, err
}
