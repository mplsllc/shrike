package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"git.mp.ls/mpls/shrike/internal/config"
	"git.mp.ls/mpls/shrike/internal/crawler"
	"git.mp.ls/mpls/shrike/internal/db"
	"git.mp.ls/mpls/shrike/internal/metrics"
	"git.mp.ls/mpls/shrike/internal/repository"
	"git.mp.ls/mpls/shrike/internal/version"
)

func main() {
	log.Printf("Shrike crawler %s starting", version.Version)

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

	// Initialize server discovery and load RDAP bootstrap
	discovery := crawler.NewServerDiscovery(nil)
	log.Println("Loading IANA RDAP bootstrap file...")
	if err := discovery.LoadRDAPBootstrap(ctx); err != nil {
		log.Printf("Warning: failed to load RDAP bootstrap: %v (RDAP lookups will be unavailable)", err)
	} else {
		rdapCount, _ := discovery.Stats()
		log.Printf("Loaded RDAP bootstrap: %d TLDs with RDAP support", rdapCount)
	}

	// Initialize components
	rateLimiter := crawler.NewRateLimiter(1.0, 3) // 1 QPS default, burst of 3
	rdapClient := crawler.NewRDAPClient(discovery)
	whoisClient := crawler.NewWhoisClient()
	dnsResolver := crawler.NewDNSResolver()
	domainRepo := repository.NewDomainRepository(pool)
	dnsRepo := repository.NewDNSRepository(pool)
	scheduler := crawler.NewScheduler(pool, rateLimiter)

	// Parser registry with likexian as fallback
	likexianParser := crawler.NewLikexianParser()
	registry := crawler.NewParserRegistry(likexianParser)

	// Worker pool
	workerPool := crawler.NewWorkerPool(
		cfg.CrawlerWorkers,
		scheduler,
		discovery,
		rateLimiter,
		rdapClient,
		whoisClient,
		dnsResolver,
		domainRepo,
		dnsRepo,
		registry,
		cfg.CrawlerDefaultInterval,
	)

	workerPool.Start(ctx)
	log.Printf("Crawler running with %d workers", cfg.CrawlerWorkers)

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down crawler...")
	cancel()
	workerPool.Stop()
}
