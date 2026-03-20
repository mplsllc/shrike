package crawler

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"git.mp.ls/mpls/shrike/internal/metrics"
	"git.mp.ls/mpls/shrike/internal/models"
	"git.mp.ls/mpls/shrike/internal/repository"
)

// WorkerPool manages a pool of crawl workers that process jobs from the scheduler.
type WorkerPool struct {
	numWorkers  int
	scheduler   *Scheduler
	discovery   *ServerDiscovery
	rateLimiter *RateLimiter
	rdapClient  *RDAPClient
	whoisClient *WhoisClient
	dnsResolver *DNSResolver
	domainRepo  *repository.DomainRepository
	dnsRepo     *repository.DNSRepository
	registry    *ParserRegistry

	// Default interval between re-crawls
	defaultInterval time.Duration

	stopCh chan struct{}
	wg     sync.WaitGroup
}

func NewWorkerPool(
	numWorkers int,
	scheduler *Scheduler,
	discovery *ServerDiscovery,
	rateLimiter *RateLimiter,
	rdapClient *RDAPClient,
	whoisClient *WhoisClient,
	dnsResolver *DNSResolver,
	domainRepo *repository.DomainRepository,
	dnsRepo *repository.DNSRepository,
	registry *ParserRegistry,
	defaultInterval time.Duration,
) *WorkerPool {
	return &WorkerPool{
		numWorkers:      numWorkers,
		scheduler:       scheduler,
		discovery:       discovery,
		rateLimiter:     rateLimiter,
		rdapClient:      rdapClient,
		whoisClient:     whoisClient,
		dnsResolver:     dnsResolver,
		domainRepo:      domainRepo,
		dnsRepo:         dnsRepo,
		registry:        registry,
		defaultInterval: defaultInterval,
		stopCh:          make(chan struct{}),
	}
}

// Start launches the worker goroutines.
func (wp *WorkerPool) Start(ctx context.Context) {
	for i := 0; i < wp.numWorkers; i++ {
		wp.wg.Add(1)
		go wp.worker(ctx, i)
	}
	log.Printf("Started %d crawler workers", wp.numWorkers)
}

// Stop signals all workers to stop and waits for them to finish.
func (wp *WorkerPool) Stop() {
	close(wp.stopCh)
	wp.wg.Wait()
	log.Println("All crawler workers stopped")
}

func (wp *WorkerPool) worker(ctx context.Context, id int) {
	defer wp.wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		case <-wp.stopCh:
			return
		default:
		}

		// Fetch a batch of jobs
		jobs, err := wp.scheduler.NextBatch(ctx)
		if err != nil {
			log.Printf("Worker %d: error fetching jobs: %v", id, err)
			time.Sleep(5 * time.Second)
			continue
		}

		if len(jobs) == 0 {
			// No jobs available, wait before polling again
			time.Sleep(2 * time.Second)
			continue
		}

		for _, job := range jobs {
			select {
			case <-ctx.Done():
				return
			case <-wp.stopCh:
				return
			default:
			}

			wp.processJob(ctx, job)
		}
	}
}

func (wp *WorkerPool) processJob(ctx context.Context, job models.CrawlJob) {
	// Recover from panics — a single bad response should not kill the worker pool
	defer func() {
		if r := recover(); r != nil {
			log.Printf("PANIC in job %d (%s %s): %v", job.ID, job.JobType, job.Target, r)
			wp.scheduler.MarkFailed(ctx, job.ID, fmt.Sprintf("panic: %v", r))
		}
	}()

	if err := wp.scheduler.MarkRunning(ctx, job.ID); err != nil {
		log.Printf("Error marking job %d running: %v", job.ID, err)
		return
	}

	var err error
	switch job.JobType {
	case models.JobTypeDomainWhois:
		err = wp.processDomainWhois(ctx, job)
	case models.JobTypeDNS:
		err = wp.processDNS(ctx, job)
	default:
		log.Printf("Unknown job type: %s", job.JobType)
		err = wp.scheduler.MarkFailed(ctx, job.ID, "unknown job type")
		return
	}

	if err != nil {
		log.Printf("Job %d (%s %s) failed: %v", job.ID, job.JobType, job.Target, err)
		wp.scheduler.MarkFailed(ctx, job.ID, err.Error())
	} else {
		wp.scheduler.MarkDone(ctx, job.ID, wp.defaultInterval)
	}
}

func (wp *WorkerPool) processDomainWhois(ctx context.Context, job models.CrawlJob) error {
	domain := strings.ToLower(job.Target)
	tld := TLDFromDomain(domain)
	now := time.Now().UTC()

	// Upsert domain entity
	domainID, err := wp.domainRepo.Upsert(ctx, domain, tld)
	if err != nil {
		return err
	}

	var snap *models.DomainSnapshot

	// Try RDAP first (structured JSON, preferred)
	if wp.discovery.HasRDAP(tld) {
		server := wp.discovery.RDAPServer(tld)
		wp.rateLimiter.Wait(server)

		start := time.Now()
		rdapResp, err := wp.rdapClient.QueryDomain(ctx, domain)
		duration := time.Since(start).Seconds()
		metrics.CrawlDuration.WithLabelValues(server).Observe(duration)

		if err == nil {
			snap = NormalizeRDAPResponse(rdapResp, domainID, now)
			metrics.CrawlTotal.WithLabelValues(tld, "success").Inc()
		} else {
			log.Printf("RDAP failed for %s, falling back to WHOIS: %v", domain, err)
			metrics.CrawlTotal.WithLabelValues(tld, "rdap_failed").Inc()
		}
	}

	// Fall back to raw WHOIS if RDAP unavailable or failed
	if snap == nil {
		whoisServer, err := wp.discovery.WhoisServer(ctx, tld)
		if err != nil {
			return err
		}

		wp.rateLimiter.Wait(whoisServer)

		start := time.Now()
		rawResp, finalServer, err := wp.whoisClient.QueryWithReferral(ctx, whoisServer, domain)
		duration := time.Since(start).Seconds()
		metrics.CrawlDuration.WithLabelValues(finalServer).Observe(duration)

		if err != nil {
			metrics.CrawlTotal.WithLabelValues(tld, "error").Inc()
			return err
		}

		if IsRateLimited(rawResp) {
			metrics.RateLimitHits.WithLabelValues(finalServer).Inc()
			wp.rateLimiter.ExponentialBackoff(finalServer, job.ErrorCount)
			return fmt.Errorf("rate limited by %s", finalServer)
		}

		// Parse through the registry
		var parserName string
		snap, parserName, err = wp.registry.Parse(rawResp, tld, domainID, now)
		if err != nil {
			return err
		}
		_ = parserName
		metrics.CrawlTotal.WithLabelValues(tld, "success").Inc()
	}

	// Store snapshot (with dedup)
	stored, err := wp.domainRepo.InsertSnapshotIfChanged(ctx, snap)
	if err != nil {
		return err
	}
	if stored {
		metrics.SnapshotsStored.WithLabelValues("domain").Inc()
	}

	return nil
}

func (wp *WorkerPool) processDNS(ctx context.Context, job models.CrawlJob) error {
	domain := strings.ToLower(job.Target)

	// Look up the domain entity
	d, err := wp.domainRepo.GetByName(ctx, domain)
	if err != nil {
		return err
	}
	if d == nil {
		// Domain not in DB yet — skip DNS for now, it'll be created by WHOIS crawl
		return nil
	}

	records, err := wp.dnsResolver.ResolveAll(ctx, domain, d.ID)
	if err != nil {
		return err
	}

	stored, err := wp.dnsRepo.InsertBatch(ctx, records)
	if err != nil {
		return err
	}
	if stored > 0 {
		metrics.SnapshotsStored.WithLabelValues("dns").Add(float64(stored))
	}

	return nil
}

