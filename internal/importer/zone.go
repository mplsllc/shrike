package importer

import (
	"bufio"
	"context"
	"io"
	"log"
	"strings"

	"git.mp.ls/mpls/shrike/internal/crawler"
	"git.mp.ls/mpls/shrike/internal/repository"
)

// ZoneImporter parses DNS zone files and enqueues discovered domains for crawling.
// Zone files list all domains in a TLD — one domain per line (simplified).
// Format varies, but typically: "domain.tld. NS ns1.example.com."
type ZoneImporter struct {
	domainRepo *repository.DomainRepository
	scheduler  *crawler.Scheduler
}

func NewZoneImporter(domainRepo *repository.DomainRepository, scheduler *crawler.Scheduler) *ZoneImporter {
	return &ZoneImporter{domainRepo: domainRepo, scheduler: scheduler}
}

// Import reads a zone file and enqueues new domains for crawling.
func (zi *ZoneImporter) Import(ctx context.Context, reader io.Reader, tld string) (stats ImportStats, err error) {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 64*1024), 64*1024)

	seen := make(map[string]bool, 1000000) // dedup within this import

	for scanner.Scan() {
		line := scanner.Text()

		// Skip comments and empty lines
		if line == "" || line[0] == ';' || line[0] == '$' {
			continue
		}

		// Extract domain name (first field before whitespace)
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}

		domain := strings.ToLower(strings.TrimSuffix(fields[0], "."))
		if domain == "" || domain == tld {
			continue
		}

		// Ensure it's a direct child of the TLD (not a subdomain)
		if !strings.HasSuffix(domain, "."+tld) {
			continue
		}

		if seen[domain] {
			continue
		}
		seen[domain] = true
		stats.Processed++

		// Check if domain already exists
		existing, err := zi.domainRepo.GetByName(ctx, domain)
		if err != nil {
			stats.Errors++
			continue
		}
		if existing != nil {
			stats.Unchanged++
			continue
		}

		// New domain — enqueue for crawling
		if err := zi.scheduler.EnqueueDomain(ctx, domain, tld, 2); err != nil {
			log.Printf("Error enqueueing %s: %v", domain, err)
			stats.Errors++
			continue
		}
		stats.Stored++

		if stats.Stored%10000 == 0 {
			log.Printf("Zone import: %d new domains enqueued (%d processed)", stats.Stored, stats.Processed)
		}
	}

	return stats, scanner.Err()
}
