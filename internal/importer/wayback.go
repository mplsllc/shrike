package importer

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"git.mp.ls/mpls/shrike/internal/repository"
)

// WaybackImporter retrieves historical WHOIS data from the Internet Archive
// Wayback Machine. It uses the CDX API to find archived WHOIS lookup pages
// and the id_ URL pattern to fetch clean (unrewritten) HTML for parsing.
//
// Rate limit: 1 request/second by default. Contact info@archive.org for
// higher limits if running a large backfill.
type WaybackImporter struct {
	domainRepo *repository.DomainRepository
	pool       *pgxpool.Pool
	client     *http.Client
	delay      time.Duration
}

type WaybackStats struct {
	DomainsProcessed int
	CapturesFound    int
	SnapshotsStored  int
	Errors           int
}

// WHOIS lookup sites with their URL patterns
var waybackWhoisSites = map[string]string{
	"whois":       "who.is/whois/",
	"whoiscom":    "www.whois.com/whois/",
	"domaintools": "whois.domaintools.com/",
}

func NewWaybackImporter(domainRepo *repository.DomainRepository, pool *pgxpool.Pool) *WaybackImporter {
	return &WaybackImporter{
		domainRepo: domainRepo,
		pool:       pool,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		delay: 1 * time.Second, // Be polite to the Internet Archive
	}
}

// ImportKnownDomains searches the Wayback Machine for historical WHOIS data
// for domains already in the database.
func (w *WaybackImporter) ImportKnownDomains(ctx context.Context, limit int) (*WaybackStats, error) {
	stats := &WaybackStats{}

	query := `SELECT id, name FROM domains ORDER BY id`
	if limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", limit)
	}

	rows, err := w.pool.Query(ctx, query)
	if err != nil {
		return stats, fmt.Errorf("querying domains: %w", err)
	}
	defer rows.Close()

	type domainRow struct {
		ID   int64
		Name string
	}
	var domains []domainRow
	for rows.Next() {
		var d domainRow
		if err := rows.Scan(&d.ID, &d.Name); err != nil {
			return stats, err
		}
		domains = append(domains, d)
	}
	rows.Close()

	for i, d := range domains {
		if i > 0 && i%50 == 0 {
			log.Printf("Wayback progress: %d/%d domains, %d captures, %d snapshots stored",
				i, len(domains), stats.CapturesFound, stats.SnapshotsStored)
		}

		domainStats, err := w.importDomainCaptures(ctx, d.Name, d.ID)
		if err != nil {
			log.Printf("  Error processing %s: %v", d.Name, err)
			stats.Errors++
			continue
		}

		stats.DomainsProcessed++
		stats.CapturesFound += domainStats.CapturesFound
		stats.SnapshotsStored += domainStats.SnapshotsStored
	}

	return stats, nil
}

// ImportDomain searches for a specific domain's WHOIS history.
func (w *WaybackImporter) ImportDomain(ctx context.Context, name string) (*WaybackStats, error) {
	// Ensure domain exists
	tld := name
	if idx := strings.LastIndex(name, "."); idx >= 0 {
		tld = name[idx+1:]
	}
	domainID, err := w.domainRepo.Upsert(ctx, name, tld)
	if err != nil {
		return nil, fmt.Errorf("upserting domain: %w", err)
	}

	return w.importDomainCaptures(ctx, name, domainID)
}

// ScanSite finds all domains archived on a specific WHOIS lookup site.
func (w *WaybackImporter) ScanSite(ctx context.Context, site string, limit int) (*WaybackStats, error) {
	stats := &WaybackStats{}

	prefix, ok := waybackWhoisSites[site]
	if !ok {
		return nil, fmt.Errorf("unknown site %q (valid: whois, whoiscom, domaintools)", site)
	}

	// Query CDX for all URLs under this WHOIS site
	cdxURL := fmt.Sprintf(
		"http://web.archive.org/cdx/search/cdx?url=%s*&output=json&fl=original,timestamp&filter=statuscode:200&collapse=urlkey",
		prefix)
	if limit > 0 {
		cdxURL += fmt.Sprintf("&limit=%d", limit)
	}

	log.Printf("Scanning Wayback Machine for %s...", prefix)

	captures, err := w.queryCDX(ctx, cdxURL)
	if err != nil {
		return stats, fmt.Errorf("querying CDX: %w", err)
	}

	log.Printf("Found %d unique URLs", len(captures))

	// Group captures by domain
	domainCaptures := make(map[string][]waybackCapture)
	for _, cap := range captures {
		domain := extractDomainFromURL(cap.URL)
		if domain != "" {
			domainCaptures[domain] = append(domainCaptures[domain], cap)
		}
	}

	log.Printf("Covering %d unique domains", len(domainCaptures))

	for domain, caps := range domainCaptures {
		stats.DomainsProcessed++
		stats.CapturesFound += len(caps)

		tld := domain
		if idx := strings.LastIndex(domain, "."); idx >= 0 {
			tld = domain[idx+1:]
		}
		domainID, err := w.domainRepo.Upsert(ctx, domain, tld)
		if err != nil {
			log.Printf("  Error upserting %s: %v", domain, err)
			stats.Errors++
			continue
		}

		for _, cap := range caps {
			stored, err := w.processCapture(ctx, cap, domain, domainID)
			if err != nil {
				stats.Errors++
				continue
			}
			if stored {
				stats.SnapshotsStored++
			}
		}

		if stats.DomainsProcessed%100 == 0 {
			log.Printf("Scan progress: %d domains, %d snapshots stored",
				stats.DomainsProcessed, stats.SnapshotsStored)
		}
	}

	return stats, nil
}

type waybackCapture struct {
	URL       string
	Timestamp string
}

func (w *WaybackImporter) importDomainCaptures(ctx context.Context, name string, domainID int64) (*WaybackStats, error) {
	stats := &WaybackStats{}

	// Check all WHOIS sites for this domain
	for siteName, prefix := range waybackWhoisSites {
		targetURL := prefix + name
		cdxURL := fmt.Sprintf(
			"http://web.archive.org/cdx/search/cdx?url=%s&output=json&fl=original,timestamp&filter=statuscode:200",
			targetURL)

		captures, err := w.queryCDX(ctx, cdxURL)
		if err != nil {
			// CDX 404 just means no captures
			continue
		}

		if len(captures) > 0 {
			log.Printf("  %s: %d captures on %s", name, len(captures), siteName)
		}

		stats.CapturesFound += len(captures)

		for _, cap := range captures {
			stored, err := w.processCapture(ctx, cap, name, domainID)
			if err != nil {
				stats.Errors++
				continue
			}
			if stored {
				stats.SnapshotsStored++
			}
		}
	}

	return stats, nil
}

func (w *WaybackImporter) processCapture(ctx context.Context, cap waybackCapture, domain string, domainID int64) (bool, error) {
	observedAt, err := time.Parse("20060102150405", cap.Timestamp)
	if err != nil {
		return false, fmt.Errorf("parsing timestamp: %w", err)
	}

	// Use id_ to get the original page without Wayback rewriting
	pageURL := fmt.Sprintf("https://web.archive.org/web/%sid_/%s", cap.Timestamp, cap.URL)

	time.Sleep(w.delay)

	html, err := w.fetchPage(ctx, pageURL)
	if err != nil {
		return false, err
	}

	whoisText := extractWhoisFromHTML(html)
	if whoisText == "" {
		return false, nil
	}

	snap := parseRawWhoisText(whoisText, observedAt)
	if snap == nil {
		return false, nil
	}

	snap.DomainID = domainID
	snap.Source = "wayback_archive"
	snap.RawWhois = &whoisText

	// Check for PII in historical pre-GDPR data
	if snap.RegistrantEmail != nil || snap.RegistrantName != nil {
		snap.ContainsPII = true
	}

	stored, err := w.domainRepo.InsertSnapshotIfChanged(ctx, snap)
	if err != nil {
		return false, fmt.Errorf("inserting snapshot: %w", err)
	}

	return stored, nil
}

func (w *WaybackImporter) queryCDX(ctx context.Context, cdxURL string) ([]waybackCapture, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", cdxURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Shrike/1.0 (WHOIS history database; https://shrike.mp.ls; contact: patrick@mp.ls)")

	time.Sleep(w.delay)

	resp, err := w.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		return nil, nil
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	// CDX returns JSON array: [["urlkey","timestamp",...], ["field1","field2",...], ...]
	body, err := io.ReadAll(io.LimitReader(resp.Body, 50*1024*1024))
	if err != nil {
		return nil, err
	}

	// Try JSON array format first
	var rows [][]string
	if err := json.Unmarshal(body, &rows); err == nil && len(rows) > 1 {
		var captures []waybackCapture
		for _, row := range rows[1:] { // Skip header row
			if len(row) >= 2 {
				captures = append(captures, waybackCapture{
					URL:       row[0],
					Timestamp: row[1],
				})
			}
		}
		return captures, nil
	}

	// Fallback: newline-delimited text (original timestamp url ...)
	var captures []waybackCapture
	scanner := bufio.NewScanner(strings.NewReader(string(body)))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 2 {
			captures = append(captures, waybackCapture{
				URL:       fields[0],
				Timestamp: fields[1],
			})
		}
	}

	return captures, nil
}

func (w *WaybackImporter) fetchPage(ctx context.Context, pageURL string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", pageURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "Shrike/1.0 (WHOIS history database; https://shrike.mp.ls; contact: patrick@mp.ls)")

	resp, err := w.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
	if err != nil {
		return "", err
	}

	return string(body), nil
}
