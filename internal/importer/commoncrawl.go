package importer

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"git.mp.ls/mpls/shrike/internal/models"
	"git.mp.ls/mpls/shrike/internal/repository"
)

// CCImporter scrapes historical WHOIS data from Common Crawl archives.
// It queries the CDX index for WHOIS lookup pages (who.is, whois.com, lookup.icann.org)
// and extracts WHOIS text from the HTML.
type CCImporter struct {
	domainRepo *repository.DomainRepository
	pool       *pgxpool.Pool
	client     *http.Client
}

type CCStats struct {
	PagesFound      int
	Parsed          int
	SnapshotsStored int
	Errors          int
}

// cdxEntry represents a single entry from the Common Crawl CDX index
type cdxEntry struct {
	URL       string `json:"url"`
	Timestamp string `json:"timestamp"` // YYYYMMDDhhmmss
	Status    string `json:"status"`
	Digest    string `json:"digest"`
	Length    string `json:"length"`
	Offset   string `json:"offset"`
	Filename string `json:"filename"`
}

// WHOIS lookup site URL patterns we search for
var whoisSitePatterns = []string{
	"who.is/whois/*",
	"www.whois.com/whois/*",
}

func NewCCImporter(domainRepo *repository.DomainRepository, pool *pgxpool.Pool) *CCImporter {
	return &CCImporter{
		domainRepo: domainRepo,
		pool:       pool,
		client: &http.Client{
			Timeout: 60 * time.Second,
		},
	}
}

// ListCrawls returns available Common Crawl crawl IDs
func (c *CCImporter) ListCrawls(ctx context.Context) ([]string, error) {
	resp, err := c.client.Get("https://index.commoncrawl.org/collinfo.json")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var collections []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&collections); err != nil {
		return nil, err
	}

	var ids []string
	for _, col := range collections {
		ids = append(ids, col.ID)
	}
	return ids, nil
}

// ImportCrawl searches a specific Common Crawl archive for WHOIS pages and imports them.
func (c *CCImporter) ImportCrawl(ctx context.Context, crawlID string, limit int) (*CCStats, error) {
	stats := &CCStats{}

	for _, pattern := range whoisSitePatterns {
		log.Printf("Searching %s for %s...", crawlID, pattern)

		entries, err := c.queryCDX(ctx, crawlID, pattern, limit)
		if err != nil {
			log.Printf("  Error querying CDX for %s: %v", pattern, err)
			continue
		}

		log.Printf("  Found %d pages", len(entries))
		stats.PagesFound += len(entries)

		for i, entry := range entries {
			if limit > 0 && stats.Parsed >= limit {
				break
			}

			if i > 0 && i%50 == 0 {
				log.Printf("  Progress: %d/%d pages processed", i, len(entries))
			}

			// Extract domain name from URL
			domainName := extractDomainFromURL(entry.URL)
			if domainName == "" {
				continue
			}

			// Parse timestamp
			observedAt, err := time.Parse("20060102150405", entry.Timestamp)
			if err != nil {
				continue
			}

			// Fetch the WARC record
			html, err := c.fetchWARCRecord(ctx, entry.Filename, entry.Offset, entry.Length)
			if err != nil {
				stats.Errors++
				continue
			}

			// Parse WHOIS text from HTML
			whoisText := extractWhoisFromHTML(html)
			if whoisText == "" {
				stats.Errors++
				continue
			}

			stats.Parsed++

			// Parse the WHOIS text into a snapshot
			snap := parseRawWhoisText(whoisText, observedAt)
			if snap == nil {
				continue
			}

			// Upsert the domain
			tld := domainName
			if idx := strings.LastIndex(domainName, "."); idx >= 0 {
				tld = domainName[idx+1:]
			}
			domainID, err := c.domainRepo.Upsert(ctx, domainName, tld)
			if err != nil {
				log.Printf("  Error upserting domain %s: %v", domainName, err)
				stats.Errors++
				continue
			}

			snap.DomainID = domainID
			snap.Source = "commoncrawl"
			snap.RawWhois = &whoisText

			// Insert snapshot (dedup via hash)
			stored, err := c.domainRepo.InsertSnapshotIfChanged(ctx, snap)
			if err != nil {
				log.Printf("  Error inserting snapshot for %s: %v", domainName, err)
				stats.Errors++
				continue
			}

			if stored {
				stats.SnapshotsStored++
			}

			// Be polite to Common Crawl
			time.Sleep(200 * time.Millisecond)
		}
	}

	return stats, nil
}

func (c *CCImporter) queryCDX(ctx context.Context, crawlID, urlPattern string, limit int) ([]cdxEntry, error) {
	u := fmt.Sprintf("https://index.commoncrawl.org/%s-index?url=%s&output=json&filter=statuscode:200",
		crawlID, urlPattern)
	if limit > 0 {
		u += fmt.Sprintf("&limit=%d", limit)
	}

	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Shrike/1.0 (WHOIS history database; https://shrike.mp.ls)")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	// CDX returns newline-delimited JSON
	var entries []cdxEntry
	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	for scanner.Scan() {
		var entry cdxEntry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			continue
		}
		entries = append(entries, entry)
	}

	return entries, scanner.Err()
}

func (c *CCImporter) fetchWARCRecord(ctx context.Context, filename, offset, length string) (string, error) {
	u := fmt.Sprintf("https://data.commoncrawl.org/%s", filename)

	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Range", fmt.Sprintf("bytes=%s-%s", offset, addStrings(offset, length)))
	req.Header.Set("User-Agent", "Shrike/1.0 (WHOIS history database; https://shrike.mp.ls)")

	resp, err := c.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	// WARC records in Common Crawl are gzipped
	gz, err := gzip.NewReader(resp.Body)
	if err != nil {
		return "", fmt.Errorf("gzip: %w", err)
	}
	defer gz.Close()

	body, err := io.ReadAll(io.LimitReader(gz, 5*1024*1024)) // 5MB limit
	if err != nil {
		return "", fmt.Errorf("reading WARC: %w", err)
	}

	// Extract HTML body from WARC record
	// WARC has headers, then \r\n\r\n, then HTTP response with its own headers, then \r\n\r\n, then body
	parts := bytes.SplitN(body, []byte("\r\n\r\n"), 3)
	if len(parts) < 3 {
		return "", fmt.Errorf("invalid WARC structure")
	}

	return string(parts[2]), nil
}

// extractDomainFromURL gets the queried domain from a WHOIS lookup URL
// e.g., "https://who.is/whois/example.com" -> "example.com"
func extractDomainFromURL(rawURL string) string {
	// who.is/whois/example.com
	if idx := strings.Index(rawURL, "/whois/"); idx >= 0 {
		domain := rawURL[idx+7:]
		// Strip trailing slashes and query params
		if qIdx := strings.IndexAny(domain, "?#/"); qIdx >= 0 {
			domain = domain[:qIdx]
		}
		domain = strings.ToLower(strings.TrimSpace(domain))
		// Basic validation — must have at least one dot
		if strings.Contains(domain, ".") && !strings.Contains(domain, " ") {
			return domain
		}
	}
	return ""
}

// extractWhoisFromHTML attempts to extract WHOIS text from archived WHOIS lookup pages
var (
	// who.is wraps WHOIS in a <pre> tag with class="df-raw"
	whoIsPreRe = regexp.MustCompile(`(?s)<pre[^>]*class="[^"]*df-raw[^"]*"[^>]*>(.*?)</pre>`)
	// whois.com uses <pre class="df-raw"> or similar
	whoisComPreRe = regexp.MustCompile(`(?s)<pre[^>]*class="[^"]*domain[_-]?whois[^"]*"[^>]*>(.*?)</pre>`)
	// Generic fallback: large <pre> blocks that look like WHOIS
	genericPreRe = regexp.MustCompile(`(?s)<pre[^>]*>(.*?)</pre>`)
	// HTML entity cleanup
	htmlEntityRe = regexp.MustCompile(`&[a-z]+;|&#[0-9]+;`)
)

func extractWhoisFromHTML(html string) string {
	// Try specific selectors first
	for _, re := range []*regexp.Regexp{whoIsPreRe, whoisComPreRe} {
		if m := re.FindStringSubmatch(html); len(m) >= 2 {
			return cleanHTMLWhois(m[1])
		}
	}

	// Fallback: find the largest <pre> block that looks like WHOIS
	matches := genericPreRe.FindAllStringSubmatch(html, -1)
	var best string
	for _, m := range matches {
		if len(m) >= 2 {
			text := cleanHTMLWhois(m[1])
			// WHOIS responses typically contain these keywords
			if (strings.Contains(strings.ToLower(text), "domain name") ||
				strings.Contains(strings.ToLower(text), "registrar") ||
				strings.Contains(strings.ToLower(text), "name server")) &&
				len(text) > len(best) {
				best = text
			}
		}
	}

	return best
}

func cleanHTMLWhois(s string) string {
	// Strip HTML tags
	tagRe := regexp.MustCompile(`<[^>]*>`)
	s = tagRe.ReplaceAllString(s, "")
	// Decode common entities
	s = strings.ReplaceAll(s, "&amp;", "&")
	s = strings.ReplaceAll(s, "&lt;", "<")
	s = strings.ReplaceAll(s, "&gt;", ">")
	s = strings.ReplaceAll(s, "&quot;", "\"")
	s = strings.ReplaceAll(s, "&#39;", "'")
	s = htmlEntityRe.ReplaceAllString(s, "")
	return strings.TrimSpace(s)
}

// parseRawWhoisText does basic key-value extraction from raw WHOIS text
func parseRawWhoisText(text string, observedAt time.Time) *models.DomainSnapshot {
	snap := &models.DomainSnapshot{
		ObservedAt: observedAt,
	}

	var nameServers []string
	var statusCodes []string

	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "%") || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(strings.ToLower(parts[0]))
		value := strings.TrimSpace(parts[1])
		if value == "" {
			continue
		}

		switch key {
		case "registrar":
			snap.Registrar = &value
		case "registrant name", "registrant":
			snap.RegistrantName = &value
		case "registrant organization", "registrant org":
			snap.RegistrantOrg = &value
		case "registrant email":
			snap.RegistrantEmail = &value
			snap.ContainsPII = true
		case "registrant country", "registrant country/economy":
			snap.RegistrantCountry = &value
		case "name server", "nserver":
			nameServers = append(nameServers, strings.ToLower(value))
		case "domain status", "status":
			// Strip the URL that ICANN adds after status codes
			if idx := strings.Index(value, " "); idx > 0 {
				value = value[:idx]
			}
			statusCodes = append(statusCodes, strings.ToLower(value))
		case "creation date", "created", "registered":
			if t := parseFlexibleDate(value); t != nil {
				snap.CreatedDate = t
			}
		case "updated date", "last updated", "changed":
			if t := parseFlexibleDate(value); t != nil {
				snap.UpdatedDate = t
			}
		case "registry expiry date", "expiry date", "expire", "expires":
			if t := parseFlexibleDate(value); t != nil {
				snap.ExpiryDate = t
			}
		}
	}

	if snap.Registrar == nil && len(nameServers) == 0 {
		return nil // Not enough data to be useful
	}

	snap.NameServers = nameServers
	snap.StatusCodes = statusCodes

	return snap
}

func parseFlexibleDate(s string) *time.Time {
	layouts := []string{
		time.RFC3339,
		"2006-01-02T15:04:05Z",
		"2006-01-02T15:04:05",
		"2006-01-02 15:04:05",
		"2006-01-02",
		"02-Jan-2006",
		"02.01.2006",
		"02/01/2006",
		"January 2, 2006",
		"Jan 2, 2006",
		"20060102",
	}
	for _, layout := range layouts {
		t, err := time.Parse(layout, strings.TrimSpace(s))
		if err == nil {
			return &t
		}
	}
	return nil
}

// addStrings adds two numeric strings (used for byte range calculations)
func addStrings(a, b string) string {
	ai, bi := 0, 0
	fmt.Sscanf(a, "%d", &ai)
	fmt.Sscanf(b, "%d", &bi)
	return fmt.Sprintf("%d", ai+bi-1)
}
