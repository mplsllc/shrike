package importer

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"git.mp.ls/mpls/shrike/internal/repository"
)

// CTImporter queries crt.sh for certificate transparency data.
// For each domain, it retrieves certificate issuance history and uses it to:
// 1. Update domain first_seen if CT data predates our earliest snapshot
// 2. Store cert metadata in domain_snapshots.extra for timeline enrichment
type CTImporter struct {
	domainRepo *repository.DomainRepository
	pool       *pgxpool.Pool
	client     *http.Client
}

type CTStats struct {
	DomainsProcessed int
	CertsFound       int
	EarliestUpdated  int
	EarliestDate     *time.Time
}

// crtshEntry represents a single certificate from crt.sh JSON API
type crtshEntry struct {
	ID             int64  `json:"id"`
	IssuerCAID     int64  `json:"issuer_ca_id"`
	IssuerName     string `json:"issuer_name"`
	CommonName     string `json:"common_name"`
	NameValue      string `json:"name_value"`
	SerialNumber   string `json:"serial_number"`
	EntryTimestamp string `json:"entry_timestamp"`
	NotBefore      string `json:"not_before"`
	NotAfter       string `json:"not_after"`
}

func NewCTImporter(domainRepo *repository.DomainRepository, pool *pgxpool.Pool) *CTImporter {
	return &CTImporter{
		domainRepo: domainRepo,
		pool:       pool,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// ImportKnownDomains queries crt.sh for all domains in our database.
// limit=0 means all domains.
func (c *CTImporter) ImportKnownDomains(ctx context.Context, limit int) (*CTStats, error) {
	stats := &CTStats{}

	// Get known domains
	query := `SELECT id, name, first_seen FROM domains ORDER BY id`
	if limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", limit)
	}

	rows, err := c.pool.Query(ctx, query)
	if err != nil {
		return stats, fmt.Errorf("querying domains: %w", err)
	}
	defer rows.Close()

	type domainRow struct {
		ID        int64
		Name      string
		FirstSeen time.Time
	}
	var domains []domainRow
	for rows.Next() {
		var d domainRow
		if err := rows.Scan(&d.ID, &d.Name, &d.FirstSeen); err != nil {
			return stats, fmt.Errorf("scanning domain: %w", err)
		}
		domains = append(domains, d)
	}
	rows.Close()

	for i, d := range domains {
		if i > 0 && i%100 == 0 {
			log.Printf("CT import progress: %d/%d domains processed, %d certs found",
				i, len(domains), stats.CertsFound)
		}

		entries, err := c.queryCrtsh(ctx, d.Name)
		if err != nil {
			log.Printf("  Error querying crt.sh for %s: %v", d.Name, err)
			// Rate limit — crt.sh is generous but don't hammer it
			time.Sleep(2 * time.Second)
			continue
		}

		stats.DomainsProcessed++
		stats.CertsFound += len(entries)

		if len(entries) == 0 {
			time.Sleep(500 * time.Millisecond)
			continue
		}

		// Find earliest cert date
		var earliest time.Time
		for _, e := range entries {
			notBefore := parseCTDate(e.NotBefore)
			if notBefore != nil && (earliest.IsZero() || notBefore.Before(earliest)) {
				earliest = *notBefore
			}
		}

		// Update first_seen if CT data is older
		if !earliest.IsZero() && (d.FirstSeen.IsZero() || earliest.Before(d.FirstSeen)) {
			_, err := c.pool.Exec(ctx,
				`UPDATE domains SET first_seen = $1 WHERE id = $2 AND (first_seen > $1 OR first_seen = '0001-01-01')`,
				earliest, d.ID)
			if err != nil {
				log.Printf("  Error updating first_seen for %s: %v", d.Name, err)
			} else {
				stats.EarliestUpdated++
			}
		}

		// Store cert count and date range in extra on latest snapshot
		certMeta := map[string]interface{}{
			"ct_certs_total":   len(entries),
			"ct_earliest_cert": earliest.Format(time.RFC3339),
			"ct_latest_cert":   findLatestCert(entries).Format(time.RFC3339),
			"ct_imported_at":   time.Now().UTC().Format(time.RFC3339),
		}
		metaJSON, _ := json.Marshal(certMeta)

		_, err = c.pool.Exec(ctx,
			`UPDATE domain_snapshots SET extra = COALESCE(extra, '{}'::jsonb) || $1::jsonb
			 WHERE domain_id = $2 AND observed_at = (
				SELECT MAX(observed_at) FROM domain_snapshots WHERE domain_id = $2
			 )`,
			string(metaJSON), d.ID)
		if err != nil {
			log.Printf("  Error updating snapshot extra for %s: %v", d.Name, err)
		}

		// Be polite to crt.sh
		time.Sleep(1 * time.Second)
	}

	return stats, nil
}

// ImportDomain queries crt.sh for a single domain and returns stats.
func (c *CTImporter) ImportDomain(ctx context.Context, name string) (*CTStats, error) {
	stats := &CTStats{}

	entries, err := c.queryCrtsh(ctx, name)
	if err != nil {
		return stats, fmt.Errorf("querying crt.sh: %w", err)
	}

	stats.DomainsProcessed = 1
	stats.CertsFound = len(entries)

	if len(entries) == 0 {
		return stats, nil
	}

	var earliest time.Time
	for _, e := range entries {
		notBefore := parseCTDate(e.NotBefore)
		if notBefore != nil && (earliest.IsZero() || notBefore.Before(earliest)) {
			earliest = *notBefore
		}
	}
	stats.EarliestDate = &earliest

	log.Printf("  %s: %d certificates, earliest %s, latest %s",
		name, len(entries), earliest.Format("2006-01-02"), findLatestCert(entries).Format("2006-01-02"))

	return stats, nil
}

func (c *CTImporter) queryCrtsh(ctx context.Context, domain string) ([]crtshEntry, error) {
	u := fmt.Sprintf("https://crt.sh/?q=%s&output=json", url.QueryEscape(domain))

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

	// Limit response size to 10MB
	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	var entries []crtshEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, fmt.Errorf("parsing JSON: %w", err)
	}

	return entries, nil
}

func parseCTDate(s string) *time.Time {
	// crt.sh returns dates like "2024-01-15T00:00:00"
	for _, layout := range []string{
		"2006-01-02T15:04:05",
		"2006-01-02T15:04:05Z",
		time.RFC3339,
		"2006-01-02",
	} {
		t, err := time.Parse(layout, s)
		if err == nil {
			return &t
		}
	}
	return nil
}

func findLatestCert(entries []crtshEntry) time.Time {
	var latest time.Time
	for _, e := range entries {
		notBefore := parseCTDate(e.NotBefore)
		if notBefore != nil && notBefore.After(latest) {
			latest = *notBefore
		}
	}
	return latest
}
