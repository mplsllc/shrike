package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/klauspost/compress/zstd"

	"git.mp.ls/mpls/shrike/internal/config"
	"git.mp.ls/mpls/shrike/internal/db"
	"git.mp.ls/mpls/shrike/internal/version"
)

func main() {
	log.Printf("Shrike export %s starting", version.Version)

	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	ctx := context.Background()
	pool, err := db.Connect(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer pool.Close()

	exportDir := cfg.ExportDir
	if err := os.MkdirAll(exportDir, 0755); err != nil {
		log.Fatalf("Failed to create export dir: %v", err)
	}

	timestamp := time.Now().UTC().Format("20060102")
	manifest := Manifest{
		Version:   version.Version,
		CreatedAt: time.Now().UTC(),
		Files:     make([]ManifestFile, 0),
	}

	// Export domains + latest snapshots (PII redacted — no registrant_name, email, phone, address)
	// registrant_org included only when it's clearly an organization, raw_whois stripped
	if err := exportTable(ctx, pool, exportDir, "domains_"+timestamp+".jsonl.zst",
		`SELECT row_to_json(t) FROM (
			SELECT d.id, d.name, d.tld, d.first_seen, d.last_seen,
				ds.observed_at, ds.registrar,
				CASE WHEN ds.contains_pii THEN '[REDACTED]' ELSE ds.registrant_org END AS registrant_org,
				ds.registrant_country,
				ds.name_servers, ds.status_codes,
				ds.created_date, ds.updated_date, ds.expiry_date,
				ds.dnssec, ds.source
			FROM domains d
			LEFT JOIN LATERAL (
				SELECT observed_at, registrar, registrant_org, registrant_country,
					name_servers, status_codes, created_date, updated_date, expiry_date,
					dnssec, source, contains_pii
				FROM domain_snapshots WHERE domain_id = d.id ORDER BY observed_at DESC LIMIT 1
			) ds ON true
		) t`, &manifest); err != nil {
		log.Printf("Error exporting domains: %v", err)
	}

	// Export IP blocks + latest snapshots
	if err := exportTable(ctx, pool, exportDir, "ip_blocks_"+timestamp+".jsonl.zst",
		`SELECT row_to_json(t) FROM (
			SELECT b.id, b.cidr::text as cidr, b.version, b.rir, b.first_seen, b.last_seen,
				s.observed_at, s.net_name, s.org_name, s.country, s.status, s.source
			FROM ip_blocks b
			LEFT JOIN LATERAL (
				SELECT * FROM ip_snapshots WHERE ip_block_id = b.id ORDER BY observed_at DESC LIMIT 1
			) s ON true
		) t`, &manifest); err != nil {
		log.Printf("Error exporting IP blocks: %v", err)
	}

	// Export ASNs + latest snapshots
	if err := exportTable(ctx, pool, exportDir, "asns_"+timestamp+".jsonl.zst",
		`SELECT row_to_json(t) FROM (
			SELECT a.id, a.number, a.rir, a.first_seen, a.last_seen,
				s.observed_at, s.name, s.org_name, s.country, s.source
			FROM asns a
			LEFT JOIN LATERAL (
				SELECT * FROM asn_snapshots WHERE asn_id = a.id ORDER BY observed_at DESC LIMIT 1
			) s ON true
		) t`, &manifest); err != nil {
		log.Printf("Error exporting ASNs: %v", err)
	}

	// Export DNS records (latest per domain+type+name+value)
	if err := exportTable(ctx, pool, exportDir, "dns_records_"+timestamp+".jsonl.zst",
		`SELECT row_to_json(t) FROM (
			SELECT DISTINCT ON (domain_id, record_type, name, value)
				observed_at, domain_id, record_type, name, value, ttl, priority, source
			FROM dns_records ORDER BY domain_id, record_type, name, value, observed_at DESC
		) t`, &manifest); err != nil {
		log.Printf("Error exporting DNS records: %v", err)
	}

	// Write manifest
	manifestPath := filepath.Join(exportDir, "manifest_"+timestamp+".json")
	manifestData, _ := json.MarshalIndent(manifest, "", "  ")
	if err := os.WriteFile(manifestPath, manifestData, 0644); err != nil {
		log.Fatalf("Failed to write manifest: %v", err)
	}

	log.Printf("Export complete: %d files written to %s", len(manifest.Files), exportDir)
}

// Manifest describes an export.
type Manifest struct {
	Version   string         `json:"version"`
	CreatedAt time.Time      `json:"created_at"`
	Files     []ManifestFile `json:"files"`
}

type ManifestFile struct {
	Name       string `json:"name"`
	Size       int64  `json:"size"`
	Records    int    `json:"records"`
	SHA256     string `json:"sha256"`
}

func exportTable(ctx context.Context, pool *pgxpool.Pool, dir, filename, query string, manifest *Manifest) error {
	log.Printf("Exporting %s...", filename)

	path := filepath.Join(dir, filename)
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("creating file: %w", err)
	}
	defer f.Close()

	hasher := sha256.New()
	multiWriter := io.MultiWriter(f, hasher)

	encoder, err := zstd.NewWriter(multiWriter)
	if err != nil {
		return fmt.Errorf("creating zstd writer: %w", err)
	}
	defer encoder.Close()

	rows, err := pool.Query(ctx, query)
	if err != nil {
		return fmt.Errorf("querying: %w", err)
	}
	defer rows.Close()

	records := 0
	for rows.Next() {
		var jsonRow []byte
		if err := rows.Scan(&jsonRow); err != nil {
			return fmt.Errorf("scanning row: %w", err)
		}
		encoder.Write(jsonRow)
		encoder.Write([]byte("\n"))
		records++

		if records%100000 == 0 {
			log.Printf("  %s: %d records...", filename, records)
		}
	}

	encoder.Close()

	// Get file size
	info, err := os.Stat(path)
	if err != nil {
		return err
	}

	manifest.Files = append(manifest.Files, ManifestFile{
		Name:    filename,
		Size:    info.Size(),
		Records: records,
		SHA256:  hex.EncodeToString(hasher.Sum(nil)),
	})

	log.Printf("  %s: %d records, %d bytes", filename, records, info.Size())
	return nil
}
