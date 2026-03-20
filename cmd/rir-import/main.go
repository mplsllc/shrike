package main

import (
	"compress/bzip2"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"git.mp.ls/mpls/shrike/internal/config"
	"git.mp.ls/mpls/shrike/internal/db"
	"git.mp.ls/mpls/shrike/internal/importer"
	"git.mp.ls/mpls/shrike/internal/repository"
	"git.mp.ls/mpls/shrike/internal/version"
)

const ripeDBURL = "https://ftp.ripe.net/ripe/dbase/ripe.db.gz"

func main() {
	log.Printf("Shrike RIR importer %s", version.Version)

	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: shrike-rir-import <command> [args]\n\n")
		fmt.Fprintf(os.Stderr, "Commands:\n")
		fmt.Fprintf(os.Stderr, "  ripe [file]                      Import current RIPE WHOIS dump\n")
		fmt.Fprintf(os.Stderr, "  apnic [file]                     Import current APNIC WHOIS dump\n")
		fmt.Fprintf(os.Stderr, "  delegation <rir|all> [date-range] Import RIR delegation stats\n")
		fmt.Fprintf(os.Stderr, "\nDelegation examples:\n")
		fmt.Fprintf(os.Stderr, "  delegation all                   Current delegation from all 5 RIRs\n")
		fmt.Fprintf(os.Stderr, "  delegation ripencc               Current RIPE delegation\n")
		fmt.Fprintf(os.Stderr, "  delegation all 2020-01:2025-12   Monthly from Jan 2020 to Dec 2025\n")
		fmt.Fprintf(os.Stderr, "  delegation arin 2010-01:2020-12  Monthly ARIN from 2010 to 2020\n")
		os.Exit(1)
	}

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

	ipRepo := repository.NewIPRepository(pool)
	asnRepo := repository.NewASNRepository(pool)

	switch strings.ToLower(os.Args[1]) {
	case "ripe":
		importRIPE(ctx, ipRepo, asnRepo)
	case "apnic":
		importAPNIC(ctx, ipRepo, asnRepo)
	case "delegation":
		importDelegation(ctx, ipRepo, asnRepo)
	default:
		log.Fatalf("Unknown command: %s", os.Args[1])
	}
}

func importRIPE(ctx context.Context, ipRepo *repository.IPRepository, asnRepo *repository.ASNRepository) {
	var reader io.Reader

	if len(os.Args) >= 3 {
		f, err := os.Open(os.Args[2])
		if err != nil {
			log.Fatalf("Failed to open file: %v", err)
		}
		defer f.Close()
		reader = f
	} else {
		log.Printf("Downloading RIPE database from %s...", ripeDBURL)
		resp, err := http.Get(ripeDBURL)
		if err != nil {
			log.Fatalf("Failed to download: %v", err)
		}
		defer resp.Body.Close()
		reader = resp.Body
	}

	if len(os.Args) >= 3 && strings.HasSuffix(os.Args[2], ".gz") {
		gz, err := gzip.NewReader(reader)
		if err != nil {
			log.Fatalf("Failed to open gzip: %v", err)
		}
		defer gz.Close()
		reader = gz
	} else if len(os.Args) < 3 {
		gz, err := gzip.NewReader(reader)
		if err != nil {
			log.Fatalf("Failed to open gzip: %v", err)
		}
		defer gz.Close()
		reader = gz
	}

	ri := importer.NewRIPEImporter(ipRepo, asnRepo)
	stats, err := ri.Import(ctx, reader)
	if err != nil {
		log.Fatalf("Import failed: %v", err)
	}

	log.Printf("RIPE import complete: processed=%d stored=%d errors=%d",
		stats.Processed, stats.Stored, stats.Errors)
}

func importAPNIC(ctx context.Context, ipRepo *repository.IPRepository, asnRepo *repository.ASNRepository) {
	const apnicURL = "https://ftp.apnic.net/public/apnic/whois/apnic.db.inetnum.gz"

	var reader io.Reader

	if len(os.Args) >= 3 {
		f, err := os.Open(os.Args[2])
		if err != nil {
			log.Fatalf("Failed to open file: %v", err)
		}
		defer f.Close()
		reader = f
	} else {
		log.Printf("Downloading APNIC database from %s...", apnicURL)
		resp, err := http.Get(apnicURL)
		if err != nil {
			log.Fatalf("Failed to download: %v", err)
		}
		defer resp.Body.Close()
		reader = resp.Body
	}

	if (len(os.Args) >= 3 && strings.HasSuffix(os.Args[2], ".gz")) || len(os.Args) < 3 {
		gz, err := gzip.NewReader(reader)
		if err != nil {
			log.Fatalf("Failed to open gzip: %v", err)
		}
		defer gz.Close()
		reader = gz
	}

	// APNIC uses the same RPSL format as RIPE
	ri := importer.NewRIPEImporter(ipRepo, asnRepo)
	stats, err := ri.Import(ctx, reader)
	if err != nil {
		log.Fatalf("Import failed: %v", err)
	}

	log.Printf("APNIC import complete: processed=%d stored=%d errors=%d",
		stats.Processed, stats.Stored, stats.Errors)
}

func importDelegation(ctx context.Context, ipRepo *repository.IPRepository, asnRepo *repository.ASNRepository) {
	if len(os.Args) < 3 {
		log.Fatalf("Usage: shrike-rir-import delegation <rir|all> [start:end]")
	}

	rirArg := strings.ToLower(os.Args[2])
	di := importer.NewDelegationImporter(ipRepo, asnRepo)

	// Determine which RIRs to import
	var rirs []string
	if rirArg == "all" {
		rirs = []string{"ripencc", "arin", "apnic", "lacnic", "afrinic"}
	} else {
		if _, ok := importer.RIRDelegationSources[rirArg]; !ok {
			log.Fatalf("Unknown RIR: %s (valid: ripencc, arin, apnic, lacnic, afrinic, all)", rirArg)
		}
		rirs = []string{rirArg}
	}

	// Determine date range
	var dates []time.Time
	if len(os.Args) >= 4 {
		// Parse date range like 2020-01:2025-12
		parts := strings.Split(os.Args[3], ":")
		if len(parts) != 2 {
			log.Fatalf("Invalid date range format. Use YYYY-MM:YYYY-MM (e.g., 2020-01:2025-12)")
		}
		start, err := time.Parse("2006-01", parts[0])
		if err != nil {
			log.Fatalf("Invalid start date: %v", err)
		}
		end, err := time.Parse("2006-01", parts[1])
		if err != nil {
			log.Fatalf("Invalid end date: %v", err)
		}
		dates = importer.HistoricalDates(start, end)
	} else {
		// Current month only
		now := time.Now()
		dates = []time.Time{time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)}
	}

	totalStats := &importer.Stats{}

	for _, rir := range rirs {
		source := importer.RIRDelegationSources[rir]

		for _, date := range dates {
			if date.Before(source.Earliest) {
				continue
			}

			url := source.URLFunc(date)
			log.Printf("Fetching %s delegation for %s...", rir, date.Format("2006-01"))

			reader, cleanup, err := fetchDelegation(url, source.Compression)
			if err != nil {
				log.Printf("  Skipping %s %s: %v", rir, date.Format("2006-01"), err)
				continue
			}

			stats, err := di.Import(ctx, reader, date)
			cleanup()

			if err != nil {
				log.Printf("  Error importing %s %s: %v", rir, date.Format("2006-01"), err)
				continue
			}

			log.Printf("  %s %s: %d IP blocks, %d ASNs",
				rir, date.Format("2006-01"), stats.IPBlocksProcessed, stats.ASNsProcessed)

			totalStats.IPBlocksProcessed += stats.IPBlocksProcessed
			totalStats.ASNsProcessed += stats.ASNsProcessed
		}
	}

	log.Printf("Delegation import complete: %d IP blocks, %d ASNs total",
		totalStats.IPBlocksProcessed, totalStats.ASNsProcessed)
}

func fetchDelegation(url, compression string) (io.Reader, func(), error) {
	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Get(url)
	if err != nil {
		return nil, nil, fmt.Errorf("downloading: %w", err)
	}

	if resp.StatusCode != 200 {
		resp.Body.Close()
		return nil, nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	cleanup := func() { resp.Body.Close() }

	switch compression {
	case "bz2":
		return bzip2.NewReader(resp.Body), cleanup, nil
	case "gz":
		gz, err := gzip.NewReader(resp.Body)
		if err != nil {
			resp.Body.Close()
			return nil, nil, fmt.Errorf("gzip: %w", err)
		}
		cleanup = func() { gz.Close(); resp.Body.Close() }
		return gz, cleanup, nil
	default:
		return resp.Body, cleanup, nil
	}
}
