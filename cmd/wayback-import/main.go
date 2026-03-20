package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strconv"

	"git.mp.ls/mpls/shrike/internal/config"
	"git.mp.ls/mpls/shrike/internal/db"
	"git.mp.ls/mpls/shrike/internal/importer"
	"git.mp.ls/mpls/shrike/internal/repository"
	"git.mp.ls/mpls/shrike/internal/version"
)

func main() {
	log.Printf("Shrike Wayback Machine WHOIS importer %s", version.Version)

	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: shrike-wayback-import <command> [args]\n\n")
		fmt.Fprintf(os.Stderr, "Searches the Internet Archive Wayback Machine for historical\n")
		fmt.Fprintf(os.Stderr, "WHOIS lookup pages and extracts WHOIS data.\n\n")
		fmt.Fprintf(os.Stderr, "Commands:\n")
		fmt.Fprintf(os.Stderr, "  known [limit]        Process domains already in the database\n")
		fmt.Fprintf(os.Stderr, "  domain <name>        Process a specific domain\n")
		fmt.Fprintf(os.Stderr, "  scan <site> [limit]  Scan a WHOIS site for all archived domains\n")
		fmt.Fprintf(os.Stderr, "\nSites: whois (who.is), whoiscom (whois.com), domaintools\n")
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  shrike-wayback-import known 500\n")
		fmt.Fprintf(os.Stderr, "  shrike-wayback-import domain google.com\n")
		fmt.Fprintf(os.Stderr, "  shrike-wayback-import scan whois 1000\n")
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

	domainRepo := repository.NewDomainRepository(pool)
	wb := importer.NewWaybackImporter(domainRepo, pool)

	switch os.Args[1] {
	case "known":
		limit := 0
		if len(os.Args) >= 3 {
			limit, _ = strconv.Atoi(os.Args[2])
		}
		stats, err := wb.ImportKnownDomains(ctx, limit)
		if err != nil {
			log.Fatalf("Import failed: %v", err)
		}
		log.Printf("Wayback import complete: domains=%d captures=%d snapshots=%d",
			stats.DomainsProcessed, stats.CapturesFound, stats.SnapshotsStored)

	case "domain":
		if len(os.Args) < 3 {
			log.Fatalf("Usage: shrike-wayback-import domain <name>")
		}
		stats, err := wb.ImportDomain(ctx, os.Args[2])
		if err != nil {
			log.Fatalf("Import failed: %v", err)
		}
		log.Printf("Wayback import for %s: captures=%d snapshots=%d",
			os.Args[2], stats.CapturesFound, stats.SnapshotsStored)

	case "scan":
		if len(os.Args) < 3 {
			log.Fatalf("Usage: shrike-wayback-import scan <site> [limit]")
		}
		site := os.Args[2]
		limit := 0
		if len(os.Args) >= 4 {
			limit, _ = strconv.Atoi(os.Args[3])
		}
		stats, err := wb.ScanSite(ctx, site, limit)
		if err != nil {
			log.Fatalf("Scan failed: %v", err)
		}
		log.Printf("Wayback scan complete: pages=%d domains=%d snapshots=%d",
			stats.CapturesFound, stats.DomainsProcessed, stats.SnapshotsStored)

	default:
		log.Fatalf("Unknown command: %s", os.Args[1])
	}
}
