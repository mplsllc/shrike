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
	log.Printf("Shrike Common Crawl WHOIS importer %s", version.Version)

	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: shrike-cc-import <crawl-id> [limit]\n\n")
		fmt.Fprintf(os.Stderr, "Searches Common Crawl archives for WHOIS lookup pages\n")
		fmt.Fprintf(os.Stderr, "(who.is, whois.com) and extracts historical WHOIS data.\n\n")
		fmt.Fprintf(os.Stderr, "Examples:\n")
		fmt.Fprintf(os.Stderr, "  shrike-cc-import CC-MAIN-2024-10         Search one crawl\n")
		fmt.Fprintf(os.Stderr, "  shrike-cc-import CC-MAIN-2024-10 1000    Limit to 1000 pages\n")
		fmt.Fprintf(os.Stderr, "  shrike-cc-import list                    List available crawl IDs\n")
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
	ccImporter := importer.NewCCImporter(domainRepo, pool)

	switch os.Args[1] {
	case "list":
		crawls, err := ccImporter.ListCrawls(ctx)
		if err != nil {
			log.Fatalf("Failed to list crawls: %v", err)
		}
		for _, c := range crawls {
			fmt.Println(c)
		}

	default:
		crawlID := os.Args[1]
		limit := 0
		if len(os.Args) >= 3 {
			limit, _ = strconv.Atoi(os.Args[2])
		}

		stats, err := ccImporter.ImportCrawl(ctx, crawlID, limit)
		if err != nil {
			log.Fatalf("Import failed: %v", err)
		}
		log.Printf("CC import complete: pages=%d parsed=%d snapshots=%d errors=%d",
			stats.PagesFound, stats.Parsed, stats.SnapshotsStored, stats.Errors)
	}
}
