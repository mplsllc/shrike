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
	log.Printf("Shrike CT log importer %s", version.Version)

	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: shrike-ct-import <command> [args]\n\n")
		fmt.Fprintf(os.Stderr, "Commands:\n")
		fmt.Fprintf(os.Stderr, "  known [limit]   Import CT history for domains already in the database\n")
		fmt.Fprintf(os.Stderr, "  domain <name>   Import CT history for a specific domain\n")
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  shrike-ct-import known 1000    Process first 1000 known domains\n")
		fmt.Fprintf(os.Stderr, "  shrike-ct-import domain google.com\n")
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
	ctImporter := importer.NewCTImporter(domainRepo, pool)

	switch os.Args[1] {
	case "known":
		limit := 0
		if len(os.Args) >= 3 {
			limit, _ = strconv.Atoi(os.Args[2])
		}
		stats, err := ctImporter.ImportKnownDomains(ctx, limit)
		if err != nil {
			log.Fatalf("Import failed: %v", err)
		}
		log.Printf("CT import complete: domains=%d certs=%d earliest_updated=%d",
			stats.DomainsProcessed, stats.CertsFound, stats.EarliestUpdated)

	case "domain":
		if len(os.Args) < 3 {
			log.Fatalf("Usage: shrike-ct-import domain <name>")
		}
		stats, err := ctImporter.ImportDomain(ctx, os.Args[2])
		if err != nil {
			log.Fatalf("Import failed: %v", err)
		}
		log.Printf("CT import for %s: certs=%d earliest=%v",
			os.Args[2], stats.CertsFound, stats.EarliestDate)

	default:
		log.Fatalf("Unknown command: %s", os.Args[1])
	}
}
