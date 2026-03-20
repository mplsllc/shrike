package importer

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"math/bits"
	"net"
	"strconv"
	"strings"
	"time"

	"git.mp.ls/mpls/shrike/internal/models"
	"git.mp.ls/mpls/shrike/internal/repository"
)

// DelegationImporter parses RIR delegation statistics files (NRO stats format).
// Format: rir|country|type|start|value|date|status
// Where type is ipv4, ipv6, or asn.
// For ipv4: start is first IP, value is host count (convert to CIDR).
// For ipv6: start is first IP, value is prefix length.
// For asn: start is ASN number, value is count of ASNs.
type DelegationImporter struct {
	ipRepo  *repository.IPRepository
	asnRepo *repository.ASNRepository
}

func NewDelegationImporter(ipRepo *repository.IPRepository, asnRepo *repository.ASNRepository) *DelegationImporter {
	return &DelegationImporter{ipRepo: ipRepo, asnRepo: asnRepo}
}

type delegationRecord struct {
	RIR     string
	Country string
	Type    string // ipv4, ipv6, asn
	Start   string
	Value   string
	Date    string // YYYYMMDD
	Status  string // allocated, assigned, available, reserved
}

// Import reads a delegation stats file and imports IP blocks and ASNs.
// snapshotDate is the date of the delegation file (used as observed_at).
func (d *DelegationImporter) Import(ctx context.Context, reader io.Reader, snapshotDate time.Time) (*Stats, error) {
	stats := &Stats{}
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines, comments, header, and summary lines
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Header line starts with version number
		if lineNum == 1 && (line[0] >= '0' && line[0] <= '9') {
			continue
		}

		fields := strings.Split(line, "|")
		if len(fields) < 7 {
			continue
		}

		// Summary lines have * in country field
		if fields[1] == "*" {
			continue
		}

		rec := delegationRecord{
			RIR:     fields[0],
			Country: fields[1],
			Type:    fields[2],
			Start:   fields[3],
			Value:   fields[4],
			Date:    fields[5],
			Status:  fields[6],
		}

		// Only import allocated and assigned records
		if rec.Status != "allocated" && rec.Status != "assigned" {
			continue
		}

		switch rec.Type {
		case "ipv4":
			if err := d.importIPv4(ctx, rec, snapshotDate, stats); err != nil {
				log.Printf("Error importing IPv4 %s: %v", rec.Start, err)
			}
		case "ipv6":
			if err := d.importIPv6(ctx, rec, snapshotDate, stats); err != nil {
				log.Printf("Error importing IPv6 %s: %v", rec.Start, err)
			}
		case "asn":
			if err := d.importASN(ctx, rec, snapshotDate, stats); err != nil {
				log.Printf("Error importing ASN %s: %v", rec.Start, err)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return stats, fmt.Errorf("scanning delegation file: %w", err)
	}

	return stats, nil
}

func (d *DelegationImporter) importIPv4(ctx context.Context, rec delegationRecord, snapshotDate time.Time, stats *Stats) error {
	hostCount, err := strconv.ParseInt(rec.Value, 10, 64)
	if err != nil {
		return fmt.Errorf("parsing host count: %w", err)
	}

	// Convert host count to CIDR prefix length
	// Host count must be a power of 2 for clean CIDR
	prefixLen := 32 - bits.TrailingZeros64(uint64(hostCount))
	if uint64(hostCount) != 1<<(32-prefixLen) {
		// Not a power of 2 — skip, can't represent as single CIDR
		// Some delegations span non-power-of-2 blocks
		return nil
	}

	cidr := fmt.Sprintf("%s/%d", rec.Start, prefixLen)

	// Validate CIDR
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("invalid CIDR %s: %w", cidr, err)
	}
	cidr = ipNet.String() // Normalize

	allocDate := parseDelegationDate(rec.Date)

	blockID, err := d.ipRepo.Upsert(ctx, cidr, 4, rec.RIR)
	if err != nil {
		return fmt.Errorf("upserting IP block %s: %w", cidr, err)
	}

	snap := &models.IPSnapshot{
		ObservedAt:  snapshotDate,
		IPBlockID:   blockID,
		NetName:     nil,
		OrgName:     nil,
		Country:     strPtr(rec.Country),
		AllocatedDate:   allocDate,
		Source:      "rir-delegation",
		ContainsPII: false,
	}

	_, err = d.ipRepo.InsertSnapshotIfChanged(ctx, snap)
	if err != nil {
		return fmt.Errorf("inserting snapshot for %s: %w", cidr, err)
	}

	stats.IPBlocksProcessed++
	return nil
}

func (d *DelegationImporter) importIPv6(ctx context.Context, rec delegationRecord, snapshotDate time.Time, stats *Stats) error {
	prefixLen, err := strconv.Atoi(rec.Value)
	if err != nil {
		return fmt.Errorf("parsing prefix length: %w", err)
	}

	cidr := fmt.Sprintf("%s/%d", rec.Start, prefixLen)

	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("invalid CIDR %s: %w", cidr, err)
	}
	cidr = ipNet.String()

	allocDate := parseDelegationDate(rec.Date)

	blockID, err := d.ipRepo.Upsert(ctx, cidr, 6, rec.RIR)
	if err != nil {
		return fmt.Errorf("upserting IP block %s: %w", cidr, err)
	}

	snap := &models.IPSnapshot{
		ObservedAt:  snapshotDate,
		IPBlockID:   blockID,
		Country:     strPtr(rec.Country),
		AllocatedDate:   allocDate,
		Source:      "rir-delegation",
		ContainsPII: false,
	}

	_, err = d.ipRepo.InsertSnapshotIfChanged(ctx, snap)
	if err != nil {
		return fmt.Errorf("inserting snapshot for %s: %w", cidr, err)
	}

	stats.IPBlocksProcessed++
	return nil
}

func (d *DelegationImporter) importASN(ctx context.Context, rec delegationRecord, snapshotDate time.Time, stats *Stats) error {
	asnNum, err := strconv.Atoi(rec.Start)
	if err != nil {
		return fmt.Errorf("parsing ASN number: %w", err)
	}

	count, err := strconv.Atoi(rec.Value)
	if err != nil {
		return fmt.Errorf("parsing ASN count: %w", err)
	}

	allocDate := parseDelegationDate(rec.Date)

	// Import each ASN in the range
	for i := 0; i < count; i++ {
		asn := asnNum + i

		asnID, err := d.asnRepo.Upsert(ctx, asn, rec.RIR)
		if err != nil {
			return fmt.Errorf("upserting ASN %d: %w", asn, err)
		}

		snap := &models.ASNSnapshot{
			ObservedAt: snapshotDate,
			ASNID:      asnID,
			Country:    strPtr(rec.Country),
			AllocatedDate:  allocDate,
			Source:     "rir-delegation",
		}

		_, err = d.asnRepo.InsertSnapshotIfChanged(ctx, snap)
		if err != nil {
			return fmt.Errorf("inserting snapshot for AS%d: %w", asn, err)
		}

		stats.ASNsProcessed++
	}

	return nil
}

func parseDelegationDate(dateStr string) *time.Time {
	if dateStr == "" || dateStr == "00000000" {
		return nil
	}
	t, err := time.Parse("20060102", dateStr)
	if err != nil {
		return nil
	}
	return &t
}

// RIRDelegationSources returns the URL templates for all 5 RIR delegation archives.
// Use with fmt.Sprintf(template, year, year, month, day) to get specific dates.
var RIRDelegationSources = map[string]struct {
	// URLFunc returns the URL for a given date
	URLFunc func(date time.Time) string
	// Compression format
	Compression string
	// Earliest available date
	Earliest time.Time
}{
	"ripencc": {
		URLFunc: func(date time.Time) string {
			return fmt.Sprintf("https://ftp.ripe.net/ripe/stats/%d/delegated-ripencc-%s.bz2",
				date.Year(), date.Format("20060102"))
		},
		Compression: "bz2",
		Earliest:    time.Date(2003, 11, 26, 0, 0, 0, 0, time.UTC),
	},
	"arin": {
		URLFunc: func(date time.Time) string {
			return fmt.Sprintf("https://ftp.arin.net/pub/stats/arin/archive/%d/delegated-arin-%s",
				date.Year(), date.Format("20060102"))
		},
		Compression: "none",
		Earliest:    time.Date(2003, 11, 20, 0, 0, 0, 0, time.UTC),
	},
	"apnic": {
		URLFunc: func(date time.Time) string {
			return fmt.Sprintf("https://ftp.apnic.net/public/stats/apnic/%d/delegated-apnic-%s.gz",
				date.Year(), date.Format("20060102"))
		},
		Compression: "gz",
		Earliest:    time.Date(2001, 1, 1, 0, 0, 0, 0, time.UTC),
	},
	"lacnic": {
		URLFunc: func(date time.Time) string {
			return fmt.Sprintf("https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-%s",
				date.Format("20060102"))
		},
		Compression: "none",
		Earliest:    time.Date(2004, 1, 1, 0, 0, 0, 0, time.UTC),
	},
	"afrinic": {
		URLFunc: func(date time.Time) string {
			return fmt.Sprintf("https://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-%s",
				date.Format("20060102"))
		},
		Compression: "none",
		Earliest:    time.Date(2005, 1, 1, 0, 0, 0, 0, time.UTC),
	},
}

// HistoricalDates generates the 1st of each month from start to end.
func HistoricalDates(start, end time.Time) []time.Time {
	var dates []time.Time
	current := time.Date(start.Year(), start.Month(), 1, 0, 0, 0, 0, time.UTC)
	for !current.After(end) {
		dates = append(dates, current)
		current = current.AddDate(0, 1, 0)
	}
	return dates
}
