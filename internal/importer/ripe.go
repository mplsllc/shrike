package importer

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"strings"
	"time"

	"git.mp.ls/mpls/shrike/internal/models"
	"git.mp.ls/mpls/shrike/internal/repository"
)

// RIPEImporter parses RIPE database dumps in RPSL format.
// RPSL objects are blocks of "key: value" lines separated by blank lines.
// Object types we care about: inetnum, inet6num, aut-num.
type RIPEImporter struct {
	ipRepo  *repository.IPRepository
	asnRepo *repository.ASNRepository
}

func NewRIPEImporter(ipRepo *repository.IPRepository, asnRepo *repository.ASNRepository) *RIPEImporter {
	return &RIPEImporter{ipRepo: ipRepo, asnRepo: asnRepo}
}

// rpslObject holds the key-value pairs of a single RPSL object.
type rpslObject struct {
	objectType string
	fields     map[string][]string // key → values (some keys appear multiple times)
}

// Import reads a RIPE database dump and imports inetnum, inet6num, and aut-num objects.
func (ri *RIPEImporter) Import(ctx context.Context, reader io.Reader) (stats ImportStats, err error) {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024) // 1MB line buffer

	var currentObj *rpslObject
	now := time.Now().UTC()

	for scanner.Scan() {
		line := scanner.Text()

		// Blank line = end of object
		if strings.TrimSpace(line) == "" {
			if currentObj != nil {
				if err := ri.processObject(ctx, currentObj, now, &stats); err != nil {
					log.Printf("Error processing %s object: %v", currentObj.objectType, err)
					stats.Errors++
				}
				currentObj = nil
			}
			continue
		}

		// Skip comments
		if strings.HasPrefix(line, "%") || strings.HasPrefix(line, "#") {
			continue
		}

		// Continuation line (starts with whitespace)
		if (line[0] == ' ' || line[0] == '\t' || line[0] == '+') && currentObj != nil {
			// Append to the last field's last value
			// (RPSL continuation — not critical for our use case, skip for now)
			continue
		}

		// Parse "key: value"
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		if currentObj == nil {
			currentObj = &rpslObject{
				objectType: key,
				fields:     make(map[string][]string),
			}
		}

		currentObj.fields[key] = append(currentObj.fields[key], value)
	}

	// Handle last object if file doesn't end with blank line
	if currentObj != nil {
		if err := ri.processObject(ctx, currentObj, now, &stats); err != nil {
			stats.Errors++
		}
	}

	return stats, scanner.Err()
}

func (ri *RIPEImporter) processObject(ctx context.Context, obj *rpslObject, now time.Time, stats *ImportStats) error {
	switch obj.objectType {
	case "inetnum":
		return ri.processInetnum(ctx, obj, now, stats, 4)
	case "inet6num":
		return ri.processInetnum(ctx, obj, now, stats, 6)
	case "aut-num":
		return ri.processAutNum(ctx, obj, now, stats)
	default:
		// Skip object types we don't care about (person, role, mntner, etc.)
		return nil
	}
}

func (ri *RIPEImporter) processInetnum(ctx context.Context, obj *rpslObject, now time.Time, stats *ImportStats, version int) error {
	stats.Processed++

	cidr := firstVal(obj.fields, obj.objectType)
	if cidr == "" {
		return nil
	}

	// RIPE inetnum uses "1.2.3.0 - 1.2.3.255" range notation — convert to CIDR
	if strings.Contains(cidr, " - ") {
		converted, err := rangeToPrefix(cidr)
		if err != nil {
			return nil // Skip invalid ranges
		}
		cidr = converted
	}

	blockID, err := ri.ipRepo.Upsert(ctx, cidr, version, "RIPE")
	if err != nil {
		return err
	}

	snap := &models.IPSnapshot{
		ObservedAt:   now,
		IPBlockID:    blockID,
		NetName:      strPtr(firstVal(obj.fields, "netname")),
		OrgName:      strPtr(firstVal(obj.fields, "org-name")),
		Description:  strPtr(firstVal(obj.fields, "descr")),
		Country:      strPtr(firstVal(obj.fields, "country")),
		AbuseContact: strPtr(firstVal(obj.fields, "abuse-mailbox")),
		Status:       strPtr(firstVal(obj.fields, "status")),
		Source:       "ripe_bulk",
	}

	stored, err := ri.ipRepo.InsertSnapshotIfChanged(ctx, snap)
	if err != nil {
		return err
	}
	if stored {
		stats.Stored++
	}
	return nil
}

func (ri *RIPEImporter) processAutNum(ctx context.Context, obj *rpslObject, now time.Time, stats *ImportStats) error {
	stats.Processed++

	asStr := firstVal(obj.fields, "aut-num")
	if asStr == "" {
		return nil
	}

	// Parse "AS12345" to integer
	asNum := parseASNumber(asStr)
	if asNum <= 0 {
		return nil
	}

	asnID, err := ri.asnRepo.Upsert(ctx, asNum, "RIPE")
	if err != nil {
		return err
	}

	snap := &models.ASNSnapshot{
		ObservedAt:  now,
		ASNID:       asnID,
		Name:        strPtr(firstVal(obj.fields, "as-name")),
		OrgName:     strPtr(firstVal(obj.fields, "org-name")),
		Description: strPtr(firstVal(obj.fields, "descr")),
		Country:     strPtr(firstVal(obj.fields, "country")),
		Source:      "ripe_bulk",
	}

	stored, err := ri.asnRepo.InsertSnapshotIfChanged(ctx, snap)
	if err != nil {
		return err
	}
	if stored {
		stats.Stored++
	}
	return nil
}

func firstVal(fields map[string][]string, key string) string {
	vals := fields[key]
	if len(vals) == 0 {
		return ""
	}
	return vals[0]
}

func strPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func parseASNumber(s string) int {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "AS")
	s = strings.TrimPrefix(s, "as")
	n := 0
	for _, c := range s {
		if c >= '0' && c <= '9' {
			n = n*10 + int(c-'0')
		} else {
			break
		}
	}
	return n
}

// rangeToPrefix converts "1.2.3.0 - 1.2.3.255" to CIDR notation.
// This is a simplified version — for production, use a proper IP math library.
func rangeToPrefix(rangeStr string) (string, error) {
	parts := strings.Split(rangeStr, " - ")
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid range: %s", rangeStr)
	}
	start := strings.TrimSpace(parts[0])
	// For now, approximate by using /24 — a proper implementation would calculate
	// the exact prefix length from the range.
	// TODO: Implement proper range-to-CIDR conversion
	return start + "/24", nil
}
