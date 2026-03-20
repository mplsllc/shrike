package crawler

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"git.mp.ls/mpls/shrike/internal/models"
	"git.mp.ls/mpls/shrike/internal/hash"
)

// DNSResolver enumerates DNS records for a domain.
type DNSResolver struct {
	resolver *net.Resolver
	timeout  time.Duration
}

func NewDNSResolver() *DNSResolver {
	return &DNSResolver{
		resolver: net.DefaultResolver,
		timeout:  10 * time.Second,
	}
}

// ResolveAll fetches all standard DNS record types for a domain.
// Returns a slice of DNSRecord models ready for storage.
func (dr *DNSResolver) ResolveAll(ctx context.Context, domain string, domainID int64) ([]models.DNSRecord, error) {
	ctx, cancel := context.WithTimeout(ctx, dr.timeout)
	defer cancel()

	now := time.Now().UTC()
	var records []models.DNSRecord

	// A records
	if ips, err := dr.resolver.LookupHost(ctx, domain); err == nil {
		for _, ip := range ips {
			parsed := net.ParseIP(ip)
			if parsed == nil {
				continue
			}
			recType := "A"
			if parsed.To4() == nil {
				recType = "AAAA"
			}
			rec := models.DNSRecord{
				ObservedAt: now,
				DomainID:   domainID,
				RecordType: recType,
				Name:       "@",
				Value:      ip,
				Source:     "crawl",
			}
			rec.Hash = hash.HashDNSRecord(&rec)
			records = append(records, rec)
		}
	}

	// MX records
	if mxs, err := dr.resolver.LookupMX(ctx, domain); err == nil {
		for _, mx := range mxs {
			prio := int(mx.Pref)
			rec := models.DNSRecord{
				ObservedAt: now,
				DomainID:   domainID,
				RecordType: "MX",
				Name:       "@",
				Value:      strings.TrimSuffix(mx.Host, "."),
				Priority:   &prio,
				Source:     "crawl",
			}
			rec.Hash = hash.HashDNSRecord(&rec)
			records = append(records, rec)
		}
	}

	// NS records
	if nss, err := dr.resolver.LookupNS(ctx, domain); err == nil {
		for _, ns := range nss {
			rec := models.DNSRecord{
				ObservedAt: now,
				DomainID:   domainID,
				RecordType: "NS",
				Name:       "@",
				Value:      strings.TrimSuffix(ns.Host, "."),
				Source:     "crawl",
			}
			rec.Hash = hash.HashDNSRecord(&rec)
			records = append(records, rec)
		}
	}

	// TXT records
	if txts, err := dr.resolver.LookupTXT(ctx, domain); err == nil {
		// Sort for consistent ordering
		sort.Strings(txts)
		for _, txt := range txts {
			rec := models.DNSRecord{
				ObservedAt: now,
				DomainID:   domainID,
				RecordType: "TXT",
				Name:       "@",
				Value:      txt,
				Source:     "crawl",
			}
			rec.Hash = hash.HashDNSRecord(&rec)
			records = append(records, rec)
		}
	}

	// CNAME record
	if cname, err := dr.resolver.LookupCNAME(ctx, domain); err == nil {
		cname = strings.TrimSuffix(cname, ".")
		// Only add if it's actually different from the domain itself
		if !strings.EqualFold(cname, domain) {
			rec := models.DNSRecord{
				ObservedAt: now,
				DomainID:   domainID,
				RecordType: "CNAME",
				Name:       "@",
				Value:      cname,
				Source:     "crawl",
			}
			rec.Hash = hash.HashDNSRecord(&rec)
			records = append(records, rec)
		}
	}

	return records, nil
}

// ResolveSingle resolves a single record type for a domain.
func (dr *DNSResolver) ResolveSingle(ctx context.Context, domain string, recordType string) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, dr.timeout)
	defer cancel()

	switch strings.ToUpper(recordType) {
	case "A", "AAAA":
		return dr.resolver.LookupHost(ctx, domain)
	case "MX":
		mxs, err := dr.resolver.LookupMX(ctx, domain)
		if err != nil {
			return nil, err
		}
		var results []string
		for _, mx := range mxs {
			results = append(results, fmt.Sprintf("%d %s", mx.Pref, strings.TrimSuffix(mx.Host, ".")))
		}
		return results, nil
	case "NS":
		nss, err := dr.resolver.LookupNS(ctx, domain)
		if err != nil {
			return nil, err
		}
		var results []string
		for _, ns := range nss {
			results = append(results, strings.TrimSuffix(ns.Host, "."))
		}
		return results, nil
	case "TXT":
		return dr.resolver.LookupTXT(ctx, domain)
	case "CNAME":
		cname, err := dr.resolver.LookupCNAME(ctx, domain)
		if err != nil {
			return nil, err
		}
		return []string{strings.TrimSuffix(cname, ".")}, nil
	default:
		return nil, fmt.Errorf("unsupported record type: %s", recordType)
	}
}
