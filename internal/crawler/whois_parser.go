package crawler

import (
	"fmt"
	"strings"
	"time"

	whoisparser "github.com/likexian/whois-parser"

	"git.mp.ls/mpls/shrike/internal/models"
)

// LikexianParser wraps the likexian/whois-parser library behind the Parser interface.
// This is a bridge dependency — the parser registry will gradually replace it
// with custom per-TLD templates as they mature.
type LikexianParser struct{}

func NewLikexianParser() *LikexianParser {
	return &LikexianParser{}
}

func (lp *LikexianParser) Name() string { return "likexian" }

func (lp *LikexianParser) Parse(rawWhois string, domainID int64, observedAt time.Time) (snap *models.DomainSnapshot, err error) {
	// Recover from panics in the third-party parser — WHOIS responses are unpredictable
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("likexian parser panic: %v", r)
			snap = nil
		}
	}()

	result, err := whoisparser.Parse(rawWhois)
	if err != nil {
		return nil, err
	}

	snap = &models.DomainSnapshot{
		ObservedAt: observedAt,
		DomainID:   domainID,
		Source:     "whois",
		RawWhois:   &rawWhois,
	}

	// Registrar — safely access fields
	if result.Registrar.Name != "" {
		snap.Registrar = &result.Registrar.Name
	}

	// Registrant
	if result.Registrant.Name != "" {
		snap.RegistrantName = &result.Registrant.Name
	}
	if result.Registrant.Organization != "" {
		snap.RegistrantOrg = &result.Registrant.Organization
	}
	if result.Registrant.Email != "" {
		snap.RegistrantEmail = &result.Registrant.Email
	}
	if result.Registrant.Country != "" {
		snap.RegistrantCountry = &result.Registrant.Country
	}

	// Nameservers
	if len(result.Domain.NameServers) > 0 {
		ns := make([]string, len(result.Domain.NameServers))
		for i, n := range result.Domain.NameServers {
			ns[i] = strings.ToLower(n)
		}
		snap.NameServers = ns
	}

	// Status codes
	if len(result.Domain.Status) > 0 {
		snap.StatusCodes = result.Domain.Status
	}

	// Dates
	if result.Domain.CreatedDate != "" {
		if t, err := parseFlexibleDate(result.Domain.CreatedDate); err == nil {
			snap.CreatedDate = &t
		}
	}
	if result.Domain.UpdatedDate != "" {
		if t, err := parseFlexibleDate(result.Domain.UpdatedDate); err == nil {
			snap.UpdatedDate = &t
		}
	}
	if result.Domain.ExpirationDate != "" {
		if t, err := parseFlexibleDate(result.Domain.ExpirationDate); err == nil {
			snap.ExpiryDate = &t
		}
	}

	// DNSSEC
	if result.Domain.DNSSec {
		dnssec := true
		snap.DNSSEC = &dnssec
	}

	// PII detection
	snap.ContainsPII = detectPII(snap)

	return snap, nil
}
