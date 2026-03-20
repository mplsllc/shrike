package crawler

import (
	"strings"
	"sync"
	"time"

	"git.mp.ls/mpls/shrike/internal/models"
)

// Parser is the interface all WHOIS response parsers implement.
// The parser registry picks the right implementation per TLD/registrar.
type Parser interface {
	// Parse takes a raw WHOIS response and returns a partially filled DomainSnapshot.
	// domainID and observedAt are set by the caller.
	Parse(rawWhois string, domainID int64, observedAt time.Time) (*models.DomainSnapshot, error)

	// Name returns the parser name for logging/metrics.
	Name() string
}

// ParserRegistry manages the selection of parsers for WHOIS responses.
// It owns the decision of which parser handles a given response.
type ParserRegistry struct {
	mu sync.RWMutex

	// Per-TLD parsers (e.g., "uk" → UK-specific parser)
	tldParsers map[string]Parser

	// Per-registrar parsers (e.g., "GoDaddy" → GoDaddy-specific parser)
	registrarParsers map[string]Parser

	// Fallback parser (likexian wrapper)
	fallbackParser Parser

	// Last resort: generic key-value extraction
	genericParser Parser
}

func NewParserRegistry(fallback Parser) *ParserRegistry {
	return &ParserRegistry{
		tldParsers:       make(map[string]Parser),
		registrarParsers: make(map[string]Parser),
		fallbackParser:   fallback,
		genericParser:    &GenericParser{},
	}
}

// RegisterTLD registers a parser for a specific TLD.
func (pr *ParserRegistry) RegisterTLD(tld string, parser Parser) {
	pr.mu.Lock()
	defer pr.mu.Unlock()
	pr.tldParsers[strings.ToLower(tld)] = parser
}

// RegisterRegistrar registers a parser for a specific registrar name.
func (pr *ParserRegistry) RegisterRegistrar(registrar string, parser Parser) {
	pr.mu.Lock()
	defer pr.mu.Unlock()
	pr.registrarParsers[strings.ToLower(registrar)] = parser
}

// Parse selects the best parser for the given response and parses it.
// Priority:
//  1. TLD-specific parser
//  2. Registrar-specific parser (if registrar detected in response)
//  3. Fallback parser (likexian wrapper)
//  4. Generic key-value parser
func (pr *ParserRegistry) Parse(rawWhois string, tld string, domainID int64, observedAt time.Time) (*models.DomainSnapshot, string, error) {
	pr.mu.RLock()
	defer pr.mu.RUnlock()

	// 1. Try TLD-specific parser
	if parser, ok := pr.tldParsers[strings.ToLower(tld)]; ok {
		snap, err := parser.Parse(rawWhois, domainID, observedAt)
		if err == nil && snap != nil {
			return snap, parser.Name(), nil
		}
	}

	// 2. Try registrar-specific parser
	registrar := detectRegistrar(rawWhois)
	if registrar != "" {
		if parser, ok := pr.registrarParsers[strings.ToLower(registrar)]; ok {
			snap, err := parser.Parse(rawWhois, domainID, observedAt)
			if err == nil && snap != nil {
				return snap, parser.Name(), nil
			}
		}
	}

	// 3. Try fallback parser (likexian)
	if pr.fallbackParser != nil {
		snap, err := pr.fallbackParser.Parse(rawWhois, domainID, observedAt)
		if err == nil && snap != nil {
			return snap, pr.fallbackParser.Name(), nil
		}
	}

	// 4. Generic key-value extraction (always succeeds)
	snap, err := pr.genericParser.Parse(rawWhois, domainID, observedAt)
	return snap, pr.genericParser.Name(), err
}

// detectRegistrar attempts to identify the registrar from a raw WHOIS response.
func detectRegistrar(raw string) string {
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "registrar:") {
			return strings.TrimSpace(line[len("registrar:"):])
		}
		if strings.HasPrefix(lower, "sponsoring registrar:") {
			return strings.TrimSpace(line[len("sponsoring registrar:"):])
		}
	}
	return ""
}

// GenericParser extracts key-value pairs from raw WHOIS text.
// This is the last-resort parser — it always produces a result.
type GenericParser struct{}

func (gp *GenericParser) Name() string { return "generic" }

func (gp *GenericParser) Parse(rawWhois string, domainID int64, observedAt time.Time) (*models.DomainSnapshot, error) {
	snap := &models.DomainSnapshot{
		ObservedAt: observedAt,
		DomainID:   domainID,
		Source:     "whois",
		RawWhois:   &rawWhois,
	}

	for _, line := range strings.Split(rawWhois, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "%") || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(strings.ToLower(parts[0]))
		value := strings.TrimSpace(parts[1])
		if value == "" {
			continue
		}

		switch key {
		case "registrar", "sponsoring registrar":
			snap.Registrar = &value
		case "registrant name", "registrant":
			snap.RegistrantName = &value
		case "registrant organization", "registrant organisation":
			snap.RegistrantOrg = &value
		case "registrant email":
			snap.RegistrantEmail = &value
		case "registrant country", "registrant country/economy":
			snap.RegistrantCountry = &value
		case "name server", "nserver":
			snap.NameServers = append(snap.NameServers, strings.ToLower(strings.Fields(value)[0]))
		case "domain status", "status":
			snap.StatusCodes = append(snap.StatusCodes, value)
		case "creation date", "created", "registered", "registration date":
			if t, err := parseFlexibleDate(value); err == nil {
				snap.CreatedDate = &t
			}
		case "updated date", "last updated", "last modified", "changed":
			if t, err := parseFlexibleDate(value); err == nil {
				snap.UpdatedDate = &t
			}
		case "expiration date", "expiry date", "expires", "registry expiry date", "paid-till":
			if t, err := parseFlexibleDate(value); err == nil {
				snap.ExpiryDate = &t
			}
		case "dnssec":
			val := strings.ToLower(value)
			signed := val == "signed" || val == "yes" || val == "signeddelegation"
			snap.DNSSEC = &signed
		}
	}

	snap.ContainsPII = detectPII(snap)

	return snap, nil
}

// parseFlexibleDate tries multiple date formats common in WHOIS responses.
func parseFlexibleDate(s string) (time.Time, error) {
	formats := []string{
		time.RFC3339,
		"2006-01-02T15:04:05Z",
		"2006-01-02T15:04:05-07:00",
		"2006-01-02 15:04:05",
		"2006-01-02",
		"02-Jan-2006",
		"02/01/2006",
		"January 02 2006",
		"20060102",
	}
	s = strings.TrimSpace(s)
	for _, f := range formats {
		if t, err := time.Parse(f, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, &time.ParseError{}
}
