package crawler

import (
	"encoding/json"
	"strings"
	"time"

	"git.mp.ls/mpls/shrike/internal/models"
)

// NormalizeRDAPResponse converts an RDAP response into a DomainSnapshot.
func NormalizeRDAPResponse(resp *RDAPResponse, domainID int64, observedAt time.Time) *models.DomainSnapshot {
	snap := &models.DomainSnapshot{
		ObservedAt: observedAt,
		DomainID:   domainID,
		Source:     "rdap",
	}

	// Status codes
	if len(resp.Status) > 0 {
		snap.StatusCodes = resp.Status
	}

	// Nameservers
	for _, ns := range resp.Nameservers {
		if ns.LDHName != "" {
			snap.NameServers = append(snap.NameServers, strings.ToLower(ns.LDHName))
		}
	}

	// DNSSEC
	if resp.SecureDNS != nil {
		dnssec := resp.SecureDNS.DelegationSigned
		snap.DNSSEC = &dnssec
	}

	// Events → dates
	for _, event := range resp.Events {
		t, err := parseRDAPDate(event.EventDate)
		if err != nil {
			continue
		}
		switch event.EventAction {
		case "registration":
			snap.CreatedDate = &t
		case "last changed", "last update of RDAP database":
			snap.UpdatedDate = &t
		case "expiration":
			snap.ExpiryDate = &t
		}
	}

	// Entities → registrar, registrant, contacts
	for _, entity := range resp.Entities {
		for _, role := range entity.Roles {
			switch role {
			case "registrar":
				name := extractEntityName(entity)
				if name != "" {
					snap.Registrar = &name
				}
			case "registrant":
				extractRegistrant(entity, snap)
			case "administrative":
				if data := entityToJSON(entity); data != nil {
					snap.AdminContact = data
				}
			case "technical":
				if data := entityToJSON(entity); data != nil {
					snap.TechContact = data
				}
			}
		}
	}

	// Store raw JSON
	if resp.RawJSON != nil {
		raw := string(resp.RawJSON)
		snap.RawWhois = &raw
	}

	// Detect PII
	snap.ContainsPII = detectPII(snap)

	return snap
}

// extractEntityName gets the name from an RDAP entity, trying handle and vcard.
func extractEntityName(entity RDAPEntity) string {
	// Try handle first (often the registrar IANA ID or name)
	if entity.Handle != "" {
		return entity.Handle
	}

	// Try vcard FN (formatted name)
	if fn := extractVCardFN(entity.VCardArray); fn != "" {
		return fn
	}

	// Try publicIds
	for _, pid := range entity.PublicIDs {
		if pid.Type == "IANA Registrar ID" {
			return pid.Identifier
		}
	}

	return ""
}

// extractRegistrant pulls registrant info from an RDAP entity into the snapshot.
func extractRegistrant(entity RDAPEntity, snap *models.DomainSnapshot) {
	fn := extractVCardFN(entity.VCardArray)
	if fn != "" {
		snap.RegistrantName = &fn
	}

	org := extractVCardOrg(entity.VCardArray)
	if org != "" {
		snap.RegistrantOrg = &org
	}

	email := extractVCardEmail(entity.VCardArray)
	if email != "" {
		snap.RegistrantEmail = &email
	}

	country := extractVCardCountry(entity.VCardArray)
	if country != "" {
		snap.RegistrantCountry = &country
	}
}

// extractVCardFN extracts the FN (formatted name) from a jCard vCardArray.
// vCardArray format: ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "John Doe"], ...]]
func extractVCardFN(vcard interface{}) string {
	return extractVCardField(vcard, "fn")
}

func extractVCardOrg(vcard interface{}) string {
	return extractVCardField(vcard, "org")
}

func extractVCardEmail(vcard interface{}) string {
	return extractVCardField(vcard, "email")
}

func extractVCardCountry(vcard interface{}) string {
	// Country is nested inside "adr" which is more complex
	arr, ok := vcard.([]interface{})
	if !ok || len(arr) < 2 {
		return ""
	}
	properties, ok := arr[1].([]interface{})
	if !ok {
		return ""
	}
	for _, prop := range properties {
		propArr, ok := prop.([]interface{})
		if !ok || len(propArr) < 4 {
			continue
		}
		name, ok := propArr[0].(string)
		if !ok || name != "adr" {
			continue
		}
		// adr value can be an array where index 6 is country
		if valArr, ok := propArr[3].([]interface{}); ok && len(valArr) >= 7 {
			if country, ok := valArr[6].(string); ok {
				return country
			}
		}
	}
	return ""
}

// extractVCardField extracts a text field from a jCard vCardArray.
func extractVCardField(vcard interface{}, fieldName string) string {
	arr, ok := vcard.([]interface{})
	if !ok || len(arr) < 2 {
		return ""
	}
	properties, ok := arr[1].([]interface{})
	if !ok {
		return ""
	}
	for _, prop := range properties {
		propArr, ok := prop.([]interface{})
		if !ok || len(propArr) < 4 {
			continue
		}
		name, ok := propArr[0].(string)
		if !ok || name != fieldName {
			continue
		}
		// Value is at index 3
		if val, ok := propArr[3].(string); ok {
			return val
		}
	}
	return ""
}

func entityToJSON(entity RDAPEntity) json.RawMessage {
	data, err := json.Marshal(entity)
	if err != nil {
		return nil
	}
	return data
}

func parseRDAPDate(s string) (time.Time, error) {
	// RDAP dates are RFC 3339
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		// Some servers use date-only format
		t, err = time.Parse("2006-01-02", s)
	}
	return t, err
}

// detectPII checks if a domain snapshot likely contains personal information.
func detectPII(snap *models.DomainSnapshot) bool {
	// If registrant fields are populated and not obviously redacted, flag as PII
	if snap.RegistrantName != nil && !isRedacted(*snap.RegistrantName) {
		return true
	}
	if snap.RegistrantEmail != nil && !isRedacted(*snap.RegistrantEmail) {
		return true
	}
	return false
}

func isRedacted(s string) bool {
	lower := strings.ToLower(s)
	redactedPatterns := []string{
		"redacted",
		"not disclosed",
		"privacy",
		"proxy",
		"data protected",
		"withheld",
		"gdpr masked",
		"statutory masking",
	}
	for _, p := range redactedPatterns {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return s == "" || s == "N/A" || s == "n/a"
}
