package models

import (
	"encoding/json"
	"time"
)

type Domain struct {
	ID          int64      `json:"id"`
	Name        string     `json:"name"`
	TLD         string     `json:"tld"`
	FirstSeen   time.Time  `json:"first_seen"`
	LastSeen    time.Time  `json:"last_seen"`
	LastCrawled *time.Time `json:"last_crawled,omitempty"`
}

type DomainSnapshot struct {
	ObservedAt       time.Time        `json:"observed_at"`
	DomainID         int64            `json:"domain_id"`
	Registrar        *string          `json:"registrar,omitempty"`
	RegistrantName   *string          `json:"registrant_name,omitempty"`
	RegistrantOrg    *string          `json:"registrant_org,omitempty"`
	RegistrantEmail  *string          `json:"registrant_email,omitempty"`
	RegistrantCountry *string         `json:"registrant_country,omitempty"`
	AdminContact     json.RawMessage  `json:"admin_contact,omitempty"`
	TechContact      json.RawMessage  `json:"tech_contact,omitempty"`
	NameServers      []string         `json:"name_servers,omitempty"`
	StatusCodes      []string         `json:"status_codes,omitempty"`
	CreatedDate      *time.Time       `json:"created_date,omitempty"`
	UpdatedDate      *time.Time       `json:"updated_date,omitempty"`
	ExpiryDate       *time.Time       `json:"expiry_date,omitempty"`
	DNSSEC           *bool            `json:"dnssec,omitempty"`
	RawWhois         *string          `json:"raw_whois,omitempty"`
	Extra            json.RawMessage  `json:"extra,omitempty"`
	Source           string           `json:"source"`
	ContainsPII      bool             `json:"contains_pii"`
	Hash             []byte           `json:"-"`
}

// DomainDetail combines a domain with its latest snapshot for API responses.
type DomainDetail struct {
	Domain
	CurrentSnapshot *DomainSnapshot `json:"current_snapshot,omitempty"`
	DNSSummary      []DNSRecord     `json:"dns_summary,omitempty"`
}
