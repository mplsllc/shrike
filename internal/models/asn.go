package models

import (
	"encoding/json"
	"time"
)

type ASN struct {
	ID        int64     `json:"id"`
	Number    int       `json:"number"`
	RIR       string    `json:"rir"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

type ASNSnapshot struct {
	ObservedAt    time.Time       `json:"observed_at"`
	ASNID         int64           `json:"asn_id"`
	Name          *string         `json:"name,omitempty"`
	OrgName       *string         `json:"org_name,omitempty"`
	OrgID         *int64          `json:"org_id,omitempty"`
	Description   *string         `json:"description,omitempty"`
	Country       *string         `json:"country,omitempty"`
	AllocatedDate *time.Time      `json:"allocated_date,omitempty"`
	RawWhois      *string         `json:"raw_whois,omitempty"`
	Extra         json.RawMessage `json:"extra,omitempty"`
	Source        string          `json:"source"`
	ContainsPII   bool            `json:"contains_pii"`
	Hash          []byte          `json:"-"`
}

type ASNPrefix struct {
	ObservedAt time.Time `json:"observed_at"`
	ASNID      int64     `json:"asn_id"`
	Prefix     string    `json:"prefix"`
	ASPath     []int     `json:"as_path,omitempty"`
	Source     string    `json:"source"`
	Hash       []byte    `json:"-"`
}

type ASNDetail struct {
	ASN
	CurrentSnapshot *ASNSnapshot `json:"current_snapshot,omitempty"`
	Prefixes        []ASNPrefix  `json:"prefixes,omitempty"`
}

// IPASNHistory links IP blocks to their announcing ASNs.
type IPASNHistory struct {
	IPBlockID int64     `json:"ip_block_id"`
	ASNID     int64     `json:"asn_id"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}
