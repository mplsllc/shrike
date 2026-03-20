package models

import (
	"encoding/json"
	"net/netip"
	"time"
)

type IPBlock struct {
	ID        int64        `json:"id"`
	CIDR      string       `json:"cidr"`
	Version   int          `json:"version"`
	RIR       string       `json:"rir"`
	FirstSeen time.Time    `json:"first_seen"`
	LastSeen  time.Time    `json:"last_seen"`
}

type IPSnapshot struct {
	ObservedAt    time.Time       `json:"observed_at"`
	IPBlockID     int64           `json:"ip_block_id"`
	NetName       *string         `json:"net_name,omitempty"`
	OrgName       *string         `json:"org_name,omitempty"`
	OrgID         *int64          `json:"org_id,omitempty"`
	Description   *string         `json:"description,omitempty"`
	Country       *string         `json:"country,omitempty"`
	AbuseContact  *string         `json:"abuse_contact,omitempty"`
	AllocatedDate *time.Time      `json:"allocated_date,omitempty"`
	UpdatedDate   *time.Time      `json:"updated_date,omitempty"`
	Status        *string         `json:"status,omitempty"`
	RawWhois      *string         `json:"raw_whois,omitempty"`
	Extra         json.RawMessage `json:"extra,omitempty"`
	Source        string          `json:"source"`
	ContainsPII   bool            `json:"contains_pii"`
	Hash          []byte          `json:"-"`
}

type IPDetail struct {
	IPBlock
	CurrentSnapshot *IPSnapshot `json:"current_snapshot,omitempty"`
}

// DomainIPHistory links domains to IPs from DNS resolution.
type DomainIPHistory struct {
	DomainID  int64      `json:"domain_id"`
	IPBlockID *int64     `json:"ip_block_id,omitempty"`
	IPAddress netip.Addr `json:"ip_address"`
	FirstSeen time.Time  `json:"first_seen"`
	LastSeen  time.Time  `json:"last_seen"`
}
