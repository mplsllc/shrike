package models

import (
	"encoding/json"
	"time"
)

type DNSRecord struct {
	ObservedAt time.Time       `json:"observed_at"`
	DomainID   int64           `json:"domain_id"`
	RecordType string          `json:"record_type"`
	Name       string          `json:"name"`
	Value      string          `json:"value"`
	TTL        *int            `json:"ttl,omitempty"`
	Priority   *int            `json:"priority,omitempty"`
	Extra      json.RawMessage `json:"extra,omitempty"`
	Source     string          `json:"source"`
	Hash       []byte          `json:"-"`
}
