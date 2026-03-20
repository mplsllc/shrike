package models

import (
	"encoding/json"
	"time"
)

type Contribution struct {
	ID           int64     `json:"id"`
	Contributor  *string   `json:"contributor,omitempty"`
	APIKeyID     *int64    `json:"api_key_id,omitempty"`
	DataType     string    `json:"data_type"`
	RecordCount  int       `json:"record_count"`
	Status       string    `json:"status"`
	ImportedAt   time.Time `json:"imported_at"`
	Notes        *string   `json:"notes,omitempty"`
}

// Contribution statuses
const (
	ContribStatusPending   = "pending"
	ContribStatusReviewing = "reviewing"
	ContribStatusAccepted  = "accepted"
	ContribStatusRejected  = "rejected"
)

type ContributionRecord struct {
	ID               int64           `json:"id"`
	ContributionID   int64           `json:"contribution_id"`
	DataType         string          `json:"data_type"`
	Target           string          `json:"target"`
	RecordData       json.RawMessage `json:"record_data"`
	ValidationStatus string          `json:"validation_status"`
	ConfidenceScore  *float32        `json:"confidence_score,omitempty"`
	CreatedAt        time.Time       `json:"created_at"`
}

type RedactionRequest struct {
	ID             int64      `json:"id"`
	RequesterEmail string     `json:"requester_email"`
	DomainName     *string    `json:"domain_name,omitempty"`
	Description    string     `json:"description"`
	Status         string     `json:"status"`
	CreatedAt      time.Time  `json:"created_at"`
	CompletedAt    *time.Time `json:"completed_at,omitempty"`
}
