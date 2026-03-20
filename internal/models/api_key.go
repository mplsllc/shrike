package models

import "time"

type APIKey struct {
	ID        int64      `json:"id"`
	KeyHash   []byte     `json:"-"`
	Owner     string     `json:"owner"`
	Email     string     `json:"email"`
	Tier      string     `json:"tier"`
	CreatedAt time.Time  `json:"created_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
}

// API key tiers
const (
	TierAnonymous   = "anonymous"
	TierFree        = "free"
	TierContributor = "contributor"
)

type APIUsage struct {
	RecordedAt time.Time `json:"recorded_at"`
	APIKeyID   *int64    `json:"api_key_id,omitempty"`
	Endpoint   string    `json:"endpoint"`
	StatusCode int       `json:"status_code"`
	IPAddress  string    `json:"ip_address"`
}
