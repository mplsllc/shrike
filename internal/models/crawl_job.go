package models

import "time"

type CrawlJob struct {
	ID          int64      `json:"id"`
	JobType     string     `json:"job_type"`
	Target      string     `json:"target"`
	TargetID    *int64     `json:"target_id,omitempty"`
	Priority    int        `json:"priority"`
	State       string     `json:"state"`
	WhoisServer *string    `json:"whois_server,omitempty"`
	NextRunAt   time.Time  `json:"next_run_at"`
	LastRunAt   *time.Time `json:"last_run_at,omitempty"`
	ErrorCount  int        `json:"error_count"`
	LastError   *string    `json:"last_error,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
}

// Job types
const (
	JobTypeDomainWhois = "domain_whois"
	JobTypeDNS         = "dns"
	JobTypeIPWhois     = "ip_whois"
	JobTypeASN         = "asn"
)

// Job states
const (
	JobStatePending  = "pending"
	JobStateRunning  = "running"
	JobStateDone     = "done"
	JobStateFailed   = "failed"
	JobStateDeferred = "deferred"
)

// Crawl priorities
const (
	PriorityRealtime      = 1
	PriorityNewDomain     = 2
	PriorityNearExpiry    = 3
	PriorityStale         = 4
	PriorityRegularCrawl  = 5
	PriorityLowValue      = 8
	PriorityBulkBackfill  = 10
)

type WhoisRateLimit struct {
	Server       string     `json:"server"`
	MaxQPS       float32    `json:"max_qps"`
	Burst        int        `json:"burst"`
	LastQuery    *time.Time `json:"last_query,omitempty"`
	BackoffUntil *time.Time `json:"backoff_until,omitempty"`
}
