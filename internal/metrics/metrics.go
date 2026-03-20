package metrics

import "github.com/prometheus/client_golang/prometheus"

var (
	// Crawler metrics
	CrawlTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "shrike_crawl_total",
			Help: "Total WHOIS crawls attempted",
		},
		[]string{"tld", "status"},
	)

	CrawlDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "shrike_crawl_duration_seconds",
			Help:    "WHOIS crawl duration per server",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"whois_server"},
	)

	RateLimitHits = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "shrike_rate_limit_hits_total",
			Help: "Rate limit events per WHOIS server",
		},
		[]string{"whois_server"},
	)

	CrawlQueueDepth = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "shrike_crawl_queue_depth",
			Help: "Crawl job queue depth",
		},
		[]string{"priority", "state"},
	)

	SnapshotsStored = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "shrike_snapshots_stored_total",
			Help: "New snapshots stored (vs deduplicated)",
		},
		[]string{"pillar"},
	)

	ChangeRate = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "shrike_change_rate",
			Help: "Percentage of crawls that found changes",
		},
		[]string{"pillar"},
	)

	// API metrics
	APIRequests = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "shrike_api_requests_total",
			Help: "Total API requests",
		},
		[]string{"endpoint", "status_code", "tier"},
	)

	APIRequestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "shrike_api_request_duration_seconds",
			Help:    "API request duration",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"endpoint"},
	)

	CacheHits = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "shrike_cache_hits_total",
			Help: "Cache hits",
		},
	)

	CacheMisses = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "shrike_cache_misses_total",
			Help: "Cache misses",
		},
	)

	// Database metrics
	DBQueryDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "shrike_db_query_duration_seconds",
			Help:    "Database query duration",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"query_type"},
	)

	DBPoolActive = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "shrike_db_pool_active_connections",
			Help: "Active database pool connections",
		},
	)
)

// Register registers all Shrike metrics with the default Prometheus registry.
func Register() {
	prometheus.MustRegister(
		// Crawler
		CrawlTotal,
		CrawlDuration,
		RateLimitHits,
		CrawlQueueDepth,
		SnapshotsStored,
		ChangeRate,
		// API
		APIRequests,
		APIRequestDuration,
		CacheHits,
		CacheMisses,
		// Database
		DBQueryDuration,
		DBPoolActive,
	)
}
