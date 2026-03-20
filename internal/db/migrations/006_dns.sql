-- Shrike: DNS History (Pillar 4)

CREATE TABLE IF NOT EXISTS dns_records (
    observed_at TIMESTAMPTZ NOT NULL,
    domain_id   BIGINT NOT NULL REFERENCES domains(id),
    record_type TEXT NOT NULL,
    name        TEXT NOT NULL,
    value       TEXT NOT NULL,
    ttl         INTEGER,
    priority    INTEGER,
    extra       JSONB,
    source      TEXT NOT NULL DEFAULT 'crawl',
    hash        BYTEA NOT NULL
);

SELECT create_hypertable('dns_records', 'observed_at', if_not_exists => TRUE);

CREATE INDEX IF NOT EXISTS idx_dns_domain_time ON dns_records (domain_id, observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_dns_type ON dns_records (record_type, domain_id, observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_dns_value ON dns_records (value);
