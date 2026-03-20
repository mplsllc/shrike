-- Shrike: Crawl infrastructure

CREATE TABLE IF NOT EXISTS crawl_jobs (
    id           BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    job_type     TEXT NOT NULL,
    target       TEXT NOT NULL,
    target_id    BIGINT,
    priority     SMALLINT NOT NULL DEFAULT 5,
    state        TEXT NOT NULL DEFAULT 'pending',
    whois_server TEXT,
    next_run_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_run_at  TIMESTAMPTZ,
    error_count  SMALLINT NOT NULL DEFAULT 0,
    last_error   TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_cj_next_run ON crawl_jobs (state, next_run_at) WHERE state = 'pending';
CREATE INDEX IF NOT EXISTS idx_cj_server ON crawl_jobs (whois_server);
CREATE INDEX IF NOT EXISTS idx_cj_target ON crawl_jobs (job_type, target);

CREATE TABLE IF NOT EXISTS whois_rate_limits (
    server        TEXT PRIMARY KEY,
    max_qps       REAL NOT NULL DEFAULT 1.0,
    burst         INTEGER NOT NULL DEFAULT 3,
    last_query    TIMESTAMPTZ,
    backoff_until TIMESTAMPTZ
);
