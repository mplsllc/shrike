-- Shrike: API access and usage tracking

CREATE TABLE IF NOT EXISTS api_keys (
    id         BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    key_hash   BYTEA NOT NULL UNIQUE,
    owner      TEXT NOT NULL,
    email      TEXT NOT NULL,
    tier       TEXT NOT NULL DEFAULT 'free',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_ak_email ON api_keys (email);
CREATE INDEX IF NOT EXISTS idx_ak_tier ON api_keys (tier);

CREATE TABLE IF NOT EXISTS api_usage (
    recorded_at TIMESTAMPTZ NOT NULL,
    api_key_id  BIGINT REFERENCES api_keys(id),
    endpoint    TEXT NOT NULL,
    status_code SMALLINT NOT NULL,
    ip_address  INET NOT NULL
);

SELECT create_hypertable('api_usage', 'recorded_at', if_not_exists => TRUE);

CREATE INDEX IF NOT EXISTS idx_au_key_time ON api_usage (api_key_id, recorded_at DESC);
