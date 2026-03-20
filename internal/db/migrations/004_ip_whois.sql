-- Shrike: IP WHOIS (Pillar 2)

CREATE TABLE IF NOT EXISTS ip_blocks (
    id         BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    cidr       CIDR NOT NULL UNIQUE,
    version    SMALLINT NOT NULL,
    rir        TEXT NOT NULL,
    first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ip_blocks_cidr ON ip_blocks USING gist (cidr inet_ops);

CREATE TABLE IF NOT EXISTS ip_snapshots (
    observed_at    TIMESTAMPTZ NOT NULL,
    ip_block_id    BIGINT NOT NULL REFERENCES ip_blocks(id),
    net_name       TEXT,
    org_name       TEXT,
    org_id         BIGINT REFERENCES organizations(id),
    description    TEXT,
    country        TEXT,
    abuse_contact  TEXT,
    allocated_date DATE,
    updated_date   DATE,
    status         TEXT,
    raw_whois      TEXT,
    extra          JSONB,
    source         TEXT NOT NULL DEFAULT 'rir_bulk',
    contains_pii   BOOLEAN NOT NULL DEFAULT FALSE,
    hash           BYTEA NOT NULL
);

SELECT create_hypertable('ip_snapshots', 'observed_at', if_not_exists => TRUE);

CREATE INDEX IF NOT EXISTS idx_ips_block_time ON ip_snapshots (ip_block_id, observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_ips_org ON ip_snapshots (org_id) WHERE org_id IS NOT NULL;
