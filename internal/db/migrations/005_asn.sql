-- Shrike: ASN Records (Pillar 3)

CREATE TABLE IF NOT EXISTS asns (
    id         BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    number     INTEGER NOT NULL UNIQUE,
    rir        TEXT NOT NULL,
    first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS asn_snapshots (
    observed_at    TIMESTAMPTZ NOT NULL,
    asn_id         BIGINT NOT NULL REFERENCES asns(id),
    name           TEXT,
    org_name       TEXT,
    org_id         BIGINT REFERENCES organizations(id),
    description    TEXT,
    country        TEXT,
    allocated_date DATE,
    raw_whois      TEXT,
    extra          JSONB,
    source         TEXT NOT NULL DEFAULT 'rir_bulk',
    contains_pii   BOOLEAN NOT NULL DEFAULT FALSE,
    hash           BYTEA NOT NULL
);

SELECT create_hypertable('asn_snapshots', 'observed_at', if_not_exists => TRUE);

CREATE INDEX IF NOT EXISTS idx_asns_asn_time ON asn_snapshots (asn_id, observed_at DESC);

CREATE TABLE IF NOT EXISTS asn_prefixes (
    observed_at TIMESTAMPTZ NOT NULL,
    asn_id      BIGINT NOT NULL REFERENCES asns(id),
    prefix      CIDR NOT NULL,
    as_path     INTEGER[],
    source      TEXT NOT NULL DEFAULT 'routeviews',
    hash        BYTEA NOT NULL
);

SELECT create_hypertable('asn_prefixes', 'observed_at', if_not_exists => TRUE);

CREATE INDEX IF NOT EXISTS idx_asnp_asn_time ON asn_prefixes (asn_id, observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_asnp_prefix ON asn_prefixes USING gist (prefix inet_ops);
