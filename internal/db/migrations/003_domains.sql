-- Shrike: Domain WHOIS (Pillar 1)

CREATE TABLE IF NOT EXISTS domains (
    id           BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name         TEXT NOT NULL UNIQUE,
    tld          TEXT NOT NULL,
    first_seen   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_crawled TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_domains_name ON domains (name);
CREATE INDEX IF NOT EXISTS idx_domains_tld ON domains (tld);
CREATE INDEX IF NOT EXISTS idx_domains_name_trgm ON domains USING gin (name gin_trgm_ops);

CREATE TABLE IF NOT EXISTS domain_snapshots (
    observed_at        TIMESTAMPTZ NOT NULL,
    domain_id          BIGINT NOT NULL REFERENCES domains(id),
    registrar          TEXT,
    registrant_name    TEXT,
    registrant_org     TEXT,
    registrant_email   TEXT,
    registrant_country TEXT,
    admin_contact      JSONB,
    tech_contact       JSONB,
    name_servers       TEXT[],
    status_codes       TEXT[],
    created_date       TIMESTAMPTZ,
    updated_date       TIMESTAMPTZ,
    expiry_date        TIMESTAMPTZ,
    dnssec             BOOLEAN,
    raw_whois          TEXT,
    extra              JSONB,
    source             TEXT NOT NULL DEFAULT 'crawl',
    contains_pii       BOOLEAN NOT NULL DEFAULT FALSE,
    hash               BYTEA NOT NULL
);

SELECT create_hypertable('domain_snapshots', 'observed_at', if_not_exists => TRUE);

CREATE INDEX IF NOT EXISTS idx_ds_domain_time ON domain_snapshots (domain_id, observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_ds_registrant_org ON domain_snapshots (registrant_org) WHERE registrant_org IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_ds_registrar ON domain_snapshots (registrar) WHERE registrar IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_ds_hash ON domain_snapshots (domain_id, hash);
