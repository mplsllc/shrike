-- Shrike: Cross-reference tables

-- Domain → IP mapping (derived from DNS A/AAAA records)
CREATE TABLE IF NOT EXISTS domain_ip_history (
    domain_id   BIGINT NOT NULL REFERENCES domains(id),
    ip_block_id BIGINT REFERENCES ip_blocks(id),
    ip_address  INET NOT NULL,
    first_seen  TIMESTAMPTZ NOT NULL,
    last_seen   TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (domain_id, ip_address, first_seen)
);

CREATE INDEX IF NOT EXISTS idx_dih_ip ON domain_ip_history (ip_address);
CREATE INDEX IF NOT EXISTS idx_dih_block ON domain_ip_history (ip_block_id) WHERE ip_block_id IS NOT NULL;

-- IP → ASN mapping (derived from BGP data)
CREATE TABLE IF NOT EXISTS ip_asn_history (
    ip_block_id BIGINT NOT NULL REFERENCES ip_blocks(id),
    asn_id      BIGINT NOT NULL REFERENCES asns(id),
    first_seen  TIMESTAMPTZ NOT NULL,
    last_seen   TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (ip_block_id, asn_id, first_seen)
);

CREATE INDEX IF NOT EXISTS idx_iah_asn ON ip_asn_history (asn_id);
