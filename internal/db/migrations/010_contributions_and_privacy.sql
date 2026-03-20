-- Shrike: Community contributions and privacy/redaction

CREATE TABLE IF NOT EXISTS contributions (
    id           BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    contributor  TEXT,
    api_key_id   BIGINT REFERENCES api_keys(id),
    data_type    TEXT NOT NULL,
    record_count INTEGER NOT NULL DEFAULT 0,
    status       TEXT NOT NULL DEFAULT 'pending',
    imported_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    notes        TEXT
);

CREATE INDEX IF NOT EXISTS idx_contrib_status ON contributions (status);

CREATE TABLE IF NOT EXISTS contribution_records (
    id                BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    contribution_id   BIGINT NOT NULL REFERENCES contributions(id),
    data_type         TEXT NOT NULL,
    target            TEXT NOT NULL,
    record_data       JSONB NOT NULL,
    validation_status TEXT NOT NULL DEFAULT 'pending',
    confidence_score  REAL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_cr_contrib ON contribution_records (contribution_id);
CREATE INDEX IF NOT EXISTS idx_cr_status ON contribution_records (validation_status);

-- Redaction requests for PII removal
CREATE TABLE IF NOT EXISTS redaction_requests (
    id             BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    requester_email TEXT NOT NULL,
    domain_name    TEXT,
    description    TEXT NOT NULL,
    status         TEXT NOT NULL DEFAULT 'pending',
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at   TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_rr_status ON redaction_requests (status);
