-- Shrike: Organizations (cross-reference entity)
CREATE TABLE IF NOT EXISTS organizations (
    id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name            TEXT NOT NULL,
    name_normalized TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_org_name_trgm ON organizations USING gin (name_normalized gin_trgm_ops);
CREATE UNIQUE INDEX IF NOT EXISTS idx_org_name_normalized ON organizations (name_normalized);
