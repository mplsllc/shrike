#!/bin/bash
# Shrike Bootstrap — Seed crawl_jobs with Tranco top domains
# Usage: ./scripts/bootstrap.sh [count]
# Default: loads top 10000 domains.

set -e

COUNT=${1:-10000}
DB_URL="${DATABASE_URL:-postgres://shrike:shrike@localhost:5432/shrike?sslmode=disable}"
TRANCO_URL="https://tranco-list.eu/top-1m.csv.zip"
TMPDIR=$(mktemp -d)

echo "Shrike Bootstrap: Loading top $COUNT domains from Tranco list"

# Download Tranco top 1M
echo "Downloading Tranco list..."
curl -sL "$TRANCO_URL" -o "$TMPDIR/tranco.zip"
unzip -q "$TMPDIR/tranco.zip" -d "$TMPDIR"

TRANCO_FILE="$TMPDIR/top-1m.csv"
if [ ! -f "$TRANCO_FILE" ]; then
    echo "Error: Could not find top-1m.csv in download"
    rm -rf "$TMPDIR"
    exit 1
fi

# Build SQL insert file
echo "Building insert statements for $COUNT domains..."
SQL_FILE="$TMPDIR/insert.sql"
echo "BEGIN;" > "$SQL_FILE"

head -n "$COUNT" "$TRANCO_FILE" | while IFS=, read -r rank domain; do
    # Escape single quotes in domain names (shouldn't happen but be safe)
    domain=$(echo "$domain" | tr -d "'")
    cat >> "$SQL_FILE" << EOSQL
INSERT INTO crawl_jobs (job_type, target, priority, state, next_run_at)
VALUES ('domain_whois', '${domain}', 5, 'pending', NOW())
ON CONFLICT DO NOTHING;
INSERT INTO crawl_jobs (job_type, target, priority, state, next_run_at)
VALUES ('dns', '${domain}', 5, 'pending', NOW())
ON CONFLICT DO NOTHING;
EOSQL
done

echo "COMMIT;" >> "$SQL_FILE"

echo "Inserting into database..."
psql "$DB_URL" -q -f "$SQL_FILE" 2>&1

# Report
TOTAL=$(psql "$DB_URL" -t -c "SELECT COUNT(*) FROM crawl_jobs WHERE state = 'pending';")
echo "Done. $TOTAL pending jobs in queue."

# Cleanup
rm -rf "$TMPDIR"
echo "Crawler workers will start processing these automatically."
