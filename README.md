# Shrike

Free, open WHOIS history database. A public service for internet infrastructure data.

## What is Shrike?

Shrike collects and preserves historical WHOIS, DNS, IP, and ASN data — making it freely searchable and downloadable. An alternative to DomainTools, WhoisXML API, and SecurityTrails.

**Four data pillars:**
- Domain WHOIS — registrar, registrant, dates, status snapshots over time
- IP WHOIS — IP block ownership, RIR allocation history
- ASN records — autonomous system ownership, announced prefixes
- DNS history — A, AAAA, MX, NS, CNAME, TXT, SOA records over time

## Development Setup

### Prerequisites

- Go 1.22+
- PostgreSQL 16+ with TimescaleDB extension
- Make

### Database Setup

```bash
createdb shrike
psql shrike -c "CREATE EXTENSION IF NOT EXISTS timescaledb;"
psql shrike -c "CREATE EXTENSION IF NOT EXISTS pg_trgm;"
psql shrike -c "CREATE EXTENSION IF NOT EXISTS btree_gist;"
```

### Configuration

```bash
cp .env.example .env
# Edit .env with your database URL and settings
```

### Build

```bash
make build        # Build all binaries
make server       # Build server only
make crawler      # Build crawler only
make test         # Run tests
make vet          # Run go vet
```

### Run

```bash
# Start the web server + API
./shrike-server

# Start the crawler daemon (separate process)
./shrike-crawler

# Run database migrations
make migrate DATABASE_URL=postgres://...
```

## Architecture

- **Server** (`cmd/server`) — Web UI + REST API on port 8043
- **Crawler** (`cmd/crawler`) — WHOIS/DNS crawl daemon with per-server rate limiting
- **RIR Import** (`cmd/rir-import`) — Bulk import from ARIN, RIPE, APNIC, AFRINIC, LACNIC
- **BGP Import** (`cmd/bgp-import`) — RouteViews/RIPE RIS MRT table imports
- **Zone Import** (`cmd/zone-import`) — ICANN CZDS zone file processing

## License

MPLS Principled Libre Software v1.0 — See [LICENSE.txt](LICENSE.txt) and [PHILOSOPHY.md](PHILOSOPHY.md).

Free for individuals, small organizations, nonprofits, educators, researchers, and open source projects. See the license for full terms.

Copyright © 2025 MPLS LLC, Minneapolis, Minnesota.
