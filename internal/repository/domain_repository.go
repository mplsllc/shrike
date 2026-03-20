package repository

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"git.mp.ls/mpls/shrike/internal/models"
	"git.mp.ls/mpls/shrike/internal/hash"
)

type DomainRepository struct {
	pool *pgxpool.Pool
}

func NewDomainRepository(pool *pgxpool.Pool) *DomainRepository {
	return &DomainRepository{pool: pool}
}

// GetByName returns a domain by its name, or nil if not found.
func (r *DomainRepository) GetByName(ctx context.Context, name string) (*models.Domain, error) {
	var d models.Domain
	err := r.pool.QueryRow(ctx,
		`SELECT id, name, tld, first_seen, last_seen, last_crawled
		 FROM domains WHERE name = $1`, name).
		Scan(&d.ID, &d.Name, &d.TLD, &d.FirstSeen, &d.LastSeen, &d.LastCrawled)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("querying domain %s: %w", name, err)
	}
	return &d, nil
}

// Upsert creates or updates a domain, returning its ID.
func (r *DomainRepository) Upsert(ctx context.Context, name, tld string) (int64, error) {
	var id int64
	err := r.pool.QueryRow(ctx,
		`INSERT INTO domains (name, tld)
		 VALUES ($1, $2)
		 ON CONFLICT (name) DO UPDATE SET
			last_seen = NOW()
		 RETURNING id`, name, tld).
		Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("upserting domain %s: %w", name, err)
	}
	return id, nil
}

// InsertSnapshotIfChanged inserts a domain snapshot only if the hash differs from the latest.
// Returns true if a new snapshot was inserted.
func (r *DomainRepository) InsertSnapshotIfChanged(ctx context.Context, snap *models.DomainSnapshot) (bool, error) {
	// Compute hash
	snap.Hash = hash.HashDomainSnapshot(snap)

	// Check if latest snapshot has the same hash
	var existingHash []byte
	err := r.pool.QueryRow(ctx,
		`SELECT hash FROM domain_snapshots
		 WHERE domain_id = $1
		 ORDER BY observed_at DESC LIMIT 1`, snap.DomainID).
		Scan(&existingHash)
	if err != nil && err != pgx.ErrNoRows {
		return false, fmt.Errorf("checking existing hash: %w", err)
	}

	if existingHash != nil && bytes.Equal(existingHash, snap.Hash) {
		// No change — skip insertion
		return false, nil
	}

	// Insert new snapshot
	_, err = r.pool.Exec(ctx,
		`INSERT INTO domain_snapshots (
			observed_at, domain_id, registrar,
			registrant_name, registrant_org, registrant_email, registrant_country,
			admin_contact, tech_contact,
			name_servers, status_codes,
			created_date, updated_date, expiry_date,
			dnssec, raw_whois, extra,
			source, contains_pii, hash
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)`,
		snap.ObservedAt, snap.DomainID, snap.Registrar,
		snap.RegistrantName, snap.RegistrantOrg, snap.RegistrantEmail, snap.RegistrantCountry,
		snap.AdminContact, snap.TechContact,
		snap.NameServers, snap.StatusCodes,
		snap.CreatedDate, snap.UpdatedDate, snap.ExpiryDate,
		snap.DNSSEC, snap.RawWhois, snap.Extra,
		snap.Source, snap.ContainsPII, snap.Hash,
	)
	if err != nil {
		return false, fmt.Errorf("inserting snapshot: %w", err)
	}

	// Update last_crawled on the domain
	_, err = r.pool.Exec(ctx,
		`UPDATE domains SET last_crawled = $1, last_seen = $1 WHERE id = $2`,
		snap.ObservedAt, snap.DomainID)
	if err != nil {
		return true, fmt.Errorf("updating last_crawled: %w", err)
	}

	return true, nil
}

// GetLatestSnapshot returns the most recent snapshot for a domain.
func (r *DomainRepository) GetLatestSnapshot(ctx context.Context, domainID int64) (*models.DomainSnapshot, error) {
	var snap models.DomainSnapshot
	err := r.pool.QueryRow(ctx,
		`SELECT observed_at, domain_id, registrar,
			registrant_name, registrant_org, registrant_email, registrant_country,
			admin_contact, tech_contact,
			name_servers, status_codes,
			created_date, updated_date, expiry_date,
			dnssec, raw_whois, extra,
			source, contains_pii, hash
		 FROM domain_snapshots
		 WHERE domain_id = $1
		 ORDER BY observed_at DESC LIMIT 1`, domainID).
		Scan(
			&snap.ObservedAt, &snap.DomainID, &snap.Registrar,
			&snap.RegistrantName, &snap.RegistrantOrg, &snap.RegistrantEmail, &snap.RegistrantCountry,
			&snap.AdminContact, &snap.TechContact,
			&snap.NameServers, &snap.StatusCodes,
			&snap.CreatedDate, &snap.UpdatedDate, &snap.ExpiryDate,
			&snap.DNSSEC, &snap.RawWhois, &snap.Extra,
			&snap.Source, &snap.ContainsPII, &snap.Hash,
		)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("getting latest snapshot for domain %d: %w", domainID, err)
	}
	return &snap, nil
}

// GetHistory returns snapshots for a domain within a time range.
func (r *DomainRepository) GetHistory(ctx context.Context, domainID int64, timeRange models.TimeRange, page models.Pagination) (*models.PaginatedResult[models.DomainSnapshot], error) {
	if page.Limit <= 0 {
		page.Limit = 50
	}

	// Count total
	countQuery := `SELECT COUNT(*) FROM domain_snapshots WHERE domain_id = $1`
	args := []interface{}{domainID}
	argIdx := 2

	if timeRange.From != nil {
		countQuery += fmt.Sprintf(" AND observed_at >= $%d", argIdx)
		args = append(args, *timeRange.From)
		argIdx++
	}
	if timeRange.To != nil {
		countQuery += fmt.Sprintf(" AND observed_at <= $%d", argIdx)
		args = append(args, *timeRange.To)
		argIdx++
	}

	var total int
	if err := r.pool.QueryRow(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, fmt.Errorf("counting snapshots: %w", err)
	}

	// Fetch page
	dataQuery := `SELECT observed_at, domain_id, registrar,
		registrant_name, registrant_org, registrant_email, registrant_country,
		admin_contact, tech_contact,
		name_servers, status_codes,
		created_date, updated_date, expiry_date,
		dnssec, extra,
		source, contains_pii
	FROM domain_snapshots WHERE domain_id = $1`

	dataArgs := []interface{}{domainID}
	dataIdx := 2

	if timeRange.From != nil {
		dataQuery += fmt.Sprintf(" AND observed_at >= $%d", dataIdx)
		dataArgs = append(dataArgs, *timeRange.From)
		dataIdx++
	}
	if timeRange.To != nil {
		dataQuery += fmt.Sprintf(" AND observed_at <= $%d", dataIdx)
		dataArgs = append(dataArgs, *timeRange.To)
		dataIdx++
	}

	dataQuery += fmt.Sprintf(" ORDER BY observed_at DESC LIMIT $%d OFFSET $%d", dataIdx, dataIdx+1)
	dataArgs = append(dataArgs, page.Limit, page.Offset)

	rows, err := r.pool.Query(ctx, dataQuery, dataArgs...)
	if err != nil {
		return nil, fmt.Errorf("querying history: %w", err)
	}
	defer rows.Close()

	var snapshots []models.DomainSnapshot
	for rows.Next() {
		var snap models.DomainSnapshot
		if err := rows.Scan(
			&snap.ObservedAt, &snap.DomainID, &snap.Registrar,
			&snap.RegistrantName, &snap.RegistrantOrg, &snap.RegistrantEmail, &snap.RegistrantCountry,
			&snap.AdminContact, &snap.TechContact,
			&snap.NameServers, &snap.StatusCodes,
			&snap.CreatedDate, &snap.UpdatedDate, &snap.ExpiryDate,
			&snap.DNSSEC, &snap.Extra,
			&snap.Source, &snap.ContainsPII,
		); err != nil {
			return nil, fmt.Errorf("scanning snapshot: %w", err)
		}
		snapshots = append(snapshots, snap)
	}

	return &models.PaginatedResult[models.DomainSnapshot]{
		Data:    snapshots,
		Total:   total,
		Limit:   page.Limit,
		Offset:  page.Offset,
		HasMore: page.Offset+page.Limit < total,
	}, nil
}

// MarkCrawled updates the last_crawled timestamp.
func (r *DomainRepository) MarkCrawled(ctx context.Context, domainID int64, t time.Time) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE domains SET last_crawled = $1, last_seen = $1 WHERE id = $2`, t, domainID)
	return err
}
