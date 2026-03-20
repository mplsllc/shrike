package repository

import (
	"bytes"
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"git.mp.ls/mpls/shrike/internal/hash"
	"git.mp.ls/mpls/shrike/internal/models"
)

type ASNRepository struct {
	pool *pgxpool.Pool
}

func NewASNRepository(pool *pgxpool.Pool) *ASNRepository {
	return &ASNRepository{pool: pool}
}

// GetByNumber returns an ASN by its number.
func (r *ASNRepository) GetByNumber(ctx context.Context, number int) (*models.ASN, error) {
	var a models.ASN
	err := r.pool.QueryRow(ctx,
		`SELECT id, number, rir, first_seen, last_seen
		 FROM asns WHERE number = $1`, number).
		Scan(&a.ID, &a.Number, &a.RIR, &a.FirstSeen, &a.LastSeen)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("querying ASN %d: %w", number, err)
	}
	return &a, nil
}

// Upsert creates or updates an ASN, returning its ID.
func (r *ASNRepository) Upsert(ctx context.Context, number int, rir string) (int64, error) {
	var id int64
	err := r.pool.QueryRow(ctx,
		`INSERT INTO asns (number, rir)
		 VALUES ($1, $2)
		 ON CONFLICT (number) DO UPDATE SET last_seen = NOW()
		 RETURNING id`, number, rir).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("upserting ASN %d: %w", number, err)
	}
	return id, nil
}

// InsertSnapshotIfChanged inserts an ASN snapshot only if the hash differs.
func (r *ASNRepository) InsertSnapshotIfChanged(ctx context.Context, snap *models.ASNSnapshot) (bool, error) {
	snap.Hash = hash.HashASNSnapshot(snap)

	var existingHash []byte
	err := r.pool.QueryRow(ctx,
		`SELECT hash FROM asn_snapshots
		 WHERE asn_id = $1
		 ORDER BY observed_at DESC LIMIT 1`, snap.ASNID).Scan(&existingHash)
	if err != nil && err != pgx.ErrNoRows {
		return false, err
	}
	if existingHash != nil && bytes.Equal(existingHash, snap.Hash) {
		return false, nil
	}

	_, err = r.pool.Exec(ctx,
		`INSERT INTO asn_snapshots (
			observed_at, asn_id, name, org_name, org_id,
			description, country, allocated_date,
			raw_whois, extra, source, contains_pii, hash
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
		snap.ObservedAt, snap.ASNID, snap.Name, snap.OrgName, snap.OrgID,
		snap.Description, snap.Country, snap.AllocatedDate,
		snap.RawWhois, snap.Extra, snap.Source, snap.ContainsPII, snap.Hash,
	)
	if err != nil {
		return false, fmt.Errorf("inserting ASN snapshot: %w", err)
	}
	return true, nil
}

// InsertPrefixIfChanged inserts an ASN prefix announcement only if hash differs.
func (r *ASNRepository) InsertPrefixIfChanged(ctx context.Context, prefix *models.ASNPrefix) (bool, error) {
	prefix.Hash = hash.HashASNPrefix(prefix)

	var existingHash []byte
	err := r.pool.QueryRow(ctx,
		`SELECT hash FROM asn_prefixes
		 WHERE asn_id = $1 AND prefix = $2::cidr
		 ORDER BY observed_at DESC LIMIT 1`, prefix.ASNID, prefix.Prefix).Scan(&existingHash)
	if err != nil && err != pgx.ErrNoRows {
		return false, err
	}
	if existingHash != nil && bytes.Equal(existingHash, prefix.Hash) {
		return false, nil
	}

	_, err = r.pool.Exec(ctx,
		`INSERT INTO asn_prefixes (observed_at, asn_id, prefix, as_path, source, hash)
		 VALUES ($1, $2, $3::cidr, $4, $5, $6)`,
		prefix.ObservedAt, prefix.ASNID, prefix.Prefix, prefix.ASPath, prefix.Source, prefix.Hash)
	if err != nil {
		return false, fmt.Errorf("inserting ASN prefix: %w", err)
	}
	return true, nil
}

// GetLatestSnapshot returns the most recent snapshot for an ASN.
func (r *ASNRepository) GetLatestSnapshot(ctx context.Context, asnID int64) (*models.ASNSnapshot, error) {
	var snap models.ASNSnapshot
	err := r.pool.QueryRow(ctx,
		`SELECT observed_at, asn_id, name, org_name, org_id,
			description, country, allocated_date,
			extra, source, contains_pii
		 FROM asn_snapshots WHERE asn_id = $1
		 ORDER BY observed_at DESC LIMIT 1`, asnID).
		Scan(&snap.ObservedAt, &snap.ASNID, &snap.Name, &snap.OrgName, &snap.OrgID,
			&snap.Description, &snap.Country, &snap.AllocatedDate,
			&snap.Extra, &snap.Source, &snap.ContainsPII)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &snap, nil
}

// GetPrefixes returns currently announced prefixes for an ASN.
func (r *ASNRepository) GetPrefixes(ctx context.Context, asnID int64, page models.Pagination) (*models.PaginatedResult[models.ASNPrefix], error) {
	if page.Limit <= 0 {
		page.Limit = 50
	}

	var total int
	if err := r.pool.QueryRow(ctx,
		`SELECT COUNT(DISTINCT prefix) FROM asn_prefixes WHERE asn_id = $1`, asnID).Scan(&total); err != nil {
		return nil, err
	}

	rows, err := r.pool.Query(ctx,
		`SELECT DISTINCT ON (prefix) observed_at, asn_id, prefix::text, as_path, source
		 FROM asn_prefixes WHERE asn_id = $1
		 ORDER BY prefix, observed_at DESC
		 LIMIT $2 OFFSET $3`, asnID, page.Limit, page.Offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var prefixes []models.ASNPrefix
	for rows.Next() {
		var p models.ASNPrefix
		if err := rows.Scan(&p.ObservedAt, &p.ASNID, &p.Prefix, &p.ASPath, &p.Source); err != nil {
			return nil, err
		}
		prefixes = append(prefixes, p)
	}

	return &models.PaginatedResult[models.ASNPrefix]{
		Data: prefixes, Total: total, Limit: page.Limit, Offset: page.Offset,
		HasMore: page.Offset+page.Limit < total,
	}, nil
}
