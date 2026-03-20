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

type IPRepository struct {
	pool *pgxpool.Pool
}

func NewIPRepository(pool *pgxpool.Pool) *IPRepository {
	return &IPRepository{pool: pool}
}

// GetByCIDR returns an IP block by its CIDR notation.
func (r *IPRepository) GetByCIDR(ctx context.Context, cidr string) (*models.IPBlock, error) {
	var b models.IPBlock
	err := r.pool.QueryRow(ctx,
		`SELECT id, cidr::text, version, rir, first_seen, last_seen
		 FROM ip_blocks WHERE cidr = $1::cidr`, cidr).
		Scan(&b.ID, &b.CIDR, &b.Version, &b.RIR, &b.FirstSeen, &b.LastSeen)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("querying IP block %s: %w", cidr, err)
	}
	return &b, nil
}

// FindContaining returns the IP block that contains the given address.
func (r *IPRepository) FindContaining(ctx context.Context, address string) (*models.IPBlock, error) {
	var b models.IPBlock
	err := r.pool.QueryRow(ctx,
		`SELECT id, cidr::text, version, rir, first_seen, last_seen
		 FROM ip_blocks WHERE cidr >>= $1::inet
		 ORDER BY masklen(cidr) DESC LIMIT 1`, address).
		Scan(&b.ID, &b.CIDR, &b.Version, &b.RIR, &b.FirstSeen, &b.LastSeen)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("finding containing block for %s: %w", address, err)
	}
	return &b, nil
}

// Upsert creates or updates an IP block, returning its ID.
func (r *IPRepository) Upsert(ctx context.Context, cidr string, version int, rir string) (int64, error) {
	var id int64
	err := r.pool.QueryRow(ctx,
		`INSERT INTO ip_blocks (cidr, version, rir)
		 VALUES ($1::cidr, $2, $3)
		 ON CONFLICT (cidr) DO UPDATE SET last_seen = NOW()
		 RETURNING id`, cidr, version, rir).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("upserting IP block %s: %w", cidr, err)
	}
	return id, nil
}

// InsertSnapshotIfChanged inserts an IP snapshot only if the hash differs.
func (r *IPRepository) InsertSnapshotIfChanged(ctx context.Context, snap *models.IPSnapshot) (bool, error) {
	snap.Hash = hash.HashIPSnapshot(snap)

	var existingHash []byte
	err := r.pool.QueryRow(ctx,
		`SELECT hash FROM ip_snapshots
		 WHERE ip_block_id = $1
		 ORDER BY observed_at DESC LIMIT 1`, snap.IPBlockID).Scan(&existingHash)
	if err != nil && err != pgx.ErrNoRows {
		return false, fmt.Errorf("checking existing hash: %w", err)
	}
	if existingHash != nil && bytes.Equal(existingHash, snap.Hash) {
		return false, nil
	}

	_, err = r.pool.Exec(ctx,
		`INSERT INTO ip_snapshots (
			observed_at, ip_block_id, net_name, org_name, org_id,
			description, country, abuse_contact,
			allocated_date, updated_date, status,
			raw_whois, extra, source, contains_pii, hash
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`,
		snap.ObservedAt, snap.IPBlockID, snap.NetName, snap.OrgName, snap.OrgID,
		snap.Description, snap.Country, snap.AbuseContact,
		snap.AllocatedDate, snap.UpdatedDate, snap.Status,
		snap.RawWhois, snap.Extra, snap.Source, snap.ContainsPII, snap.Hash,
	)
	if err != nil {
		return false, fmt.Errorf("inserting IP snapshot: %w", err)
	}
	return true, nil
}

// GetLatestSnapshot returns the most recent snapshot for an IP block.
func (r *IPRepository) GetLatestSnapshot(ctx context.Context, blockID int64) (*models.IPSnapshot, error) {
	var snap models.IPSnapshot
	err := r.pool.QueryRow(ctx,
		`SELECT observed_at, ip_block_id, net_name, org_name, org_id,
			description, country, abuse_contact,
			allocated_date, updated_date, status,
			extra, source, contains_pii
		 FROM ip_snapshots WHERE ip_block_id = $1
		 ORDER BY observed_at DESC LIMIT 1`, blockID).
		Scan(&snap.ObservedAt, &snap.IPBlockID, &snap.NetName, &snap.OrgName, &snap.OrgID,
			&snap.Description, &snap.Country, &snap.AbuseContact,
			&snap.AllocatedDate, &snap.UpdatedDate, &snap.Status,
			&snap.Extra, &snap.Source, &snap.ContainsPII)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("getting latest IP snapshot: %w", err)
	}
	return &snap, nil
}

// GetHistory returns snapshots for an IP block within a time range.
func (r *IPRepository) GetHistory(ctx context.Context, blockID int64, timeRange models.TimeRange, page models.Pagination) (*models.PaginatedResult[models.IPSnapshot], error) {
	if page.Limit <= 0 {
		page.Limit = 50
	}

	args := []interface{}{blockID}
	where := "WHERE ip_block_id = $1"
	idx := 2

	if timeRange.From != nil {
		where += fmt.Sprintf(" AND observed_at >= $%d", idx)
		args = append(args, *timeRange.From)
		idx++
	}
	if timeRange.To != nil {
		where += fmt.Sprintf(" AND observed_at <= $%d", idx)
		args = append(args, *timeRange.To)
		idx++
	}

	var total int
	countArgs := make([]interface{}, len(args))
	copy(countArgs, args)
	if err := r.pool.QueryRow(ctx, "SELECT COUNT(*) FROM ip_snapshots "+where, countArgs...).Scan(&total); err != nil {
		return nil, err
	}

	query := fmt.Sprintf(`SELECT observed_at, ip_block_id, net_name, org_name, org_id,
		description, country, abuse_contact, allocated_date, updated_date, status,
		extra, source, contains_pii
		FROM ip_snapshots %s ORDER BY observed_at DESC LIMIT $%d OFFSET $%d`, where, idx, idx+1)
	args = append(args, page.Limit, page.Offset)

	rows, err := r.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var snapshots []models.IPSnapshot
	for rows.Next() {
		var s models.IPSnapshot
		if err := rows.Scan(&s.ObservedAt, &s.IPBlockID, &s.NetName, &s.OrgName, &s.OrgID,
			&s.Description, &s.Country, &s.AbuseContact, &s.AllocatedDate, &s.UpdatedDate, &s.Status,
			&s.Extra, &s.Source, &s.ContainsPII); err != nil {
			return nil, err
		}
		snapshots = append(snapshots, s)
	}

	return &models.PaginatedResult[models.IPSnapshot]{
		Data: snapshots, Total: total, Limit: page.Limit, Offset: page.Offset,
		HasMore: page.Offset+page.Limit < total,
	}, nil
}

// DomainsForIP returns domains that have resolved to a given IP address.
func (r *IPRepository) DomainsForIP(ctx context.Context, address string, page models.Pagination) (*models.PaginatedResult[models.DomainIPHistory], error) {
	if page.Limit <= 0 {
		page.Limit = 50
	}

	var total int
	if err := r.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM domain_ip_history WHERE ip_address = $1::inet`, address).Scan(&total); err != nil {
		return nil, err
	}

	rows, err := r.pool.Query(ctx,
		`SELECT domain_id, ip_block_id, ip_address::text, first_seen, last_seen
		 FROM domain_ip_history WHERE ip_address = $1::inet
		 ORDER BY last_seen DESC LIMIT $2 OFFSET $3`,
		address, page.Limit, page.Offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []models.DomainIPHistory
	for rows.Next() {
		var h models.DomainIPHistory
		var ipStr string
		if err := rows.Scan(&h.DomainID, &h.IPBlockID, &ipStr, &h.FirstSeen, &h.LastSeen); err != nil {
			return nil, err
		}
		results = append(results, h)
	}

	return &models.PaginatedResult[models.DomainIPHistory]{
		Data: results, Total: total, Limit: page.Limit, Offset: page.Offset,
		HasMore: page.Offset+page.Limit < total,
	}, nil
}
