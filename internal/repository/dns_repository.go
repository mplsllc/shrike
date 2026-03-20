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

type DNSRepository struct {
	pool *pgxpool.Pool
}

func NewDNSRepository(pool *pgxpool.Pool) *DNSRepository {
	return &DNSRepository{pool: pool}
}

// InsertIfChanged inserts a DNS record only if the hash differs from the latest.
func (r *DNSRepository) InsertIfChanged(ctx context.Context, rec *models.DNSRecord) (bool, error) {
	rec.Hash = hash.HashDNSRecord(rec)

	var existingHash []byte
	err := r.pool.QueryRow(ctx,
		`SELECT hash FROM dns_records
		 WHERE domain_id = $1 AND record_type = $2 AND name = $3 AND value = $4
		 ORDER BY observed_at DESC LIMIT 1`,
		rec.DomainID, rec.RecordType, rec.Name, rec.Value).Scan(&existingHash)
	if err != nil && err != pgx.ErrNoRows {
		return false, err
	}
	if existingHash != nil && bytes.Equal(existingHash, rec.Hash) {
		return false, nil
	}

	_, err = r.pool.Exec(ctx,
		`INSERT INTO dns_records (observed_at, domain_id, record_type, name, value, ttl, priority, extra, source, hash)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		rec.ObservedAt, rec.DomainID, rec.RecordType, rec.Name, rec.Value,
		rec.TTL, rec.Priority, rec.Extra, rec.Source, rec.Hash)
	if err != nil {
		return false, fmt.Errorf("inserting DNS record: %w", err)
	}
	return true, nil
}

// InsertBatch inserts multiple DNS records with dedup.
func (r *DNSRepository) InsertBatch(ctx context.Context, records []models.DNSRecord) (int, error) {
	stored := 0
	for i := range records {
		ok, err := r.InsertIfChanged(ctx, &records[i])
		if err != nil {
			return stored, err
		}
		if ok {
			stored++
		}
	}
	return stored, nil
}

// GetCurrentRecords returns the latest DNS records for a domain.
func (r *DNSRepository) GetCurrentRecords(ctx context.Context, domainID int64, recordType string) ([]models.DNSRecord, error) {
	query := `SELECT DISTINCT ON (record_type, name, value)
		observed_at, domain_id, record_type, name, value, ttl, priority, extra, source
		FROM dns_records WHERE domain_id = $1`
	args := []interface{}{domainID}

	if recordType != "" {
		query += " AND record_type = $2"
		args = append(args, recordType)
	}

	query += " ORDER BY record_type, name, value, observed_at DESC"

	rows, err := r.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []models.DNSRecord
	for rows.Next() {
		var rec models.DNSRecord
		if err := rows.Scan(&rec.ObservedAt, &rec.DomainID, &rec.RecordType, &rec.Name,
			&rec.Value, &rec.TTL, &rec.Priority, &rec.Extra, &rec.Source); err != nil {
			return nil, err
		}
		records = append(records, rec)
	}
	return records, nil
}

// GetHistory returns DNS record history for a domain.
func (r *DNSRepository) GetHistory(ctx context.Context, domainID int64, recordType string, timeRange models.TimeRange, page models.Pagination) (*models.PaginatedResult[models.DNSRecord], error) {
	if page.Limit <= 0 {
		page.Limit = 50
	}

	where := "WHERE domain_id = $1"
	args := []interface{}{domainID}
	idx := 2

	if recordType != "" {
		where += fmt.Sprintf(" AND record_type = $%d", idx)
		args = append(args, recordType)
		idx++
	}
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
	if err := r.pool.QueryRow(ctx, "SELECT COUNT(*) FROM dns_records "+where, countArgs...).Scan(&total); err != nil {
		return nil, err
	}

	query := fmt.Sprintf(`SELECT observed_at, domain_id, record_type, name, value, ttl, priority, extra, source
		FROM dns_records %s ORDER BY observed_at DESC LIMIT $%d OFFSET $%d`, where, idx, idx+1)
	args = append(args, page.Limit, page.Offset)

	rows, err := r.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []models.DNSRecord
	for rows.Next() {
		var rec models.DNSRecord
		if err := rows.Scan(&rec.ObservedAt, &rec.DomainID, &rec.RecordType, &rec.Name,
			&rec.Value, &rec.TTL, &rec.Priority, &rec.Extra, &rec.Source); err != nil {
			return nil, err
		}
		records = append(records, rec)
	}

	return &models.PaginatedResult[models.DNSRecord]{
		Data: records, Total: total, Limit: page.Limit, Offset: page.Offset,
		HasMore: page.Offset+page.Limit < total,
	}, nil
}

// DomainsForValue returns domains that have a DNS record with the given value (reverse lookup).
// Used for "what domains pointed to this IP?" queries.
func (r *DNSRepository) DomainsForValue(ctx context.Context, value string, page models.Pagination) (*models.PaginatedResult[models.DNSRecord], error) {
	if page.Limit <= 0 {
		page.Limit = 50
	}

	var total int
	if err := r.pool.QueryRow(ctx,
		`SELECT COUNT(DISTINCT domain_id) FROM dns_records WHERE value = $1`, value).Scan(&total); err != nil {
		return nil, err
	}

	rows, err := r.pool.Query(ctx,
		`SELECT DISTINCT ON (domain_id) observed_at, domain_id, record_type, name, value, ttl, priority, extra, source
		 FROM dns_records WHERE value = $1
		 ORDER BY domain_id, observed_at DESC
		 LIMIT $2 OFFSET $3`, value, page.Limit, page.Offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []models.DNSRecord
	for rows.Next() {
		var rec models.DNSRecord
		if err := rows.Scan(&rec.ObservedAt, &rec.DomainID, &rec.RecordType, &rec.Name,
			&rec.Value, &rec.TTL, &rec.Priority, &rec.Extra, &rec.Source); err != nil {
			return nil, err
		}
		records = append(records, rec)
	}

	return &models.PaginatedResult[models.DNSRecord]{
		Data: records, Total: total, Limit: page.Limit, Offset: page.Offset,
		HasMore: page.Offset+page.Limit < total,
	}, nil
}
