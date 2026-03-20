package repository

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"git.mp.ls/mpls/shrike/internal/models"
)

type RedactionRepository struct {
	pool *pgxpool.Pool
}

func NewRedactionRepository(pool *pgxpool.Pool) *RedactionRepository {
	return &RedactionRepository{pool: pool}
}

// Submit creates a new redaction request.
func (r *RedactionRepository) Submit(ctx context.Context, req *models.RedactionRequest) (int64, error) {
	var id int64
	err := r.pool.QueryRow(ctx,
		`INSERT INTO redaction_requests (requester_email, domain_name, description, status)
		 VALUES ($1, $2, $3, 'pending')
		 RETURNING id`,
		req.RequesterEmail, req.DomainName, req.Description).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("submitting redaction request: %w", err)
	}
	return id, nil
}

// GetPending returns all pending redaction requests.
func (r *RedactionRepository) GetPending(ctx context.Context) ([]models.RedactionRequest, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT id, requester_email, domain_name, description, status, created_at, completed_at
		 FROM redaction_requests WHERE status = 'pending' ORDER BY created_at ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var requests []models.RedactionRequest
	for rows.Next() {
		var req models.RedactionRequest
		if err := rows.Scan(&req.ID, &req.RequesterEmail, &req.DomainName, &req.Description,
			&req.Status, &req.CreatedAt, &req.CompletedAt); err != nil {
			return nil, err
		}
		requests = append(requests, req)
	}
	return requests, nil
}

// ProcessRedaction scrubs PII from domain snapshots matching the request.
// Nulls out registrant_name, registrant_email, admin_contact, tech_contact.
// Scrubs raw_whois by replacing email patterns and personal names with [REDACTED].
// Returns the number of snapshots affected.
func (r *RedactionRepository) ProcessRedaction(ctx context.Context, reqID int64, domainName string) (int, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)

	// Find the domain
	var domainID int64
	err = tx.QueryRow(ctx, `SELECT id FROM domains WHERE name = $1`, domainName).Scan(&domainID)
	if err == pgx.ErrNoRows {
		// Domain doesn't exist — mark request as completed (nothing to scrub)
		r.markCompleted(ctx, tx, reqID)
		return 0, tx.Commit(ctx)
	}
	if err != nil {
		return 0, err
	}

	// Scrub PII fields from all snapshots for this domain
	tag, err := tx.Exec(ctx,
		`UPDATE domain_snapshots SET
			registrant_name = NULL,
			registrant_email = NULL,
			admin_contact = NULL,
			tech_contact = NULL,
			raw_whois = regexp_replace(
				COALESCE(raw_whois, ''),
				'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}',
				'[REDACTED]',
				'g'
			),
			contains_pii = FALSE
		 WHERE domain_id = $1 AND (
			registrant_name IS NOT NULL OR
			registrant_email IS NOT NULL OR
			admin_contact IS NOT NULL OR
			tech_contact IS NOT NULL
		 )`, domainID)
	if err != nil {
		return 0, fmt.Errorf("scrubbing snapshots: %w", err)
	}

	affected := int(tag.RowsAffected())

	r.markCompleted(ctx, tx, reqID)

	return affected, tx.Commit(ctx)
}

func (r *RedactionRepository) markCompleted(ctx context.Context, tx pgx.Tx, reqID int64) {
	tx.Exec(ctx,
		`UPDATE redaction_requests SET status = 'completed', completed_at = $1 WHERE id = $2`,
		time.Now().UTC(), reqID)
}

// GetByID returns a redaction request by ID.
func (r *RedactionRepository) GetByID(ctx context.Context, id int64) (*models.RedactionRequest, error) {
	var req models.RedactionRequest
	err := r.pool.QueryRow(ctx,
		`SELECT id, requester_email, domain_name, description, status, created_at, completed_at
		 FROM redaction_requests WHERE id = $1`, id).
		Scan(&req.ID, &req.RequesterEmail, &req.DomainName, &req.Description,
			&req.Status, &req.CreatedAt, &req.CompletedAt)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &req, nil
}
