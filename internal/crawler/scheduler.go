package crawler

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"git.mp.ls/mpls/shrike/internal/models"
)

// Scheduler pulls jobs from the crawl_jobs table and dispatches them to workers.
type Scheduler struct {
	pool        *pgxpool.Pool
	rateLimiter *RateLimiter
	batchSize   int
}

func NewScheduler(pool *pgxpool.Pool, rateLimiter *RateLimiter) *Scheduler {
	return &Scheduler{
		pool:        pool,
		rateLimiter: rateLimiter,
		batchSize:   50,
	}
}

// NextBatch fetches the next batch of ready jobs, skipping servers in backoff.
func (s *Scheduler) NextBatch(ctx context.Context) ([]models.CrawlJob, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, job_type, target, target_id, priority, state, whois_server,
			next_run_at, last_run_at, error_count, last_error, created_at
		 FROM crawl_jobs
		 WHERE state = 'pending' AND next_run_at <= NOW()
		 ORDER BY priority ASC, next_run_at ASC
		 LIMIT $1
		 FOR UPDATE SKIP LOCKED`, s.batchSize)
	if err != nil {
		return nil, fmt.Errorf("fetching jobs: %w", err)
	}
	defer rows.Close()

	var jobs []models.CrawlJob
	for rows.Next() {
		var job models.CrawlJob
		if err := rows.Scan(
			&job.ID, &job.JobType, &job.Target, &job.TargetID, &job.Priority,
			&job.State, &job.WhoisServer, &job.NextRunAt, &job.LastRunAt,
			&job.ErrorCount, &job.LastError, &job.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scanning job: %w", err)
		}

		// Skip if the server is in backoff
		if job.WhoisServer != nil && s.rateLimiter.IsBackedOff(*job.WhoisServer) {
			continue
		}

		jobs = append(jobs, job)
	}

	return jobs, nil
}

// MarkRunning updates a job's state to running.
func (s *Scheduler) MarkRunning(ctx context.Context, jobID int64) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE crawl_jobs SET state = 'running', last_run_at = NOW() WHERE id = $1`, jobID)
	return err
}

// MarkDone marks a job as completed and schedules the next crawl.
func (s *Scheduler) MarkDone(ctx context.Context, jobID int64, nextInterval time.Duration) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE crawl_jobs SET state = 'done', error_count = 0, last_error = NULL,
		 next_run_at = NOW() + $2
		 WHERE id = $1`, jobID, nextInterval)
	return err
}

// MarkFailed records a failure and applies backoff for retry.
func (s *Scheduler) MarkFailed(ctx context.Context, jobID int64, errMsg string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE crawl_jobs SET
			state = CASE WHEN error_count >= 10 THEN 'deferred' ELSE 'pending' END,
			error_count = error_count + 1,
			last_error = $2,
			next_run_at = NOW() + (INTERVAL '1 minute' * POWER(2, LEAST(error_count, 8)))
		 WHERE id = $1`, jobID, errMsg)
	return err
}

// EnqueueDomain creates a crawl job for a domain if one doesn't already exist.
func (s *Scheduler) EnqueueDomain(ctx context.Context, domain, tld string, priority int) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO crawl_jobs (job_type, target, priority, whois_server)
		 VALUES ($1, $2, $3, NULL)
		 ON CONFLICT DO NOTHING`,
		models.JobTypeDomainWhois, domain, priority)
	if err != nil {
		return fmt.Errorf("enqueueing domain %s: %w", domain, err)
	}

	// Also enqueue DNS
	_, err = s.pool.Exec(ctx,
		`INSERT INTO crawl_jobs (job_type, target, priority)
		 VALUES ($1, $2, $3)
		 ON CONFLICT DO NOTHING`,
		models.JobTypeDNS, domain, priority)
	return err
}

// QueueDepth returns the number of pending jobs by priority.
func (s *Scheduler) QueueDepth(ctx context.Context) (map[int]int, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT priority, COUNT(*) FROM crawl_jobs WHERE state = 'pending' GROUP BY priority`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	depths := make(map[int]int)
	for rows.Next() {
		var priority, count int
		if err := rows.Scan(&priority, &count); err != nil {
			return nil, err
		}
		depths[priority] = count
	}
	return depths, nil
}

// GetJobByTarget returns an existing job for the given type and target.
func (s *Scheduler) GetJobByTarget(ctx context.Context, jobType, target string) (*models.CrawlJob, error) {
	var job models.CrawlJob
	err := s.pool.QueryRow(ctx,
		`SELECT id, job_type, target, target_id, priority, state, whois_server,
			next_run_at, last_run_at, error_count, last_error, created_at
		 FROM crawl_jobs
		 WHERE job_type = $1 AND target = $2
		 LIMIT 1`, jobType, target).
		Scan(&job.ID, &job.JobType, &job.Target, &job.TargetID, &job.Priority,
			&job.State, &job.WhoisServer, &job.NextRunAt, &job.LastRunAt,
			&job.ErrorCount, &job.LastError, &job.CreatedAt)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &job, nil
}
