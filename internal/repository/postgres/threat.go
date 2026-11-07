package postgres

import (
	"context"
	"errors"
	"fmt"

	"kaspersky_test/internal/domain"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const pgUniqueViolation = "23505"

const threatColumns = `
	md5, name, description, severity, type, status, family, source,
	confidence, tags, sha256, file_size, file_type,
	first_seen_at, last_seen_at, created_at, updated_at
`

// Create inserts a threat and maps unique MD5 violations to domain.ErrConflict.
func (r *ThreatRepo) Create(ctx context.Context, t *domain.Threat) (*domain.Threat, error) {
	const q = `
		INSERT INTO threats (
			md5, name, description, severity, type, status, family, source,
			confidence, tags, sha256, file_size, file_type,
			first_seen_at, last_seen_at, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8,
			$9, $10, $11, $12, $13,
			$14, $15, $16, $17
		)
		RETURNING ` + threatColumns

	row := r.pool.QueryRow(ctx, q,
		t.MD5, t.Name, t.Description, t.Severity, t.Type, t.Status, t.Family, t.Source,
		t.Confidence, t.Tags, t.SHA256, t.FileSize, t.FileType,
		t.FirstSeenAt, t.LastSeenAt, t.CreatedAt, t.UpdatedAt,
	)

	created, err := scanThreat(row)
	if err != nil {
		return nil, mapCreateError(err)
	}
	return created, nil
}

// GetByMD5 returns a threat by MD5 or domain.ErrNotFound if it does not exist.
func (r *ThreatRepo) GetByMD5(ctx context.Context, md5 string) (*domain.Threat, error) {
	const q = `SELECT ` + threatColumns + ` FROM threats WHERE md5 = $1`

	row := r.pool.QueryRow(ctx, q, md5)
	threat, err := scanThreat(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("%w: md5 %s", domain.ErrNotFound, md5)
		}
		return nil, err
	}
	return threat, nil
}

// Update fully replaces the mutable fields of a threat or returns domain.ErrNotFound.
func (r *ThreatRepo) Update(ctx context.Context, t *domain.Threat) (*domain.Threat, error) {
	const q = `
		UPDATE threats SET
			name          = $2,
			description   = $3,
			severity      = $4,
			type          = $5,
			status        = $6,
			family        = $7,
			source        = $8,
			confidence    = $9,
			tags          = $10,
			sha256        = $11,
			file_size     = $12,
			file_type     = $13,
			first_seen_at = $14,
			last_seen_at  = $15,
			updated_at    = $16
		WHERE md5 = $1
		RETURNING ` + threatColumns

	row := r.pool.QueryRow(ctx, q,
		t.MD5, t.Name, t.Description, t.Severity, t.Type, t.Status, t.Family, t.Source,
		t.Confidence, t.Tags, t.SHA256, t.FileSize, t.FileType,
		t.FirstSeenAt, t.LastSeenAt, t.UpdatedAt,
	)

	updated, err := scanThreat(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("%w: md5 %s", domain.ErrNotFound, t.MD5)
		}
		return nil, err
	}
	return updated, nil
}

// scanThreat scans a database row into a domain.Threat.
func scanThreat(row pgx.Row) (*domain.Threat, error) {
	var t domain.Threat
	var severity, threatType, status *string

	err := row.Scan(
		&t.MD5, &t.Name, &t.Description,
		&severity, &threatType, &status,
		&t.Family, &t.Source,
		&t.Confidence, &t.Tags, &t.SHA256, &t.FileSize, &t.FileType,
		&t.FirstSeenAt, &t.LastSeenAt, &t.CreatedAt, &t.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	if severity != nil {
		v := domain.Severity(*severity)
		t.Severity = &v
	}
	if threatType != nil {
		v := domain.ThreatType(*threatType)
		t.Type = &v
	}
	if status != nil {
		v := domain.ThreatStatus(*status)
		t.Status = &v
	}
	return &t, nil
}

// mapCreateError translates PostgreSQL unique-violation errors into domain errors.
func mapCreateError(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == pgUniqueViolation {
		return fmt.Errorf("%w: md5 already exists", domain.ErrConflict)
	}
	return err
}
