// Package postgres implements the threat repository on top of PostgreSQL.
package postgres

import (
	"kaspersky_test/internal/repository"

	"github.com/jackc/pgx/v5/pgxpool"
)

// ThreatRepo is a PostgreSQL-backed implementation of repository.ThreatRepository.
type ThreatRepo struct {
	pool *pgxpool.Pool
}

var _ repository.ThreatRepository = (*ThreatRepo)(nil)

// New returns a ThreatRepo that uses the given connection pool.
func New(pool *pgxpool.Pool) *ThreatRepo {
	return &ThreatRepo{pool: pool}
}
