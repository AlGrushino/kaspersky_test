package postgres

import (
	"kaspersky_test/internal/repository"

	"github.com/jackc/pgx/v5/pgxpool"
)

type ThreatRepo struct {
	pool *pgxpool.Pool
}

var _ repository.ThreatRepository = (*ThreatRepo)(nil)

func New(pool *pgxpool.Pool) *ThreatRepo {
	return &ThreatRepo{pool: pool}
}
