package repository

import (
	"context"
	"kaspersky_test/internal/domain"
)

type ThreatRepository interface {
	Create(ctx context.Context, t *domain.Threat) (*domain.Threat, error)
	GetByMD5(ctx context.Context, md5 string) (*domain.Threat, error)
	Update(ctx context.Context, t *domain.Threat) (*domain.Threat, error)
}
