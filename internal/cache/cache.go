package cache

import (
	"context"

	"kaspersky_test/internal/domain"
)

type ThreatCache interface {
	Get(ctx context.Context, md5 string) (*domain.Threat, error)
	Set(ctx context.Context, t *domain.Threat) error
	Delete(ctx context.Context, md5 string) error
}
