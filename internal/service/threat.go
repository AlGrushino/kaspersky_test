package service

import (
	"context"
	"kaspersky_test/internal/domain"
	"time"
)

type ThreatService struct{}

func New() *ThreatService { return &ThreatService{} }

func (s *ThreatService) Create(ctx context.Context, in domain.CreateThreatInput) (*domain.Threat, error) {
	t := in.ToThreat()
	if err := t.Validate(); err != nil {
		return nil, err // ErrValidation
	}

	now := time.Now().UTC()
	t.CreatedAt = now
	t.UpdatedAt = now
	// repository.Create(ctx, t)

	return nil, domain.ErrNotFound
}
func (s *ThreatService) Get(context.Context, string) (*domain.Threat, error) {
	return nil, domain.ErrNotFound
}
func (s *ThreatService) Update(ctx context.Context, md5 string, in domain.UpdateThreatInput) (*domain.Threat, error) {
	t := in.ToThreat(md5)
	if err := t.Validate(); err != nil {
		return nil, err
	}
	t.UpdatedAt = time.Now().UTC()

	// repository.Update(ctx, t)
	return nil, domain.ErrNotFound
}
