package service

import (
	"context"
	"kaspersky_test/internal/domain"
)

type ThreatService struct{}

func New() *ThreatService { return &ThreatService{} }

func (s *ThreatService) Create(context.Context, domain.CreateThreatInput) (*domain.Threat, error) {
	return nil, domain.ErrNotFound
}
func (s *ThreatService) Get(context.Context, string) (*domain.Threat, error) {
	return nil, domain.ErrNotFound
}
func (s *ThreatService) Update(context.Context, string, domain.UpdateThreatInput) (*domain.Threat, error) {
	return nil, domain.ErrNotFound
}
