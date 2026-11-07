// Package service implements the business logic for managing threats.
package service

import (
	"context"
	"kaspersky_test/internal/domain"
	"kaspersky_test/internal/repository"

	"time"
)

// ThreatService coordinates validation and persistence of threats.
type ThreatService struct {
	repo repository.ThreatRepository
}

// New returns a ThreatService backed by repo.
func New(repo repository.ThreatRepository) *ThreatService {
	return &ThreatService{repo: repo}
}

// Create validates and stores a new threat, setting server-managed timestamps.
func (s *ThreatService) Create(ctx context.Context, in domain.CreateThreatInput) (*domain.Threat, error) {
	md5, err := domain.NormalizeMD5(in.MD5)
	if err != nil {
		return nil, err
	}
	in.MD5 = md5

	if in.SHA256 != nil {
		sha, err := domain.NormalizeSHA256(*in.SHA256)
		if err != nil {
			return nil, err
		}
		in.SHA256 = &sha
	}

	t := in.ToThreat()
	if err := t.Validate(); err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	t.CreatedAt = now
	t.UpdatedAt = now
	if t.Tags == nil {
		t.Tags = []string{}
	}
	return s.repo.Create(ctx, &t)
}

// Get returns a threat by MD5, normalizing the hash before lookup.
func (s *ThreatService) Get(ctx context.Context, md5 string) (*domain.Threat, error) {
	md5, err := domain.NormalizeMD5(md5)
	if err != nil {
		return nil, err
	}
	return s.repo.GetByMD5(ctx, md5)
}

// Update fully replaces an existing threat and refreshes updated_at.
func (s *ThreatService) Update(ctx context.Context, md5 string, in domain.UpdateThreatInput) (*domain.Threat, error) {
	md5, err := domain.NormalizeMD5(md5)
	if err != nil {
		return nil, err
	}
	if in.SHA256 != nil {
		sha, err := domain.NormalizeSHA256(*in.SHA256)
		if err != nil {
			return nil, err
		}
		in.SHA256 = &sha
	}

	t := in.ToThreat(md5)
	if err := t.Validate(); err != nil {
		return nil, err
	}
	if t.Tags == nil {
		t.Tags = []string{}
	}

	t.UpdatedAt = time.Now().UTC()

	return s.repo.Update(ctx, &t)
}
