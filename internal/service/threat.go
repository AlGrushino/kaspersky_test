package service

import (
	"context"
	"kaspersky_test/internal/domain"
	"kaspersky_test/internal/repository"

	"time"
)

type ThreatService struct {
	repo repository.ThreatRepository
}

func New(repo repository.ThreatRepository) *ThreatService {
	return &ThreatService{repo: repo}
}

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
func (s *ThreatService) Get(ctx context.Context, md5 string) (*domain.Threat, error) {
	md5, err := domain.NormalizeMD5(md5)
	if err != nil {
		return nil, err
	}
	return s.repo.GetByMD5(ctx, md5)
}
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
