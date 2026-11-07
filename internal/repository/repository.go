// Package repository defines the storage abstraction for threats.
package repository

import (
	"context"
	"kaspersky_test/internal/domain"
)

// ThreatRepository stores and retrieves threat records.
type ThreatRepository interface {
	// Create inserts a new threat and returns the stored record.
	Create(ctx context.Context, t *domain.Threat) (*domain.Threat, error)
	// GetByMD5 returns a threat by its MD5 hash.
	GetByMD5(ctx context.Context, md5 string) (*domain.Threat, error)
	// Update fully replaces the mutable fields of an existing threat.
	Update(ctx context.Context, t *domain.Threat) (*domain.Threat, error)
}
