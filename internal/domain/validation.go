package domain

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

var (
	md5Pattern    = regexp.MustCompile(`^[a-fA-F0-9]{32}$`)
	sha256Pattern = regexp.MustCompile(`^[a-fA-F0-9]{64}$`)
)

func NormalizeMD5(s string) (string, error) {
	normalized := strings.ToLower(strings.TrimSpace(s))

	if !md5Pattern.MatchString(normalized) {
		return "", fmt.Errorf("%w: invalid md5 %q", ErrValidation, s)
	}
	return normalized, nil
}

func NormalizeSHA256(s string) (string, error) {
	normalized := strings.ToLower(strings.TrimSpace(s))
	if !sha256Pattern.MatchString(normalized) {
		return "", fmt.Errorf("%w: invalid sha256 %q", ErrValidation, s)
	}
	return normalized, nil
}

func (s Severity) Valid() bool {
	switch s {
	case SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical:
		return true
	}
	return false
}

func (t ThreatType) Valid() bool {
	switch t {
	case TypeTrojan, TypeVirus, TypeWorm, TypeRansomware, TypeSpyware,
		TypeAdware, TypeRootkit, TypeMiner, TypeOther:
		return true
	}
	return false
}

func (s ThreatStatus) Valid() bool {
	switch s {
	case StatusActive, StatusInactive, StatusFalsePositive, StatusArchived:
		return true
	}
	return false
}

func (t *Threat) Validate() error {
	if l := len(strings.TrimSpace(t.Name)); l == 0 || l > 255 {
		return fmt.Errorf("%w: name must be 1..255 chars", ErrValidation)
	}
	if t.Description != nil && len(*t.Description) > 4096 {
		return fmt.Errorf("%w: description max 4096 chars", ErrValidation)
	}
	if t.Family != nil && len(*t.Family) > 255 {
		return fmt.Errorf("%w: family max 255 chars", ErrValidation)
	}
	if t.Source != nil && len(*t.Source) > 255 {
		return fmt.Errorf("%w: source max 255 chars", ErrValidation)
	}
	if t.FileType != nil && len(*t.FileType) > 128 {
		return fmt.Errorf("%w: file_type max 128 chars", ErrValidation)
	}
	if t.Severity != nil && !t.Severity.Valid() {
		return fmt.Errorf("%w: invalid severity %q", ErrValidation, *t.Severity)
	}
	if t.Type != nil && !t.Type.Valid() {
		return fmt.Errorf("%w: invalid type %q", ErrValidation, *t.Type)
	}
	if t.Status != nil && !t.Status.Valid() {
		return fmt.Errorf("%w: invalid status %q", ErrValidation, *t.Status)
	}
	if t.Confidence != nil && (*t.Confidence < 0 || *t.Confidence > 100) {
		return fmt.Errorf("%w: confidence must be 0..100", ErrValidation)
	}
	if t.FileSize != nil && *t.FileSize < 0 {
		return fmt.Errorf("%w: file_size must be >= 0", ErrValidation)
	}
	if len(t.Tags) > 20 {
		return fmt.Errorf("%w: tags max 20", ErrValidation)
	}
	seen := make(map[string]struct{}, len(t.Tags))
	for _, tag := range t.Tags {
		if l := len(tag); l == 0 || l > 64 {
			return fmt.Errorf("%w: tag length must be 1..64", ErrValidation)
		}
		if _, dup := seen[tag]; dup {
			return fmt.Errorf("%w: duplicate tag %q", ErrValidation, tag)
		}
		seen[tag] = struct{}{}
	}
	if t.SHA256 != nil {
		if _, err := NormalizeSHA256(*t.SHA256); err != nil {
			return err
		}
	}
	if t.FirstSeenAt != nil && t.LastSeenAt != nil && t.FirstSeenAt.After(*t.LastSeenAt) {
		return errors.New("first_seen_at must be <= last_seen_at")
	}
	return nil
}
