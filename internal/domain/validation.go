package domain

import (
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"
)

var (
	md5Pattern    = regexp.MustCompile(`^[a-fA-F0-9]{32}$`)
	sha256Pattern = regexp.MustCompile(`^[a-fA-F0-9]{64}$`)
)

const (
	maxNameLen        = 255
	maxDescriptionLen = 4096
	maxFamilyLen      = 255
	maxSourceLen      = 255
	maxFileTypeLen    = 128
	maxTagsCount      = 20
	maxTagLen         = 64
)

// NormalizeMD5 trims, lower-cases and validates an MD5 hash.
func NormalizeMD5(s string) (string, error) {
	normalized := strings.ToLower(strings.TrimSpace(s))

	if !md5Pattern.MatchString(normalized) {
		return "", fmt.Errorf("%w: invalid md5 %q", ErrValidation, s)
	}
	return normalized, nil
}

// NormalizeSHA256 trims, lower-cases and validates a SHA-256 hash.
func NormalizeSHA256(s string) (string, error) {
	normalized := strings.ToLower(strings.TrimSpace(s))
	if !sha256Pattern.MatchString(normalized) {
		return "", fmt.Errorf("%w: invalid sha256 %q", ErrValidation, s)
	}
	return normalized, nil
}

// Valid reports whether s is a supported severity level.
func (s Severity) Valid() bool {
	switch s {
	case SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical:
		return true
	}
	return false
}

// Valid reports whether t is a supported threat type.
func (t ThreatType) Valid() bool {
	switch t {
	case TypeTrojan, TypeVirus, TypeWorm, TypeRansomware, TypeSpyware,
		TypeAdware, TypeRootkit, TypeMiner, TypeOther:
		return true
	}
	return false
}

// Valid reports whether s is a supported threat status.
func (s ThreatStatus) Valid() bool {
	switch s {
	case StatusActive, StatusInactive, StatusFalsePositive, StatusArchived:
		return true
	}
	return false
}

// Validate checks the domain invariants of a threat and returns ErrValidation on failure.
func (t *Threat) Validate() error {
	if l := utf8.RuneCountInString(strings.TrimSpace(t.Name)); l == 0 || l > maxNameLen {
		return fmt.Errorf("%w: name must be 1..%d chars", ErrValidation, maxNameLen)
	}
	if t.Description != nil && utf8.RuneCountInString(*t.Description) > maxDescriptionLen {
		return fmt.Errorf("%w: description max %d chars", ErrValidation, maxDescriptionLen)
	}
	if t.Family != nil && utf8.RuneCountInString(*t.Family) > maxFamilyLen {
		return fmt.Errorf("%w: family max %d chars", ErrValidation, maxFamilyLen)
	}
	if t.Source != nil && utf8.RuneCountInString(*t.Source) > maxSourceLen {
		return fmt.Errorf("%w: source max %d chars", ErrValidation, maxSourceLen)
	}
	if t.FileType != nil && utf8.RuneCountInString(*t.FileType) > maxFileTypeLen {
		return fmt.Errorf("%w: file_type max %d chars", ErrValidation, maxFileTypeLen)
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
	if len(t.Tags) > maxTagsCount {
		return fmt.Errorf("%w: tags max %d", ErrValidation, maxTagsCount)
	}
	seen := make(map[string]struct{}, len(t.Tags))
	for _, tag := range t.Tags {
		if l := utf8.RuneCountInString(tag); l == 0 || l > maxTagLen {
			return fmt.Errorf("%w: tag length must be 1..%d", ErrValidation, maxTagLen)
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
		return fmt.Errorf("%w: first_seen_at must be <= last_seen_at", ErrValidation)
	}
	return nil
}
