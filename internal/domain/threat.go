package domain

import "time"

type Severity string
type ThreatType string
type ThreatStatus string

type Threat struct {
	MD5         string
	Name        string
	Description *string
	Severity    *Severity
	Type        *ThreatType
	Status      *ThreatStatus
	Family      *string
	Source      *string
	Confidence  *int
	Tags        []string
	SHA256      *string
	FileSize    *int64
	FileType    *string
	FirstSeenAt *time.Time
	LastSeenAt  *time.Time
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type CreateThreatInput struct {
	MD5  string
	Name string
}

type UpdateThreatInput struct {
	Name string
}
