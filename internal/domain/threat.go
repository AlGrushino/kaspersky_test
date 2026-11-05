package domain

import "time"

type Severity string
type ThreatType string
type ThreatStatus string

const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

const (
	TypeTrojan     ThreatType = "trojan"
	TypeVirus      ThreatType = "virus"
	TypeWorm       ThreatType = "worm"
	TypeRansomware ThreatType = "ransomware"
	TypeSpyware    ThreatType = "spyware"
	TypeAdware     ThreatType = "adware"
	TypeRootkit    ThreatType = "rootkit"
	TypeMiner      ThreatType = "miner"
	TypeOther      ThreatType = "other"
)

const (
	StatusActive        ThreatStatus = "active"
	StatusInactive      ThreatStatus = "inactive"
	StatusFalsePositive ThreatStatus = "false_positive"
	StatusArchived      ThreatStatus = "archived"
)

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
}

type UpdateThreatInput struct {
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
}
