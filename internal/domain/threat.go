// Package domain defines threat entities, enums, validation rules and errors.
package domain

import "time"

// Severity describes the danger level of a threat.
type Severity string

// ThreatType describes the class of malicious software.
type ThreatType string

// ThreatStatus describes the lifecycle state of a threat record.
type ThreatStatus string

// Supported severity levels.
const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// Supported threat types.
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

// Supported threat statuses.
const (
	StatusActive        ThreatStatus = "active"
	StatusInactive      ThreatStatus = "inactive"
	StatusFalsePositive ThreatStatus = "false_positive"
	StatusArchived      ThreatStatus = "archived"
)

// Threat is the domain model of a threat record.
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

// CreateThreatInput contains fields accepted when creating a threat.
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

// UpdateThreatInput contains fields accepted when fully replacing a threat.
// The MD5 hash is supplied separately and cannot be changed.
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

// ToThreat converts the create input into a Threat model.
func (in CreateThreatInput) ToThreat() Threat {
	return Threat{
		MD5:         in.MD5,
		Name:        in.Name,
		Description: in.Description,
		Severity:    in.Severity,
		Type:        in.Type,
		Status:      in.Status,
		Family:      in.Family,
		Source:      in.Source,
		Confidence:  in.Confidence,
		Tags:        in.Tags,
		SHA256:      in.SHA256,
		FileSize:    in.FileSize,
		FileType:    in.FileType,
		FirstSeenAt: in.FirstSeenAt,
		LastSeenAt:  in.LastSeenAt,
	}
}

// ToThreat converts the update input into a Threat model with the given MD5.
func (in UpdateThreatInput) ToThreat(md5 string) Threat {
	return Threat{
		MD5:         md5,
		Name:        in.Name,
		Description: in.Description,
		Severity:    in.Severity,
		Type:        in.Type,
		Status:      in.Status,
		Family:      in.Family,
		Source:      in.Source,
		Confidence:  in.Confidence,
		Tags:        in.Tags,
		SHA256:      in.SHA256,
		FileSize:    in.FileSize,
		FileType:    in.FileType,
		FirstSeenAt: in.FirstSeenAt,
		LastSeenAt:  in.LastSeenAt,
	}
}
