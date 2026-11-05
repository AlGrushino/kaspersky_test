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
