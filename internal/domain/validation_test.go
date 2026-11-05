package domain

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func ptr[T any](v T) *T { return &v }

func TestNormalizeMD5(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{"valid lower", "d41d8cd98f00b204e9800998ecf8427e", "d41d8cd98f00b204e9800998ecf8427e", false},
		{"valid upper", "D41D8CD98F00B204E9800998ECF8427E", "d41d8cd98f00b204e9800998ecf8427e", false},
		{"trim spaces", "  d41d8cd98f00b204e9800998ecf8427e  ", "d41d8cd98f00b204e9800998ecf8427e", false},
		{"too short", "d41d8cd9", "", true},
		{"non hex", "z41d8cd98f00b204e9800998ecf8427e", "", true},
		{"empty", "", "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NormalizeMD5(tc.in)
			if tc.wantErr {
				if !errors.Is(err, ErrValidation) {
					t.Fatalf("expected ErrValidation, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestThreatValidate(t *testing.T) {
	valid := Threat{
		MD5:  "d41d8cd98f00b204e9800998ecf8427e",
		Name: "Trojan.Win32.Generic",
	}

	tests := []struct {
		name    string
		mutate  func(*Threat)
		wantErr bool
	}{
		{"valid minimal", func(*Threat) {}, false},
		{"empty name", func(t *Threat) { t.Name = "" }, true},
		{"name too long", func(t *Threat) { t.Name = string(make([]byte, 256)) }, true},
		{"bad severity", func(t *Threat) { s := Severity("unknown"); t.Severity = &s }, true},
		{"good severity", func(t *Threat) { s := SeverityHigh; t.Severity = &s }, false},
		{"confidence negative", func(t *Threat) { t.Confidence = ptr(-1) }, true},
		{"confidence > 100", func(t *Threat) { t.Confidence = ptr(101) }, true},
		{"confidence ok", func(t *Threat) { t.Confidence = ptr(50) }, false},
		{"negative file size", func(t *Threat) { t.FileSize = ptr(int64(-1)) }, true},
		{"too many tags", func(t *Threat) { t.Tags = make([]string, 21) }, true},
		{"dup tags", func(t *Threat) { t.Tags = []string{"a", "a"} }, true},
		{"empty tag", func(t *Threat) { t.Tags = []string{""} }, true},
		{"bad sha256", func(t *Threat) { t.SHA256 = ptr("zzz") }, true},
		{"good sha256", func(t *Threat) { t.SHA256 = ptr("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") }, false},
		{"first after last", func(t *Threat) {
			now := time.Now()
			t.FirstSeenAt = &now
			later := now.Add(-time.Hour)
			t.LastSeenAt = &later
		}, true},
		{"name 255 cyrillic chars ok", func(t *Threat) {
			t.Name = strings.Repeat("я", 255)
		}, false},
		{"name 256 cyrillic chars", func(t *Threat) {
			t.Name = strings.Repeat("я", 256)
		}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			th := valid
			tc.mutate(&th)
			err := th.Validate()
			if tc.wantErr && !errors.Is(err, ErrValidation) {
				t.Fatalf("expected ErrValidation, got %v", err)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}
