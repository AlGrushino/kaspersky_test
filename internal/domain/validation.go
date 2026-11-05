package domain

import (
	"fmt"
	"regexp"
	"strings"
)

var md5Pattern = regexp.MustCompile(`^[a-fA-F0-9]{32}$`)

func NormalizeMD5(s string) (string, error) {
	normalized := strings.ToLower(strings.TrimSpace(s))

	if !md5Pattern.MatchString(normalized) {
		return "", fmt.Errorf("%w: invalid md5 %q", ErrValidation, s)
	}
	return normalized, nil
}
