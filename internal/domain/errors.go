package domain

import "errors"

var (
	// ErrValidation indicates that input data failed validation.
	ErrValidation = errors.New("validation error")
	// ErrNotFound indicates that the requested threat does not exist.
	ErrNotFound = errors.New("not found")
	// ErrConflict indicates that a threat with the same MD5 already exists.
	ErrConflict = errors.New("conflict")
)
