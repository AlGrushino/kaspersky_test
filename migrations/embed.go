// Package migrations embeds SQL migrations applied at service startup.
package migrations

import "embed"

// FS contains the embedded goose migration files.
//
//go:embed *.sql
var FS embed.FS
