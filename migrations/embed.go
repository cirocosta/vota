// Package migrations embeds Vota's ordered SQLite migrations.
package migrations

import "embed"

// Files contains every numbered schema migration.
//
//go:embed *.sql
var Files embed.FS
