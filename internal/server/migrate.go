package server

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"sort"
	"strings"
)

// migrations holds the versioned SQL files applied in lexical order. Each
// file runs in its own transaction and is recorded in schema_migrations.
//
//go:embed migrations/*.sql
var migrations embed.FS

// Apply runs every pending migration and returns the resulting schema
// version. It is idempotent: applied versions are skipped, so booting a
// server against an existing database is a no-op.
func Apply(ctx context.Context, db *sql.DB) (int, error) {
	if _, err := db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version    INTEGER PRIMARY KEY,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)`); err != nil {
		return 0, fmt.Errorf("create schema_migrations: %w", err)
	}

	names, err := migrations.ReadDir("migrations")
	if err != nil {
		return 0, fmt.Errorf("list embedded migrations: %w", err)
	}
	sort.Slice(names, func(i, j int) bool { return names[i].Name() < names[j].Name() })

	for _, entry := range names {
		version, err := migrationVersion(entry.Name())
		if err != nil {
			return 0, err
		}

		var exists bool
		err = db.QueryRowContext(ctx,
			"SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = $1)", version).Scan(&exists)
		if err != nil {
			return 0, fmt.Errorf("check migration %d: %w", version, err)
		}
		if exists {
			continue
		}

		body, err := migrations.ReadFile("migrations/" + entry.Name())
		if err != nil {
			return 0, fmt.Errorf("read migration %s: %w", entry.Name(), err)
		}

		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return 0, fmt.Errorf("begin migration %d: %w", version, err)
		}
		if _, err := tx.ExecContext(ctx, string(body)); err != nil {
			_ = tx.Rollback()
			return 0, fmt.Errorf("apply migration %d: %w", version, err)
		}
		if _, err := tx.ExecContext(ctx,
			"INSERT INTO schema_migrations (version) VALUES ($1)", version); err != nil {
			_ = tx.Rollback()
			return 0, fmt.Errorf("record migration %d: %w", version, err)
		}
		if err := tx.Commit(); err != nil {
			return 0, fmt.Errorf("commit migration %d: %w", version, err)
		}
	}

	return SchemaVersion(ctx, db)
}

// migrationVersion extracts the numeric prefix of a NNNN_name.sql file.
func migrationVersion(name string) (int, error) {
	prefix, _, ok := strings.Cut(name, "_")
	if !ok {
		return 0, fmt.Errorf("migration file %q does not match NNNN_name.sql", name)
	}
	var version int
	if _, err := fmt.Sscanf(prefix, "%d", &version); err != nil {
		return 0, fmt.Errorf("migration file %q has no numeric prefix: %w", name, err)
	}
	return version, nil
}

// SchemaVersion reports the highest applied migration, or 0 for an empty
// database. It implements the store behind the status endpoint.
func SchemaVersion(ctx context.Context, db *sql.DB) (int, error) {
	var version int
	err := db.QueryRowContext(ctx,
		"SELECT COALESCE(MAX(version), 0) FROM schema_migrations").Scan(&version)
	if err != nil {
		return 0, fmt.Errorf("query schema version: %w", err)
	}
	return version, nil
}
