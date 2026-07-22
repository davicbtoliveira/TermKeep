package server

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib" // PostgreSQL driver for database/sql.
)

// OpenDB connects to PostgreSQL and verifies the connection. Callers own
// the returned handle and must close it.
func OpenDB(ctx context.Context, databaseURL string) (*sql.DB, error) {
	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping database: %w", err)
	}
	return db, nil
}

// DBStore adapts *sql.DB to the SchemaStore seam used by the status handler.
type DBStore struct {
	DB *sql.DB
}

// SchemaVersion implements SchemaStore.
func (s DBStore) SchemaVersion(ctx context.Context) (int, error) {
	return SchemaVersion(ctx, s.DB)
}
