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

// InstanceEmpty reports whether the instance can accept its sole bootstrap
// registration. The transaction in CreateBootstrap is the authoritative race
// check; this is only the early rejection path.
func (s DBStore) InstanceEmpty(ctx context.Context) (bool, error) {
	var empty bool
	if err := s.DB.QueryRowContext(ctx, "SELECT NOT EXISTS (SELECT 1 FROM accounts)").Scan(&empty); err != nil {
		return false, fmt.Errorf("check bootstrap state: %w", err)
	}
	return empty, nil
}

// CreateBootstrap atomically creates the first administrator and stores only
// OPAQUE registration material plus client-encrypted vault envelopes.
func (s DBStore) CreateBootstrap(ctx context.Context, account BootstrapAccount) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin bootstrap: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// PostgreSQL advisory locks serialize bootstrap attempts without a global
	// table lock. Future invitation-based registration does not use this path.
	if _, err := tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock(7345821)"); err != nil {
		return fmt.Errorf("lock bootstrap: %w", err)
	}
	var exists bool
	if err := tx.QueryRowContext(ctx, "SELECT EXISTS (SELECT 1 FROM accounts)").Scan(&exists); err != nil {
		return fmt.Errorf("check bootstrap account: %w", err)
	}
	if exists {
		return ErrBootstrapClosed
	}
	if _, err := tx.ExecContext(ctx,
		"INSERT INTO accounts (uuid, email, is_administrator) VALUES ($1, $2, $3)",
		account.AccountID, account.Email, account.Administrator); err != nil {
		return fmt.Errorf("create bootstrap account: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		"INSERT INTO opaque_records (account_uuid, record) VALUES ($1, $2)",
		account.AccountID, account.OpaqueRecord); err != nil {
		return fmt.Errorf("store OPAQUE record: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO vault_envelopes (account_uuid, password_vault_envelope, recovery_vault_envelope)
		VALUES ($1, $2, $3)`, account.AccountID, account.PasswordVaultEnvelope, account.RecoveryVaultEnvelope); err != nil {
		return fmt.Errorf("store vault envelopes: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit bootstrap: %w", err)
	}
	return nil
}

// FindAccount loads only opaque authentication and encrypted vault material.
func (s DBStore) FindAccount(ctx context.Context, email string) (StoredAccount, error) {
	var account StoredAccount
	err := s.DB.QueryRowContext(ctx, `
		SELECT a.uuid::text, a.email, a.is_administrator, r.record, v.password_vault_envelope, v.recovery_vault_envelope
		FROM accounts a
		JOIN opaque_records r ON r.account_uuid = a.uuid
		JOIN vault_envelopes v ON v.account_uuid = a.uuid
		WHERE a.email = $1`, email).Scan(
		&account.AccountID,
		&account.Email,
		&account.Administrator,
		&account.OpaqueRecord,
		&account.PasswordVaultEnvelope,
		&account.RecoveryVaultEnvelope,
	)
	if err == sql.ErrNoRows {
		return StoredAccount{}, ErrAccountNotFound
	}
	if err != nil {
		return StoredAccount{}, fmt.Errorf("load account authentication material: %w", err)
	}
	return account, nil
}

// CreateAccessToken stores a hashed access token.
func (s DBStore) CreateAccessToken(ctx context.Context, token StoredAccessToken) error {
	_, err := s.DB.ExecContext(ctx, `
		INSERT INTO access_tokens (
			token_hash, session_uuid, account_uuid, email, administrator,
			host, source_ip, created_at, last_used_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		token.TokenHash, token.SessionID, token.AccountID, token.Email, token.Administrator,
		token.Host, token.SourceIP, token.CreatedAt, token.LastUsedAt,
	)
	if err != nil {
		return fmt.Errorf("create access token: %w", err)
	}
	return nil
}

// FindAccessToken loads an access token record by token hash.
func (s DBStore) FindAccessToken(ctx context.Context, tokenHash []byte) (StoredAccessToken, error) {
	var token StoredAccessToken
	var revokedAt sql.NullTime
	err := s.DB.QueryRowContext(ctx, `
		SELECT token_hash, session_uuid::text, account_uuid::text, email, administrator,
		       host, source_ip, created_at, last_used_at, revoked_at
		FROM access_tokens
		WHERE token_hash = $1`, tokenHash).Scan(
		&token.TokenHash, &token.SessionID, &token.AccountID, &token.Email, &token.Administrator,
		&token.Host, &token.SourceIP, &token.CreatedAt, &token.LastUsedAt, &revokedAt,
	)
	if err == sql.ErrNoRows {
		return StoredAccessToken{}, ErrAccessTokenNotFound
	}
	if err != nil {
		return StoredAccessToken{}, fmt.Errorf("find access token: %w", err)
	}
	if revokedAt.Valid {
		token.RevokedAt = revokedAt.Time
	}
	return token, nil
}

// ListSessions returns active online sessions belonging to one account.
func (s DBStore) ListSessions(ctx context.Context, accountID string) ([]StoredAccessToken, error) {
	rows, err := s.DB.QueryContext(ctx, `
		SELECT session_uuid::text, account_uuid::text, host, source_ip, created_at, last_used_at
		FROM access_tokens
		WHERE account_uuid = $1 AND revoked_at IS NULL
		ORDER BY created_at DESC, session_uuid`, accountID)
	if err != nil {
		return nil, fmt.Errorf("list sessions: %w", err)
	}
	defer rows.Close()

	var sessions []StoredAccessToken
	for rows.Next() {
		var token StoredAccessToken
		if err := rows.Scan(
			&token.SessionID, &token.AccountID, &token.Host, &token.SourceIP,
			&token.CreatedAt, &token.LastUsedAt,
		); err != nil {
			return nil, fmt.Errorf("scan session: %w", err)
		}
		sessions = append(sessions, token)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate sessions: %w", err)
	}
	return sessions, nil
}

// RevokeSession marks one active session belonging to the authenticated
// account.
func (s DBStore) RevokeSession(ctx context.Context, accountID, sessionID string, now time.Time) error {
	result, err := s.DB.ExecContext(ctx, `
		UPDATE access_tokens
		SET revoked_at = $3
		WHERE account_uuid = $1 AND session_uuid = $2 AND revoked_at IS NULL`,
		accountID, sessionID, now)
	if err != nil {
		return fmt.Errorf("revoke session: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("revoke session rows affected: %w", err)
	}
	if count == 0 {
		return ErrSessionNotFound
	}
	return nil
}

// TouchAccessToken records observable online use without exposing request
// content.
func (s DBStore) TouchAccessToken(ctx context.Context, tokenHash []byte, now time.Time) error {
	result, err := s.DB.ExecContext(ctx,
		"UPDATE access_tokens SET last_used_at = $2 WHERE token_hash = $1",
		tokenHash, now)
	if err != nil {
		return fmt.Errorf("touch access token: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("touch access token rows affected: %w", err)
	}
	if count == 0 {
		return ErrAccessTokenNotFound
	}
	return nil
}

// CreateInvite persists an invitation.
func (s DBStore) CreateInvite(ctx context.Context, invite StoredInvite) error {
	_, err := s.DB.ExecContext(ctx, `
		INSERT INTO invites (uuid, email, token_hash, created_by, created_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)`,
		invite.InviteID, invite.Email, invite.TokenHash, invite.CreatedBy, invite.CreatedAt, invite.ExpiresAt,
	)
	if err != nil {
		return fmt.Errorf("create invite: %w", err)
	}
	return nil
}

// ListInvites returns all invitations ordered by creation timestamp.
func (s DBStore) ListInvites(ctx context.Context) ([]StoredInvite, error) {
	rows, err := s.DB.QueryContext(ctx, `
		SELECT uuid::text, email, token_hash, created_by::text, created_at, expires_at,
		       COALESCE(consumed_by::text, ''), consumed_at, revoked_at
		FROM invites
		ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("list invites: %w", err)
	}
	defer rows.Close()

	var out []StoredInvite
	for rows.Next() {
		var inv StoredInvite
		var consumedBy string
		var consumedAt, revokedAt sql.NullTime
		if err := rows.Scan(&inv.InviteID, &inv.Email, &inv.TokenHash, &inv.CreatedBy, &inv.CreatedAt, &inv.ExpiresAt, &consumedBy, &consumedAt, &revokedAt); err != nil {
			return nil, fmt.Errorf("scan invite: %w", err)
		}
		inv.ConsumedBy = consumedBy
		if consumedAt.Valid {
			inv.ConsumedAt = consumedAt.Time
		}
		if revokedAt.Valid {
			inv.RevokedAt = revokedAt.Time
		}
		out = append(out, inv)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate invites: %w", err)
	}
	return out, nil
}

// RevokeInvite marks an unconsumed invitation as revoked.
func (s DBStore) RevokeInvite(ctx context.Context, inviteID string) error {
	res, err := s.DB.ExecContext(ctx, `
		UPDATE invites SET revoked_at = now() WHERE uuid = $1 AND revoked_at IS NULL AND consumed_at IS NULL`,
		inviteID,
	)
	if err != nil {
		return fmt.Errorf("revoke invite: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("revoke invite rows affected: %w", err)
	}
	if n == 0 {
		return ErrInviteNotFound
	}
	return nil
}

// ValidateInvite checks that a token is active and bound to the supplied
// canonical email. CreateInvitedAccount repeats this check transactionally.
func (s DBStore) ValidateInvite(ctx context.Context, tokenHash []byte, email string, now time.Time) error {
	var exists bool
	err := s.DB.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM invites
			WHERE token_hash = $1
			  AND email = $2
			  AND consumed_at IS NULL
			  AND revoked_at IS NULL
			  AND expires_at > $3
		)`, tokenHash, email, now).Scan(&exists)
	if err != nil {
		return fmt.Errorf("validate invite: %w", err)
	}
	if !exists {
		return ErrInvalidInvite
	}
	return nil
}

// CreateInvitedAccount creates the account material and consumes its invite
// in one transaction. Locking the invite row makes concurrent finishes
// resolve to exactly one successful registration.
func (s DBStore) CreateInvitedAccount(ctx context.Context, tokenHash []byte, account BootstrapAccount, now time.Time) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin invited registration: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var inviteID string
	err = tx.QueryRowContext(ctx, `
		SELECT uuid::text
		FROM invites
		WHERE token_hash = $1
		  AND email = $2
		  AND consumed_at IS NULL
		  AND revoked_at IS NULL
		  AND expires_at > $3
		FOR UPDATE`, tokenHash, account.Email, now).Scan(&inviteID)
	if err == sql.ErrNoRows {
		return ErrInvalidInvite
	}
	if err != nil {
		return fmt.Errorf("lock invite: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		"INSERT INTO accounts (uuid, email, is_administrator) VALUES ($1, $2, FALSE)",
		account.AccountID, account.Email); err != nil {
		return fmt.Errorf("create invited account: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		"INSERT INTO opaque_records (account_uuid, record) VALUES ($1, $2)",
		account.AccountID, account.OpaqueRecord); err != nil {
		return fmt.Errorf("store invited OPAQUE record: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO vault_envelopes (account_uuid, password_vault_envelope, recovery_vault_envelope)
		VALUES ($1, $2, $3)`, account.AccountID, account.PasswordVaultEnvelope, account.RecoveryVaultEnvelope); err != nil {
		return fmt.Errorf("store invited vault envelopes: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE invites
		SET consumed_by = $1, consumed_at = $2
		WHERE uuid = $3`, account.AccountID, now, inviteID); err != nil {
		return fmt.Errorf("consume invite: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit invited registration: %w", err)
	}
	return nil
}

// ListAccounts returns only the UUID, email, and lifecycle status permitted
// on the administrative surface.
func (s DBStore) ListAccounts(ctx context.Context) ([]AccountSummary, error) {
	rows, err := s.DB.QueryContext(ctx, `
		SELECT uuid::text, email, 'active'
		FROM accounts
		ORDER BY created_at, uuid`)
	if err != nil {
		return nil, fmt.Errorf("list accounts: %w", err)
	}
	defer rows.Close()

	var accounts []AccountSummary
	for rows.Next() {
		var account AccountSummary
		if err := rows.Scan(&account.AccountID, &account.Email, &account.Status); err != nil {
			return nil, fmt.Errorf("scan account: %w", err)
		}
		accounts = append(accounts, account)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate accounts: %w", err)
	}
	return accounts, nil
}
