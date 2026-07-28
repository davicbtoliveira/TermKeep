package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib" // PostgreSQL driver for database/sql.
)

const trashRetention = 30 * 24 * time.Hour
const syncChangeRetention = 30 * 24 * time.Hour

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
	DB  *sql.DB
	Now func() time.Time
}

func (s DBStore) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

func trashExpirationCutoff(now time.Time) time.Time {
	return now.Add(-trashRetention)
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

// ListAuditEvents returns operational events in stable reverse chronological
// order. AccountID scopes ordinary users; an empty value is administrative.
func (s DBStore) ListAuditEvents(ctx context.Context, query AuditQuery) ([]AuditEvent, error) {
	var accountID any
	if query.AccountID != "" {
		accountID = query.AccountID
	}
	var beforeAt, beforeID any
	if !query.BeforeAt.IsZero() {
		beforeAt = query.BeforeAt
		beforeID = query.BeforeID
	}
	rows, err := s.DB.QueryContext(ctx, `
		SELECT uuid::text, event_type, COALESCE(account_uuid::text, ''),
		       COALESCE(actor_uuid::text, ''), COALESCE(session_uuid::text, ''),
		       COALESCE(invite_uuid::text, ''), source_ip, occurred_at
		FROM audit_events
		WHERE ($1::uuid IS NULL OR account_uuid = $1)
		  AND ($2::timestamptz IS NULL OR (occurred_at, uuid) < ($2, $3::uuid))
		ORDER BY occurred_at DESC, uuid DESC
		LIMIT $4`, accountID, beforeAt, beforeID, query.Limit)
	if err != nil {
		return nil, fmt.Errorf("list audit events: %w", err)
	}
	defer rows.Close()

	var events []AuditEvent
	for rows.Next() {
		var event AuditEvent
		if err := rows.Scan(
			&event.EventID, &event.Type, &event.AccountID, &event.ActorID,
			&event.SessionID, &event.InviteID, &event.SourceIP, &event.OccurredAt,
		); err != nil {
			return nil, fmt.Errorf("scan audit event: %w", err)
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate audit events: %w", err)
	}
	return events, nil
}

// CreateAuditEvent persists fixed operational metadata only.
func (s DBStore) CreateAuditEvent(ctx context.Context, event AuditEvent) error {
	nullableUUID := func(value string) any {
		if value == "" {
			return nil
		}
		return value
	}
	_, err := s.DB.ExecContext(ctx, `
		INSERT INTO audit_events (
			uuid, event_type, account_uuid, actor_uuid, session_uuid,
			invite_uuid, source_ip, occurred_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		event.EventID, event.Type, nullableUUID(event.AccountID),
		nullableUUID(event.ActorID), nullableUUID(event.SessionID),
		nullableUUID(event.InviteID), event.SourceIP, event.OccurredAt)
	if err != nil {
		return fmt.Errorf("create audit event: %w", err)
	}
	return nil
}

// DeleteAuditEventsBefore enforces configured retention without exposing
// event contents to application logs.
func (s DBStore) DeleteAuditEventsBefore(ctx context.Context, cutoff time.Time) error {
	if _, err := s.DB.ExecContext(ctx,
		"DELETE FROM audit_events WHERE occurred_at < $1", cutoff); err != nil {
		return fmt.Errorf("delete expired audit events: %w", err)
	}
	return nil
}

// PutItem atomically accepts revision 1 for creation or exactly the next
// revision for an existing opaque item.
func (s DBStore) PutItem(ctx context.Context, accountID string, item OpaqueItem) error {
	result, err := s.DB.ExecContext(ctx, `
		INSERT INTO vault_items (
			account_uuid, item_uuid, schema_version, revision, envelope
		)
		SELECT $1::uuid, $2::uuid, $3::integer, $4::bigint, $5::bytea
		WHERE $4::bigint = 1
		ON CONFLICT (account_uuid, item_uuid) DO UPDATE
		SET schema_version = EXCLUDED.schema_version,
		    revision = EXCLUDED.revision,
		    envelope = EXCLUDED.envelope,
		    updated_at = now()
		WHERE vault_items.revision + 1 = EXCLUDED.revision`,
		accountID, item.ItemID, item.SchemaVersion, int64(item.Revision), item.Envelope)
	if err != nil {
		return fmt.Errorf("put opaque item: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("put opaque item rows affected: %w", err)
	}
	if count == 0 {
		return ErrItemRevisionConflict
	}
	return nil
}

// ListItems returns opaque envelopes for one authenticated account.
func (s DBStore) ListItems(ctx context.Context, accountID string) ([]OpaqueItem, error) {
	rows, err := s.DB.QueryContext(ctx, `
		SELECT item_uuid::text, schema_version, revision,
		       deleted, purged, envelope
		FROM vault_items
		WHERE account_uuid = $1 AND NOT deleted
		ORDER BY item_uuid`, accountID)
	if err != nil {
		return nil, fmt.Errorf("list opaque items: %w", err)
	}
	defer rows.Close()

	var items []OpaqueItem
	for rows.Next() {
		var item OpaqueItem
		var revision int64
		if err := rows.Scan(
			&item.ItemID,
			&item.SchemaVersion,
			&revision,
			&item.Deleted,
			&item.Purged,
			&item.Envelope,
		); err != nil {
			return nil, fmt.Errorf("scan opaque item: %w", err)
		}
		item.Revision = uint64(revision)
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate opaque items: %w", err)
	}
	return items, nil
}

// Sync applies an idempotent mutation batch and reads subsequent opaque
// changes in one transaction. The mutation ledger and change cursor commit at
// the same durability boundary as vault_items.
func (s DBStore) Sync(
	ctx context.Context,
	accountID string,
	cursor string,
	mutations []VaultMutation,
) (SyncResult, error) {
	inputCursor, err := parseSyncCursor(cursor)
	if err != nil {
		return SyncResult{}, err
	}
	acceptedAt := s.now()
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return SyncResult{}, fmt.Errorf("begin synchronization: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `
		DELETE FROM vault_changes
		WHERE account_uuid = $1 AND created_at < $2`,
		accountID, acceptedAt.Add(-syncChangeRetention),
	); err != nil {
		return SyncResult{}, fmt.Errorf("prune synchronization changes: %w", err)
	}
	if err := purgeExpiredVaultItems(
		ctx, tx, accountID, acceptedAt,
	); err != nil {
		return SyncResult{}, err
	}

	result := SyncResult{}
	for _, mutation := range mutations {
		applied, err := applyVaultMutation(
			ctx, tx, accountID, mutation, acceptedAt)
		if err != nil {
			return SyncResult{}, err
		}
		if applied {
			result.AppliedMutationIDs = append(
				result.AppliedMutationIDs, mutation.MutationID)
		}
	}

	var currentCursor uint64
	err = tx.QueryRowContext(ctx, `
		SELECT COALESCE(
			(SELECT cursor FROM vault_sync_state WHERE account_uuid = $1),
			0
		)`, accountID).Scan(&currentCursor)
	if err != nil {
		return SyncResult{}, fmt.Errorf("read synchronization cursor: %w", err)
	}
	if inputCursor > currentCursor {
		return SyncResult{}, ErrInvalidSyncCursor
	}

	var retainedChanges uint64
	err = tx.QueryRowContext(ctx, `
		SELECT count(*)
		FROM vault_changes
		WHERE account_uuid = $1
		  AND cursor > $2
		  AND cursor <= $3`,
		accountID, inputCursor, currentCursor,
	).Scan(&retainedChanges)
	if err != nil {
		return SyncResult{}, fmt.Errorf(
			"count retained synchronization changes: %w", err)
	}
	if retainedChanges != currentCursor-inputCursor {
		result.FullSnapshot = true
		if err := appendVaultSnapshot(
			ctx, tx, accountID, &result,
		); err != nil {
			return SyncResult{}, err
		}
		result.Cursor = strconv.FormatUint(currentCursor, 10)
		if err := tx.Commit(); err != nil {
			return SyncResult{}, fmt.Errorf(
				"commit synchronization: %w", err)
		}
		return result, nil
	}

	rows, err := tx.QueryContext(ctx, `
		SELECT cursor, item_uuid::text, schema_version, revision,
		       revision_uuid::text, parent_revision_uuids::text,
		       deleted, purged, envelope
		FROM vault_changes
		WHERE account_uuid = $1 AND cursor > $2
		ORDER BY cursor
		LIMIT 500`, accountID, inputCursor)
	if err != nil {
		return SyncResult{}, fmt.Errorf("list synchronization changes: %w", err)
	}
	outputCursor := inputCursor
	for rows.Next() {
		var (
			item          OpaqueItem
			revision      int64
			change        uint64
			parentIDsText string
		)
		if err := rows.Scan(
			&change,
			&item.ItemID,
			&item.SchemaVersion,
			&revision,
			&item.RevisionID,
			&parentIDsText,
			&item.Deleted,
			&item.Purged,
			&item.Envelope,
		); err != nil {
			rows.Close()
			return SyncResult{}, fmt.Errorf("scan synchronization change: %w", err)
		}
		item.Revision = uint64(revision)
		item.ParentRevisionIDs, err = parsePostgresUUIDArray(parentIDsText)
		if err != nil {
			rows.Close()
			return SyncResult{}, fmt.Errorf(
				"parse synchronization change parents: %w", err)
		}
		result.Changes = append(result.Changes, item)
		outputCursor = change
	}
	if err := rows.Close(); err != nil {
		return SyncResult{}, fmt.Errorf("close synchronization changes: %w", err)
	}
	if err := rows.Err(); err != nil {
		return SyncResult{}, fmt.Errorf("iterate synchronization changes: %w", err)
	}
	result.Cursor = strconv.FormatUint(outputCursor, 10)
	if err := tx.Commit(); err != nil {
		return SyncResult{}, fmt.Errorf("commit synchronization: %w", err)
	}
	return result, nil
}

func purgeExpiredVaultItems(
	ctx context.Context,
	tx *sql.Tx,
	accountID string,
	acceptedAt time.Time,
) error {
	rows, err := tx.QueryContext(ctx, `
		SELECT revision.item_uuid::text,
		       revision.schema_version,
		       revision.revision,
		       revision.revision_uuid::text
		FROM vault_item_heads AS head
		JOIN vault_revisions AS revision
		  ON revision.account_uuid = head.account_uuid
		 AND revision.item_uuid = head.item_uuid
		 AND revision.revision_uuid = head.revision_uuid
		WHERE head.account_uuid = $1
		  AND revision.deleted
		  AND NOT revision.purged
		  AND revision.tombstoned_at <= $2
		  AND NOT EXISTS (
		      SELECT 1
		      FROM vault_item_heads AS other
		      WHERE other.account_uuid = head.account_uuid
		        AND other.item_uuid = head.item_uuid
		        AND other.revision_uuid <> head.revision_uuid
		  )
		ORDER BY revision.item_uuid
		FOR UPDATE OF revision`,
		accountID, trashExpirationCutoff(acceptedAt),
	)
	if err != nil {
		return fmt.Errorf("list expired trash: %w", err)
	}
	type expiredItem struct {
		itemID        string
		schemaVersion int
		revision      int64
		revisionID    string
	}
	var expired []expiredItem
	for rows.Next() {
		var item expiredItem
		if err := rows.Scan(
			&item.itemID,
			&item.schemaVersion,
			&item.revision,
			&item.revisionID,
		); err != nil {
			rows.Close()
			return fmt.Errorf("scan expired trash: %w", err)
		}
		expired = append(expired, item)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close expired trash: %w", err)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate expired trash: %w", err)
	}

	for _, item := range expired {
		if item.revision >= int64(maximumItemRevision) {
			return fmt.Errorf(
				"purge expired trash: %w", ErrItemRevisionConflict)
		}
		var tombstoneID string
		if err := tx.QueryRowContext(
			ctx, "SELECT gen_random_uuid()::text",
		).Scan(&tombstoneID); err != nil {
			return fmt.Errorf("create Tombstone ID: %w", err)
		}
		_, err := applyVaultMutation(
			ctx,
			tx,
			accountID,
			VaultMutation{
				MutationID:   tombstoneID,
				BaseRevision: uint64(item.revision),
				Item: OpaqueItem{
					ItemID:            item.itemID,
					SchemaVersion:     item.schemaVersion,
					Revision:          uint64(item.revision + 1),
					RevisionID:        tombstoneID,
					ParentRevisionIDs: []string{item.revisionID},
					Deleted:           true,
					Purged:            true,
				},
			},
			acceptedAt,
		)
		if err != nil {
			return fmt.Errorf("purge expired trash: %w", err)
		}
	}
	return nil
}

func appendVaultSnapshot(
	ctx context.Context,
	tx *sql.Tx,
	accountID string,
	result *SyncResult,
) error {
	rows, err := tx.QueryContext(ctx, `
		SELECT revision.item_uuid::text,
		       revision.schema_version,
		       revision.revision,
		       revision.revision_uuid::text,
		       revision.parent_revision_uuids::text,
		       revision.deleted,
		       revision.purged,
		       revision.envelope
		FROM vault_item_heads AS head
		JOIN vault_revisions AS revision
		  ON revision.account_uuid = head.account_uuid
		 AND revision.item_uuid = head.item_uuid
		 AND revision.revision_uuid = head.revision_uuid
		WHERE head.account_uuid = $1
		ORDER BY revision.item_uuid, revision.revision_uuid`,
		accountID,
	)
	if err != nil {
		return fmt.Errorf("list full vault snapshot: %w", err)
	}
	for rows.Next() {
		var (
			item          OpaqueItem
			revision      int64
			parentIDsText string
		)
		if err := rows.Scan(
			&item.ItemID,
			&item.SchemaVersion,
			&revision,
			&item.RevisionID,
			&parentIDsText,
			&item.Deleted,
			&item.Purged,
			&item.Envelope,
		); err != nil {
			rows.Close()
			return fmt.Errorf("scan full vault snapshot: %w", err)
		}
		item.Revision = uint64(revision)
		item.ParentRevisionIDs, err =
			parsePostgresUUIDArray(parentIDsText)
		if err != nil {
			rows.Close()
			return fmt.Errorf(
				"parse full vault snapshot parents: %w", err)
		}
		result.Changes = append(result.Changes, item)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close full vault snapshot: %w", err)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate full vault snapshot: %w", err)
	}
	return nil
}

func applyVaultMutation(
	ctx context.Context,
	tx *sql.Tx,
	accountID string,
	mutation VaultMutation,
	acceptedAt time.Time,
) (bool, error) {
	digest := vaultMutationDigest(mutation)
	var (
		itemID        string
		baseRevision  int64
		revision      int64
		revisionID    string
		parentIDsText string
		storedDigest  []byte
	)
	err := tx.QueryRowContext(ctx, `
		SELECT item_uuid::text, base_revision, revision,
		       revision_uuid::text, parent_revision_uuids::text,
		       envelope_sha256
		FROM vault_mutations
		WHERE account_uuid = $1 AND mutation_uuid = $2`,
		accountID, mutation.MutationID).Scan(
		&itemID, &baseRevision, &revision, &revisionID,
		&parentIDsText, &storedDigest)
	switch {
	case err == nil:
		if itemID != mutation.Item.ItemID ||
			uint64(baseRevision) != mutation.BaseRevision ||
			uint64(revision) != mutation.Item.Revision ||
			revisionID != mutation.Item.RevisionID ||
			!bytes.Equal(storedDigest, digest[:]) {
			return false, ErrMutationIDReuse
		}
		return true, nil
	case !errors.Is(err, sql.ErrNoRows):
		return false, fmt.Errorf("read mutation ledger: %w", err)
	}

	parentsArray := "{" + strings.Join(
		mutation.Item.ParentRevisionIDs, ",") + "}"
	if mutation.BaseRevision == 0 {
		var exists bool
		err = tx.QueryRowContext(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM vault_revisions
				WHERE account_uuid = $1 AND item_uuid = $2
			) OR EXISTS (
				SELECT 1 FROM vault_items
				WHERE account_uuid = $1 AND item_uuid = $2
			)`, accountID, mutation.Item.ItemID).Scan(&exists)
		if err != nil {
			return false, fmt.Errorf("check initial revision: %w", err)
		}
		if exists {
			return false, ErrItemRevisionConflict
		}
	} else {
		var (
			parentCount int
			maxRevision int64
		)
		err = tx.QueryRowContext(ctx, `
			SELECT count(*), COALESCE(max(revision), 0)
			FROM vault_revisions
			WHERE account_uuid = $1
			  AND item_uuid = $2
			  AND revision_uuid = ANY($3::uuid[])`,
			accountID, mutation.Item.ItemID, parentsArray,
		).Scan(&parentCount, &maxRevision)
		if err != nil {
			return false, fmt.Errorf("read revision parents: %w", err)
		}
		if parentCount != len(mutation.Item.ParentRevisionIDs) ||
			uint64(maxRevision) != mutation.BaseRevision {
			return false, ErrItemRevisionConflict
		}
		var (
			headCount         int
			parentHeadCount   int
			purgedParentHeads int
		)
		err = tx.QueryRowContext(ctx, `
			SELECT
				count(*),
				count(*) FILTER (
					WHERE head.revision_uuid = ANY($3::uuid[])
				),
				count(*) FILTER (
					WHERE head.revision_uuid = ANY($3::uuid[])
					  AND revision.purged
				)
			FROM vault_item_heads AS head
			JOIN vault_revisions AS revision
			  ON revision.account_uuid = head.account_uuid
			 AND revision.revision_uuid = head.revision_uuid
			WHERE head.account_uuid = $1
			  AND head.item_uuid = $2`,
			accountID, mutation.Item.ItemID, parentsArray,
		).Scan(&headCount, &parentHeadCount, &purgedParentHeads)
		if err != nil {
			return false, fmt.Errorf("read revision heads: %w", err)
		}
		if mutation.Item.Purged && parentHeadCount != headCount {
			return false, ErrItemRevisionConflict
		}
		if !mutation.Item.Deleted &&
			len(mutation.Item.ParentRevisionIDs) == 1 &&
			purgedParentHeads == 1 {
			return false, ErrItemRevisionConflict
		}
	}

	result, err := tx.ExecContext(ctx, `
		INSERT INTO vault_revisions (
			account_uuid, revision_uuid, item_uuid, schema_version,
			revision, parent_revision_uuids, envelope, deleted, purged,
			content_purged, created_at, tombstoned_at
		)
		VALUES (
			$1, $2, $3, $4, $5,
			$6::uuid[],
			$7, $8, $9, $9,
			$10::timestamptz,
			CASE WHEN $8 THEN $10::timestamptz ELSE NULL END
		)
		ON CONFLICT DO NOTHING`,
		accountID,
		mutation.Item.RevisionID,
		mutation.Item.ItemID,
		mutation.Item.SchemaVersion,
		int64(mutation.Item.Revision),
		parentsArray,
		mutation.Item.Envelope,
		mutation.Item.Deleted,
		mutation.Item.Purged,
		acceptedAt,
	)
	if err != nil {
		return false, fmt.Errorf("append vault revision: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("read appended vault revision: %w", err)
	}
	if count != 1 {
		return false, ErrMutationIDReuse
	}

	if _, err := tx.ExecContext(ctx, `
		DELETE FROM vault_item_heads
		WHERE account_uuid = $1
		  AND item_uuid = $2
		  AND revision_uuid = ANY($3::uuid[])`,
		accountID, mutation.Item.ItemID, parentsArray,
	); err != nil {
		return false, fmt.Errorf("replace parent revision heads: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO vault_item_heads (
			account_uuid, item_uuid, revision_uuid
		)
		VALUES ($1, $2, $3)`,
		accountID, mutation.Item.ItemID, mutation.Item.RevisionID,
	); err != nil {
		return false, fmt.Errorf("record revision head: %w", err)
	}
	if mutation.Item.Purged {
		if _, err := tx.ExecContext(ctx, `
			UPDATE vault_revisions
			SET envelope = NULL,
			    content_purged = true
			WHERE account_uuid = $1
			  AND item_uuid = $2
			  AND revision_uuid <> $3`,
			accountID,
			mutation.Item.ItemID,
			mutation.Item.RevisionID,
		); err != nil {
			return false, fmt.Errorf("purge revision content: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `
			DELETE FROM vault_changes
			WHERE account_uuid = $1 AND item_uuid = $2`,
			accountID, mutation.Item.ItemID,
		); err != nil {
			return false, fmt.Errorf("remove purged change content: %w", err)
		}
	}

	var headCount int
	err = tx.QueryRowContext(ctx, `
		SELECT count(*)
		FROM vault_item_heads
		WHERE account_uuid = $1 AND item_uuid = $2`,
		accountID, mutation.Item.ItemID).Scan(&headCount)
	if err != nil {
		return false, fmt.Errorf("count revision heads: %w", err)
	}
	if headCount == 1 {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO vault_items (
				account_uuid, item_uuid, schema_version, revision,
				deleted, purged, envelope
			)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
			ON CONFLICT (account_uuid, item_uuid) DO UPDATE
			SET schema_version = EXCLUDED.schema_version,
			    revision = EXCLUDED.revision,
			    deleted = EXCLUDED.deleted,
			    purged = EXCLUDED.purged,
			    envelope = EXCLUDED.envelope,
			    updated_at = $8`,
			accountID,
			mutation.Item.ItemID,
			mutation.Item.SchemaVersion,
			int64(mutation.Item.Revision),
			mutation.Item.Deleted,
			mutation.Item.Purged,
			mutation.Item.Envelope,
			acceptedAt,
		); err != nil {
			return false, fmt.Errorf("project unconflicted revision: %w", err)
		}
	}

	var changeCursor int64
	err = tx.QueryRowContext(ctx, `
		INSERT INTO vault_sync_state (account_uuid, cursor)
		VALUES ($1, 1)
		ON CONFLICT (account_uuid) DO UPDATE
		SET cursor = vault_sync_state.cursor + 1
		RETURNING cursor`, accountID).Scan(&changeCursor)
	if err != nil {
		return false, fmt.Errorf("advance synchronization cursor: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO vault_changes (
			account_uuid, cursor, item_uuid, schema_version, revision,
			revision_uuid, parent_revision_uuids, deleted, purged, envelope,
			created_at
		)
		VALUES (
			$1, $2, $3, $4, $5, $6,
			$7::uuid[],
			$8, $9, $10, $11
		)`,
		accountID,
		changeCursor,
		mutation.Item.ItemID,
		mutation.Item.SchemaVersion,
		int64(mutation.Item.Revision),
		mutation.Item.RevisionID,
		parentsArray,
		mutation.Item.Deleted,
		mutation.Item.Purged,
		mutation.Item.Envelope,
		acceptedAt,
	); err != nil {
		return false, fmt.Errorf("record synchronization change: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO vault_mutations (
			account_uuid, mutation_uuid, item_uuid, base_revision,
			revision, revision_uuid, parent_revision_uuids,
			envelope_sha256, change_cursor, created_at
		)
		VALUES (
			$1, $2, $3, $4, $5, $6,
			$7::uuid[],
			$8, $9, $10
		)`,
		accountID,
		mutation.MutationID,
		mutation.Item.ItemID,
		int64(mutation.BaseRevision),
		int64(mutation.Item.Revision),
		mutation.Item.RevisionID,
		parentsArray,
		digest[:],
		changeCursor,
		acceptedAt,
	); err != nil {
		return false, fmt.Errorf("record mutation ledger: %w", err)
	}
	return true, nil
}

func parseSyncCursor(value string) (uint64, error) {
	if value == "" {
		return 0, nil
	}
	cursor, err := strconv.ParseUint(value, 10, 63)
	if err != nil {
		return 0, ErrInvalidSyncCursor
	}
	return cursor, nil
}

func vaultMutationDigest(mutation VaultMutation) [sha256.Size]byte {
	hash := sha256.New()
	_, _ = fmt.Fprintf(
		hash,
		"%s\n%d\n%s\n%d\n%d\n%s\n%t\n%t\n",
		mutation.MutationID,
		mutation.BaseRevision,
		mutation.Item.ItemID,
		mutation.Item.SchemaVersion,
		mutation.Item.Revision,
		mutation.Item.RevisionID,
		mutation.Item.Deleted,
		mutation.Item.Purged,
	)
	parentIDs := append([]string(nil), mutation.Item.ParentRevisionIDs...)
	sort.Strings(parentIDs)
	for _, parentID := range parentIDs {
		_, _ = fmt.Fprintln(hash, parentID)
	}
	_, _ = hash.Write(mutation.Item.Envelope)
	var digest [sha256.Size]byte
	copy(digest[:], hash.Sum(nil))
	return digest
}

func parsePostgresUUIDArray(value string) ([]string, error) {
	if value == "{}" {
		return []string{}, nil
	}
	if len(value) < 2 || value[0] != '{' || value[len(value)-1] != '}' {
		return nil, errors.New("invalid UUID array")
	}
	values := make([]string, 0)
	for _, entry := range bytes.Split([]byte(value[1:len(value)-1]), []byte(",")) {
		id := string(entry)
		if !validUUID(id) {
			return nil, errors.New("invalid revision UUID")
		}
		values = append(values, id)
	}
	return values, nil
}
