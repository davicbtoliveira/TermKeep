-- Encrypted trash, permanent Tombstones, and prunable change history.
ALTER TABLE vault_revisions
    ALTER COLUMN envelope DROP NOT NULL,
    ADD COLUMN deleted BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN purged BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN content_purged BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN tombstoned_at TIMESTAMPTZ,
    ADD CONSTRAINT vault_revisions_content_state CHECK (
        (content_purged AND envelope IS NULL) OR
        (NOT content_purged AND envelope IS NOT NULL)
    ),
    ADD CONSTRAINT vault_revisions_tombstone_state CHECK (
        NOT purged OR (deleted AND content_purged)
    );

CREATE INDEX idx_vault_revisions_expired_trash
    ON vault_revisions(account_uuid, tombstoned_at)
    WHERE deleted AND NOT purged;

ALTER TABLE vault_changes
    ALTER COLUMN envelope DROP NOT NULL,
    ADD COLUMN deleted BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN purged BOOLEAN NOT NULL DEFAULT false,
    ADD CONSTRAINT vault_changes_content_state CHECK (
        (purged AND deleted AND envelope IS NULL) OR
        (NOT purged AND envelope IS NOT NULL)
    );

ALTER TABLE vault_items
    ALTER COLUMN envelope DROP NOT NULL,
    ADD COLUMN deleted BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN purged BOOLEAN NOT NULL DEFAULT false,
    ADD CONSTRAINT vault_items_content_state CHECK (
        (purged AND deleted AND envelope IS NULL) OR
        (NOT purged AND envelope IS NOT NULL)
    );

-- Mutation idempotency remains durable after old incremental changes are
-- pruned. change_cursor remains useful technical metadata, not ownership.
ALTER TABLE vault_mutations
    DROP CONSTRAINT vault_mutations_account_uuid_change_cursor_fkey;
