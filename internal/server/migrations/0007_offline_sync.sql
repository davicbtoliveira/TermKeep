-- Durable idempotent mutations and per-account incremental change cursors.
CREATE TABLE vault_sync_state (
    account_uuid UUID PRIMARY KEY REFERENCES accounts(uuid) ON DELETE CASCADE,
    cursor       BIGINT NOT NULL CHECK (cursor >= 0)
);

CREATE TABLE vault_changes (
    account_uuid   UUID NOT NULL REFERENCES accounts(uuid) ON DELETE CASCADE,
    cursor         BIGINT NOT NULL CHECK (cursor > 0),
    item_uuid      UUID NOT NULL,
    schema_version INTEGER NOT NULL CHECK (schema_version > 0),
    revision       BIGINT NOT NULL CHECK (revision > 0),
    envelope       BYTEA NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (account_uuid, cursor)
);

CREATE INDEX idx_vault_changes_account_item
    ON vault_changes(account_uuid, item_uuid, cursor);

-- Existing current items become initial change history for upgraded Clients.
INSERT INTO vault_changes (
    account_uuid, cursor, item_uuid, schema_version, revision, envelope,
    created_at
)
SELECT account_uuid,
       row_number() OVER (
           PARTITION BY account_uuid ORDER BY item_uuid
       ),
       item_uuid, schema_version, revision, envelope, updated_at
FROM vault_items;

INSERT INTO vault_sync_state (account_uuid, cursor)
SELECT account_uuid, max(cursor)
FROM vault_changes
GROUP BY account_uuid;

CREATE TABLE vault_mutations (
    account_uuid    UUID NOT NULL REFERENCES accounts(uuid) ON DELETE CASCADE,
    mutation_uuid   UUID NOT NULL,
    item_uuid       UUID NOT NULL,
    base_revision   BIGINT NOT NULL CHECK (base_revision >= 0),
    revision        BIGINT NOT NULL CHECK (revision = base_revision + 1),
    envelope_sha256 BYTEA NOT NULL,
    change_cursor   BIGINT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (account_uuid, mutation_uuid),
    FOREIGN KEY (account_uuid, change_cursor)
        REFERENCES vault_changes(account_uuid, cursor) ON DELETE CASCADE
);
