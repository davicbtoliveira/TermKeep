-- Append-only revision DAG. Mutation UUIDs become immutable revision UUIDs
-- for new writes; deterministic UUIDs identify history created before this
-- migration.
CREATE TABLE vault_revisions (
    account_uuid         UUID NOT NULL REFERENCES accounts(uuid) ON DELETE CASCADE,
    revision_uuid        UUID NOT NULL,
    item_uuid            UUID NOT NULL,
    schema_version       INTEGER NOT NULL CHECK (schema_version > 0),
    revision             BIGINT NOT NULL CHECK (revision > 0),
    parent_revision_uuids UUID[] NOT NULL DEFAULT '{}',
    envelope             BYTEA NOT NULL,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (account_uuid, revision_uuid),
    UNIQUE (account_uuid, item_uuid, revision_uuid)
);

CREATE INDEX idx_vault_revisions_account_item
    ON vault_revisions(account_uuid, item_uuid, revision);

ALTER TABLE vault_changes
    ADD COLUMN revision_uuid UUID,
    ADD COLUMN parent_revision_uuids UUID[];

UPDATE vault_changes AS change
SET revision_uuid = md5(
        change.account_uuid::text || ':' ||
        change.item_uuid::text || ':' ||
        change.revision::text
    )::uuid,
    parent_revision_uuids = CASE
        WHEN EXISTS (
            SELECT 1
            FROM vault_changes AS parent
            WHERE parent.account_uuid = change.account_uuid
              AND parent.item_uuid = change.item_uuid
              AND parent.revision = change.revision - 1
        )
        THEN ARRAY[
            md5(
                change.account_uuid::text || ':' ||
                change.item_uuid::text || ':' ||
                (change.revision - 1)::text
            )::uuid
        ]
        ELSE '{}'::uuid[]
    END;

ALTER TABLE vault_changes
    ALTER COLUMN revision_uuid SET NOT NULL,
    ALTER COLUMN parent_revision_uuids SET NOT NULL;

INSERT INTO vault_revisions (
    account_uuid, revision_uuid, item_uuid, schema_version, revision,
    parent_revision_uuids, envelope, created_at
)
SELECT account_uuid, revision_uuid, item_uuid, schema_version, revision,
       parent_revision_uuids, envelope, created_at
FROM vault_changes
ON CONFLICT (account_uuid, revision_uuid) DO NOTHING;

CREATE TABLE vault_item_heads (
    account_uuid  UUID NOT NULL,
    item_uuid     UUID NOT NULL,
    revision_uuid UUID NOT NULL,
    PRIMARY KEY (account_uuid, item_uuid, revision_uuid),
    FOREIGN KEY (account_uuid, item_uuid, revision_uuid)
        REFERENCES vault_revisions(account_uuid, item_uuid, revision_uuid)
        ON DELETE CASCADE
);

INSERT INTO vault_item_heads (account_uuid, item_uuid, revision_uuid)
SELECT DISTINCT ON (account_uuid, item_uuid)
       account_uuid, item_uuid, revision_uuid
FROM vault_revisions
ORDER BY account_uuid, item_uuid, revision DESC, created_at DESC;

ALTER TABLE vault_mutations
    ADD COLUMN revision_uuid UUID,
    ADD COLUMN parent_revision_uuids UUID[];

UPDATE vault_mutations AS mutation
SET revision_uuid = change.revision_uuid,
    parent_revision_uuids = change.parent_revision_uuids
FROM vault_changes AS change
WHERE change.account_uuid = mutation.account_uuid
  AND change.cursor = mutation.change_cursor;

ALTER TABLE vault_mutations
    ALTER COLUMN revision_uuid SET NOT NULL,
    ALTER COLUMN parent_revision_uuids SET NOT NULL;
