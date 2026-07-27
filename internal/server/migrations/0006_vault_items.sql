-- Encrypted vault records. The server understands only account ownership,
-- opaque item UUID, schema version, revision, and ciphertext envelope.
CREATE TABLE vault_items (
    account_uuid   UUID NOT NULL REFERENCES accounts(uuid) ON DELETE CASCADE,
    item_uuid      UUID NOT NULL,
    schema_version INTEGER NOT NULL CHECK (schema_version > 0),
    revision       BIGINT NOT NULL CHECK (revision > 0),
    envelope       BYTEA NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (account_uuid, item_uuid)
);

CREATE INDEX idx_vault_items_account
    ON vault_items(account_uuid, item_uuid);
