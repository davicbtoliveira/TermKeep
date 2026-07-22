-- First-account bootstrap: OPAQUE data and vault envelopes are opaque bytes.
-- The server has no password, recovery key, or decryptable vault material.
ALTER TABLE accounts
    ADD COLUMN is_administrator BOOLEAN NOT NULL DEFAULT FALSE;

CREATE TABLE opaque_records (
    account_uuid  UUID PRIMARY KEY REFERENCES accounts(uuid) ON DELETE CASCADE,
    record        BYTEA NOT NULL
);

CREATE TABLE vault_envelopes (
    account_uuid               UUID PRIMARY KEY REFERENCES accounts(uuid) ON DELETE CASCADE,
    password_vault_envelope    BYTEA NOT NULL,
    recovery_vault_envelope    BYTEA NOT NULL,
    format_version             SMALLINT NOT NULL DEFAULT 1 CHECK (format_version > 0)
);
