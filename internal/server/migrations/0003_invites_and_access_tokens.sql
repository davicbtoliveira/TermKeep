-- Migration 0003: invites and access tokens table schema.
CREATE TABLE access_tokens (
    token_hash     BYTEA PRIMARY KEY,
    account_uuid   UUID NOT NULL REFERENCES accounts(uuid) ON DELETE CASCADE,
    email          TEXT NOT NULL,
    administrator  BOOLEAN NOT NULL,
    expires_at     TIMESTAMPTZ NOT NULL
);

CREATE TABLE invites (
    uuid         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email        TEXT NOT NULL,
    token_hash   BYTEA NOT NULL,
    created_by   UUID NOT NULL REFERENCES accounts(uuid) ON DELETE CASCADE,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at   TIMESTAMPTZ NOT NULL,
    consumed_by  UUID REFERENCES accounts(uuid) ON DELETE SET NULL,
    consumed_at  TIMESTAMPTZ,
    revoked_at   TIMESTAMPTZ
);

CREATE INDEX idx_access_tokens_expires_at ON access_tokens(expires_at);
CREATE INDEX idx_invites_email ON invites(email);
