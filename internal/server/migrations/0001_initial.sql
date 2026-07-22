-- Initial TermKeep schema: one row per account, no credential material.
-- OPAQUE envelopes and vault blobs arrive in later migrations; the server
-- must never store anything that can decrypt a vault.
CREATE TABLE accounts (
    uuid       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email      TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
