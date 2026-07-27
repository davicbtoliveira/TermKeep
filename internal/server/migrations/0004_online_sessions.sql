-- Full online sessions replace the bootstrap slice's short-lived tokens.
ALTER TABLE access_tokens
    ADD COLUMN session_uuid UUID NOT NULL DEFAULT gen_random_uuid(),
    ADD COLUMN host TEXT NOT NULL DEFAULT 'unknown',
    ADD COLUMN source_ip TEXT NOT NULL DEFAULT '',
    ADD COLUMN created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    ADD COLUMN last_used_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    ADD COLUMN revoked_at TIMESTAMPTZ,
    DROP COLUMN expires_at;

CREATE UNIQUE INDEX idx_access_tokens_session_uuid
    ON access_tokens(session_uuid);

CREATE INDEX idx_access_tokens_account_active
    ON access_tokens(account_uuid)
    WHERE revoked_at IS NULL;
