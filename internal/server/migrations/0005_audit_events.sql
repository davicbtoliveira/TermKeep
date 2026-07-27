-- Security audit events use fixed operational fields. No free-form payload
-- exists where vault content or raw authentication material could leak.
CREATE TABLE audit_events (
    uuid          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_type    TEXT NOT NULL,
    account_uuid  UUID,
    actor_uuid    UUID,
    session_uuid  UUID,
    invite_uuid   UUID,
    source_ip     TEXT NOT NULL DEFAULT '',
    occurred_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_audit_events_account_time
    ON audit_events(account_uuid, occurred_at DESC, uuid DESC);

CREATE INDEX idx_audit_events_time
    ON audit_events(occurred_at DESC, uuid DESC);
