ALTER TABLE admin_sessions
    ADD COLUMN csrf_hash BYTEA NOT NULL DEFAULT decode(repeat('00', 32), 'hex')
        CHECK (octet_length(csrf_hash) = 32),
    ADD COLUMN acr TEXT NOT NULL DEFAULT ''
        CHECK (length(acr) <= 512);

UPDATE admin_sessions SET revoked_at = COALESCE(revoked_at, now());

CREATE TABLE oidc_login_transactions (
    state_hash BYTEA PRIMARY KEY CHECK (octet_length(state_hash) = 32),
    browser_hash BYTEA NOT NULL CHECK (octet_length(browser_hash) = 32),
    nonce TEXT NOT NULL CHECK (length(nonce) BETWEEN 32 AND 128),
    code_verifier TEXT NOT NULL CHECK (length(code_verifier) BETWEEN 43 AND 128),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    CHECK (expires_at > created_at)
);
CREATE INDEX oidc_login_transactions_expiry ON oidc_login_transactions(expires_at);

CREATE TABLE admin_auth_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor TEXT NOT NULL CHECK (length(actor) BETWEEN 1 AND 128),
    action TEXT NOT NULL CHECK (action IN ('admin.login', 'admin.logout')),
    outcome TEXT NOT NULL CHECK (outcome IN ('success', 'denied')),
    correlation_id TEXT NOT NULL CHECK (length(correlation_id) BETWEEN 1 AND 128),
    reason_code TEXT NOT NULL CHECK (length(reason_code) BETWEEN 1 AND 128)
);
CREATE INDEX admin_auth_events_occurred_at ON admin_auth_events(occurred_at DESC, id DESC);

CREATE FUNCTION qg_reject_admin_auth_event_mutation() RETURNS trigger
LANGUAGE plpgsql
AS $function$
BEGIN
    RAISE EXCEPTION 'administrator authentication events are append-only';
END;
$function$;
CREATE TRIGGER admin_auth_events_append_only
    BEFORE UPDATE OR DELETE ON admin_auth_events
    FOR EACH ROW EXECUTE FUNCTION qg_reject_admin_auth_event_mutation();
