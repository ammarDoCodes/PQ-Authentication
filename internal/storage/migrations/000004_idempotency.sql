CREATE TABLE idempotency_records (
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    key_hash BYTEA NOT NULL CHECK (octet_length(key_hash) = 32),
    request_hash BYTEA NOT NULL CHECK (octet_length(request_hash) = 32),
    response_status INTEGER,
    response_headers JSONB,
    response_body BYTEA,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL DEFAULT now() + interval '24 hours',
    PRIMARY KEY (tenant_id, key_hash),
    CHECK (expires_at > created_at),
    CHECK (
        (response_status IS NULL AND response_headers IS NULL AND response_body IS NULL)
        OR
        (response_status BETWEEN 200 AND 499 AND jsonb_typeof(response_headers) = 'object' AND response_body IS NOT NULL)
    )
);
CREATE INDEX idempotency_records_expiry ON idempotency_records(tenant_id, expires_at);
ALTER TABLE idempotency_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE idempotency_records FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON idempotency_records
    USING (tenant_id = NULLIF(current_setting('qg.tenant_id', true), '')::UUID)
    WITH CHECK (tenant_id = NULLIF(current_setting('qg.tenant_id', true), '')::UUID);
