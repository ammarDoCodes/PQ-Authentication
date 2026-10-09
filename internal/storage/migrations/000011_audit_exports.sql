CREATE TABLE export_jobs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    row_count INTEGER NOT NULL CHECK (row_count BETWEEN 0 AND 5000),
    payload_ciphertext BYTEA NOT NULL CHECK (octet_length(payload_ciphertext) BETWEEN 33 AND 8388608),
    UNIQUE (tenant_id, id),
    CHECK (expires_at > requested_at)
);
CREATE INDEX export_jobs_tenant_expiry ON export_jobs(tenant_id, expires_at);
ALTER TABLE export_jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE export_jobs FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON export_jobs
    USING (tenant_id = NULLIF(current_setting('qg.tenant_id', true), '')::UUID)
    WITH CHECK (tenant_id = NULLIF(current_setting('qg.tenant_id', true), '')::UUID);

CREATE FUNCTION public.qg_purge_expired_exports(p_tenant_id UUID, p_batch_limit INTEGER)
RETURNS INTEGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $function$
DECLARE
    deleted_count INTEGER;
BEGIN
    WITH expired AS (
        SELECT id FROM public.export_jobs
        WHERE tenant_id = p_tenant_id AND expires_at <= pg_catalog.now()
        ORDER BY expires_at
        LIMIT GREATEST(1, LEAST(COALESCE(p_batch_limit, 100), 100))
    )
    DELETE FROM public.export_jobs AS exports
    USING expired
    WHERE exports.tenant_id = p_tenant_id AND exports.id = expired.id;
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$function$;
REVOKE ALL ON FUNCTION public.qg_purge_expired_exports(UUID, INTEGER) FROM PUBLIC;
REVOKE UPDATE, DELETE ON TABLE export_jobs FROM PUBLIC;

DO $block$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'quantumgate') THEN
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.qg_purge_expired_exports(UUID, INTEGER) TO quantumgate';
        EXECUTE 'REVOKE UPDATE, DELETE ON TABLE public.export_jobs FROM quantumgate';
    END IF;
END
$block$;
