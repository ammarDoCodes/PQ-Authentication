CREATE TABLE public.service_access_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    application_id UUID NOT NULL,
    credential_id UUID NOT NULL,
    token_hash BYTEA NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
    scopes TEXT[] NOT NULL CHECK (
        cardinality(scopes) BETWEEN 1 AND 8
        AND scopes <@ ARRAY['decisions:evaluate', 'observations:write', 'posture:read', 'events:write']::TEXT[]
    ),
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    CHECK (expires_at > created_at AND expires_at <= created_at + interval '5 minutes'),
    FOREIGN KEY (tenant_id, application_id) REFERENCES public.applications(tenant_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, credential_id) REFERENCES public.application_credentials(tenant_id, id) ON DELETE RESTRICT,
    UNIQUE (tenant_id, id)
);
CREATE INDEX service_access_tokens_application_expiry
    ON public.service_access_tokens(tenant_id, application_id, expires_at)
    WHERE revoked_at IS NULL;
ALTER TABLE public.service_access_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.service_access_tokens FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON public.service_access_tokens
    USING (tenant_id = NULLIF(current_setting('qg.tenant_id', true), '')::UUID)
    WITH CHECK (tenant_id = NULLIF(current_setting('qg.tenant_id', true), '')::UUID);
CREATE POLICY qg_service_token_auth_owner ON public.service_access_tokens FOR SELECT
    USING (current_user = pg_catalog.pg_get_userbyid((SELECT relowner FROM pg_catalog.pg_class WHERE oid = 'public.service_access_tokens'::regclass)));

-- The SECURITY DEFINER lookup can see only the rows needed to authenticate a
-- caller. Runtime sessions cannot assume the migration role or use these
-- owner-only SELECT policies directly.
CREATE POLICY qg_service_credential_auth_owner ON public.tenants FOR SELECT
    USING (current_user = pg_catalog.pg_get_userbyid((SELECT relowner FROM pg_catalog.pg_class WHERE oid = 'public.tenants'::regclass)));
CREATE POLICY qg_service_credential_auth_owner ON public.applications FOR SELECT
    USING (current_user = pg_catalog.pg_get_userbyid((SELECT relowner FROM pg_catalog.pg_class WHERE oid = 'public.applications'::regclass)));
CREATE POLICY qg_service_credential_auth_owner ON public.application_credentials FOR SELECT
    USING (current_user = pg_catalog.pg_get_userbyid((SELECT relowner FROM pg_catalog.pg_class WHERE oid = 'public.application_credentials'::regclass)));

CREATE FUNCTION public.qg_authenticate_application_credential(p_application_id UUID, p_credential_hash BYTEA)
RETURNS TABLE(tenant_id UUID, application_id UUID, credential_id UUID, scopes TEXT[])
LANGUAGE SQL VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $function$
    SELECT app.tenant_id, app.id, credential.id, credential.scopes
    FROM public.applications AS app
    JOIN public.tenants AS tenant ON tenant.id = app.tenant_id
    JOIN public.application_credentials AS credential
      ON credential.tenant_id = app.tenant_id AND credential.application_id = app.id
    WHERE app.id = p_application_id
      AND octet_length(p_credential_hash) = 32
      AND credential.credential_hash = p_credential_hash
      AND credential.revoked_at IS NULL
      AND credential.expires_at > clock_timestamp()
      AND app.status = 'active'
      AND tenant.status = 'active'
$function$;

CREATE FUNCTION public.qg_validate_service_access_token(p_token_hash BYTEA)
RETURNS TABLE(tenant_id UUID, application_id UUID, credential_id UUID, token_id UUID, scopes TEXT[], expires_at TIMESTAMPTZ)
LANGUAGE SQL VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $function$
    SELECT token.tenant_id, token.application_id, token.credential_id, token.id, token.scopes, token.expires_at
    FROM public.service_access_tokens AS token
    JOIN public.application_credentials AS credential
      ON credential.tenant_id = token.tenant_id AND credential.id = token.credential_id
    JOIN public.applications AS app
      ON app.tenant_id = token.tenant_id AND app.id = token.application_id
    JOIN public.tenants AS tenant ON tenant.id = token.tenant_id
    WHERE octet_length(p_token_hash) = 32
      AND token.token_hash = p_token_hash
      AND token.revoked_at IS NULL
      AND token.expires_at > clock_timestamp()
      AND credential.revoked_at IS NULL
      AND credential.expires_at > clock_timestamp()
      AND app.status = 'active'
      AND tenant.status = 'active'
$function$;

REVOKE ALL ON FUNCTION public.qg_authenticate_application_credential(UUID, BYTEA) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.qg_validate_service_access_token(BYTEA) FROM PUBLIC;
DO $block$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'quantumgate') THEN
        GRANT EXECUTE ON FUNCTION public.qg_authenticate_application_credential(UUID, BYTEA) TO quantumgate;
        GRANT EXECUTE ON FUNCTION public.qg_validate_service_access_token(BYTEA) TO quantumgate;
    END IF;
END
$block$;
