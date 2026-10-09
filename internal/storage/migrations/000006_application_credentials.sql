ALTER TABLE public.application_credentials
    ADD COLUMN scopes TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[];

-- Previously issued credentials had no declared permissions. Revoke them before
-- enforcing the new scope contract so they cannot silently retain broad access.
UPDATE public.application_credentials
SET revoked_at = COALESCE(revoked_at, clock_timestamp())
WHERE cardinality(scopes) = 0;

ALTER TABLE public.application_credentials
    ADD CONSTRAINT application_credentials_scopes_check CHECK (
        cardinality(scopes) BETWEEN 1 AND 8
        AND scopes <@ ARRAY['decisions:evaluate', 'observations:write', 'posture:read', 'events:write']::TEXT[]
    );

CREATE INDEX application_credentials_active_app
    ON public.application_credentials(tenant_id, application_id, created_at DESC)
    WHERE revoked_at IS NULL;
