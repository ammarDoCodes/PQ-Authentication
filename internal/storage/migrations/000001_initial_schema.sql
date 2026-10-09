CREATE TABLE tenants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    display_name TEXT NOT NULL CHECK (length(display_name) BETWEEN 1 AND 120),
    status TEXT NOT NULL CHECK (status IN ('active', 'suspended', 'deleting')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenants FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tenants
    USING (id = NULLIF(current_setting('qg.tenant_id', true), '')::UUID)
    WITH CHECK (id = NULLIF(current_setting('qg.tenant_id', true), '')::UUID);

CREATE TABLE tenant_members (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    issuer TEXT NOT NULL CHECK (length(issuer) BETWEEN 1 AND 2048),
    subject TEXT NOT NULL CHECK (length(subject) BETWEEN 1 AND 512),
    role TEXT NOT NULL CHECK (role IN ('tenant_admin', 'security_engineer', 'developer', 'auditor')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, issuer, subject),
    UNIQUE (tenant_id, id)
);
ALTER TABLE tenant_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_members FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tenant_members
    USING (tenant_id = NULLIF(current_setting('qg.tenant_id', true), '')::UUID)
    WITH CHECK (tenant_id = NULLIF(current_setting('qg.tenant_id', true), '')::UUID);

CREATE TABLE environments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 80),
    lifecycle TEXT NOT NULL CHECK (lifecycle IN ('development', 'staging', 'production')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, name),
    UNIQUE (tenant_id, id)
);
ALTER TABLE environments ENABLE ROW LEVEL SECURITY;
ALTER TABLE environments FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON environments
    USING (tenant_id = NULLIF(current_setting('qg.tenant_id', true), '')::UUID)
    WITH CHECK (tenant_id = NULLIF(current_setting('qg.tenant_id', true), '')::UUID);

CREATE TABLE applications (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    environment_id UUID NOT NULL,
    external_id TEXT NOT NULL CHECK (length(external_id) BETWEEN 1 AND 128),
    display_name TEXT NOT NULL CHECK (length(display_name) BETWEEN 1 AND 120),
    integration_mode TEXT NOT NULL CHECK (integration_mode IN ('sdk', 'gateway', 'control-plane')),
    status TEXT NOT NULL CHECK (status IN ('active', 'disabled')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, external_id),
    UNIQUE (tenant_id, id),
    FOREIGN KEY (tenant_id, environment_id) REFERENCES environments(tenant_id, id) ON DELETE RESTRICT
);
ALTER TABLE applications ENABLE ROW LEVEL SECURITY;
ALTER TABLE applications FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON applications
    USING (tenant_id = NULLIF(current_setting('qg.tenant_id', true), '')::UUID)
    WITH CHECK (tenant_id = NULLIF(current_setting('qg.tenant_id', true), '')::UUID);

CREATE TABLE application_credentials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    application_id UUID NOT NULL,
    credential_hash BYTEA NOT NULL UNIQUE CHECK (octet_length(credential_hash) = 32),
    label TEXT NOT NULL CHECK (length(label) BETWEEN 1 AND 80),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    FOREIGN KEY (tenant_id, application_id) REFERENCES applications(tenant_id, id) ON DELETE RESTRICT,
    UNIQUE (tenant_id, id)
);
ALTER TABLE application_credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE application_credentials FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON application_credentials
    USING (tenant_id = NULLIF(current_setting('qg.tenant_id', true), '')::UUID)
    WITH CHECK (tenant_id = NULLIF(current_setting('qg.tenant_id', true), '')::UUID);

CREATE TABLE identity_adapters (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    application_id UUID NOT NULL,
    adapter_type TEXT NOT NULL CHECK (adapter_type IN ('oidc', 'session-cookie', 'service-identity')),
    issuer TEXT NOT NULL CHECK (length(issuer) BETWEEN 1 AND 2048),
    audience TEXT NOT NULL CHECK (length(audience) BETWEEN 1 AND 512),
    config JSONB NOT NULL DEFAULT '{}'::JSONB CHECK (jsonb_typeof(config) = 'object'),
    status TEXT NOT NULL CHECK (status IN ('active', 'disabled', 'verification_required')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY (tenant_id, application_id) REFERENCES applications(tenant_id, id) ON DELETE RESTRICT,
    UNIQUE (tenant_id, id)
);
ALTER TABLE identity_adapters ENABLE ROW LEVEL SECURITY;
ALTER TABLE identity_adapters FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON identity_adapters
    USING (tenant_id = NULLIF(current_setting('qg.tenant_id', true), '')::UUID)
    WITH CHECK (tenant_id = NULLIF(current_setting('qg.tenant_id', true), '')::UUID);

CREATE TABLE policy_revisions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    application_id UUID NOT NULL,
    revision BIGINT NOT NULL CHECK (revision > 0),
    state TEXT NOT NULL CHECK (state IN ('draft', 'scheduled', 'active', 'retired')),
    document JSONB NOT NULL CHECK (
        jsonb_typeof(document) = 'object'
        AND document ? 'mode'
        AND document ? 'allowed_profiles'
        AND document ? 'fallback'
        AND document ? 'stale_behavior'
        AND document ? 'route_rules'
        AND document ? 'identity_requirements'
        AND document ? 'exceptions'
        AND document ? 'effective_window'
        AND document->>'mode' IN ('classical-approved', 'hybrid-approved', 'pqc-approved', 'observe-only')
        AND jsonb_typeof(document->'allowed_profiles') = 'array'
    ),
    content_hash BYTEA NOT NULL CHECK (octet_length(content_hash) = 32),
    created_by TEXT NOT NULL CHECK (length(created_by) BETWEEN 1 AND 512),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    effective_at TIMESTAMPTZ,
    retired_at TIMESTAMPTZ,
    FOREIGN KEY (tenant_id, application_id) REFERENCES applications(tenant_id, id) ON DELETE RESTRICT,
    UNIQUE (tenant_id, application_id, revision),
    UNIQUE (tenant_id, application_id, id)
);
CREATE UNIQUE INDEX one_active_policy_per_application
    ON policy_revisions(tenant_id, application_id) WHERE state = 'active';
ALTER TABLE policy_revisions ENABLE ROW LEVEL SECURITY;
ALTER TABLE policy_revisions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON policy_revisions
    USING (tenant_id = NULLIF(current_setting('qg.tenant_id', true), '')::UUID)
    WITH CHECK (tenant_id = NULLIF(current_setting('qg.tenant_id', true), '')::UUID);

CREATE TABLE algorithm_profiles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    registry_version BIGINT NOT NULL CHECK (registry_version > 0),
    profile_id TEXT NOT NULL CHECK (length(profile_id) BETWEEN 1 AND 128),
    provider TEXT NOT NULL CHECK (length(provider) BETWEEN 1 AND 256),
    provider_version TEXT NOT NULL CHECK (length(provider_version) BETWEEN 1 AND 128),
    use_case TEXT NOT NULL CHECK (length(use_case) BETWEEN 1 AND 128),
    lifecycle TEXT NOT NULL CHECK (lifecycle IN ('approved', 'deprecated', 'disabled')),
    source_reference TEXT NOT NULL CHECK (length(source_reference) BETWEEN 1 AND 2048),
    reviewed_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, registry_version, profile_id),
    UNIQUE (tenant_id, id)
);
ALTER TABLE algorithm_profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE algorithm_profiles FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON algorithm_profiles
    USING (tenant_id = NULLIF(current_setting('qg.tenant_id', true), '')::UUID)
    WITH CHECK (tenant_id = NULLIF(current_setting('qg.tenant_id', true), '')::UUID);

CREATE TABLE key_references (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    application_id UUID NOT NULL,
    purpose TEXT NOT NULL CHECK (purpose IN ('signing', 'key-encryption', 'session', 'data-encryption')),
    provider TEXT NOT NULL CHECK (length(provider) BETWEEN 1 AND 256),
    provider_reference TEXT NOT NULL CHECK (length(provider_reference) BETWEEN 1 AND 1024),
    algorithm_profile_id UUID,
    version BIGINT NOT NULL CHECK (version > 0),
    state TEXT NOT NULL CHECK (state IN ('provisioning', 'active', 'rotation_due', 'disabled', 'revoked', 'expired', 'destroyed')),
    public_material BYTEA,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    activates_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    FOREIGN KEY (tenant_id, application_id) REFERENCES applications(tenant_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, algorithm_profile_id) REFERENCES algorithm_profiles(tenant_id, id) ON DELETE RESTRICT,
    UNIQUE (tenant_id, application_id, purpose, version),
    UNIQUE (tenant_id, id)
);
ALTER TABLE key_references ENABLE ROW LEVEL SECURITY;
ALTER TABLE key_references FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON key_references
    USING (tenant_id = NULLIF(current_setting('qg.tenant_id', true), '')::UUID)
    WITH CHECK (tenant_id = NULLIF(current_setting('qg.tenant_id', true), '')::UUID);

CREATE TABLE migration_observations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    application_id UUID NOT NULL,
    source TEXT NOT NULL CHECK (length(source) BETWEEN 1 AND 128),
    protocol TEXT NOT NULL CHECK (length(protocol) BETWEEN 1 AND 128),
    algorithm_profile TEXT NOT NULL CHECK (length(algorithm_profile) BETWEEN 1 AND 128),
    blocker TEXT,
    confidence TEXT NOT NULL CHECK (confidence IN ('low', 'medium', 'high')),
    evidence JSONB NOT NULL DEFAULT '{}'::JSONB CHECK (jsonb_typeof(evidence) = 'object'),
    observed_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY (tenant_id, application_id) REFERENCES applications(tenant_id, id) ON DELETE RESTRICT,
    UNIQUE (tenant_id, id)
);
ALTER TABLE migration_observations ENABLE ROW LEVEL SECURITY;
ALTER TABLE migration_observations FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON migration_observations
    USING (tenant_id = NULLIF(current_setting('qg.tenant_id', true), '')::UUID)
    WITH CHECK (tenant_id = NULLIF(current_setting('qg.tenant_id', true), '')::UUID);

CREATE TABLE audit_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    schema_version INTEGER NOT NULL CHECK (schema_version > 0),
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor TEXT NOT NULL CHECK (length(actor) BETWEEN 1 AND 512),
    action TEXT NOT NULL CHECK (length(action) BETWEEN 1 AND 128),
    target_type TEXT NOT NULL CHECK (length(target_type) BETWEEN 1 AND 128),
    target_id TEXT,
    outcome TEXT NOT NULL CHECK (outcome IN ('success', 'denied', 'failure')),
    correlation_id TEXT NOT NULL CHECK (length(correlation_id) BETWEEN 1 AND 128),
    reason_code TEXT NOT NULL CHECK (length(reason_code) BETWEEN 1 AND 128),
    source_context JSONB NOT NULL DEFAULT '{}'::JSONB CHECK (jsonb_typeof(source_context) = 'object'),
    UNIQUE (tenant_id, id)
);
CREATE INDEX audit_events_tenant_time ON audit_events(tenant_id, occurred_at DESC, id DESC);
ALTER TABLE audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_events FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON audit_events
    USING (tenant_id = NULLIF(current_setting('qg.tenant_id', true), '')::UUID)
    WITH CHECK (tenant_id = NULLIF(current_setting('qg.tenant_id', true), '')::UUID);

CREATE FUNCTION qg_reject_audit_mutation() RETURNS trigger
LANGUAGE plpgsql
AS $function$
BEGIN
    RAISE EXCEPTION 'audit events are append-only';
END;
$function$;
CREATE TRIGGER audit_events_append_only
    BEFORE UPDATE OR DELETE ON audit_events
    FOR EACH ROW EXECUTE FUNCTION qg_reject_audit_mutation();

CREATE TABLE admin_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    token_hash BYTEA NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
    issuer TEXT NOT NULL CHECK (length(issuer) BETWEEN 1 AND 2048),
    subject TEXT NOT NULL CHECK (length(subject) BETWEEN 1 AND 512),
    auth_time TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    CHECK (expires_at > created_at)
);
