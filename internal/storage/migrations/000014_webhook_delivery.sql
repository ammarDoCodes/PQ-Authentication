CREATE TABLE public.webhook_signing_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    application_id UUID NOT NULL,
    provider TEXT NOT NULL CHECK (length(provider) BETWEEN 1 AND 64),
    provider_reference TEXT NOT NULL CHECK (length(provider_reference) BETWEEN 16 AND 1024),
    algorithm TEXT NOT NULL CHECK (algorithm = 'Ed25519'),
    public_material BYTEA CHECK (public_material IS NULL OR octet_length(public_material) BETWEEN 32 AND 128),
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    state TEXT NOT NULL DEFAULT 'active' CHECK (state IN ('provisioning','active','rotation_due','disabled','revoked','expired','destroyed')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    expires_at TIMESTAMPTZ NOT NULL,
    retired_at TIMESTAMPTZ,
    FOREIGN KEY (tenant_id, application_id) REFERENCES public.applications(tenant_id, id) ON DELETE RESTRICT,
    UNIQUE (tenant_id, application_id, id),
    UNIQUE (tenant_id, application_id, provider, provider_reference),
    CHECK (expires_at > created_at)
);
ALTER TABLE public.webhook_signing_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.webhook_signing_keys FORCE ROW LEVEL SECURITY;
CREATE POLICY webhook_signing_keys_tenant_scope ON public.webhook_signing_keys
    USING (tenant_id = NULLIF(current_setting('qg.tenant_id', true), '')::UUID
        OR current_user = pg_catalog.pg_get_userbyid((SELECT relowner FROM pg_catalog.pg_class WHERE oid = 'public.webhook_signing_keys'::regclass)))
    WITH CHECK (tenant_id = NULLIF(current_setting('qg.tenant_id', true), '')::UUID
        OR current_user = pg_catalog.pg_get_userbyid((SELECT relowner FROM pg_catalog.pg_class WHERE oid = 'public.webhook_signing_keys'::regclass)));
REVOKE ALL ON TABLE public.webhook_signing_keys FROM PUBLIC;

CREATE FUNCTION public.qg_guard_webhook_signing_key() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public, pg_temp
AS $function$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'webhook verification keys are retained';
    END IF;
    IF ROW(NEW.id, NEW.tenant_id, NEW.application_id, NEW.provider, NEW.provider_reference,
           NEW.algorithm, NEW.version, NEW.created_at, NEW.expires_at)
       IS DISTINCT FROM
       ROW(OLD.id, OLD.tenant_id, OLD.application_id, OLD.provider, OLD.provider_reference,
           OLD.algorithm, OLD.version, OLD.created_at, OLD.expires_at) THEN
        RAISE EXCEPTION 'webhook provider reference identity is immutable';
    END IF;
    IF OLD.public_material IS NOT NULL AND NEW.public_material IS DISTINCT FROM OLD.public_material THEN
        RAISE EXCEPTION 'webhook verification key material is immutable';
    END IF;
    IF OLD.public_material IS NULL AND NEW.public_material IS NOT NULL AND NEW.state <> 'active' THEN
        RAISE EXCEPTION 'only active signing keys can publish verification material';
    END IF;
    IF OLD.retired_at IS NOT NULL AND NEW.retired_at IS DISTINCT FROM OLD.retired_at THEN
        RAISE EXCEPTION 'webhook verification key retirement is immutable';
    END IF;
    IF NEW.state IS DISTINCT FROM OLD.state AND NOT (
        (OLD.state = 'provisioning' AND NEW.state IN ('active','disabled','revoked','expired')) OR
        (OLD.state = 'active' AND NEW.state IN ('rotation_due','disabled','revoked','expired')) OR
        (OLD.state = 'rotation_due' AND NEW.state IN ('disabled','revoked','expired')) OR
        (OLD.state = 'disabled' AND NEW.state IN ('revoked','expired')) OR
        (OLD.state IN ('revoked','expired') AND NEW.state = 'destroyed')
    ) THEN
        RAISE EXCEPTION 'invalid webhook signing key lifecycle transition';
    END IF;
    IF ROW(NEW.state, NEW.public_material, NEW.retired_at) IS DISTINCT FROM
       ROW(OLD.state, OLD.public_material, OLD.retired_at) AND NEW.updated_at <= OLD.updated_at THEN
        RAISE EXCEPTION 'webhook signing key updates must advance their timestamp';
    END IF;
    IF ROW(NEW.state, NEW.public_material, NEW.retired_at) IS NOT DISTINCT FROM
       ROW(OLD.state, OLD.public_material, OLD.retired_at) AND NEW.updated_at IS DISTINCT FROM OLD.updated_at THEN
        RAISE EXCEPTION 'webhook signing key timestamp cannot change by itself';
    END IF;
    RETURN NEW;
END
$function$;
CREATE TRIGGER webhook_signing_keys_immutable
    BEFORE UPDATE OR DELETE ON public.webhook_signing_keys
    FOR EACH ROW EXECUTE FUNCTION public.qg_guard_webhook_signing_key();
REVOKE ALL ON FUNCTION public.qg_guard_webhook_signing_key() FROM PUBLIC;

CREATE FUNCTION public.qg_valid_webhook_event_types(p_event_types TEXT[])
RETURNS BOOLEAN
LANGUAGE SQL
IMMUTABLE
STRICT
SET search_path = pg_catalog, public, pg_temp
AS $function$
    SELECT cardinality(p_event_types) BETWEEN 1 AND 6
       AND p_event_types <@ ARRAY['policy.activated','policy.rollback','key.rotation_due','key.revoked','adapter.failure','posture.blocker_found']::TEXT[]
       AND cardinality(p_event_types) = (SELECT count(DISTINCT event_type) FROM unnest(p_event_types) AS t(event_type))
$function$;
REVOKE ALL ON FUNCTION public.qg_valid_webhook_event_types(TEXT[]) FROM PUBLIC;

CREATE TABLE public.webhook_destinations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    application_id UUID NOT NULL,
    endpoint_url TEXT NOT NULL CHECK (length(endpoint_url) BETWEEN 1 AND 2048),
    event_types TEXT[] NOT NULL CHECK (public.qg_valid_webhook_event_types(event_types)),
    signing_key_id UUID NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    revision BIGINT NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY (tenant_id, application_id) REFERENCES public.applications(tenant_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, application_id, signing_key_id)
        REFERENCES public.webhook_signing_keys(tenant_id, application_id, id) ON DELETE RESTRICT,
    UNIQUE (tenant_id, application_id, id)
);
CREATE INDEX webhook_destinations_application ON public.webhook_destinations(tenant_id, application_id, id);
ALTER TABLE public.webhook_destinations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.webhook_destinations FORCE ROW LEVEL SECURITY;
CREATE POLICY webhook_destinations_tenant_scope ON public.webhook_destinations
    USING (tenant_id = NULLIF(current_setting('qg.tenant_id', true), '')::UUID
        OR current_user = pg_catalog.pg_get_userbyid((SELECT relowner FROM pg_catalog.pg_class WHERE oid = 'public.webhook_destinations'::regclass)))
    WITH CHECK (tenant_id = NULLIF(current_setting('qg.tenant_id', true), '')::UUID
        OR current_user = pg_catalog.pg_get_userbyid((SELECT relowner FROM pg_catalog.pg_class WHERE oid = 'public.webhook_destinations'::regclass)));
REVOKE ALL ON TABLE public.webhook_destinations FROM PUBLIC;

CREATE FUNCTION public.qg_guard_webhook_destination_capacity() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public, pg_temp
AS $function$
DECLARE
    locked_application UUID;
    destination_count INTEGER;
BEGIN
    SELECT id INTO locked_application FROM public.applications
    WHERE tenant_id = NEW.tenant_id AND id = NEW.application_id FOR UPDATE;
    IF locked_application IS NULL THEN
        RAISE EXCEPTION 'webhook application is unavailable';
    END IF;
    SELECT count(*) INTO destination_count FROM public.webhook_destinations
    WHERE tenant_id = NEW.tenant_id AND application_id = NEW.application_id;
    IF destination_count >= 20 THEN
        RAISE EXCEPTION 'webhook destination limit reached';
    END IF;
    RETURN NEW;
END
$function$;
CREATE TRIGGER webhook_destinations_capacity_guard
    BEFORE INSERT ON public.webhook_destinations
    FOR EACH ROW EXECUTE FUNCTION public.qg_guard_webhook_destination_capacity();
REVOKE ALL ON FUNCTION public.qg_guard_webhook_destination_capacity() FROM PUBLIC;

CREATE FUNCTION public.qg_guard_webhook_destination() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public, pg_temp
AS $function$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'webhook destination history is retained';
    END IF;
    IF ROW(NEW.id, NEW.tenant_id, NEW.application_id, NEW.created_at)
       IS DISTINCT FROM ROW(OLD.id, OLD.tenant_id, OLD.application_id, OLD.created_at) THEN
        RAISE EXCEPTION 'webhook destination identity is immutable';
    END IF;
    IF ROW(NEW.endpoint_url, NEW.event_types, NEW.signing_key_id, NEW.enabled) IS DISTINCT FROM
       ROW(OLD.endpoint_url, OLD.event_types, OLD.signing_key_id, OLD.enabled) THEN
        IF NEW.revision <> OLD.revision + 1 OR NEW.updated_at <= OLD.updated_at THEN
            RAISE EXCEPTION 'webhook destination revision must advance';
        END IF;
    ELSIF ROW(NEW.revision, NEW.updated_at) IS DISTINCT FROM ROW(OLD.revision, OLD.updated_at) THEN
        RAISE EXCEPTION 'webhook destination revision cannot change without configuration';
    END IF;
    RETURN NEW;
END
$function$;
CREATE TRIGGER webhook_destinations_revision_guard
    BEFORE UPDATE OR DELETE ON public.webhook_destinations
    FOR EACH ROW EXECUTE FUNCTION public.qg_guard_webhook_destination();
REVOKE ALL ON FUNCTION public.qg_guard_webhook_destination() FROM PUBLIC;

CREATE TABLE public.webhook_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    application_id UUID NOT NULL,
    schema_version INTEGER NOT NULL DEFAULT 1 CHECK (schema_version = 1),
    event_type TEXT NOT NULL CHECK (event_type IN (
        'policy.activated','policy.rollback','key.rotation_due','key.revoked','adapter.failure','posture.blocker_found'
    )),
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    correlation_id TEXT NOT NULL CHECK (correlation_id ~ '^[A-Za-z0-9_.:-]{1,128}$'),
    resource_type TEXT NOT NULL CHECK (resource_type IN ('policy_revision','key_reference','identity_adapter','migration_observation')),
    resource_id UUID NOT NULL,
    reason_code TEXT NOT NULL CHECK (reason_code IN (
        'POLICY_ACTIVATED','POLICY_ROLLED_BACK','ROLLBACK_COMPATIBILITY','ROLLBACK_SECURITY',
        'ROLLBACK_INCIDENT','ROLLBACK_OTHER','KEY_ROTATION_DUE','KEY_REVOKED',
        'ADAPTER_VERIFICATION_FAILED','POSTURE_BLOCKER_FOUND'
    )),
    FOREIGN KEY (tenant_id, application_id) REFERENCES public.applications(tenant_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, id) REFERENCES public.audit_events(tenant_id, id) ON DELETE RESTRICT,
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, application_id, id),
    CHECK (
        (event_type = 'policy.activated' AND resource_type = 'policy_revision' AND reason_code = 'POLICY_ACTIVATED') OR
        (event_type = 'policy.rollback' AND resource_type = 'policy_revision' AND reason_code IN (
            'POLICY_ROLLED_BACK','ROLLBACK_COMPATIBILITY','ROLLBACK_SECURITY','ROLLBACK_INCIDENT','ROLLBACK_OTHER')) OR
        (event_type = 'key.rotation_due' AND resource_type = 'key_reference' AND reason_code = 'KEY_ROTATION_DUE') OR
        (event_type = 'key.revoked' AND resource_type = 'key_reference' AND reason_code = 'KEY_REVOKED') OR
        (event_type = 'adapter.failure' AND resource_type = 'identity_adapter' AND reason_code = 'ADAPTER_VERIFICATION_FAILED') OR
        (event_type = 'posture.blocker_found' AND resource_type = 'migration_observation' AND reason_code = 'POSTURE_BLOCKER_FOUND')
    )
);
CREATE INDEX webhook_events_application_time ON public.webhook_events(tenant_id, application_id, occurred_at DESC, id DESC);
ALTER TABLE public.webhook_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.webhook_events FORCE ROW LEVEL SECURITY;
CREATE POLICY webhook_events_tenant_scope ON public.webhook_events
    USING (tenant_id = NULLIF(current_setting('qg.tenant_id', true), '')::UUID
        OR current_user = pg_catalog.pg_get_userbyid((SELECT relowner FROM pg_catalog.pg_class WHERE oid = 'public.webhook_events'::regclass)))
    WITH CHECK (tenant_id = NULLIF(current_setting('qg.tenant_id', true), '')::UUID
        OR current_user = pg_catalog.pg_get_userbyid((SELECT relowner FROM pg_catalog.pg_class WHERE oid = 'public.webhook_events'::regclass)));
REVOKE ALL ON TABLE public.webhook_events FROM PUBLIC;

CREATE FUNCTION public.qg_reject_webhook_event_mutation() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public, pg_temp
AS $function$
BEGIN
    RAISE EXCEPTION 'webhook events are immutable';
END
$function$;
CREATE TRIGGER webhook_events_immutable
    BEFORE UPDATE OR DELETE ON public.webhook_events
    FOR EACH ROW EXECUTE FUNCTION public.qg_reject_webhook_event_mutation();
REVOKE ALL ON FUNCTION public.qg_reject_webhook_event_mutation() FROM PUBLIC;

CREATE TABLE public.webhook_deliveries (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    application_id UUID NOT NULL,
    event_id UUID NOT NULL,
    destination_id UUID NOT NULL,
    state TEXT NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','delivering','retry','delivered','dead','cancelled')),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    cycle_attempts INTEGER NOT NULL DEFAULT 0 CHECK (cycle_attempts >= 0),
    manual_retries INTEGER NOT NULL DEFAULT 0 CHECK (manual_retries BETWEEN 0 AND 5),
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    lease_token UUID,
    lease_until TIMESTAMPTZ,
    last_status_code INTEGER CHECK (last_status_code BETWEEN 100 AND 599),
    last_error_code TEXT CHECK (last_error_code IS NULL OR last_error_code IN (
        'SIGNING_PROVIDER_UNAVAILABLE','SIGNING_AUDIT_UNAVAILABLE','SIGNING_FAILED','SIGNATURE_INVALID','EVENT_ENVELOPE_INVALID',
        'DELIVERY_CONFIGURATION_INVALID','DESTINATION_REJECTED','HTTP_REDIRECT_REJECTED',
        'HTTP_PERMANENT_FAILURE','HTTP_RETRYABLE','TLS_VERIFICATION_FAILED','DNS_FAILURE',
        'HTTP_TIMEOUT','HTTP_NETWORK_FAILURE','SSRF_DESTINATION_REJECTED','ATTEMPTS_EXHAUSTED',
        'DESTINATION_DISABLED'
    )),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    delivered_at TIMESTAMPTZ,
    FOREIGN KEY (tenant_id, application_id, event_id)
        REFERENCES public.webhook_events(tenant_id, application_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, application_id, destination_id)
        REFERENCES public.webhook_destinations(tenant_id, application_id, id) ON DELETE RESTRICT,
    UNIQUE (tenant_id, destination_id, event_id),
    CHECK ((state = 'delivering' AND lease_token IS NOT NULL AND lease_until IS NOT NULL) OR
           (state <> 'delivering' AND lease_token IS NULL AND lease_until IS NULL)),
    CHECK ((state = 'delivered') = (delivered_at IS NOT NULL))
);
CREATE INDEX webhook_deliveries_due ON public.webhook_deliveries(next_attempt_at, created_at, id)
    WHERE state IN ('pending','retry','delivering');
CREATE INDEX webhook_deliveries_tenant_destination ON public.webhook_deliveries(tenant_id, destination_id, created_at DESC, id DESC);
ALTER TABLE public.webhook_deliveries ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.webhook_deliveries FORCE ROW LEVEL SECURITY;
CREATE POLICY webhook_deliveries_tenant_scope ON public.webhook_deliveries
    USING (tenant_id = NULLIF(current_setting('qg.tenant_id', true), '')::UUID
        OR current_user = pg_catalog.pg_get_userbyid((SELECT relowner FROM pg_catalog.pg_class WHERE oid = 'public.webhook_deliveries'::regclass)))
    WITH CHECK (tenant_id = NULLIF(current_setting('qg.tenant_id', true), '')::UUID
        OR current_user = pg_catalog.pg_get_userbyid((SELECT relowner FROM pg_catalog.pg_class WHERE oid = 'public.webhook_deliveries'::regclass)));
REVOKE ALL ON TABLE public.webhook_deliveries FROM PUBLIC;

CREATE FUNCTION public.qg_guard_webhook_delivery() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public, pg_temp
AS $function$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'webhook delivery history is retained';
    END IF;
    IF ROW(NEW.id, NEW.tenant_id, NEW.application_id, NEW.event_id, NEW.destination_id, NEW.created_at)
       IS DISTINCT FROM ROW(OLD.id, OLD.tenant_id, OLD.application_id, OLD.event_id, OLD.destination_id, OLD.created_at) THEN
        RAISE EXCEPTION 'webhook delivery identity is immutable';
    END IF;
    IF OLD.state IN ('delivered','cancelled') THEN
        RAISE EXCEPTION 'terminal webhook delivery state is immutable';
    END IF;
    IF NEW.state IS DISTINCT FROM OLD.state AND NOT (
        (OLD.state IN ('pending','retry') AND NEW.state IN ('delivering','cancelled')) OR
        (OLD.state = 'delivering' AND NEW.state IN ('retry','delivered','dead','cancelled')) OR
        (OLD.state = 'dead' AND NEW.state = 'pending')
    ) THEN
        RAISE EXCEPTION 'invalid webhook delivery transition';
    END IF;
    IF OLD.state = 'dead' AND NEW.state = 'pending' THEN
        IF NEW.manual_retries <> OLD.manual_retries + 1 OR NEW.cycle_attempts <> 0 OR NEW.attempts <> OLD.attempts OR
           NEW.lease_token IS NOT NULL OR NEW.lease_until IS NOT NULL OR NEW.delivered_at IS NOT NULL OR
           NEW.last_status_code IS NOT NULL OR NEW.last_error_code IS NOT NULL THEN
            RAISE EXCEPTION 'manual retry must preserve event identity and reset only the retry cycle';
        END IF;
    ELSIF NEW.manual_retries <> OLD.manual_retries THEN
        RAISE EXCEPTION 'manual retry counter can change only when re-queuing a dead delivery';
    END IF;
    IF NEW.state = 'delivering' AND OLD.state IN ('pending','retry','delivering') THEN
        IF NEW.attempts <> OLD.attempts + 1 OR NEW.cycle_attempts <> OLD.cycle_attempts + 1 OR
           NEW.lease_token IS NULL OR NEW.lease_token = OLD.lease_token OR NEW.lease_until <= clock_timestamp() OR
           NEW.delivered_at IS NOT NULL OR NEW.manual_retries <> OLD.manual_retries OR
           NEW.last_status_code IS DISTINCT FROM OLD.last_status_code OR NEW.last_error_code IS DISTINCT FROM OLD.last_error_code THEN
            RAISE EXCEPTION 'claiming a webhook delivery must advance attempt counters';
        END IF;
    ELSIF OLD.state = 'delivering' AND NEW.state IN ('retry','delivered','dead','cancelled') THEN
        IF NEW.attempts <> OLD.attempts OR NEW.cycle_attempts <> OLD.cycle_attempts OR
           NEW.lease_token IS NOT NULL OR NEW.lease_until IS NOT NULL OR
           (NEW.state = 'delivered') <> (NEW.delivered_at IS NOT NULL) THEN
            RAISE EXCEPTION 'webhook delivery completion is invalid';
        END IF;
        IF NEW.state = 'delivered' AND (NEW.last_status_code NOT BETWEEN 200 AND 299 OR NEW.last_error_code IS NOT NULL) THEN
            RAISE EXCEPTION 'delivered webhook requires a successful HTTP response';
        ELSIF NEW.state = 'retry' AND (NEW.cycle_attempts >= 8 OR NEW.last_error_code IS NULL OR NEW.last_error_code NOT IN (
            'SIGNING_PROVIDER_UNAVAILABLE','SIGNING_AUDIT_UNAVAILABLE','HTTP_RETRYABLE','DNS_FAILURE','HTTP_TIMEOUT','HTTP_NETWORK_FAILURE')) THEN
            RAISE EXCEPTION 'only bounded transient failures can be retried';
        ELSIF NEW.state = 'dead' AND (NEW.last_error_code IS NULL OR
            (NEW.cycle_attempts < 8 AND NEW.last_error_code NOT IN (
                'SIGNING_FAILED','SIGNATURE_INVALID','EVENT_ENVELOPE_INVALID','DELIVERY_CONFIGURATION_INVALID',
                'DESTINATION_REJECTED','HTTP_REDIRECT_REJECTED','HTTP_PERMANENT_FAILURE',
                'TLS_VERIFICATION_FAILED','SSRF_DESTINATION_REJECTED'))) THEN
            RAISE EXCEPTION 'permanent failure or exhausted retry count is required';
        ELSIF NEW.state = 'cancelled' AND NEW.last_error_code IS DISTINCT FROM 'DESTINATION_DISABLED' THEN
            RAISE EXCEPTION 'only disabled destinations can cancel delivery';
        END IF;
    ELSIF OLD.state IN ('pending','retry') AND NEW.state = 'cancelled' THEN
        IF NEW.attempts <> OLD.attempts OR NEW.cycle_attempts <> OLD.cycle_attempts OR
           NEW.delivered_at IS NOT NULL OR NEW.lease_token IS NOT NULL OR NEW.lease_until IS NOT NULL OR
           NEW.manual_retries <> OLD.manual_retries OR NEW.last_error_code IS DISTINCT FROM 'DESTINATION_DISABLED' THEN
            RAISE EXCEPTION 'webhook delivery cancellation is invalid';
        END IF;
    ELSIF NEW.state = OLD.state THEN
        RAISE EXCEPTION 'webhook delivery updates must use a state transition';
    END IF;
    IF ROW(NEW.state, NEW.attempts, NEW.cycle_attempts, NEW.manual_retries, NEW.next_attempt_at,
           NEW.lease_token, NEW.lease_until, NEW.last_status_code, NEW.last_error_code, NEW.updated_at, NEW.delivered_at)
       IS DISTINCT FROM
       ROW(OLD.state, OLD.attempts, OLD.cycle_attempts, OLD.manual_retries, OLD.next_attempt_at,
           OLD.lease_token, OLD.lease_until, OLD.last_status_code, OLD.last_error_code, OLD.updated_at, OLD.delivered_at)
       AND NEW.updated_at <= OLD.updated_at THEN
        RAISE EXCEPTION 'webhook delivery updates must advance their timestamp';
    END IF;
    RETURN NEW;
END
$function$;
CREATE TRIGGER webhook_deliveries_state_guard
    BEFORE UPDATE OR DELETE ON public.webhook_deliveries
    FOR EACH ROW EXECUTE FUNCTION public.qg_guard_webhook_delivery();
REVOKE ALL ON FUNCTION public.qg_guard_webhook_delivery() FROM PUBLIC;

CREATE FUNCTION public.qg_claim_webhook_deliveries(p_limit INTEGER)
RETURNS TABLE(delivery_id UUID, tenant_id UUID, lease_token UUID, attempt INTEGER, cycle_attempt INTEGER)
LANGUAGE SQL
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $function$
    WITH candidates AS (
        SELECT d.id
        FROM public.webhook_deliveries AS d
        WHERE (d.state IN ('pending','retry') AND d.next_attempt_at <= clock_timestamp())
           OR (d.state = 'delivering' AND d.lease_until <= clock_timestamp())
        ORDER BY d.next_attempt_at, d.created_at, d.id
        LIMIT LEAST(GREATEST(p_limit, 1), 5)
        FOR UPDATE SKIP LOCKED
    ), claimed AS (
        UPDATE public.webhook_deliveries AS d
        SET state = 'delivering', attempts = d.attempts + 1, cycle_attempts = d.cycle_attempts + 1,
            lease_token = gen_random_uuid(), lease_until = clock_timestamp() + interval '2 minutes',
            updated_at = GREATEST(clock_timestamp(), d.updated_at + interval '1 microsecond')
        FROM candidates AS c
        WHERE d.id = c.id
        RETURNING d.id, d.tenant_id, d.lease_token, d.attempts, d.cycle_attempts
    )
    SELECT c.id AS delivery_id, c.tenant_id, c.lease_token, c.attempts, c.cycle_attempts FROM claimed AS c
$function$;
ALTER FUNCTION public.qg_claim_webhook_deliveries(INTEGER) SET search_path TO pg_catalog, public, pg_temp;
REVOKE ALL ON FUNCTION public.qg_claim_webhook_deliveries(INTEGER) FROM PUBLIC;

CREATE FUNCTION public.qg_get_webhook_public_key(p_key_id UUID)
RETURNS TABLE(key_id UUID, algorithm TEXT, public_material BYTEA, created_at TIMESTAMPTZ, expires_at TIMESTAMPTZ, retired_at TIMESTAMPTZ)
LANGUAGE SQL
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $function$
    SELECT k.id, k.algorithm, k.public_material, k.created_at, k.expires_at, k.retired_at
    FROM public.webhook_signing_keys AS k
    WHERE k.id = p_key_id AND k.public_material IS NOT NULL
$function$;
ALTER FUNCTION public.qg_get_webhook_public_key(UUID) SET search_path TO pg_catalog, public, pg_temp;
REVOKE ALL ON FUNCTION public.qg_get_webhook_public_key(UUID) FROM PUBLIC;

DO $block$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'quantumgate') THEN
        GRANT SELECT, INSERT, UPDATE ON public.webhook_signing_keys TO quantumgate;
        GRANT SELECT, INSERT, UPDATE ON public.webhook_destinations TO quantumgate;
        GRANT SELECT, INSERT, UPDATE ON public.webhook_events TO quantumgate;
        GRANT SELECT, INSERT, UPDATE ON public.webhook_deliveries TO quantumgate;
        GRANT EXECUTE ON FUNCTION public.qg_claim_webhook_deliveries(INTEGER) TO quantumgate;
        GRANT EXECUTE ON FUNCTION public.qg_get_webhook_public_key(UUID) TO quantumgate;
        GRANT EXECUTE ON FUNCTION public.qg_valid_webhook_event_types(TEXT[]) TO quantumgate;
    END IF;
END
$block$;
