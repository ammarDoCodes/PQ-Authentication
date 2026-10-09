ALTER TABLE policy_revisions
    ADD COLUMN lifecycle_updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    ADD COLUMN lifecycle_version BIGINT NOT NULL DEFAULT 1 CHECK (lifecycle_version > 0);

CREATE FUNCTION qg_guard_policy_revision() RETURNS trigger
LANGUAGE plpgsql
AS $function$
BEGIN
    IF ROW(NEW.tenant_id, NEW.application_id, NEW.revision, NEW.document, NEW.content_hash, NEW.created_by, NEW.created_at)
       IS DISTINCT FROM
       ROW(OLD.tenant_id, OLD.application_id, OLD.revision, OLD.document, OLD.content_hash, OLD.created_by, OLD.created_at) THEN
        RAISE EXCEPTION 'policy revision content is immutable';
    END IF;
    IF NEW.state IS DISTINCT FROM OLD.state AND NOT (
        (OLD.state = 'draft' AND NEW.state IN ('scheduled', 'active', 'retired')) OR
        (OLD.state = 'scheduled' AND NEW.state IN ('active', 'retired')) OR
        (OLD.state = 'active' AND NEW.state = 'retired')
    ) THEN
        RAISE EXCEPTION 'invalid policy revision state transition';
    END IF;
    IF ROW(NEW.state, NEW.effective_at, NEW.retired_at, NEW.lifecycle_updated_at)
       IS DISTINCT FROM
       ROW(OLD.state, OLD.effective_at, OLD.retired_at, OLD.lifecycle_updated_at) THEN
        IF NEW.lifecycle_version <> OLD.lifecycle_version + 1 THEN
            RAISE EXCEPTION 'policy lifecycle version must advance by one';
        END IF;
    ELSIF NEW.lifecycle_version IS DISTINCT FROM OLD.lifecycle_version THEN
        RAISE EXCEPTION 'policy lifecycle version cannot change without a lifecycle update';
    END IF;
    RETURN NEW;
END
$function$;
CREATE TRIGGER policy_revisions_immutable_content
    BEFORE UPDATE ON policy_revisions
    FOR EACH ROW EXECUTE FUNCTION qg_guard_policy_revision();
REVOKE ALL ON FUNCTION qg_guard_policy_revision() FROM PUBLIC;

-- The schedule queue identifies a revision by tenant and revision ID. The
-- primary key on id alone does not let PostgreSQL enforce that tenant pair.
ALTER TABLE policy_revisions
    ADD CONSTRAINT policy_revisions_tenant_id_unique UNIQUE (tenant_id, id);

CREATE TABLE policy_schedule_queue (
    tenant_id UUID NOT NULL,
    policy_id UUID NOT NULL,
    scheduled_for TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, policy_id),
    FOREIGN KEY (tenant_id, policy_id) REFERENCES policy_revisions(tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX policy_schedule_queue_due ON policy_schedule_queue(scheduled_for, tenant_id, policy_id);
ALTER TABLE policy_schedule_queue ENABLE ROW LEVEL SECURITY;
ALTER TABLE policy_schedule_queue FORCE ROW LEVEL SECURITY;
CREATE POLICY policy_schedule_scope ON policy_schedule_queue
    USING (
        tenant_id = NULLIF(current_setting('qg.tenant_id', true), '')::UUID
        OR current_user = pg_catalog.pg_get_userbyid((SELECT relowner FROM pg_catalog.pg_class WHERE oid = 'policy_schedule_queue'::regclass))
    )
    WITH CHECK (
        tenant_id = NULLIF(current_setting('qg.tenant_id', true), '')::UUID
        OR current_user = pg_catalog.pg_get_userbyid((SELECT relowner FROM pg_catalog.pg_class WHERE oid = 'policy_schedule_queue'::regclass))
    );
REVOKE ALL ON TABLE policy_schedule_queue FROM PUBLIC;

CREATE FUNCTION qg_schedule_policy(p_tenant_id UUID, p_policy_id UUID, p_scheduled_for TIMESTAMPTZ)
RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path FROM CURRENT
AS $function$
BEGIN
    IF NULLIF(current_setting('qg.tenant_id', true), '')::UUID IS DISTINCT FROM p_tenant_id THEN
        RAISE EXCEPTION 'tenant scope does not match scheduled policy' USING ERRCODE = '42501';
    END IF;
    INSERT INTO policy_schedule_queue(tenant_id, policy_id, scheduled_for)
    VALUES (p_tenant_id, p_policy_id, p_scheduled_for)
    ON CONFLICT (tenant_id, policy_id) DO UPDATE SET scheduled_for = EXCLUDED.scheduled_for, created_at = now();
END
$function$;

CREATE FUNCTION qg_cancel_policy_schedule(p_tenant_id UUID, p_policy_id UUID)
RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path FROM CURRENT
AS $function$
BEGIN
    IF NULLIF(current_setting('qg.tenant_id', true), '')::UUID IS DISTINCT FROM p_tenant_id THEN
        RAISE EXCEPTION 'tenant scope does not match scheduled policy' USING ERRCODE = '42501';
    END IF;
    DELETE FROM policy_schedule_queue
    WHERE tenant_id = p_tenant_id AND policy_id = p_policy_id;
END
$function$;

CREATE FUNCTION qg_claim_due_policy_schedules(p_limit INTEGER)
RETURNS TABLE(tenant_id UUID, policy_id UUID)
LANGUAGE SQL
SECURITY DEFINER
SET search_path FROM CURRENT
AS $function$
    SELECT schedule.tenant_id, schedule.policy_id
    FROM policy_schedule_queue AS schedule
    WHERE schedule.scheduled_for <= clock_timestamp()
    ORDER BY schedule.scheduled_for, schedule.tenant_id, schedule.policy_id
    LIMIT LEAST(GREATEST(p_limit, 1), 50)
$function$;

DO $block$
DECLARE
    policy_schema TEXT := current_schema();
BEGIN
    EXECUTE format('ALTER FUNCTION %I.qg_schedule_policy(UUID, UUID, TIMESTAMPTZ) SET search_path TO %I, pg_catalog, pg_temp', policy_schema, policy_schema);
    EXECUTE format('ALTER FUNCTION %I.qg_cancel_policy_schedule(UUID, UUID) SET search_path TO %I, pg_catalog, pg_temp', policy_schema, policy_schema);
    EXECUTE format('ALTER FUNCTION %I.qg_claim_due_policy_schedules(INTEGER) SET search_path TO %I, pg_catalog, pg_temp', policy_schema, policy_schema);
END
$block$;

REVOKE ALL ON FUNCTION qg_schedule_policy(UUID, UUID, TIMESTAMPTZ) FROM PUBLIC;
REVOKE ALL ON FUNCTION qg_cancel_policy_schedule(UUID, UUID) FROM PUBLIC;
REVOKE ALL ON FUNCTION qg_claim_due_policy_schedules(INTEGER) FROM PUBLIC;
DO $block$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'quantumgate') THEN
        EXECUTE format('REVOKE ALL ON TABLE %I.policy_schedule_queue FROM quantumgate', current_schema());
        EXECUTE format('GRANT EXECUTE ON FUNCTION %I.qg_schedule_policy(UUID, UUID, TIMESTAMPTZ) TO quantumgate', current_schema());
        EXECUTE format('GRANT EXECUTE ON FUNCTION %I.qg_cancel_policy_schedule(UUID, UUID) TO quantumgate', current_schema());
        EXECUTE format('GRANT EXECUTE ON FUNCTION %I.qg_claim_due_policy_schedules(INTEGER) TO quantumgate', current_schema());
    END IF;
END
$block$;
