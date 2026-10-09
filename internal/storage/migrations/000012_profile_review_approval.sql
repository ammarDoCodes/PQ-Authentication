ALTER TABLE algorithm_profiles
    DROP CONSTRAINT algorithm_profiles_lifecycle_check,
    DROP CONSTRAINT algorithm_profiles_tenant_id_registry_version_profile_id_key,
    ALTER COLUMN reviewed_at DROP NOT NULL,
    ADD COLUMN revision BIGINT NOT NULL DEFAULT 1 CHECK (revision > 0),
    ADD COLUMN submitted_by TEXT,
    ADD COLUMN reviewed_by TEXT,
    ADD COLUMN review_reference TEXT,
    ADD COLUMN review_evidence JSONB,
    ADD COLUMN profile_hash BYTEA,
    ADD COLUMN lifecycle_updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    ADD COLUMN lifecycle_version BIGINT NOT NULL DEFAULT 1 CHECK (lifecycle_version > 0);

-- Existing approved rows predate independent reviewer evidence. Fail closed by
-- disabling them rather than treating their timestamp as an approval record.
UPDATE algorithm_profiles SET lifecycle = 'disabled', reviewed_at = NULL WHERE lifecycle = 'approved';

ALTER TABLE algorithm_profiles
    ADD CONSTRAINT algorithm_profiles_lifecycle_check
        CHECK (lifecycle IN ('pending_review', 'approved', 'rejected', 'deprecated', 'disabled')),
    ADD CONSTRAINT algorithm_profiles_hash_length
        CHECK (profile_hash IS NULL OR octet_length(profile_hash) = 32),
    ADD CONSTRAINT algorithm_profiles_review_reference_length
        CHECK (review_reference IS NULL OR length(review_reference) BETWEEN 1 AND 2048),
    ADD CONSTRAINT algorithm_profiles_reviewer_length
        CHECK ((submitted_by IS NULL OR length(submitted_by) BETWEEN 1 AND 128) AND
               (reviewed_by IS NULL OR length(reviewed_by) BETWEEN 1 AND 128)),
    ADD CONSTRAINT algorithm_profiles_review_evidence_object
        CHECK (review_evidence IS NULL OR jsonb_typeof(review_evidence) = 'object'),
    ADD CONSTRAINT algorithm_profiles_pending_review_evidence
        CHECK (lifecycle <> 'pending_review' OR (
            submitted_by IS NOT NULL AND profile_hash IS NOT NULL AND review_evidence IS NOT NULL AND
            reviewed_by IS NULL AND reviewed_at IS NULL AND review_reference IS NULL
        )),
    ADD CONSTRAINT algorithm_profiles_completed_review_evidence
        CHECK (lifecycle NOT IN ('approved', 'rejected') OR (
            submitted_by IS NOT NULL AND reviewed_by IS NOT NULL AND reviewed_by <> submitted_by AND
            reviewed_at IS NOT NULL AND review_reference IS NOT NULL AND profile_hash IS NOT NULL AND
            review_evidence IS NOT NULL
        ));

ALTER TABLE algorithm_profiles
    ADD CONSTRAINT algorithm_profiles_tenant_revision_profile_key
        UNIQUE (tenant_id, registry_version, profile_id, revision);

CREATE UNIQUE INDEX algorithm_profiles_one_pending_review
    ON algorithm_profiles (tenant_id, registry_version, profile_id)
    WHERE lifecycle = 'pending_review';
CREATE UNIQUE INDEX algorithm_profiles_one_approved_review
    ON algorithm_profiles (tenant_id, registry_version, profile_id)
    WHERE lifecycle = 'approved';

CREATE FUNCTION qg_guard_algorithm_profile_review() RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = pg_catalog, public, pg_temp
AS $function$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'algorithm profile review records are immutable';
    END IF;

    IF TG_OP = 'INSERT' THEN
        IF NEW.lifecycle <> 'pending_review' OR NEW.lifecycle_version <> 1 OR NEW.revision < 1 OR
           NEW.submitted_by IS NULL OR NEW.profile_hash IS NULL OR NEW.review_evidence IS NULL OR
           NEW.reviewed_by IS NOT NULL OR NEW.reviewed_at IS NOT NULL OR NEW.review_reference IS NOT NULL THEN
            RAISE EXCEPTION 'algorithm profiles must begin as complete pending reviews';
        END IF;
        RETURN NEW;
    END IF;

    IF ROW(NEW.id, NEW.tenant_id, NEW.registry_version, NEW.profile_id, NEW.provider,
           NEW.provider_version, NEW.use_case, NEW.source_reference, NEW.created_at,
           NEW.revision, NEW.submitted_by, NEW.review_evidence, NEW.profile_hash)
       IS DISTINCT FROM
       ROW(OLD.id, OLD.tenant_id, OLD.registry_version, OLD.profile_id, OLD.provider,
           OLD.provider_version, OLD.use_case, OLD.source_reference, OLD.created_at,
           OLD.revision, OLD.submitted_by, OLD.review_evidence, OLD.profile_hash) THEN
        RAISE EXCEPTION 'algorithm profile review evidence is immutable';
    END IF;

    IF NEW.lifecycle_version <> OLD.lifecycle_version + 1 THEN
        RAISE EXCEPTION 'algorithm profile lifecycle version must advance exactly once';
    END IF;

    IF OLD.lifecycle = 'pending_review' AND NEW.lifecycle IN ('approved', 'rejected') THEN
        IF NEW.reviewed_by IS NULL OR NEW.reviewed_by = NEW.submitted_by OR NEW.reviewed_at IS NULL OR
           NEW.review_reference IS NULL OR btrim(NEW.review_reference) = '' THEN
            RAISE EXCEPTION 'profile review requires a distinct reviewer and evidence reference';
        END IF;
    ELSIF OLD.lifecycle = 'approved' AND NEW.lifecycle IN ('deprecated', 'disabled') THEN
        IF ROW(NEW.reviewed_by, NEW.reviewed_at, NEW.review_reference)
           IS DISTINCT FROM ROW(OLD.reviewed_by, OLD.reviewed_at, OLD.review_reference) THEN
            RAISE EXCEPTION 'profile lifecycle retirement cannot rewrite approval evidence';
        END IF;
    ELSE
        RAISE EXCEPTION 'invalid algorithm profile lifecycle transition';
    END IF;

    NEW.lifecycle_updated_at := clock_timestamp();
    RETURN NEW;
END;
$function$;

CREATE TRIGGER algorithm_profiles_immutable_review
    BEFORE INSERT OR UPDATE OR DELETE ON algorithm_profiles
    FOR EACH ROW EXECUTE FUNCTION qg_guard_algorithm_profile_review();

REVOKE ALL ON FUNCTION qg_guard_algorithm_profile_review() FROM PUBLIC;
