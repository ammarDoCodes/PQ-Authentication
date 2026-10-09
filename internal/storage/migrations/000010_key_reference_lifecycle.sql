ALTER TABLE public.key_references
    ADD COLUMN updated_at TIMESTAMPTZ NOT NULL DEFAULT now();

CREATE INDEX key_references_application_id
    ON public.key_references(tenant_id, application_id, id);
CREATE INDEX key_references_application_purpose_version
    ON public.key_references(tenant_id, application_id, purpose, version DESC);
