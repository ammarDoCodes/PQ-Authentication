CREATE INDEX migration_observations_application_id
    ON public.migration_observations(tenant_id, application_id, id);
