\set ON_ERROR_STOP on
\getenv qg_app_password QG_APP_PASSWORD
\getenv qg_migration_password QG_MIGRATION_PASSWORD
\getenv qg_database POSTGRES_DB
\set qg_create_local_admin false
\getenv qg_create_local_admin QG_CREATE_LOCAL_ADMIN

\if :qg_create_local_admin
\getenv qg_admin_user QG_POSTGRES_ADMIN_USER
\getenv qg_admin_password POSTGRES_PASSWORD
SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'qg_admin_user') AS qg_admin_exists \gset
\if :qg_admin_exists
ALTER ROLE :"qg_admin_user" LOGIN PASSWORD :'qg_admin_password'
  SUPERUSER CREATEDB CREATEROLE INHERIT REPLICATION BYPASSRLS;
\else
CREATE ROLE :"qg_admin_user" LOGIN PASSWORD :'qg_admin_password'
  SUPERUSER CREATEDB CREATEROLE INHERIT REPLICATION BYPASSRLS;
\endif
\endif

SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'quantumgate') AS qg_runtime_exists \gset
\if :qg_runtime_exists
ALTER ROLE quantumgate LOGIN PASSWORD :'qg_app_password'
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
\else
CREATE ROLE quantumgate LOGIN PASSWORD :'qg_app_password'
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
\endif

SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'quantumgate_migrator') AS qg_migrator_exists \gset
\if :qg_migrator_exists
ALTER ROLE quantumgate_migrator LOGIN PASSWORD :'qg_migration_password'
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
\else
CREATE ROLE quantumgate_migrator LOGIN PASSWORD :'qg_migration_password'
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
\endif

ALTER DATABASE :"qg_database" OWNER TO quantumgate_migrator;
ALTER SCHEMA public OWNER TO quantumgate_migrator;
ALTER TABLE IF EXISTS public.qg_schema_migrations OWNER TO quantumgate_migrator;
ALTER TABLE IF EXISTS public.tenants OWNER TO quantumgate_migrator;
ALTER TABLE IF EXISTS public.tenant_members OWNER TO quantumgate_migrator;
ALTER TABLE IF EXISTS public.environments OWNER TO quantumgate_migrator;
ALTER TABLE IF EXISTS public.applications OWNER TO quantumgate_migrator;
ALTER TABLE IF EXISTS public.application_credentials OWNER TO quantumgate_migrator;
ALTER TABLE IF EXISTS public.identity_adapters OWNER TO quantumgate_migrator;
ALTER TABLE IF EXISTS public.policy_revisions OWNER TO quantumgate_migrator;
ALTER TABLE IF EXISTS public.algorithm_profiles OWNER TO quantumgate_migrator;
ALTER TABLE IF EXISTS public.key_references OWNER TO quantumgate_migrator;
ALTER TABLE IF EXISTS public.migration_observations OWNER TO quantumgate_migrator;
ALTER TABLE IF EXISTS public.audit_events OWNER TO quantumgate_migrator;
ALTER TABLE IF EXISTS public.admin_sessions OWNER TO quantumgate_migrator;
ALTER TABLE IF EXISTS public.oidc_login_transactions OWNER TO quantumgate_migrator;
ALTER TABLE IF EXISTS public.admin_auth_events OWNER TO quantumgate_migrator;
ALTER TABLE IF EXISTS public.rate_limit_buckets OWNER TO quantumgate_migrator;
ALTER TABLE IF EXISTS public.idempotency_records OWNER TO quantumgate_migrator;
ALTER TABLE IF EXISTS public.export_jobs OWNER TO quantumgate_migrator;
ALTER TABLE IF EXISTS public.policy_schedule_queue OWNER TO quantumgate_migrator;
ALTER TABLE IF EXISTS public.service_access_tokens OWNER TO quantumgate_migrator;
SELECT to_regprocedure('public.qg_reject_audit_mutation()') IS NOT NULL AS qg_audit_function_exists \gset
\if :qg_audit_function_exists
ALTER FUNCTION public.qg_reject_audit_mutation() OWNER TO quantumgate_migrator;
\endif
SELECT to_regprocedure('public.qg_reject_admin_auth_event_mutation()') IS NOT NULL AS qg_auth_function_exists \gset
\if :qg_auth_function_exists
ALTER FUNCTION public.qg_reject_admin_auth_event_mutation() OWNER TO quantumgate_migrator;
\endif
SELECT to_regprocedure('public.qg_guard_policy_revision()') IS NOT NULL AS qg_policy_guard_exists \gset
\if :qg_policy_guard_exists
ALTER FUNCTION public.qg_guard_policy_revision() OWNER TO quantumgate_migrator;
REVOKE ALL ON FUNCTION public.qg_guard_policy_revision() FROM PUBLIC, quantumgate;
\endif
SELECT to_regprocedure('public.qg_guard_algorithm_profile_review()') IS NOT NULL AS qg_profile_review_guard_exists \gset
\if :qg_profile_review_guard_exists
ALTER FUNCTION public.qg_guard_algorithm_profile_review() OWNER TO quantumgate_migrator;
REVOKE ALL ON FUNCTION public.qg_guard_algorithm_profile_review() FROM PUBLIC, quantumgate;
\endif
SELECT to_regprocedure('public.qg_schedule_policy(uuid,uuid,timestamp with time zone)') IS NOT NULL AS qg_schedule_function_exists \gset
\if :qg_schedule_function_exists
ALTER FUNCTION public.qg_schedule_policy(uuid, uuid, timestamptz) OWNER TO quantumgate_migrator;
REVOKE ALL ON FUNCTION public.qg_schedule_policy(uuid, uuid, timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.qg_schedule_policy(uuid, uuid, timestamptz) TO quantumgate;
\endif
SELECT to_regprocedure('public.qg_cancel_policy_schedule(uuid,uuid)') IS NOT NULL AS qg_cancel_function_exists \gset
\if :qg_cancel_function_exists
ALTER FUNCTION public.qg_cancel_policy_schedule(uuid, uuid) OWNER TO quantumgate_migrator;
REVOKE ALL ON FUNCTION public.qg_cancel_policy_schedule(uuid, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.qg_cancel_policy_schedule(uuid, uuid) TO quantumgate;
\endif
SELECT to_regprocedure('public.qg_claim_due_policy_schedules(integer)') IS NOT NULL AS qg_claim_function_exists \gset
\if :qg_claim_function_exists
ALTER FUNCTION public.qg_claim_due_policy_schedules(integer) OWNER TO quantumgate_migrator;
REVOKE ALL ON FUNCTION public.qg_claim_due_policy_schedules(integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.qg_claim_due_policy_schedules(integer) TO quantumgate;
\endif
SELECT to_regprocedure('public.qg_authenticate_application_credential(uuid,bytea)') IS NOT NULL AS qg_auth_credential_function_exists \gset
\if :qg_auth_credential_function_exists
ALTER FUNCTION public.qg_authenticate_application_credential(uuid, bytea) OWNER TO quantumgate_migrator;
REVOKE ALL ON FUNCTION public.qg_authenticate_application_credential(uuid, bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.qg_authenticate_application_credential(uuid, bytea) TO quantumgate;
\endif
SELECT to_regprocedure('public.qg_validate_service_access_token(bytea)') IS NOT NULL AS qg_validate_token_function_exists \gset
\if :qg_validate_token_function_exists
ALTER FUNCTION public.qg_validate_service_access_token(bytea) OWNER TO quantumgate_migrator;
REVOKE ALL ON FUNCTION public.qg_validate_service_access_token(bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.qg_validate_service_access_token(bytea) TO quantumgate;
\endif
SELECT to_regprocedure('public.qg_purge_expired_exports(uuid,integer)') IS NOT NULL AS qg_export_purge_function_exists \gset
\if :qg_export_purge_function_exists
ALTER FUNCTION public.qg_purge_expired_exports(uuid, integer) OWNER TO quantumgate_migrator;
REVOKE ALL ON FUNCTION public.qg_purge_expired_exports(uuid, integer) FROM PUBLIC, quantumgate;
GRANT EXECUTE ON FUNCTION public.qg_purge_expired_exports(uuid, integer) TO quantumgate;
\endif
REVOKE ALL PRIVILEGES ON DATABASE :"qg_database" FROM PUBLIC;
REVOKE ALL PRIVILEGES ON DATABASE :"qg_database" FROM quantumgate;
REVOKE ALL PRIVILEGES ON SCHEMA public FROM PUBLIC;
REVOKE ALL PRIVILEGES ON SCHEMA public FROM quantumgate;
GRANT CONNECT ON DATABASE :"qg_database" TO quantumgate, quantumgate_migrator;
GRANT USAGE ON SCHEMA public TO quantumgate;
GRANT USAGE, CREATE ON SCHEMA public TO quantumgate_migrator;
REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM quantumgate;
REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM quantumgate;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO quantumgate;
GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA public TO quantumgate;
ALTER DEFAULT PRIVILEGES FOR ROLE quantumgate_migrator IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO quantumgate;
ALTER DEFAULT PRIVILEGES FOR ROLE quantumgate_migrator IN SCHEMA public
  GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO quantumgate;

SELECT to_regclass('public.policy_schedule_queue') IS NOT NULL AS qg_schedule_queue_exists \gset
\if :qg_schedule_queue_exists
REVOKE ALL ON TABLE public.policy_schedule_queue FROM PUBLIC, quantumgate;
\endif

SELECT to_regclass('public.export_jobs') IS NOT NULL AS qg_export_jobs_exists \gset
\if :qg_export_jobs_exists
REVOKE UPDATE, DELETE ON TABLE public.export_jobs FROM PUBLIC, quantumgate;
GRANT SELECT, INSERT ON TABLE public.export_jobs TO quantumgate;
\endif

SELECT to_regclass('public.qg_schema_migrations') IS NOT NULL AS qg_has_migration_history \gset
\if :qg_has_migration_history
REVOKE ALL ON TABLE public.qg_schema_migrations FROM quantumgate;
\endif
