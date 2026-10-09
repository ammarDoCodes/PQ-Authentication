package storage

import (
	"bytes"
	"crypto/sha256"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEmbeddedMigrationsAreVersionedAndTenantBound(t *testing.T) {
	migrations, err := LoadMigrations()
	if err != nil {
		t.Fatal(err)
	}
	if len(migrations) == 0 {
		t.Fatal("expected at least one embedded migration")
	}
	for i, migration := range migrations {
		if i > 0 && migrations[i-1].Version >= migration.Version {
			t.Fatalf("migrations are not strictly ordered at %s", migration.Name)
		}
		if len(migration.Checksum) != sha256.Size {
			t.Fatalf("invalid checksum length for %s", migration.Name)
		}
	}
	sql := strings.ToLower(migrations[0].SQL)
	for _, required := range []string{"enable row level security", "force row level security", "audit_events_append_only", "current_setting('qg.tenant_id'"} {
		if !strings.Contains(sql, required) {
			t.Fatalf("initial migration missing required control %q", required)
		}
	}
}

func TestAuthenticationLimitsIdempotencyAndPolicyScheduleMigrationsExist(t *testing.T) {
	migrations, err := LoadMigrations()
	if err != nil {
		t.Fatal(err)
	}
	contents := make(map[int64]string, len(migrations))
	for _, migration := range migrations {
		contents[migration.Version] = strings.ToLower(migration.SQL)
	}
	for version, required := range map[int64][]string{
		2:  {"oidc_login_transactions", "admin_sessions", "admin_auth_events_append_only"},
		3:  {"rate_limit_buckets", "primary key (bucket_hash, window_started_at)"},
		4:  {"idempotency_records", "force row level security", "primary key (tenant_id, key_hash)", "interval '24 hours'"},
		5:  {"lifecycle_updated_at", "lifecycle_version", "policy_revisions_immutable_content", "qg_schedule_policy", "qg_cancel_policy_schedule", "qg_claim_due_policy_schedules", "policy_schedule_queue", "force row level security", "security definer", "pg_temp"},
		11: {"create table export_jobs", "payload_ciphertext bytea", "octet_length(payload_ciphertext)", "row_count between 0 and 5000", "force row level security", "current_setting('qg.tenant_id'", "export_jobs_tenant_expiry", "qg_purge_expired_exports", "security definer", "set search_path = pg_catalog, public, pg_temp", "revoke update, delete on table export_jobs"},
		12: {"pending_review", "reviewed_by <> submitted_by", "algorithm_profiles_one_pending_review", "algorithm_profiles_one_approved_review", "qg_guard_algorithm_profile_review", "profile review evidence is immutable", "invalid algorithm profile lifecycle transition", "set search_path = pg_catalog, public, pg_temp", "update algorithm_profiles set lifecycle = 'disabled', reviewed_at = null where lifecycle = 'approved'"},
		14: {"webhook_signing_keys", "webhook_destinations", "webhook_events", "webhook_deliveries", "force row level security", "qg_claim_webhook_deliveries", "for update skip locked", "qg_get_webhook_public_key", "webhook events are immutable", "webhook delivery history is retained", "manual retry must preserve event identity", "webhook destination limit reached", "signing_audit_unavailable", "references public.audit_events(tenant_id, id) on delete restrict", "revoke all on table public.webhook_events from public"},
	} {
		migrationSQL, ok := contents[version]
		if !ok {
			t.Fatalf("migration version %d is missing", version)
		}
		for _, fragment := range required {
			if !strings.Contains(migrationSQL, fragment) {
				t.Errorf("migration %d is missing %q", version, fragment)
			}
		}
	}
}

func TestServiceTokenSecurityDefinerFunctionsPinTheirSearchPath(t *testing.T) {
	migrations, err := LoadMigrations()
	if err != nil {
		t.Fatal(err)
	}
	var serviceTokenMigration string
	for _, migration := range migrations {
		if migration.Version == 7 {
			serviceTokenMigration = strings.ToLower(migration.SQL)
			break
		}
	}
	for _, required := range []string{
		"set search_path = pg_catalog, public, pg_temp",
		"security definer",
	} {
		if !strings.Contains(serviceTokenMigration, required) {
			t.Errorf("service-token migration is missing pinned security-definer configuration %q", required)
		}
	}
	if count := strings.Count(serviceTokenMigration, "set search_path = pg_catalog, public, pg_temp"); count != 2 {
		t.Errorf("both credential lookup functions must pin their search_path, got %d declarations", count)
	}
}

func TestMigrationChecksumIsContentSensitive(t *testing.T) {
	left := sha256.Sum256([]byte("migration-a"))
	right := sha256.Sum256([]byte("migration-b"))
	if bytes.Equal(left[:], right[:]) {
		t.Fatal("different migration content must produce different checksums")
	}
}

func TestMigrationSourceFilesAreNotEmpty(t *testing.T) {
	migrations, err := LoadMigrations()
	if err != nil {
		t.Fatal(err)
	}
	for _, migration := range migrations {
		if strings.TrimSpace(migration.SQL) == "" {
			t.Fatalf("empty migration: %s", migration.Name)
		}
		if _, err := os.Stat(filepath.Join("migrations", migration.Name)); err != nil {
			t.Fatalf("embedded migration source is missing: %s", migration.Name)
		}
	}
}
