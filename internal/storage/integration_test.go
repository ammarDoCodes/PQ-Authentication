package storage

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/stdlib"

	"quantumgate/internal/keyprovider"
	"quantumgate/internal/webhook"
)

func TestPostgresMigrationTenantIsolationAndAuditImmutability(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL is not configured")
	}
	runtimeDSN := os.Getenv("TEST_RUNTIME_DATABASE_URL")
	if runtimeDSN == "" {
		t.Skip("TEST_RUNTIME_DATABASE_URL is not configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	base, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal("connect to test PostgreSQL: ", err)
	}
	t.Cleanup(func() { _ = base.Close(context.Background()) })

	random := make([]byte, 8)
	if _, err := rand.Read(random); err != nil {
		t.Fatal(err)
	}
	databaseName := "qgtest_" + hex.EncodeToString(random)
	quotedDatabase := pgx.Identifier{databaseName}.Sanitize()
	baseConfig, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal("parse test database configuration: ", err)
	}
	quotedOwner := pgx.Identifier{baseConfig.User}.Sanitize()
	if _, err := base.Exec(ctx, "CREATE DATABASE "+quotedDatabase+" OWNER "+quotedOwner, pgx.QueryExecModeSimpleProtocol); err != nil {
		t.Fatal("create isolated test database: ", err)
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		if _, err := base.Exec(cleanupCtx, "DROP DATABASE "+quotedDatabase, pgx.QueryExecModeSimpleProtocol); err != nil {
			t.Errorf("drop isolated test database: %v", err)
		}
	})

	baseConfig.Database = databaseName
	if baseConfig.RuntimeParams == nil {
		baseConfig.RuntimeParams = map[string]string{}
	}
	baseConfig.RuntimeParams["search_path"] = "public"
	conn, err := pgx.ConnectConfig(ctx, baseConfig)
	if err != nil {
		t.Fatal("connect to isolated test database: ", err)
	}
	defer conn.Close(context.Background())

	if err := ApplyMigrations(ctx, conn); err != nil {
		t.Fatal("apply clean migrations: ", err)
	}
	if _, err := conn.Exec(ctx, "GRANT CONNECT ON DATABASE "+quotedDatabase+" TO quantumgate"); err != nil {
		t.Fatal("grant runtime database access: ", err)
	}
	if _, err := conn.Exec(ctx, "GRANT USAGE ON SCHEMA public TO quantumgate"); err != nil {
		t.Fatal("grant runtime schema access: ", err)
	}
	if _, err := conn.Exec(ctx, "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO quantumgate"); err != nil {
		t.Fatal("grant runtime table access: ", err)
	}
	if _, err := conn.Exec(ctx, "GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA public TO quantumgate"); err != nil {
		t.Fatal("grant runtime sequence access: ", err)
	}
	if _, err := conn.Exec(ctx, "REVOKE ALL ON TABLE public.qg_schema_migrations, public.policy_schedule_queue FROM quantumgate"); err != nil {
		t.Fatal("revoke runtime access to internal tables: ", err)
	}
	runtimeConfig, err := pgx.ParseConfig(runtimeDSN)
	if err != nil {
		t.Fatal("parse runtime PostgreSQL configuration: ", err)
	}
	runtimeConfig.Database = databaseName
	if runtimeConfig.RuntimeParams == nil {
		runtimeConfig.RuntimeParams = map[string]string{}
	}
	runtimeConfig.RuntimeParams["search_path"] = "public"
	runtimeConn, err := pgx.ConnectConfig(ctx, runtimeConfig)
	if err != nil {
		t.Fatal("connect using the non-owner runtime role: ", err)
	}
	defer runtimeConn.Close(context.Background())
	if err := VerifyTenantSafePGXRole(ctx, runtimeConn); err != nil {
		t.Fatal("runtime database role is unsafe: ", err)
	}
	runtimeSQL := stdlib.OpenDB(*runtimeConfig)
	defer runtimeSQL.Close()

	tenantA := "10000000-0000-4000-8000-000000000001"
	tenantB := "20000000-0000-4000-8000-000000000002"
	if err := createTestTenant(ctx, runtimeConn, tenantA, "Tenant A"); err != nil {
		t.Fatal(err)
	}
	if err := createTestTenant(ctx, runtimeConn, tenantB, "Tenant B"); err != nil {
		t.Fatal(err)
	}

	environmentID := "30000000-0000-4000-8000-000000000003"
	applicationID := "40000000-0000-4000-8000-000000000004"
	if err := withTenant(ctx, runtimeConn, tenantA, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "INSERT INTO environments(id, tenant_id, name, lifecycle) VALUES ($1, $2, 'prod', 'production')", environmentID, tenantA); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, "INSERT INTO applications(id, tenant_id, environment_id, external_id, display_name, integration_mode, status) VALUES ($1, $2, $3, 'existing-app', 'Existing app', 'sdk', 'active')", applicationID, tenantA, environmentID)
		return err
	}); err != nil {
		t.Fatal("create tenant A application: ", err)
	}

	webhookMetadata := NewWebhookKeyProviderMetadataStore(runtimeSQL)
	webhookReference := "vault_" + strings.Repeat("B", 43)
	providerScope := keyprovider.Scope{TenantID: tenantA, ApplicationID: applicationID, Environment: "production"}
	createdWebhookMetadata, err := webhookMetadata.Create(ctx, providerScope, keyprovider.Metadata{
		Provider: keyprovider.VaultTransit, Reference: webhookReference, Purpose: keyprovider.PurposeSigning,
		Algorithm: keyprovider.AlgorithmEd25519, State: keyprovider.StateProvisioning,
		CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(), ExpiresAt: time.Now().Add(time.Hour).UTC(),
	})
	if err != nil || createdWebhookMetadata.Version != 1 {
		t.Fatalf("create isolated webhook provider metadata = %#v, %v", createdWebhookMetadata, err)
	}
	if err := webhookMetadata.Lock(ctx, providerScope, webhookReference, func(item *keyprovider.Metadata) error {
		item.State = keyprovider.StateActive
		item.UpdatedAt = time.Now().UTC().Add(time.Second)
		return nil
	}); err != nil {
		t.Fatalf("activate webhook provider metadata = %v", err)
	}
	if _, err := webhookMetadata.Read(ctx, providerScope, webhookReference); err != nil {
		t.Fatalf("read webhook provider metadata = %v", err)
	}
	otherWebhookScope := providerScope
	otherWebhookScope.TenantID = tenantB
	if _, err := webhookMetadata.Read(ctx, otherWebhookScope, webhookReference); !errors.Is(err, keyprovider.ErrKeyNotFound) {
		t.Fatalf("cross-tenant webhook provider metadata read = %v", err)
	}
	if err := withTenant(ctx, runtimeConn, tenantA, func(tx pgx.Tx) error {
		var visibleInGenericKeyAPI int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM key_references WHERE tenant_id = $1 AND provider_reference = $2`, tenantA, webhookReference).
			Scan(&visibleInGenericKeyAPI); err != nil {
			return err
		}
		if visibleInGenericKeyAPI != 0 {
			return fmt.Errorf("webhook provider reference leaked into %d general key rows", visibleInGenericKeyAPI)
		}
		return nil
	}); err != nil {
		t.Fatal("check generic key-reference visibility: ", err)
	}
	var webhookProviderKeyID string
	if err := withTenant(ctx, runtimeConn, tenantA, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT id::text FROM webhook_signing_keys WHERE tenant_id = $1 AND provider_reference = $2`, tenantA, webhookReference).
			Scan(&webhookProviderKeyID)
	}); err != nil {
		t.Fatal("read webhook provider key ID: ", err)
	}
	var publicKeyAbsent bool
	if err := runtimeSQL.QueryRowContext(ctx, `SELECT NOT EXISTS(SELECT 1 FROM public.qg_get_webhook_public_key($1::uuid))`, webhookProviderKeyID).
		Scan(&publicKeyAbsent); err != nil || !publicKeyAbsent {
		t.Fatalf("unpublished public key lookup: absent=%v error=%v", publicKeyAbsent, err)
	}

	providerMetadata := NewKeyProviderMetadataStore(runtimeSQL)
	providerReference := "vault_" + strings.Repeat("A", 43)
	created, err := providerMetadata.Create(ctx, providerScope, keyprovider.Metadata{
		Provider: keyprovider.VaultTransit, Reference: providerReference,
		Purpose: keyprovider.PurposeSigning, Algorithm: keyprovider.AlgorithmEd25519,
		State: keyprovider.StateProvisioning, CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
		ExpiresAt: time.Now().Add(time.Hour).UTC(),
	})
	if err != nil || created.Version != 1 {
		t.Fatalf("create provider metadata = %#v, %v", created, err)
	}
	duplicateReferenceErr := withTenant(ctx, runtimeConn, tenantA, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO key_references
			(tenant_id, application_id, purpose, provider, provider_reference, version, state, expires_at)
			VALUES ($1, $2, 'signing', 'vault-transit', $3, $4, 'provisioning', $5)`,
			tenantA, applicationID, providerReference, int64(created.Version+1), time.Now().Add(time.Hour).UTC())
		return err
	})
	var duplicateReferencePGError *pgconn.PgError
	if !errors.As(duplicateReferenceErr, &duplicateReferencePGError) ||
		duplicateReferencePGError.Code != "23505" ||
		duplicateReferencePGError.ConstraintName != "key_references_vault_provider_reference" {
		t.Fatalf("migration 13 must reject duplicate scoped Vault references with its unique index; error=%v", duplicateReferenceErr)
	}
	if err := providerMetadata.Lock(ctx, providerScope, providerReference, func(item *keyprovider.Metadata) error {
		if item.State != keyprovider.StateProvisioning {
			return keyprovider.ErrStaleTransition
		}
		item.State = keyprovider.StateActive
		item.UpdatedAt = time.Now().UTC()
		return nil
	}); err != nil {
		t.Fatalf("activate provider metadata = %v", err)
	}
	loaded, err := providerMetadata.Read(ctx, providerScope, providerReference)
	if err != nil || loaded.State != keyprovider.StateActive || loaded.Version != created.Version {
		t.Fatalf("read provider metadata = %#v, %v", loaded, err)
	}
	otherScope := providerScope
	otherScope.TenantID = tenantB
	if _, err := providerMetadata.Read(ctx, otherScope, providerReference); !errors.Is(err, keyprovider.ErrKeyNotFound) {
		t.Fatalf("cross-tenant provider metadata read = %v", err)
	}
	auditSink := NewKeyProviderAuditSink(runtimeSQL)
	event := keyprovider.AuditEvent{
		TenantID: tenantA, ApplicationID: applicationID, Environment: "production",
		Actor: "test-security-engineer", CorrelationID: "vault-key-test-correlation",
		Provider: keyprovider.VaultTransit, Purpose: keyprovider.PurposeSigning,
		Algorithm: keyprovider.AlgorithmEd25519, Operation: keyprovider.OperationGenerate,
		Phase: "started", Outcome: "requested", ReasonCode: "KEY_GENERATION_REQUESTED",
	}
	if err := auditSink.RecordKeyOperation(ctx, event); err != nil {
		t.Fatalf("write provider audit intent = %v", err)
	}
	event.KeyReferenceHash = strings.Repeat("a", 64)
	event.Phase, event.Outcome, event.ReasonCode = "completed", "success", "KEY_GENERATED"
	if err := auditSink.RecordKeyOperation(ctx, event); err != nil {
		t.Fatalf("write provider completion audit = %v", err)
	}
	if err := withTenant(ctx, runtimeConn, tenantA, func(tx pgx.Tx) error {
		var count int
		var rawSource string
		if err := tx.QueryRow(ctx, `SELECT count(*), string_agg(source_context::text, ' ')
			FROM audit_events WHERE correlation_id = $1`, event.CorrelationID).Scan(&count, &rawSource); err != nil {
			return err
		}
		if count != 2 || strings.Contains(rawSource, "signing payload canary") {
			return fmt.Errorf("provider audit rows=%d contain unexpected data", count)
		}
		return nil
	}); err != nil {
		t.Fatalf("verify provider audit redaction/correlation = %v", err)
	}

	err = withTenant(ctx, runtimeConn, tenantB, func(tx pgx.Tx) error {
		var found string
		return tx.QueryRow(ctx, "SELECT id FROM applications WHERE id = $1", applicationID).Scan(&found)
	})
	if !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("cross-tenant application read should be invisible, got %v", err)
	}

	err = withTenant(ctx, runtimeConn, tenantB, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, "INSERT INTO environments(id, tenant_id, name, lifecycle) VALUES ($1, $2, 'forged', 'production')", "50000000-0000-4000-8000-000000000005", tenantA)
		return err
	})
	if err == nil {
		t.Fatal("cross-tenant write should be rejected by row-level security")
	}

	auditID := ""
	if err := withTenant(ctx, runtimeConn, tenantA, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `INSERT INTO audit_events(tenant_id, schema_version, actor, action, target_type, target_id, outcome, correlation_id, reason_code)
			VALUES ($1, 1, 'test-operator', 'application.created', 'application', $2, 'success', 'test-correlation', 'CREATED') RETURNING id::text`, tenantA, applicationID).Scan(&auditID)
	}); err != nil {
		t.Fatal("create audit event: ", err)
	}

	for _, statement := range []string{
		"UPDATE audit_events SET action = 'tampered' WHERE id = $1",
		"DELETE FROM audit_events WHERE id = $1",
	} {
		err := withTenant(ctx, runtimeConn, tenantA, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, statement, auditID)
			return err
		})
		if err == nil {
			t.Fatalf("audit mutation unexpectedly succeeded: %s", statement)
		}
	}

	var signingKeyID string
	destinationIDs := make([]string, 0, 2)
	var webhookEventID string
	const eventCorrelation = "webhook-queue-correlation"
	outboxTx, err := runtimeSQL.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal("begin webhook outbox transaction: ", err)
	}
	if _, err := outboxTx.ExecContext(ctx, "SELECT set_config('qg.tenant_id', $1, true)", tenantA); err != nil {
		_ = outboxTx.Rollback()
		t.Fatal("set webhook tenant scope: ", err)
	}
	publicMaterial := make([]byte, 44)
	if err := outboxTx.QueryRowContext(ctx, `INSERT INTO webhook_signing_keys
		(tenant_id, application_id, provider, provider_reference, algorithm, public_material, expires_at)
		VALUES ($1, $2, 'test-provider', $3, 'Ed25519', $4, clock_timestamp() + interval '1 year') RETURNING id::text`,
		tenantA, applicationID, "test-provider-reference-001", publicMaterial).Scan(&signingKeyID); err != nil {
		_ = outboxTx.Rollback()
		t.Fatal("create webhook signing metadata: ", err)
	}
	for index := 1; index <= 2; index++ {
		var destinationID string
		endpoint := fmt.Sprintf("https://hooks%d.example.com/qg/events", index)
		if err := outboxTx.QueryRowContext(ctx, `INSERT INTO webhook_destinations
			(tenant_id, application_id, endpoint_url, event_types, signing_key_id)
			VALUES ($1, $2, $3, ARRAY['policy.activated']::TEXT[], $4) RETURNING id::text`,
			tenantA, applicationID, endpoint, signingKeyID).Scan(&destinationID); err != nil {
			_ = outboxTx.Rollback()
			t.Fatal("create webhook destination: ", err)
		}
		destinationIDs = append(destinationIDs, destinationID)
	}
	var webhookAuditID string
	if err := outboxTx.QueryRowContext(ctx, `INSERT INTO audit_events
		(tenant_id, schema_version, actor, action, target_type, target_id, outcome, correlation_id, reason_code)
		VALUES ($1, 1, 'test-operator', 'policy.activated', 'policy_revision', $2, 'success', $3, 'ACTIVATED') RETURNING id::text`,
		tenantA, "50000000-0000-4000-8000-000000000005", eventCorrelation).Scan(&webhookAuditID); err != nil {
		_ = outboxTx.Rollback()
		t.Fatal("insert source audit: ", err)
	}
	if err := webhook.QueueTx(ctx, outboxTx, webhookAuditID, tenantA, applicationID, webhook.PolicyActivated,
		"policy_revision", "50000000-0000-4000-8000-000000000005", "POLICY_ACTIVATED", eventCorrelation,
		"test-operator", "security_engineer"); err != nil {
		_ = outboxTx.Rollback()
		t.Fatal("queue webhook from source audit: ", err)
	}
	if err := outboxTx.QueryRowContext(ctx, `SELECT id::text FROM webhook_events WHERE tenant_id = $1 AND correlation_id = $2`,
		tenantA, eventCorrelation).Scan(&webhookEventID); err != nil {
		_ = outboxTx.Rollback()
		t.Fatal("read queued webhook identity: ", err)
	}
	if webhookEventID != webhookAuditID {
		_ = outboxTx.Rollback()
		t.Fatalf("webhook event ID %s does not match deterministic source audit ID %s", webhookEventID, webhookAuditID)
	}
	if err := outboxTx.Commit(); err != nil {
		t.Fatal("commit webhook outbox transaction: ", err)
	}
	if err := withTenant(ctx, runtimeConn, tenantA, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO webhook_events
			(id, tenant_id, application_id, event_type, correlation_id, resource_type, resource_id, reason_code)
			VALUES ('60000000-0000-4000-8000-000000000006', $1, $2, 'policy.activated',
				'orphan-webhook-event', 'policy_revision', '50000000-0000-4000-8000-000000000005', 'POLICY_ACTIVATED')`,
			tenantA, applicationID)
		return err
	}); err == nil {
		t.Fatal("runtime role inserted a webhook event without a matching source audit")
	}

	type claimResult struct {
		id, tenant, lease string
		attempt, cycle    int
		err               error
	}
	claims := make(chan claimResult, 2)
	var claimGroup sync.WaitGroup
	for index := 0; index < 2; index++ {
		claimGroup.Add(1)
		go func() {
			defer claimGroup.Done()
			var result claimResult
			result.err = runtimeSQL.QueryRowContext(ctx, `SELECT delivery_id::text, tenant_id::text, lease_token::text, attempt, cycle_attempt
				FROM public.qg_claim_webhook_deliveries(1)`).Scan(&result.id, &result.tenant, &result.lease, &result.attempt, &result.cycle)
			claims <- result
		}()
	}
	claimGroup.Wait()
	close(claims)
	claimedIDs := make([]string, 0, 2)
	claimByID := make(map[string]claimResult, 2)
	for result := range claims {
		if result.err != nil || result.tenant != tenantA || result.attempt != 1 || result.cycle != 1 {
			t.Fatalf("webhook claim = %+v", result)
		}
		if _, duplicate := claimByID[result.id]; duplicate {
			t.Fatalf("concurrent webhook workers claimed duplicate delivery %s", result.id)
		}
		claimByID[result.id] = result
		claimedIDs = append(claimedIDs, result.id)
	}
	if len(claimedIDs) != 2 {
		t.Fatalf("concurrent workers claimed %d rows, want 2", len(claimedIDs))
	}

	if err := withTenant(ctx, runtimeConn, tenantB, func(tx pgx.Tx) error {
		var visible int
		if err := tx.QueryRow(ctx, `SELECT (SELECT count(*) FROM webhook_events WHERE id = $1) +
			(SELECT count(*) FROM webhook_deliveries WHERE event_id = $1) +
			(SELECT count(*) FROM webhook_destinations WHERE id = $2) +
			(SELECT count(*) FROM webhook_destinations WHERE id = $3)`,
			webhookEventID, destinationIDs[0], destinationIDs[1]).Scan(&visible); err != nil {
			return err
		}
		if visible != 0 {
			return fmt.Errorf("tenant B can see %d tenant A webhook rows", visible)
		}
		return nil
	}); err != nil {
		t.Fatal("cross-tenant outbox lookup failed: ", err)
	}
	secondClaim := claimByID[claimedIDs[1]]
	if err := withTenant(ctx, runtimeConn, tenantA, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE webhook_deliveries SET state = 'retry', next_attempt_at = clock_timestamp(),
			lease_token = NULL, lease_until = NULL, last_error_code = 'SIGNING_AUDIT_UNAVAILABLE',
			updated_at = GREATEST(clock_timestamp(), updated_at + interval '1 microsecond')
			WHERE id = $1 AND state = 'delivering' AND lease_token = $2`, secondClaim.id, secondClaim.lease)
		return err
	}); err != nil {
		t.Fatal("transient signing-audit failure was rejected by retry guard: ", err)
	}
	var retryClaimedID string
	var retryCycle int
	var retryLease string
	if err := runtimeSQL.QueryRowContext(ctx, `SELECT delivery_id::text, lease_token::text, cycle_attempt
		FROM public.qg_claim_webhook_deliveries(1)`).Scan(&retryClaimedID, &retryLease, &retryCycle); err != nil ||
		retryClaimedID != secondClaim.id || retryCycle != 2 {
		t.Fatalf("retryable signing-audit failure was not reclaimed: id=%s cycle=%d error=%v", retryClaimedID, retryCycle, err)
	}
	if err := withTenant(ctx, runtimeConn, tenantA, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE webhook_deliveries SET state = 'retry', next_attempt_at = clock_timestamp(),
			lease_token = NULL, lease_until = NULL, last_error_code = 'SIGNING_FAILED',
			updated_at = GREATEST(clock_timestamp(), updated_at + interval '1 microsecond')
			WHERE id = $1 AND state = 'delivering' AND lease_token = $2`, retryClaimedID, retryLease)
		return err
	}); err == nil {
		t.Fatal("permanent signing failure was accepted as an automatic retry")
	}
	var auditSource string
	if err := withTenant(ctx, runtimeConn, tenantA, func(tx pgx.Tx) error {
		var count int
		if err := tx.QueryRow(ctx, `SELECT count(*), string_agg(source_context::text, ' ') FROM audit_events
			WHERE correlation_id = $1`, eventCorrelation).Scan(&count, &auditSource); err != nil {
			return err
		}
		if count != 2 {
			return fmt.Errorf("correlated source and queue audit count is %d", count)
		}
		return nil
	}); err != nil {
		t.Fatal("verify webhook audit correlation: ", err)
	}
	if strings.Contains(auditSource, "hooks") || strings.Contains(auditSource, "test-provider-reference") {
		t.Fatal("webhook audit leaked an endpoint or provider reference")
	}
	var publicAlgorithm string
	var returnedPublic []byte
	if err := runtimeSQL.QueryRowContext(ctx, `SELECT algorithm, public_material FROM public.qg_get_webhook_public_key($1)`, signingKeyID).
		Scan(&publicAlgorithm, &returnedPublic); err != nil || publicAlgorithm != "Ed25519" || !bytes.Equal(returnedPublic, publicMaterial) {
		t.Fatalf("public webhook key lookup = %q, matching=%v, error=%v", publicAlgorithm, bytes.Equal(returnedPublic, publicMaterial), err)
	}

	for _, statement := range []string{
		"UPDATE webhook_events SET reason_code = 'TAMPERED' WHERE id = $1",
		"DELETE FROM webhook_events WHERE id = $1",
		"UPDATE webhook_signing_keys SET public_material = decode('01', 'hex') WHERE id = $1",
		"UPDATE webhook_deliveries SET attempts = attempts + 1, updated_at = clock_timestamp() WHERE id = $1",
		"DELETE FROM webhook_deliveries WHERE id = $1",
	} {
		id := webhookEventID
		if strings.Contains(statement, "webhook_signing_keys") {
			id = signingKeyID
		} else if strings.Contains(statement, "webhook_deliveries") {
			id = claimedIDs[0]
		}
		err := withTenant(ctx, runtimeConn, tenantA, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, statement, id)
			return err
		})
		if err == nil {
			t.Fatalf("runtime role unexpectedly mutated immutable or state-guarded webhook data: %s", statement)
		}
	}
	firstClaim := claimByID[claimedIDs[0]]
	if err := withTenant(ctx, runtimeConn, tenantA, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE webhook_deliveries SET state = 'dead', last_error_code = 'HTTP_PERMANENT_FAILURE',
			lease_token = NULL, lease_until = NULL, next_attempt_at = clock_timestamp(),
			updated_at = GREATEST(clock_timestamp(), updated_at + interval '1 microsecond') WHERE id = $1 AND lease_token = $2`,
			firstClaim.id, firstClaim.lease); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE webhook_deliveries SET state = 'pending', cycle_attempts = 0,
			manual_retries = manual_retries + 1, next_attempt_at = clock_timestamp(), last_status_code = NULL,
			last_error_code = NULL, updated_at = GREATEST(clock_timestamp(), updated_at + interval '1 microsecond')
			WHERE id = $1 AND state = 'dead'`, firstClaim.id)
		return err
	}); err != nil {
		t.Fatal("manual retry state transition rejected: ", err)
	}
	if err := withTenant(ctx, runtimeConn, tenantA, func(tx pgx.Tx) error {
		var state string
		var attempts, cycle, manualRetries int
		var actualEvent string
		if err := tx.QueryRow(ctx, `SELECT state, attempts, cycle_attempts, manual_retries, event_id::text
			FROM webhook_deliveries WHERE id = $1`, firstClaim.id).Scan(&state, &attempts, &cycle, &manualRetries, &actualEvent); err != nil {
			return err
		}
		if state != "pending" || attempts != 1 || cycle != 0 || manualRetries != 1 || actualEvent != webhookEventID {
			return fmt.Errorf("manual retry changed event identity or counters: %s/%d/%d/%d/%s", state, attempts, cycle, manualRetries, actualEvent)
		}
		return nil
	}); err != nil {
		t.Fatal("manual retry identity check: ", err)
	}
}

func TestProfileReviewMigrationDisablesLegacyApprovals(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL is not configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	base, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal("connect to test PostgreSQL: ", err)
	}
	t.Cleanup(func() { _ = base.Close(context.Background()) })

	random := make([]byte, 8)
	if _, err := rand.Read(random); err != nil {
		t.Fatal(err)
	}
	databaseName := "qgupgrade_" + hex.EncodeToString(random)
	quotedDatabase := pgx.Identifier{databaseName}.Sanitize()
	baseConfig, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal("parse test database configuration: ", err)
	}
	quotedOwner := pgx.Identifier{baseConfig.User}.Sanitize()
	if _, err := base.Exec(ctx, "CREATE DATABASE "+quotedDatabase+" OWNER "+quotedOwner, pgx.QueryExecModeSimpleProtocol); err != nil {
		t.Fatal("create isolated upgrade-test database: ", err)
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		if _, err := base.Exec(cleanupCtx, "DROP DATABASE "+quotedDatabase, pgx.QueryExecModeSimpleProtocol); err != nil {
			t.Errorf("drop isolated upgrade-test database: %v", err)
		}
	})

	baseConfig.Database = databaseName
	if baseConfig.RuntimeParams == nil {
		baseConfig.RuntimeParams = map[string]string{}
	}
	baseConfig.RuntimeParams["search_path"] = "public"
	conn, err := pgx.ConnectConfig(ctx, baseConfig)
	if err != nil {
		t.Fatal("connect to isolated upgrade-test database: ", err)
	}
	defer conn.Close(context.Background())

	migrations, err := LoadMigrations()
	if err != nil {
		t.Fatal("load migration set: ", err)
	}
	if _, err := conn.Exec(ctx, `CREATE TABLE qg_schema_migrations (
		version BIGINT PRIMARY KEY,
		name TEXT NOT NULL,
		checksum BYTEA NOT NULL CHECK (octet_length(checksum) = 32),
		applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
	)`); err != nil {
		t.Fatal("create migration history: ", err)
	}
	var lastVersion int64
	for _, migration := range migrations {
		if migration.Version >= 12 {
			break
		}
		tx, err := conn.Begin(ctx)
		if err != nil {
			t.Fatal("begin legacy migration: ", err)
		}
		if _, err = tx.Exec(ctx, migration.SQL, pgx.QueryExecModeSimpleProtocol); err == nil {
			_, err = tx.Exec(ctx, "INSERT INTO qg_schema_migrations(version, name, checksum) VALUES ($1, $2, $3)",
				migration.Version, migration.Name, migration.Checksum)
		}
		if err != nil {
			_ = tx.Rollback(ctx)
			t.Fatalf("apply legacy migration %d: %v", migration.Version, err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatalf("commit legacy migration %d: %v", migration.Version, err)
		}
		lastVersion = migration.Version
	}
	if lastVersion != 11 {
		t.Fatalf("expected to prepare schema through migration 11, got %d", lastVersion)
	}

	const tenantID = "60000000-0000-4000-8000-000000000006"
	if err := createTestTenant(ctx, conn, tenantID, "Legacy approval tenant"); err != nil {
		t.Fatal("create legacy approval tenant: ", err)
	}
	if err := withTenant(ctx, conn, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO algorithm_profiles
			(tenant_id, registry_version, profile_id, provider, provider_version, use_case, lifecycle, source_reference, reviewed_at)
			VALUES ($1, 1, 'tls13-classical', 'test-provider', '1.0', 'tls', 'approved', 'https://registry.example/profile', clock_timestamp())`, tenantID)
		return err
	}); err != nil {
		t.Fatal("seed pre-review approval: ", err)
	}

	if err := ApplyMigrations(ctx, conn); err != nil {
		t.Fatal("apply profile-review upgrade: ", err)
	}
	var lifecycle string
	var reviewedAtIsNull bool
	if err := withTenant(ctx, conn, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT lifecycle, reviewed_at IS NULL FROM algorithm_profiles
			WHERE tenant_id = $1 AND profile_id = 'tls13-classical'`, tenantID).Scan(&lifecycle, &reviewedAtIsNull)
	}); err != nil {
		t.Fatal("read upgraded legacy approval: ", err)
	}
	if lifecycle != "disabled" || !reviewedAtIsNull {
		t.Fatalf("legacy approval without independent review evidence must be disabled, got lifecycle=%q reviewed_at_null=%v", lifecycle, reviewedAtIsNull)
	}
}

func createTestTenant(ctx context.Context, conn *pgx.Conn, id, name string) error {
	return withTenant(ctx, conn, id, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, "INSERT INTO tenants(id, display_name, status) VALUES ($1, $2, 'active')", id, name)
		return err
	})
}

func withTenant(ctx context.Context, conn *pgx.Conn, tenantID string, operation func(pgx.Tx) error) error {
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, "SELECT set_config('qg.tenant_id', $1, true)", tenantID); err != nil {
		return err
	}
	if err := operation(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
