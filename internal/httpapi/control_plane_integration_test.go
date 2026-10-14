package httpapi

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"

	"quantumgate/internal/auth"
	"quantumgate/internal/config"
	"quantumgate/internal/gateway"
	"quantumgate/internal/storage"
)

type integrationTokenVerifier struct{ principal auth.Principal }

func (v integrationTokenVerifier) Verify(context.Context, string) (auth.Principal, error) {
	return v.principal, nil
}

func TestControlPlaneTenantIsolationAndRoleAuthorization(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL is not configured")
	}
	runtimeDSN := os.Getenv("TEST_RUNTIME_DATABASE_URL")
	if runtimeDSN == "" {
		t.Skip("TEST_RUNTIME_DATABASE_URL is not configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	base, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal("connect to test PostgreSQL: ", err)
	}
	t.Cleanup(func() { _ = base.Close(context.Background()) })

	randomID := make([]byte, 8)
	if _, err := rand.Read(randomID); err != nil {
		t.Fatal(err)
	}
	// Cryptographically random names isolate databases across concurrent test runs.
	databaseName := "qgapi_" + hex.EncodeToString(randomID)
	quotedDatabase := pgx.Identifier{databaseName}.Sanitize()
	pgConfig, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal("parse test PostgreSQL configuration: ", err)
	}
	quotedOwner := pgx.Identifier{pgConfig.User}.Sanitize()
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

	pgConfig.Database = databaseName
	if pgConfig.RuntimeParams == nil {
		pgConfig.RuntimeParams = map[string]string{}
	}
	pgConfig.RuntimeParams["search_path"] = "public"
	conn, err := pgx.ConnectConfig(ctx, pgConfig)
	if err != nil {
		t.Fatal("connect to isolated test database: ", err)
	}
	defer conn.Close(context.Background())
	if err := storage.ApplyMigrations(ctx, conn); err != nil {
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
	if _, err := conn.Exec(ctx, "REVOKE UPDATE, DELETE ON TABLE public.export_jobs FROM quantumgate"); err != nil {
		t.Fatal("restrict runtime export access: ", err)
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
	db := stdlib.OpenDB(*runtimeConfig)
	db.SetMaxOpenConns(4)
	defer db.Close()
	if err := storage.VerifyTenantSafeRole(ctx, db); err != nil {
		t.Fatal("runtime database role is unsafe: ", err)
	}
	var canMutateExportRows bool
	if err := db.QueryRowContext(ctx, `SELECT has_table_privilege(current_user, 'public.export_jobs', 'UPDATE')
		OR has_table_privilege(current_user, 'public.export_jobs', 'DELETE')`).Scan(&canMutateExportRows); err != nil || canMutateExportRows {
		t.Fatalf("runtime role must not directly update or delete export rows: %v, query error %v", canMutateExportRows, err)
	}
	tenantA := "10000000-0000-4000-8000-000000000001"
	tenantB := "20000000-0000-4000-8000-000000000002"
	applicationA := "40000000-0000-4000-8000-000000000004"
	createControlPlaneFixture(t, ctx, conn, tenantA, "Tenant A", "developer", "30000000-0000-4000-8000-000000000003", applicationA)
	createControlPlaneFixture(t, ctx, conn, tenantB, "Tenant B", "auditor", "50000000-0000-4000-8000-000000000005", "")

	server := &Server{
		DB: db, Store: db,
		Auth:         integrationTokenVerifier{principal: auth.Principal{Issuer: "https://id.example", Subject: "admin-1"}},
		PublicOrigin: "https://console.example", RateLimitKey: []byte(strings.Repeat("k", 32)), CryptoMode: config.CryptoObserve,
		OIDC: &auth.OIDCFlow{},
	}
	handler := server.Handler()
	for attempt := 0; attempt < adminLoginLimit; attempt++ {
		loginRequest := httptest.NewRequest(http.MethodGet, "/auth/login", nil)
		loginRequest.RemoteAddr = "198.51.100.51:43100"
		loginResponse := httptest.NewRecorder()
		handler.ServeHTTP(loginResponse, loginRequest)
		if loginResponse.Code != http.StatusFound {
			t.Fatalf("login initiation %d should be allowed, got %d %s", attempt+1, loginResponse.Code, loginResponse.Body.String())
		}
	}
	limitedLogin := httptest.NewRequest(http.MethodGet, "/auth/login", nil)
	limitedLogin.RemoteAddr = "198.51.100.51:43100"
	limitedResponse := httptest.NewRecorder()
	handler.ServeHTTP(limitedResponse, limitedLogin)
	if limitedResponse.Code != http.StatusTooManyRequests || limitedResponse.Header().Get("Retry-After") == "" {
		t.Fatalf("login initiation must be rate limited after five requests with retry guidance, got %d %s", limitedResponse.Code, limitedResponse.Body.String())
	}
	requestSequence := 0
	nextKey := func() string {
		requestSequence++
		return fmt.Sprintf("integration-test-key-%08d", requestSequence)
	}
	requestWithKey := func(method, path, tenant string, body, key string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer verified-test-token")
		r.Header.Set("X-QG-Tenant-ID", tenant)
		if unsafeMethod(method) {
			r.Header.Set(idempotencyKeyHeader, key)
		}
		if body != "" {
			r.Header.Set("Content-Type", "application/json")
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, r)
		return response
	}
	request := func(method, path, tenant string, body string) *httptest.ResponseRecorder {
		return requestWithKey(method, path, tenant, body, nextKey())
	}

	response := request(http.MethodGet, "/v1/applications/"+applicationA, tenantA, "")
	if response.Code != http.StatusOK {
		t.Fatalf("tenant A should read its application, got %d %s", response.Code, response.Body.String())
	}
	response = request(http.MethodGet, "/v1/applications/"+applicationA, tenantB, "")
	if response.Code != http.StatusNotFound || strings.Contains(response.Body.String(), "Tenant A") {
		t.Fatalf("tenant B must not discover tenant A application, got %d %s", response.Code, response.Body.String())
	}
	response = request(http.MethodPost, "/v1/tenants/"+tenantB+"/environments", tenantB, `{"name":"blocked","lifecycle":"production"}`)
	if response.Code != http.StatusForbidden {
		t.Fatalf("auditor role must not create environments, got %d %s", response.Code, response.Body.String())
	}

	var auditCount int
	if err := withIntegrationTenant(ctx, conn, tenantB, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE action = 'authorization.denied' AND outcome = 'denied'`).Scan(&auditCount)
	}); err != nil {
		t.Fatal("read authorization audit: ", err)
	}
	if auditCount != 1 {
		t.Fatalf("expected one denied-action audit event for tenant B, got %d", auditCount)
	}

	exportFrom := time.Now().UTC().Add(-time.Hour)
	exportTo := time.Now().UTC()
	exportBody, _ := json.Marshal(map[string]string{
		"from": exportFrom.Format(time.RFC3339Nano), "to": exportTo.Format(time.RFC3339Nano),
	})
	exportKey := nextKey()
	exportPath := "/v1/tenants/" + tenantB + "/exports"
	response = requestWithKey(http.MethodPost, exportPath, tenantB, string(exportBody), exportKey)
	if response.Code != http.StatusCreated {
		t.Fatalf("auditor should create a bounded audit export, got %d %s", response.Code, response.Body.String())
	}
	var createdExport auditExportView
	if err := json.Unmarshal(response.Body.Bytes(), &createdExport); err != nil || createdExport.ID == "" || createdExport.RowCount != 1 || createdExport.Status != "ready" {
		t.Fatalf("audit export response is invalid: %v %s", err, response.Body.String())
	}
	response = requestWithKey(http.MethodPost, exportPath, tenantB, string(exportBody), exportKey)
	var replayedExport auditExportView
	if response.Code != http.StatusCreated || response.Header().Get("Idempotency-Replayed") != "true" ||
		json.Unmarshal(response.Body.Bytes(), &replayedExport) != nil || replayedExport.ID != createdExport.ID {
		t.Fatalf("audit export retry must replay the original job, got %d %s", response.Code, response.Body.String())
	}
	response = requestWithKey(http.MethodPost, "/v1/tenants/"+tenantA+"/exports", tenantA, string(exportBody), nextKey())
	if response.Code != http.StatusForbidden {
		t.Fatalf("developer role must not create audit exports, got %d %s", response.Code, response.Body.String())
	}
	response = request(http.MethodGet, "/v1/exports/"+createdExport.ID, tenantB, "")
	if response.Code != http.StatusOK {
		t.Fatalf("export owner should read export status, got %d %s", response.Code, response.Body.String())
	}
	response = request(http.MethodGet, "/v1/exports/"+createdExport.ID+"/download", tenantB, "")
	if response.Code != http.StatusOK || response.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("export owner should download JSON, got %d %s", response.Code, response.Body.String())
	}
	var exportDocument auditExportDocument
	if err := json.Unmarshal(response.Body.Bytes(), &exportDocument); err != nil || len(exportDocument.Events) != 1 ||
		exportDocument.Events[0].Action != "authorization.denied" || strings.Contains(response.Body.String(), "source_context") {
		t.Fatalf("export must contain the redacted audit snapshot: %v %s", err, response.Body.String())
	}
	if err := withIntegrationTenant(ctx, conn, tenantA, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO tenant_members(tenant_id, issuer, subject, role)
			VALUES ($1, 'https://id.example', 'export-reader', 'auditor')`, tenantA)
		return err
	}); err != nil {
		t.Fatal("create cross-tenant export reader: ", err)
	}
	exportReader := &Server{
		DB: db, Store: db,
		Auth:         integrationTokenVerifier{principal: auth.Principal{Issuer: "https://id.example", Subject: "export-reader"}},
		PublicOrigin: "https://console.example", RateLimitKey: []byte(strings.Repeat("k", 32)), CryptoMode: config.CryptoObserve,
	}
	crossTenantHandler := exportReader.Handler()
	crossTenantRequest := httptest.NewRequest(http.MethodGet, "/v1/exports/"+createdExport.ID, nil)
	crossTenantRequest.Header.Set("Authorization", "Bearer verified-test-token")
	crossTenantRequest.Header.Set("X-QG-Tenant-ID", tenantA)
	crossTenantResponse := httptest.NewRecorder()
	crossTenantHandler.ServeHTTP(crossTenantResponse, crossTenantRequest)
	if crossTenantResponse.Code != http.StatusNotFound {
		t.Fatalf("another tenant must not discover export metadata, got %d %s", crossTenantResponse.Code, crossTenantResponse.Body.String())
	}
	var storedExport []byte
	if err := withIntegrationTenant(ctx, conn, tenantB, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT payload_ciphertext FROM export_jobs WHERE tenant_id = $1 AND id = $2`, tenantB, createdExport.ID).Scan(&storedExport)
	}); err != nil {
		t.Fatal("read stored export ciphertext: ", err)
	}
	if bytes.Contains(storedExport, []byte("authorization.denied")) || !bytes.HasPrefix(storedExport, auditExportBodyPrefix) {
		t.Fatal("audit export payload must be versioned ciphertext without plaintext events")
	}
	if err := withIntegrationTenant(ctx, conn, tenantB, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE export_jobs SET requested_at = now() - interval '2 seconds',
			expires_at = now() - interval '1 second' WHERE tenant_id = $1 AND id = $2`, tenantB, createdExport.ID)
		return err
	}); err != nil {
		t.Fatal("expire test export: ", err)
	}
	for _, path := range []string{"/v1/exports/" + createdExport.ID, "/v1/exports/" + createdExport.ID + "/download"} {
		response = request(http.MethodGet, path, tenantB, "")
		if response.Code != http.StatusNotFound {
			t.Fatalf("expired export must not be readable at %s, got %d %s", path, response.Code, response.Body.String())
		}
	}
	response = requestWithKey(http.MethodPost, exportPath, tenantB, string(exportBody), nextKey())
	if response.Code != http.StatusCreated {
		t.Fatalf("runtime role should purge expired exports through the restricted cleanup function, got %d %s", response.Code, response.Body.String())
	}
	var expiredExportRemains bool
	if err := withIntegrationTenant(ctx, conn, tenantB, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM export_jobs WHERE tenant_id = $1 AND id = $2)`, tenantB, createdExport.ID).Scan(&expiredExportRemains)
	}); err != nil || expiredExportRemains {
		t.Fatalf("expired export should be removed by bounded cleanup: remains=%v, err=%v", expiredExportRemains, err)
	}

	applicationBody := `{"environment_id":"30000000-0000-4000-8000-000000000003","external_id":"new-app","display_name":"New app","integration_mode":"sdk"}`
	applicationKey := nextKey()
	response = requestWithKey(http.MethodPost, "/v1/tenants/"+tenantA+"/applications", tenantA, applicationBody, applicationKey)
	if response.Code != http.StatusCreated {
		t.Fatalf("developer role should register an application in its tenant, got %d %s", response.Code, response.Body.String())
	}
	var created applicationView
	if err := json.Unmarshal(response.Body.Bytes(), &created); err != nil || created.ID == "" {
		t.Fatalf("application response is invalid: %v %s", err, response.Body.String())
	}
	if created.ID == applicationA {
		t.Fatal("created application reused an existing identifier")
	}
	response = requestWithKey(http.MethodPost, "/v1/tenants/"+tenantA+"/applications", tenantA, applicationBody, applicationKey)
	var replayed applicationView
	if response.Code != http.StatusCreated || response.Header().Get("Idempotency-Replayed") != "true" ||
		json.Unmarshal(response.Body.Bytes(), &replayed) != nil || replayed.ID != created.ID {
		t.Fatalf("retry with the same key must replay the original application response, got %d %s", response.Code, response.Body.String())
	}
	response = requestWithKey(http.MethodPost, "/v1/tenants/"+tenantA+"/applications", tenantA,
		strings.Replace(applicationBody, "New app", "Changed app", 1), applicationKey)
	if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "IDEMPOTENCY_KEY_REUSED") {
		t.Fatalf("reusing a key with a changed request must be rejected, got %d %s", response.Code, response.Body.String())
	}
	response = request(http.MethodPost, "/v1/tenants/"+tenantA+"/applications", tenantA, applicationBody)
	if response.Code != http.StatusConflict || strings.Contains(response.Body.String(), "CONTROL_PLANE_UNAVAILABLE") {
		t.Fatalf("duplicate application must return a stable conflict response, got %d %s", response.Code, response.Body.String())
	}

	sessionToken := strings.Repeat("s", 43)
	csrfToken := strings.Repeat("c", 43)
	if _, err := conn.Exec(ctx, `INSERT INTO admin_sessions
		(token_hash, issuer, subject, auth_time, csrf_hash, acr, expires_at)
		VALUES ($1, 'https://id.example', 'admin-1', now(), $2, 'urn:test:mfa', now() + interval '8 hours')`,
		hashToken(sessionToken), hashToken(csrfToken)); err != nil {
		t.Fatal("create test admin session: ", err)
	}
	sessionRequest := func(includeCSRF bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/v1/tenants/"+tenantA+"/applications", strings.NewReader(
			`{"environment_id":"30000000-0000-4000-8000-000000000003","external_id":"cookie-app","display_name":"Cookie app","integration_mode":"sdk"}`))
		r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionToken})
		r.Header.Set("X-QG-Tenant-ID", tenantA)
		r.Header.Set(idempotencyKeyHeader, nextKey())
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", server.PublicOrigin)
		if includeCSRF {
			r.AddCookie(&http.Cookie{Name: csrfCookieName, Value: csrfToken})
			r.Header.Set("X-QG-CSRF-Token", csrfToken)
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, r)
		return response
	}
	response = sessionRequest(true)
	if response.Code != http.StatusCreated {
		t.Fatalf("valid browser session and CSRF token should authorize application creation, got %d %s", response.Code, response.Body.String())
	}
	response = sessionRequest(false)
	if response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), "CSRF_REJECTED") {
		t.Fatalf("cookie-authenticated mutation without CSRF must be rejected, got %d %s", response.Code, response.Body.String())
	}

	adminServer := &Server{
		DB: db, Store: db, OIDCIssuer: "https://id.example", CryptoMode: config.CryptoObserve,
		IdentityAllowedHosts: []string{"login.customer.example", "keys.customer.example"},
		Auth:                 integrationTokenVerifier{principal: auth.Principal{Issuer: "https://id.example", Subject: "admin-2"}},
		RateLimitKey:         []byte(strings.Repeat("k", 32)),
	}
	if err := withIntegrationTenant(ctx, conn, tenantA, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO tenant_members(tenant_id, issuer, subject, role) VALUES ($1, 'https://id.example', 'admin-2', 'tenant_admin')`, tenantA)
		return err
	}); err != nil {
		t.Fatal("create tenant administrator fixture: ", err)
	}
	adminHandler := adminServer.Handler()
	adminRequestWithKey := func(method, path, body, key string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer verified-test-token")
		r.Header.Set("X-QG-Tenant-ID", tenantA)
		if unsafeMethod(method) {
			r.Header.Set(idempotencyKeyHeader, key)
		}
		if body != "" {
			r.Header.Set("Content-Type", "application/json")
		}
		response := httptest.NewRecorder()
		adminHandler.ServeHTTP(response, r)
		return response
	}
	adminRequest := func(method, path, body string) *httptest.ResponseRecorder {
		return adminRequestWithKey(method, path, body, nextKey())
	}
	adminRequestWithETag := func(method, path, body, etag string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer verified-test-token")
		r.Header.Set("X-QG-Tenant-ID", tenantA)
		if unsafeMethod(method) {
			r.Header.Set(idempotencyKeyHeader, nextKey())
		}
		if body != "" {
			r.Header.Set("Content-Type", "application/json")
		}
		if etag != "" {
			r.Header.Set("If-Match", etag)
		}
		response := httptest.NewRecorder()
		adminHandler.ServeHTTP(response, r)
		return response
	}
	response = adminRequest(http.MethodGet, "/v1/tenants/"+tenantA, "")
	if response.Code != http.StatusOK || response.Header().Get("ETag") == "" {
		t.Fatalf("tenant read should return an ETag for conditional updates: %d %s", response.Code, response.Body.String())
	}
	oldETag := response.Header().Get("ETag")
	response = adminRequest(http.MethodGet, "/v1/applications/"+created.ID, "")
	if response.Code != http.StatusOK || response.Header().Get("ETag") == "" {
		t.Fatalf("application read should return a version ETag: %d %s", response.Code, response.Body.String())
	}
	applicationETag := response.Header().Get("ETag")
	response = adminRequestWithETag(http.MethodPatch, "/v1/applications/"+created.ID, `{"display_name":"Renamed app"}`, applicationETag)
	if response.Code != http.StatusOK {
		t.Fatalf("tenant administrator should update application metadata with its ETag: %d %s", response.Code, response.Body.String())
	}
	response = adminRequestWithETag(http.MethodPatch, "/v1/applications/"+created.ID, `{"display_name":"Stale rename"}`, applicationETag)
	if response.Code != http.StatusPreconditionFailed {
		t.Fatalf("stale application ETag should be rejected: %d %s", response.Code, response.Body.String())
	}
	adapterPath := "/v1/applications/" + created.ID + "/identity-adapters"
	response = adminRequest(http.MethodPost, adapterPath,
		`{"adapter_type":"oidc","issuer":"https://login.customer.example/tenant-a","audience":"customer-app","required_acr":"urn:customer:mfa"}`)
	if response.Code != http.StatusCreated || response.Header().Get("ETag") == "" || !strings.Contains(response.Body.String(), `"status":"verification_required"`) {
		t.Fatalf("tenant administrator should register an allowlisted OIDC identity adapter: %d %s", response.Code, response.Body.String())
	}
	var identityAdapter struct {
		ID          string `json:"id"`
		RequiredACR string `json:"required_acr"`
		Status      string `json:"status"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &identityAdapter); err != nil || identityAdapter.ID == "" || identityAdapter.RequiredACR != "urn:customer:mfa" {
		t.Fatalf("identity adapter response is invalid: %v %s", err, response.Body.String())
	}
	initialAdapterETag := response.Header().Get("ETag")
	response = adminRequest(http.MethodGet, adapterPath, "")
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), identityAdapter.ID) {
		t.Fatalf("application identity adapter inventory should be readable: %d %s", response.Code, response.Body.String())
	}
	response = adminRequestWithETag(http.MethodPatch, "/v1/identity-adapters/"+identityAdapter.ID,
		`{"required_acr":"urn:customer:phishing-resistant"}`, initialAdapterETag)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"status":"verification_required"`) ||
		!strings.Contains(response.Body.String(), `"required_acr":"urn:customer:phishing-resistant"`) {
		t.Fatalf("adapter changes should clear verification and preserve the updated ACR: %d %s", response.Code, response.Body.String())
	}
	adapterETag := response.Header().Get("ETag")
	response = adminRequestWithETag(http.MethodPatch, "/v1/identity-adapters/"+identityAdapter.ID,
		`{"audience":"stale-audience"}`, initialAdapterETag)
	if response.Code != http.StatusPreconditionFailed {
		t.Fatalf("stale identity adapter ETag should be rejected: %d %s", response.Code, response.Body.String())
	}
	response = adminRequest(http.MethodGet, "/v1/applications/"+created.ID+"/posture", "")
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"assessment_status":"inventory_only"`) ||
		!strings.Contains(response.Body.String(), "ACTIVE_POLICY_MISSING") || !strings.Contains(response.Body.String(), "POSTURE_NOT_OBSERVED") ||
		!strings.Contains(response.Body.String(), `"verification_required":1`) {
		t.Fatalf("application posture should clearly report its incomplete inventory state: %d %s", response.Code, response.Body.String())
	}
	response = adminRequest(http.MethodGet, "/v1/applications/"+created.ID+"/observations", "")
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"evidence_redacted":true`) {
		t.Fatalf("observations should be listed with sensitive evidence redacted: %d %s", response.Code, response.Body.String())
	}
	if err := withIntegrationTenant(ctx, conn, tenantA, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO migration_observations
			(tenant_id, application_id, source, protocol, algorithm_profile, blocker, confidence, evidence, observed_at)
			VALUES ($1, $2, 'test-scanner', 'TLS 1.3', 'tls13-classical', 'HYBRID_NOT_SEEN', 'medium', '{"secret":"redact-me"}'::jsonb, clock_timestamp())`, tenantA, created.ID)
		return err
	}); err != nil {
		t.Fatal("create synthetic posture observation: ", err)
	}
	response = adminRequest(http.MethodGet, "/v1/applications/"+created.ID+"/observations?limit=10", "")
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "HYBRID_NOT_SEEN") || strings.Contains(response.Body.String(), "redact-me") {
		t.Fatalf("observation list should expose blocker metadata but not raw evidence: %d %s", response.Code, response.Body.String())
	}
	response = adminRequest(http.MethodGet, "/v1/applications/"+created.ID+"/posture", "")
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"count":1`) || !strings.Contains(response.Body.String(), `"open_blockers":1`) {
		t.Fatalf("posture should summarize observation blockers: %d %s", response.Code, response.Body.String())
	}
	response = adminRequestWithETag(http.MethodPost, "/v1/identity-adapters/"+identityAdapter.ID+"/disable", "", adapterETag)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"status":"disabled"`) ||
		!strings.Contains(response.Body.String(), `"required_acr":"urn:customer:phishing-resistant"`) {
		t.Fatalf("disabling an adapter should preserve its inventory metadata: %d %s", response.Code, response.Body.String())
	}
	disabledETag := response.Header().Get("ETag")
	response = adminRequestWithETag(http.MethodPost, "/v1/identity-adapters/"+identityAdapter.ID+"/disable", "", disabledETag)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"status":"disabled"`) {
		t.Fatalf("repeating adapter disable with the current ETag should be a safe no-op: %d %s", response.Code, response.Body.String())
	}
	credentialBody := `{"label":"gateway","scopes":["decisions:evaluate","observations:write","posture:read"],"expires_in_seconds":3600}`
	credentialPath := "/v1/applications/" + created.ID + "/credentials/rotate"
	credentialKey := nextKey()
	response = adminRequestWithKey(http.MethodPost, credentialPath, credentialBody, credentialKey)
	if response.Code != http.StatusCreated {
		t.Fatalf("tenant administrator should rotate an application credential: %d %s", response.Code, response.Body.String())
	}
	var credential struct {
		ID     string   `json:"credential_id"`
		Secret string   `json:"client_secret"`
		Scopes []string `json:"scopes"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &credential); err != nil || credential.ID == "" || !strings.HasPrefix(credential.Secret, "qgc_") || len(credential.Scopes) != 3 {
		t.Fatalf("credential response is invalid: %v %s", err, response.Body.String())
	}
	response = adminRequestWithKey(http.MethodPost, credentialPath, credentialBody, credentialKey)
	var replayedCredential struct {
		ID     string `json:"credential_id"`
		Secret string `json:"client_secret"`
	}
	if response.Code != http.StatusCreated || response.Header().Get("Idempotency-Replayed") != "true" ||
		json.Unmarshal(response.Body.Bytes(), &replayedCredential) != nil || replayedCredential.ID != credential.ID || replayedCredential.Secret != credential.Secret {
		t.Fatalf("credential rotation retry should replay the one-time secret: %d %s", response.Code, response.Body.String())
	}
	var credentialHash []byte
	if err := withIntegrationTenant(ctx, conn, tenantA, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT credential_hash FROM application_credentials WHERE tenant_id = $1 AND id = $2`, tenantA, credential.ID).Scan(&credentialHash)
	}); err != nil || len(credentialHash) != 32 || strings.Contains(string(credentialHash), credential.Secret) {
		t.Fatalf("database must store only the credential hash: hash length=%d err=%v", len(credentialHash), err)
	}
	tokenRequest := func(secret, scope string) *httptest.ResponseRecorder {
		form := url.Values{"grant_type": {"client_credentials"}, "scope": {scope}}
		r := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
		r.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(created.ID+":"+secret)))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		response := httptest.NewRecorder()
		adminHandler.ServeHTTP(response, r)
		return response
	}
	tokenResponse := tokenRequest(credential.Secret, "decisions:evaluate")
	var mintedToken struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
		Scope       string `json:"scope"`
	}
	if tokenResponse.Code != http.StatusOK || json.Unmarshal(tokenResponse.Body.Bytes(), &mintedToken) != nil ||
		!strings.HasPrefix(mintedToken.AccessToken, "qgt_") || mintedToken.TokenType != "Bearer" || mintedToken.ExpiresIn != 300 || mintedToken.Scope != "decisions:evaluate" {
		t.Fatalf("valid scoped credential should mint a short-lived bearer token: %d %s", tokenResponse.Code, tokenResponse.Body.String())
	}
	observationTokenResponse := tokenRequest(credential.Secret, "observations:write")
	var observationToken struct {
		AccessToken string `json:"access_token"`
		Scope       string `json:"scope"`
	}
	if observationTokenResponse.Code != http.StatusOK || json.Unmarshal(observationTokenResponse.Body.Bytes(), &observationToken) != nil ||
		!strings.HasPrefix(observationToken.AccessToken, "qgt_") || observationToken.Scope != "observations:write" {
		t.Fatalf("valid observation scope should mint a short-lived bearer token: %d %s", observationTokenResponse.Code, observationTokenResponse.Body.String())
	}
	postureTokenResponse := tokenRequest(credential.Secret, "posture:read")
	var postureToken struct {
		AccessToken string `json:"access_token"`
		Scope       string `json:"scope"`
	}
	if postureTokenResponse.Code != http.StatusOK || json.Unmarshal(postureTokenResponse.Body.Bytes(), &postureToken) != nil ||
		!strings.HasPrefix(postureToken.AccessToken, "qgt_") || postureToken.Scope != "posture:read" {
		t.Fatalf("valid posture scope should mint a short-lived bearer token: %d %s", postureTokenResponse.Code, postureTokenResponse.Body.String())
	}
	observationBodyBytes, err := json.Marshal(map[string]any{
		"source": "quantumgate-go-sdk", "protocol": "TLS 1.3", "algorithm_profile": "tls13-classical",
		"blocker": "TELEMETRY_INGESTED", "confidence": "high", "observed_at": time.Now().UTC(),
		"evidence": map[string]string{"key_exchange": "X25519", "signature_scheme": "rsa_pss_rsae_sha256", "endpoint_role": "client"},
	})
	if err != nil {
		t.Fatal("marshal service observation: ", err)
	}
	serviceObservationRequest := func(token, targetApplication, key, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/v1/applications/"+targetApplication+"/observations", strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set(idempotencyKeyHeader, key)
		result := httptest.NewRecorder()
		adminHandler.ServeHTTP(result, r)
		return result
	}
	observationKey := nextKey()
	observationResponse := serviceObservationRequest(observationToken.AccessToken, created.ID, observationKey, string(observationBodyBytes))
	var ingestedObservation struct {
		ID string `json:"observation_id"`
	}
	if observationResponse.Code != http.StatusCreated || json.Unmarshal(observationResponse.Body.Bytes(), &ingestedObservation) != nil || ingestedObservation.ID == "" {
		t.Fatalf("scoped application token should ingest an observation: %d %s", observationResponse.Code, observationResponse.Body.String())
	}
	replayedObservation := serviceObservationRequest(observationToken.AccessToken, created.ID, observationKey, string(observationBodyBytes))
	var replayedObservationBody struct {
		ID string `json:"observation_id"`
	}
	if replayedObservation.Code != http.StatusCreated || replayedObservation.Header().Get("Idempotency-Replayed") != "true" ||
		json.Unmarshal(replayedObservation.Body.Bytes(), &replayedObservationBody) != nil || replayedObservationBody.ID != ingestedObservation.ID {
		t.Fatalf("observation ingestion retries should replay the original result: %d %s", replayedObservation.Code, replayedObservation.Body.String())
	}
	changedObservation := strings.Replace(string(observationBodyBytes), "TELEMETRY_INGESTED", "CHANGED_BLOCKER", 1)
	if reused := serviceObservationRequest(observationToken.AccessToken, created.ID, observationKey, changedObservation); reused.Code != http.StatusConflict {
		t.Fatalf("changed telemetry must not reuse an idempotency key: %d %s", reused.Code, reused.Body.String())
	}
	if denied := serviceObservationRequest(mintedToken.AccessToken, created.ID, nextKey(), string(observationBodyBytes)); denied.Code != http.StatusForbidden {
		t.Fatalf("a token without observation scope must be denied: %d %s", denied.Code, denied.Body.String())
	}
	if hidden := serviceObservationRequest(observationToken.AccessToken, applicationA, nextKey(), string(observationBodyBytes)); hidden.Code != http.StatusNotFound {
		t.Fatalf("an application token must not write to another application's observations: %d %s", hidden.Code, hidden.Body.String())
	}
	servicePostureRequest := func(token, targetApplication string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, "/v1/applications/"+targetApplication+"/posture", nil)
		r.Header.Set("Authorization", "Bearer "+token)
		result := httptest.NewRecorder()
		adminHandler.ServeHTTP(result, r)
		return result
	}
	if posture := servicePostureRequest(postureToken.AccessToken, created.ID); posture.Code != http.StatusOK || !strings.Contains(posture.Body.String(), `"assessment_status":"inventory_only"`) {
		t.Fatalf("posture:read token should access its application's inventory: %d %s", posture.Code, posture.Body.String())
	}
	if denied := servicePostureRequest(observationToken.AccessToken, created.ID); denied.Code != http.StatusForbidden {
		t.Fatalf("observation-only token must not read posture: %d %s", denied.Code, denied.Body.String())
	}
	if hidden := servicePostureRequest(postureToken.AccessToken, applicationA); hidden.Code != http.StatusNotFound {
		t.Fatalf("posture token must not read another application's inventory: %d %s", hidden.Code, hidden.Body.String())
	}
	response = adminRequest(http.MethodGet, "/v1/applications/"+created.ID+"/observations?limit=10", "")
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "TELEMETRY_INGESTED") || strings.Contains(response.Body.String(), "X25519") {
		t.Fatalf("ingested telemetry should appear in the redacted inventory without evidence values: %d %s", response.Code, response.Body.String())
	}
	keyPath := "/v1/applications/" + created.ID + "/keys/rotate"
	keyExpiry := time.Now().UTC().AddDate(1, 0, 0)
	keyBodyBytes, err := json.Marshal(map[string]any{
		"purpose": "signing", "provider": "external-hsm-reference", "provider_reference": "pkcs11://hsm-one/slot/4/key-2026",
		"expires_at": keyExpiry,
	})
	if err != nil {
		t.Fatal("marshal key reference request: ", err)
	}
	response = adminRequest(http.MethodPost, keyPath, string(keyBodyBytes))
	var firstKey struct {
		ID      string `json:"id"`
		Version int64  `json:"version"`
		State   string `json:"state"`
	}
	if response.Code != http.StatusCreated || json.Unmarshal(response.Body.Bytes(), &firstKey) != nil ||
		firstKey.ID == "" || firstKey.Version != 1 || firstKey.State != "provisioning" {
		t.Fatalf("key rotation should create a metadata-only provisioning reference: %d %s", response.Code, response.Body.String())
	}
	firstKeyETag := response.Header().Get("ETag")
	if notReady := adminRequestWithETag(http.MethodPost, "/v1/keys/"+firstKey.ID+"/activate", `{"provider_resource_confirmed":false}`, firstKeyETag); notReady.Code != http.StatusBadRequest {
		t.Fatalf("activation should require explicit external provider confirmation: %d %s", notReady.Code, notReady.Body.String())
	}
	response = adminRequestWithETag(http.MethodPost, "/v1/keys/"+firstKey.ID+"/activate", `{"provider_resource_confirmed":true}`, firstKeyETag)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"state":"active"`) {
		t.Fatalf("confirmed external provider reference should activate: %d %s", response.Code, response.Body.String())
	}
	keyBodyBytes, err = json.Marshal(map[string]any{
		"purpose": "signing", "provider": "external-hsm-reference", "provider_reference": "pkcs11://hsm-one/slot/4/key-2027",
		"expires_at": keyExpiry.AddDate(1, 0, 0),
	})
	if err != nil {
		t.Fatal("marshal replacement key reference request: ", err)
	}
	response = adminRequest(http.MethodPost, keyPath, string(keyBodyBytes))
	var replacementKey struct {
		ID      string `json:"id"`
		Version int64  `json:"version"`
		State   string `json:"state"`
	}
	if response.Code != http.StatusCreated || json.Unmarshal(response.Body.Bytes(), &replacementKey) != nil ||
		replacementKey.ID == "" || replacementKey.Version != 2 || replacementKey.State != "provisioning" {
		t.Fatalf("replacement rotation should create a second provisioning reference: %d %s", response.Code, response.Body.String())
	}
	response = adminRequestWithETag(http.MethodPost, "/v1/keys/"+replacementKey.ID+"/activate", `{"provider_resource_confirmed":true}`, response.Header().Get("ETag"))
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"state":"active"`) {
		t.Fatalf("new provider-confirmed version should activate: %d %s", response.Code, response.Body.String())
	}
	replacementKeyETag := response.Header().Get("ETag")
	response = adminRequest(http.MethodGet, "/v1/applications/"+created.ID+"/keys", "")
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"state":"rotation_due"`) || !strings.Contains(response.Body.String(), `"version":2`) {
		t.Fatalf("activating a replacement should mark the prior key version rotation-due: %d %s", response.Code, response.Body.String())
	}
	if material := adminRequest(http.MethodGet, "/v1/keys/"+firstKey.ID+"/public-material", ""); material.Code != http.StatusNotFound {
		t.Fatalf("the reference-only lifecycle must not invent public key material: %d %s", material.Code, material.Body.String())
	}
	response = adminRequestWithETag(http.MethodPost, "/v1/keys/"+replacementKey.ID+"/disable", "", replacementKeyETag)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"state":"disabled"`) {
		t.Fatalf("key reference should disable with its current ETag: %d %s", response.Code, response.Body.String())
	}
	response = adminRequestWithETag(http.MethodPost, "/v1/keys/"+replacementKey.ID+"/revoke", "", response.Header().Get("ETag"))
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"state":"revoked"`) {
		t.Fatalf("disabled key reference should revoke with its current ETag: %d %s", response.Code, response.Body.String())
	}
	accessTokenHash := sha256.Sum256([]byte(mintedToken.AccessToken))
	var activeTokenCount int
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM public.qg_validate_service_access_token($1)`, accessTokenHash[:]).Scan(&activeTokenCount); err != nil || activeTokenCount != 1 {
		t.Fatalf("new bearer token should validate as active: count=%d err=%v", activeTokenCount, err)
	}
	if err := withIntegrationTenant(ctx, conn, tenantA, func(tx pgx.Tx) error {
		var storedTokenHash []byte
		if err := tx.QueryRow(ctx, `SELECT token_hash FROM service_access_tokens WHERE tenant_id = $1 AND application_id = $2`, tenantA, created.ID).Scan(&storedTokenHash); err != nil {
			return err
		}
		if string(storedTokenHash) != string(accessTokenHash[:]) {
			return fmt.Errorf("service token plaintext was stored instead of its hash")
		}
		return nil
	}); err != nil {
		t.Fatal("verify service token hash storage: ", err)
	}
	introspectRequest := func(secret, token string) *httptest.ResponseRecorder {
		form := url.Values{"token": {token}}
		r := httptest.NewRequest(http.MethodPost, "/oauth/introspect", strings.NewReader(form.Encode()))
		r.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(created.ID+":"+secret)))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		result := httptest.NewRecorder()
		adminHandler.ServeHTTP(result, r)
		return result
	}
	introspectionResponse := introspectRequest(credential.Secret, mintedToken.AccessToken)
	if introspectionResponse.Code != http.StatusOK || !strings.Contains(introspectionResponse.Body.String(), `"active":true`) || !strings.Contains(introspectionResponse.Body.String(), `"scope":"decisions:evaluate"`) {
		t.Fatalf("client should introspect its active service token: %d %s", introspectionResponse.Code, introspectionResponse.Body.String())
	}
	if escalation := tokenRequest(credential.Secret, "events:write"); escalation.Code != http.StatusBadRequest || !strings.Contains(escalation.Body.String(), "invalid_scope") {
		t.Fatalf("client must not mint a scope it was not granted: %d %s", escalation.Code, escalation.Body.String())
	}
	response = adminRequestWithKey(http.MethodPost, credentialPath, credentialBody, nextKey())
	if response.Code != http.StatusCreated {
		t.Fatalf("credential rotation should revoke the prior client credential: %d %s", response.Code, response.Body.String())
	}
	var replacementCredential struct {
		Secret string `json:"client_secret"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &replacementCredential); err != nil || replacementCredential.Secret == "" {
		t.Fatalf("replacement credential response is invalid: %v %s", err, response.Body.String())
	}
	if stale := tokenRequest(credential.Secret, "decisions:evaluate"); stale.Code != http.StatusUnauthorized {
		t.Fatalf("a rotated credential should no longer mint tokens: %d %s", stale.Code, stale.Body.String())
	}
	introspectionResponse = introspectRequest(replacementCredential.Secret, mintedToken.AccessToken)
	if introspectionResponse.Code != http.StatusOK || !strings.Contains(introspectionResponse.Body.String(), `"active":false`) {
		t.Fatalf("rotating a credential should make its access tokens inactive: %d %s", introspectionResponse.Code, introspectionResponse.Body.String())
	}
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM public.qg_validate_service_access_token($1)`, accessTokenHash[:]).Scan(&activeTokenCount); err != nil || activeTokenCount != 0 {
		t.Fatalf("rotating a credential should immediately invalidate its access tokens: count=%d err=%v", activeTokenCount, err)
	}
	response = adminRequest(http.MethodGet, "/v1/applications/"+created.ID, "")
	applicationETag = response.Header().Get("ETag")
	response = adminRequestWithETag(http.MethodPost, "/v1/applications/"+created.ID+"/disable", "", applicationETag)
	if response.Code != http.StatusOK || response.Header().Get("ETag") == "" {
		t.Fatalf("application disable should update the versioned state: %d %s", response.Code, response.Body.String())
	}
	response = adminRequest(http.MethodGet, "/v1/applications/"+created.ID, "")
	response = adminRequestWithETag(http.MethodPost, "/v1/applications/"+created.ID+"/disable", "", response.Header().Get("ETag"))
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"status":"disabled"`) {
		t.Fatalf("disabling an already disabled application should be an audited no-op: %d %s", response.Code, response.Body.String())
	}
	var disableNoopAuditCount int
	if err := withIntegrationTenant(ctx, conn, tenantA, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE action = 'application.disable_noop' AND target_id = $1`, created.ID).Scan(&disableNoopAuditCount)
	}); err != nil || disableNoopAuditCount != 1 {
		t.Fatalf("repeated disable should write one no-op audit event, count=%d err=%v", disableNoopAuditCount, err)
	}
	patchTenant := func(etag string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPatch, "/v1/tenants/"+tenantA, strings.NewReader(`{"display_name":"Tenant A renamed"}`))
		r.Header.Set("Authorization", "Bearer verified-test-token")
		r.Header.Set("X-QG-Tenant-ID", tenantA)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set(idempotencyKeyHeader, nextKey())
		if etag != "" {
			r.Header.Set("If-Match", etag)
		}
		response := httptest.NewRecorder()
		adminHandler.ServeHTTP(response, r)
		return response
	}
	response = patchTenant(oldETag)
	if response.Code != http.StatusOK {
		t.Fatalf("tenant admin should update tenant metadata with its ETag: %d %s", response.Code, response.Body.String())
	}
	response = patchTenant(oldETag)
	if response.Code != http.StatusPreconditionFailed {
		t.Fatalf("stale tenant ETag should be rejected: %d %s", response.Code, response.Body.String())
	}
	response = adminRequest(http.MethodPost, "/v1/tenants/"+tenantA+"/members", `{"subject":"admin-3","role":"tenant_admin"}`)
	if response.Code != http.StatusCreated {
		t.Fatalf("tenant admin should add a member: %d %s", response.Code, response.Body.String())
	}
	var addedMember struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &addedMember); err != nil || !validUUID(addedMember.ID) {
		t.Fatalf("member response did not contain a valid ID: %v %s", err, response.Body.String())
	}
	var adminID string
	if err := withIntegrationTenant(ctx, conn, tenantA, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT id::text FROM tenant_members WHERE tenant_id = $1 AND issuer = 'https://id.example' AND subject = 'admin-2'`, tenantA).Scan(&adminID)
	}); err != nil {
		t.Fatal("read bootstrapped test administrator: ", err)
	}
	memberSession := strings.Repeat("m", 43)
	if _, err := conn.Exec(ctx, `INSERT INTO admin_sessions
		(token_hash, issuer, subject, auth_time, csrf_hash, acr, expires_at)
		VALUES ($1, 'https://id.example', 'admin-2', now(), $2, 'urn:test:mfa', now() + interval '8 hours')`,
		hashToken(memberSession), hashToken(csrfToken)); err != nil {
		t.Fatal("create member session: ", err)
	}
	response = adminRequest(http.MethodDelete, "/v1/tenants/"+tenantA+"/members/"+adminID, "")
	if response.Code != http.StatusNoContent {
		t.Fatalf("tenant admin should be able to remove a non-final administrator, got %d %s", response.Code, response.Body.String())
	}
	var memberSessionRevoked bool
	if err := conn.QueryRow(ctx, `SELECT revoked_at IS NOT NULL FROM admin_sessions WHERE token_hash = $1`, hashToken(memberSession)).Scan(&memberSessionRevoked); err != nil || !memberSessionRevoked {
		t.Fatalf("removing a tenant member must revoke their admin sessions: revoked=%v err=%v", memberSessionRevoked, err)
	}
	adminServer.Auth = integrationTokenVerifier{principal: auth.Principal{Issuer: "https://id.example", Subject: "admin-3"}}
	response = adminRequest(http.MethodDelete, "/v1/tenants/"+tenantA+"/members/"+addedMember.ID, "")
	if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "LAST_TENANT_ADMIN") {
		t.Fatalf("the last tenant administrator must not be removable, got %d %s", response.Code, response.Body.String())
	}

	policyAction := func(method, path, body, etag string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer verified-test-token")
		r.Header.Set("X-QG-Tenant-ID", tenantA)
		r.Header.Set(idempotencyKeyHeader, nextKey())
		if body != "" {
			r.Header.Set("Content-Type", "application/json")
		}
		if etag != "" {
			r.Header.Set("If-Match", etag)
		}
		response := httptest.NewRecorder()
		adminHandler.ServeHTTP(response, r)
		return response
	}
	classicalDocument := `{"mode":"classical-approved","allowed_profiles":["tls13-classical"],"fallback":"deny","stale_behavior":"observe","route_rules":[{"method":"GET","path_prefix":"/api/","allowed_profiles":["tls13-classical"]}],"identity_requirements":{"required_acrs":["urn:test:mfa"]},"exceptions":[],"effective_window":{}}`
	response = adminRequest(http.MethodGet, "/v1/tenants/"+tenantA+"/algorithm-profiles", "")
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "tls13-x25519-mlkem768") {
		t.Fatalf("approved transport profiles should be listed for tenant administrators: %d %s", response.Code, response.Body.String())
	}
	response = adminRequest(http.MethodPost, "/v1/applications/"+applicationA+"/policies", classicalDocument)
	if response.Code != http.StatusCreated {
		t.Fatalf("security role should create a policy draft: %d %s", response.Code, response.Body.String())
	}
	var firstPolicy policyView
	if err := json.Unmarshal(response.Body.Bytes(), &firstPolicy); err != nil || firstPolicy.State != "draft" || firstPolicy.ETag == "" {
		t.Fatalf("policy draft response is invalid: %v %s", err, response.Body.String())
	}
	response = adminRequest(http.MethodPost, "/v1/policies/"+firstPolicy.ID+"/simulate", `{"method":"GET","path":"/api/items","profile_id":"tls13-classical","identity_acr":"urn:test:mfa"}`)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"decision":"allow"`) {
		t.Fatalf("policy simulation should explain a matching request: %d %s", response.Code, response.Body.String())
	}
	response = policyAction(http.MethodPost, "/v1/policies/"+firstPolicy.ID+"/activate", "", firstPolicy.ETag)
	if response.Code != http.StatusOK {
		t.Fatalf("policy draft should activate with its ETag: %d %s", response.Code, response.Body.String())
	}
	hybridDocument := `{"mode":"hybrid-approved","allowed_profiles":["tls13-x25519-mlkem768"],"fallback":"deny","stale_behavior":"deny","route_rules":[],"identity_requirements":{"required_acrs":[]},"exceptions":[],"effective_window":{}}`
	response = adminRequest(http.MethodPost, "/v1/applications/"+applicationA+"/policies", hybridDocument)
	if response.Code != http.StatusCreated {
		t.Fatalf("security role should create a hybrid policy draft: %d %s", response.Code, response.Body.String())
	}
	var scheduledPolicy policyView
	if err := json.Unmarshal(response.Body.Bytes(), &scheduledPolicy); err != nil {
		t.Fatalf("scheduled policy draft response is invalid: %v", err)
	}
	scheduleAt := time.Now().UTC().Add(90 * time.Second).Format(time.RFC3339Nano)
	response = policyAction(http.MethodPost, "/v1/policies/"+scheduledPolicy.ID+"/schedule", `{"effective_at":"`+scheduleAt+`"}`, scheduledPolicy.ETag)
	if response.Code != http.StatusOK {
		t.Fatalf("draft policy should accept a future schedule: %d %s", response.Code, response.Body.String())
	}
	if err := withIntegrationTenant(ctx, conn, tenantA, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE policy_revisions SET effective_at = now() - interval '1 second',
			lifecycle_updated_at = clock_timestamp(), lifecycle_version = lifecycle_version + 1 WHERE tenant_id = $1 AND id = $2`, tenantA, scheduledPolicy.ID); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `SELECT qg_schedule_policy($1, $2, now() - interval '1 second')`, tenantA, scheduledPolicy.ID)
		return err
	}); err != nil {
		t.Fatal("make policy schedule due for the integration check: ", err)
	}
	activated, err := ProcessDuePolicySchedules(ctx, db)
	if err != nil || activated != 1 {
		t.Fatalf("scheduler should activate exactly one due revision, activated=%d err=%v", activated, err)
	}
	response = adminRequest(http.MethodGet, "/v1/policies/"+scheduledPolicy.ID, "")
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"state":"active"`) {
		t.Fatalf("scheduled policy should be active after scheduler processing: %d %s", response.Code, response.Body.String())
	}
	var activePolicy policyView
	if err := json.Unmarshal(response.Body.Bytes(), &activePolicy); err != nil {
		t.Fatal("active policy response is invalid: ", err)
	}
	rollbackBody := `{"target_revision_id":"` + firstPolicy.ID + `","reason_code":"ROLLBACK_COMPATIBILITY"}`
	response = policyAction(http.MethodPost, "/v1/policies/"+activePolicy.ID+"/rollback", rollbackBody, activePolicy.ETag)
	if response.Code != http.StatusCreated {
		t.Fatalf("active policy should roll back by creating a new revision: %d %s", response.Code, response.Body.String())
	}
	var rollbackRevision policyView
	if err := json.Unmarshal(response.Body.Bytes(), &rollbackRevision); err != nil || rollbackRevision.Revision <= activePolicy.Revision || rollbackRevision.State != "active" {
		t.Fatalf("rollback should create a later active revision: %v %s", err, response.Body.String())
	}
	response = policyAction(http.MethodPost, "/v1/policies/"+rollbackRevision.ID+"/retire", "", rollbackRevision.ETag)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"state":"retired"`) {
		t.Fatalf("active policy should retire with its current ETag: %d %s", response.Code, response.Body.String())
	}

	gatewayApplicationID := "70000000-0000-4000-8000-000000000007"
	gatewayAdapterID := "80000000-0000-4000-8000-000000000008"
	gatewayPolicyID := "90000000-0000-4000-8000-000000000009"
	gatewayPolicyDocument := `{"mode":"observe-only","allowed_profiles":["tls13-classical"],"fallback":"deny","stale_behavior":"deny","route_rules":[],"identity_requirements":{"required_acrs":[]},"exceptions":[],"effective_window":{}}`
	gatewayPolicyHash := sha256.Sum256([]byte(gatewayPolicyDocument))
	if err := withIntegrationTenant(ctx, conn, tenantA, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO applications(id, tenant_id, environment_id, external_id, display_name, integration_mode, status)
			VALUES ($1, $2, $3, 'gateway-test-app', 'Gateway integration app', 'gateway', 'active')`,
			gatewayApplicationID, tenantA, "30000000-0000-4000-8000-000000000003"); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO identity_adapters(id, tenant_id, application_id, adapter_type, issuer, audience, config, status, last_verified_at)
			VALUES ($1, $2, $3, 'oidc', 'https://id.example', 'gateway-test-client', '{"required_acr":"urn:test:mfa"}'::jsonb, 'active', clock_timestamp())`,
			gatewayAdapterID, tenantA, gatewayApplicationID); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO policy_revisions(id, tenant_id, application_id, revision, state, document, content_hash, created_by)
			VALUES ($1, $2, $3, 1, 'active', $4::jsonb, $5, 'integration-test')`,
			gatewayPolicyID, tenantA, gatewayApplicationID, gatewayPolicyDocument, gatewayPolicyHash[:])
		return err
	}); err != nil {
		t.Fatal("create gateway runtime fixture: ", err)
	}
	gatewayRoute := gateway.Route{Host: "app.customer.example", TenantID: tenantA, ApplicationID: gatewayApplicationID, UpstreamURL: "http://127.0.0.1:8081"}
	adapter, err := server.loadGatewayIdentityAdapter(ctx, gatewayRoute)
	if err != nil {
		t.Fatal("load gateway identity fixture: ", err)
	}
	server.identityVerifierMu.Lock()
	server.identityVerifiers = map[string]identityVerifierEntry{
		adapter.ID: {
			issuer: adapter.Issuer, audience: adapter.Audience, requiredACR: adapter.RequiredACR,
			updatedAt: adapter.UpdatedAt, expiresAt: time.Now().Add(time.Minute),
			verifier: integrationTokenVerifier{principal: auth.Principal{Issuer: adapter.Issuer, Subject: "gateway-user-secret", ACR: adapter.RequiredACR, AuthTime: time.Now()}},
		},
	}
	server.identityVerifierMu.Unlock()
	gatewayRequest := gateway.Request{
		RequestID: "gateway-db-integration-0001", Method: http.MethodGet, Path: "/api/items",
		ProfileID: "tls13-classical", IdentityToken: "gateway-secret-id-token", ClientIP: "203.0.113.99",
	}
	decision, err := server.Evaluate(ctx, gatewayRoute, gatewayRequest)
	if err != nil || decision.Outcome != "observe" || decision.PolicyRevisionID != gatewayPolicyID {
		t.Fatalf("observe-only gateway decision should evaluate and audit, decision=%+v err=%v", decision, err)
	}
	var auditActor, auditSource string
	if err := withIntegrationTenant(ctx, conn, tenantA, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT actor, source_context::text FROM audit_events WHERE tenant_id = $1 AND correlation_id = $2`,
			tenantA, gatewayRequest.RequestID).Scan(&auditActor, &auditSource)
	}); err != nil {
		t.Fatal("read gateway decision audit event: ", err)
	}
	if strings.Contains(auditActor, "gateway-user-secret") || strings.Contains(auditSource, gatewayRequest.IdentityToken) ||
		!strings.Contains(auditSource, "tls-terminating-gateway") || !strings.Contains(auditSource, gatewayPolicyID) {
		t.Fatalf("gateway audit must pseudonymize its actor and exclude the token: actor=%q source=%q", auditActor, auditSource)
	}

	upstreamHeaders := make(chan http.Header, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHeaders <- r.Header.Clone()
		w.Header().Set("X-QG-Upstream-Forgery", "discard")
		w.Header().Set("X-Request-ID", "upstream-forgery")
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"items":["existing application response"]}`)
	}))
	defer upstream.Close()
	referenceRoute := gatewayRoute
	referenceRoute.UpstreamURL = upstream.URL
	configuredGateway, err := gateway.New([]gateway.Route{referenceRoute}, server, nil, nil, "development")
	if err != nil {
		t.Fatal("configure gateway for the reference application: ", err)
	}
	defer configuredGateway.CloseIdleConnections()
	server.Gateway = configuredGateway
	certificate := integrationGatewayCertificate(t, referenceRoute.Host)
	gatewayServer := httptest.NewUnstartedServer(server.GatewayHandler())
	gatewayServer.TLS = &tls.Config{
		MinVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{tls.X25519MLKEM768},
		Certificates: []tls.Certificate{certificate},
	}
	gatewayServer.StartTLS()
	defer gatewayServer.Close()
	roots := x509.NewCertPool()
	roots.AddCert(certificate.Leaf)
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519MLKEM768}, ServerName: referenceRoute.Host, RootCAs: roots,
	}}}
	defer client.CloseIdleConnections()
	applicationRequest, err := http.NewRequest(http.MethodGet, gatewayServer.URL+"/api/items", nil)
	if err != nil {
		t.Fatal("create reference application request: ", err)
	}
	applicationRequest.Host = referenceRoute.Host
	applicationRequest.Header.Set("Authorization", "Bearer "+gatewayRequest.IdentityToken)
	applicationRequest.Header.Set("X-QG-Transport-Profile", "tls13-classical")
	applicationRequest.Header.Set("X-QG-Policy-Revision", "forged-policy")
	applicationRequest.Header.Set("X-Forwarded-For", "198.51.100.222")
	applicationResponse, err := client.Do(applicationRequest)
	if err != nil {
		t.Fatal("send real TLS request through gateway to existing application: ", err)
	}
	defer applicationResponse.Body.Close()
	proxiedBody, err := io.ReadAll(applicationResponse.Body)
	if err != nil || applicationResponse.StatusCode != http.StatusOK || !strings.Contains(string(proxiedBody), "existing application response") {
		t.Fatalf("gateway should return the existing application's response: status=%d err=%v body=%s", applicationResponse.StatusCode, err, proxiedBody)
	}
	var forwardedHeaders http.Header
	select {
	case forwardedHeaders = <-upstreamHeaders:
	default:
		t.Fatal("allowed request did not reach the existing application")
	}
	requestID := applicationResponse.Header.Get("X-Request-ID")
	if requestID == "" || applicationResponse.Header.Get("X-QG-Upstream-Forgery") != "" || applicationResponse.Header.Get("X-Request-ID") == "upstream-forgery" ||
		forwardedHeaders.Get("Authorization") != "Bearer "+gatewayRequest.IdentityToken ||
		forwardedHeaders.Get("X-QG-Transport-Profile") != "tls13-x25519-mlkem768" ||
		forwardedHeaders.Get("X-QG-Policy-Revision") != gatewayPolicyID ||
		forwardedHeaders.Get("X-Forwarded-For") == "198.51.100.222" {
		t.Fatalf("existing application should receive the original identity token and gateway-derived context only: response_id=%q upstream_headers=%v", requestID, forwardedHeaders)
	}
	var referenceAuditCount int
	if err := withIntegrationTenant(ctx, conn, tenantA, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE tenant_id = $1 AND correlation_id = $2
			AND action = 'authorization.decision' AND outcome = 'success'`, tenantA, requestID).Scan(&referenceAuditCount)
	}); err != nil || referenceAuditCount != 1 {
		t.Fatalf("proxied request must have one tenant-scoped successful decision audit, count=%d err=%v", referenceAuditCount, err)
	}
	if err := withIntegrationTenant(ctx, conn, tenantA, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE identity_adapters SET last_verified_at = clock_timestamp() + interval '5 minutes' WHERE tenant_id = $1 AND id = $2`, tenantA, gatewayAdapterID)
		return err
	}); err != nil {
		t.Fatal("set future identity verification timestamp: ", err)
	}
	futureDecision, futureErr := server.Evaluate(ctx, gatewayRoute, gateway.Request{
		RequestID: "gateway-db-integration-future", Method: http.MethodGet, Path: "/api/items",
		ProfileID: "tls13-classical", IdentityToken: "gateway-secret-id-token", ClientIP: "203.0.113.100",
	})
	if failure, ok := futureErr.(*gateway.Failure); !ok || failure.Code != "IDENTITY_ADAPTER_UNAVAILABLE" || futureDecision.Outcome == "allow" {
		t.Fatalf("future identity verification timestamp must reject gateway requests: decision=%+v err=%v", futureDecision, futureErr)
	}
	if err := withIntegrationTenant(ctx, conn, tenantA, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE identity_adapters SET last_verified_at = clock_timestamp() WHERE tenant_id = $1 AND id = $2`, tenantA, gatewayAdapterID)
		return err
	}); err != nil {
		t.Fatal("restore identity verification timestamp: ", err)
	}
	crossTenantRoute := gatewayRoute
	crossTenantRoute.TenantID = tenantB
	crossTenantGatewayRequest := gatewayRequest
	crossTenantGatewayRequest.RequestID = "gateway-db-integration-cross-tenant"
	crossTenantGatewayRequest.ClientIP = "203.0.113.101"
	crossTenantDecision, crossTenantErr := server.Evaluate(ctx, crossTenantRoute, crossTenantGatewayRequest)
	if crossTenantErr == nil || crossTenantDecision.Outcome == "allow" {
		t.Fatalf("tenant B must not evaluate tenant A's gateway application: decision=%+v err=%v", crossTenantDecision, crossTenantErr)
	}

	if err := withIntegrationTenant(ctx, conn, tenantA, func(tx pgx.Tx) error {
		for _, member := range []struct{ subject, role string }{
			{"profile-author", "security_engineer"}, {"profile-reviewer", "security_engineer"},
			{"profile-tenant-admin", "tenant_admin"},
		} {
			if _, err := tx.Exec(ctx, `INSERT INTO tenant_members(tenant_id, issuer, subject, role) VALUES ($1, 'https://id.example', $2, $3)`, tenantA, member.subject, member.role); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal("create profile reviewer fixtures: ", err)
	}
	if err := withIntegrationTenant(ctx, conn, tenantB, func(tx pgx.Tx) error {
		for _, subject := range []string{"other-tenant-reviewer", "other-tenant-author"} {
			if _, err := tx.Exec(ctx, `INSERT INTO tenant_members(tenant_id, issuer, subject, role) VALUES ($1, 'https://id.example', $2, 'security_engineer')`, tenantB, subject); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal("create cross-tenant profile reviewer fixture: ", err)
	}
	profileRequest := func(tenant, method, path, body, etag, key string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer verified-test-token")
		r.Header.Set("X-QG-Tenant-ID", tenant)
		if unsafeMethod(method) {
			r.Header.Set(idempotencyKeyHeader, key)
		}
		if body != "" {
			r.Header.Set("Content-Type", "application/json")
		}
		if etag != "" {
			r.Header.Set("If-Match", etag)
		}
		response := httptest.NewRecorder()
		adminHandler.ServeHTTP(response, r)
		return response
	}
	profileRequestAs := func(subject, tenant, method, path, body, etag, key string) *httptest.ResponseRecorder {
		adminServer.Auth = integrationTokenVerifier{principal: auth.Principal{Issuer: "https://id.example", Subject: subject}}
		return profileRequest(tenant, method, path, body, etag, key)
	}
	profileEvidence := func(hybrid bool) string {
		pqc := `[]`
		standard := "TLS 1.3 RFC 8446"
		if hybrid {
			pqc = `[` + `"ML-KEM-768"` + `]`
			standard = "TLS 1.3 X25519 and ML-KEM-768 provider profile"
		}
		return `{"design_record":{"standard_profile":"` + standard + `","classical_mechanisms":["X25519"],"pqc_mechanisms":` + pqc +
			`,"key_purpose_and_lifecycle":"Transport key exchange; negotiated per TLS 1.3 connection.","downgrade_detection":"SENSITIVE-REVIEW-DETAIL-DO-NOT-AUDIT","transcript_binding":"The maintained TLS implementation binds handshake messages.","test_vectors":["https://vectors.example/profile"],"interop_partners":["Example TLS implementation"],"deprecation_plan":"Disable this profile when its registry version is superseded.","rollback_plan":"Return this tenant to observe-only mode."}}`
	}
	profileGatePolicyID := "91000000-0000-4000-8000-000000000010"
	profileGatePolicyDocument := `{"mode":"classical-approved","allowed_profiles":["tls13-classical"],"fallback":"deny","stale_behavior":"deny","route_rules":[{"method":"GET","path_prefix":"/api/","allowed_profiles":["tls13-classical"]}],"identity_requirements":{"required_acrs":[]},"exceptions":[],"effective_window":{}}`
	profileGatePolicyHash := sha256.Sum256([]byte(profileGatePolicyDocument))
	if err := withIntegrationTenant(ctx, conn, tenantA, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE policy_revisions SET state = 'retired', retired_at = clock_timestamp(),
			lifecycle_updated_at = clock_timestamp(), lifecycle_version = lifecycle_version + 1
			WHERE tenant_id = $1 AND id = $2 AND state = 'active'`, tenantA, gatewayPolicyID); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO policy_revisions(id, tenant_id, application_id, revision, state, document, content_hash, created_by)
			VALUES ($1, $2, $3, 2, 'active', $4::jsonb, $5, 'profile-review-integration')`,
			profileGatePolicyID, tenantA, gatewayApplicationID, profileGatePolicyDocument, profileGatePolicyHash[:])
		return err
	}); err != nil {
		t.Fatal("create enforcement profile gate fixture: ", err)
	}
	decisionCredentialResponse := adminRequest(http.MethodPost, "/v1/applications/"+gatewayApplicationID+"/credentials/rotate",
		`{"label":"sdk-protect-integration","scopes":["decisions:evaluate","observations:write"],"expires_in_seconds":3600}`)
	var decisionCredential struct {
		Secret string `json:"client_secret"`
	}
	if decisionCredentialResponse.Code != http.StatusCreated || json.Unmarshal(decisionCredentialResponse.Body.Bytes(), &decisionCredential) != nil ||
		!validOpaqueCredential(decisionCredential.Secret) {
		t.Fatalf("SDK decision fixture should receive a scoped app credential: %d %s", decisionCredentialResponse.Code, decisionCredentialResponse.Body.String())
	}
	decisionTokenRequest := func(scope string) string {
		form := url.Values{"grant_type": {"client_credentials"}, "scope": {scope}}
		r := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
		r.SetBasicAuth(gatewayApplicationID, decisionCredential.Secret)
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, r)
		var tokenBody struct {
			AccessToken string `json:"access_token"`
			Scope       string `json:"scope"`
		}
		if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &tokenBody) != nil || tokenBody.Scope != scope || !validOpaqueAccessToken(tokenBody.AccessToken) {
			t.Fatalf("SDK decision fixture should receive its requested scoped token: %d %s", response.Code, response.Body.String())
		}
		return tokenBody.AccessToken
	}
	decisionToken := decisionTokenRequest("decisions:evaluate")
	observationOnlyToken := decisionTokenRequest("observations:write")
	decisionHandler := server.Handler()
	decisionHTTP := func(token, targetApplication, body string, curve tls.CurveID) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/v1/applications/"+targetApplication+"/decisions", strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set("Content-Type", "application/json")
		if curve != 0 {
			r.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, CurveID: curve}
		}
		result := httptest.NewRecorder()
		decisionHandler.ServeHTTP(result, r)
		return result
	}
	decisionJSON := func(method, path string) string {
		body, err := json.Marshal(decisionRequest{Method: method, Path: path, IdentityToken: gatewayRequest.IdentityToken})
		if err != nil {
			t.Fatal("marshal SDK decision request: ", err)
		}
		return string(body)
	}
	setGatewayApplicationMode := func(mode string) {
		t.Helper()
		if err := withIntegrationTenant(ctx, conn, tenantA, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `UPDATE applications SET integration_mode = $3 WHERE tenant_id = $1 AND id = $2`, tenantA, gatewayApplicationID, mode)
			return err
		}); err != nil {
			t.Fatalf("set integration fixture mode to %s: %v", mode, err)
		}
	}
	setGatewayApplicationMode("sdk")
	if invalid := decisionHTTP("invalid-token", gatewayApplicationID, decisionJSON("GET", "/api/items"), tls.X25519); invalid.Code != http.StatusUnauthorized {
		t.Fatalf("invalid application authentication must fail closed: %d %s", invalid.Code, invalid.Body.String())
	}
	if insufficient := decisionHTTP(observationOnlyToken, gatewayApplicationID, decisionJSON("GET", "/api/items"), tls.X25519); insufficient.Code != http.StatusForbidden {
		t.Fatalf("decision API must require decisions:evaluate scope: %d %s", insufficient.Code, insufficient.Body.String())
	}
	if malformed := decisionHTTP(decisionToken, gatewayApplicationID, `{}`, tls.X25519); malformed.Code != http.StatusBadRequest {
		t.Fatalf("malformed decision input must be rejected: %d %s", malformed.Code, malformed.Body.String())
	}
	if noTLS := decisionHTTP(decisionToken, gatewayApplicationID, decisionJSON("GET", "/api/items"), 0); noTLS.Code != http.StatusForbidden {
		t.Fatalf("decision API must reject missing TLS profile evidence: %d %s", noTLS.Code, noTLS.Body.String())
	}
	crossTenantApplicationID := "60000000-0000-4000-8000-000000000006"
	if err := withIntegrationTenant(ctx, conn, tenantB, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO applications(id, tenant_id, environment_id, external_id, display_name, integration_mode, status)
			VALUES ($1, $2, $3, 'cross-tenant-sdk-app', 'Cross tenant SDK app', 'sdk', 'active')`,
			crossTenantApplicationID, tenantB, "50000000-0000-4000-8000-000000000005")
		return err
	}); err != nil {
		t.Fatal("create cross-tenant decision fixture: ", err)
	}
	if crossTenant := decisionHTTP(decisionToken, crossTenantApplicationID, decisionJSON("GET", "/api/items"), tls.X25519); crossTenant.Code != http.StatusNotFound {
		t.Fatalf("decision token must not access a different tenant's application: %d %s", crossTenant.Code, crossTenant.Body.String())
	}
	firstUnapproved := decisionHTTP(decisionToken, gatewayApplicationID, decisionJSON("GET", "/api/items"), tls.X25519)
	secondUnapproved := decisionHTTP(decisionToken, gatewayApplicationID, decisionJSON("GET", "/api/items"), tls.X25519)
	if firstUnapproved.Code != http.StatusServiceUnavailable || !strings.Contains(firstUnapproved.Body.String(), "PROFILE_NOT_APPROVED") ||
		secondUnapproved.Code != http.StatusServiceUnavailable || firstUnapproved.Header().Get("X-Request-ID") == secondUnapproved.Header().Get("X-Request-ID") {
		t.Fatalf("unapproved profiles must fail closed and each call must be fresh: first=%d %s second=%d %s",
			firstUnapproved.Code, firstUnapproved.Body.String(), secondUnapproved.Code, secondUnapproved.Body.String())
	}
	var unapprovedDecisionAudits int
	if err := withIntegrationTenant(ctx, conn, tenantA, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE tenant_id = $1 AND target_type = 'application' AND target_id = $2
			AND action = 'authorization.decision' AND reason_code = 'PROFILE_NOT_APPROVED' AND source_context->>'integration' = 'sdk'`,
			tenantA, gatewayApplicationID).Scan(&unapprovedDecisionAudits)
	}); err != nil || unapprovedDecisionAudits != 2 {
		t.Fatalf("fresh unapproved SDK decisions should each have an audit event: count=%d err=%v", unapprovedDecisionAudits, err)
	}
	setGatewayApplicationMode("gateway")
	checkProfileGateFor := func(tenantID, profileID string, expected bool) {
		t.Helper()
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal("begin profile gate check: ", err)
		}
		defer tx.Rollback()
		if _, err := tx.ExecContext(ctx, `SELECT set_config('qg.tenant_id', $1, true)`, tenantID); err != nil {
			t.Fatal("set tenant context for profile gate: ", err)
		}
		got, err := profileApproved(ctx, tx, tenantID, profileID)
		if err != nil || got != expected {
			t.Fatalf("profile enforcement gate got approved=%v, want %v, err=%v", got, expected, err)
		}
	}
	checkProfileGate := func(expected bool) { checkProfileGateFor(tenantA, "tls13-classical", expected) }
	gatewayGateSequence := 0
	checkGatewayProfileGate := func(expectApproved bool) {
		t.Helper()
		gatewayGateSequence++
		request := gatewayRequest
		request.RequestID = fmt.Sprintf("profile-gate-integration-%04d", gatewayGateSequence)
		decision, err := server.Evaluate(ctx, gatewayRoute, request)
		if expectApproved {
			if err != nil || decision.Outcome != "allow" || decision.PolicyRevisionID != profileGatePolicyID {
				t.Fatalf("approved tenant profile should permit the matching gateway request: decision=%+v err=%v", decision, err)
			}
			return
		}
		if failure, ok := err.(*gateway.Failure); !ok || failure.Code != "PROFILE_NOT_APPROVED" || decision.Outcome == "allow" {
			t.Fatalf("unapproved or retired profile must fail closed at the gateway: decision=%+v err=%v", decision, err)
		}
	}
	profilePath := "/v1/tenants/" + tenantA + "/algorithm-profiles/tls13-classical/reviews"
	validEvidence := profileEvidence(false)
	response = profileRequestAs("profile-tenant-admin", tenantA, http.MethodPost, profilePath, validEvidence, "", nextKey())
	if response.Code != http.StatusForbidden {
		t.Fatalf("tenant administrator must not author a profile review: %d %s", response.Code, response.Body.String())
	}
	response = profileRequestAs("profile-author", tenantA, http.MethodPost, profilePath, `{}`, "", nextKey())
	if response.Code != http.StatusBadRequest {
		t.Fatalf("malformed profile evidence must be rejected: %d %s", response.Code, response.Body.String())
	}
	response = profileRequestAs("profile-author", tenantA, http.MethodPost,
		"/v1/tenants/"+tenantB+"/algorithm-profiles/tls13-classical/reviews", validEvidence, "", nextKey())
	if response.Code != http.StatusNotFound {
		t.Fatalf("a tenant path mismatch must not expose another tenant: %d %s", response.Code, response.Body.String())
	}
	response = profileRequestAs("profile-author", tenantA, http.MethodPost, profilePath, validEvidence, "", nextKey())
	if response.Code != http.StatusCreated || response.Header().Get("ETag") == "" {
		t.Fatalf("security engineer should submit a complete profile review: %d %s", response.Code, response.Body.String())
	}
	var profileReview struct {
		ID    string `json:"id"`
		State string `json:"state"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &profileReview); err != nil || !validUUID(profileReview.ID) || profileReview.State != "pending_review" {
		t.Fatalf("profile review submission response is invalid: %v %s", err, response.Body.String())
	}
	checkProfileGate(false)
	checkGatewayProfileGate(false)
	profileReviewETag := response.Header().Get("ETag")
	reviewActionPath := "/v1/tenants/" + tenantA + "/algorithm-profile-reviews/" + profileReview.ID
	approvalBody := `{"review_reference":"https://security.example/reviews/classical-profile"}`
	response = profileRequestAs("profile-author", tenantA, http.MethodPost, reviewActionPath+"/approve", approvalBody, profileReviewETag, nextKey())
	if response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), "INDEPENDENT_REVIEW_REQUIRED") {
		t.Fatalf("profile submitter must not approve their own review: %d %s", response.Code, response.Body.String())
	}
	var runtimeCanExecuteProfileGuard bool
	if err := db.QueryRowContext(ctx, `SELECT has_function_privilege(current_user,
		'public.qg_guard_algorithm_profile_review()'::regprocedure, 'EXECUTE')`).Scan(&runtimeCanExecuteProfileGuard); err != nil || runtimeCanExecuteProfileGuard {
		t.Fatalf("runtime role must not be able to invoke the profile guard function: executable=%v err=%v", runtimeCanExecuteProfileGuard, err)
	}
	var runtimeOwnsProfileTable bool
	if err := db.QueryRowContext(ctx, `SELECT pg_get_userbyid(relowner) = current_user
		FROM pg_class WHERE oid = 'public.algorithm_profiles'::regclass`).Scan(&runtimeOwnsProfileTable); err != nil || runtimeOwnsProfileTable {
		t.Fatalf("runtime role must not own profile rows or disable their guard: owns_table=%v err=%v", runtimeOwnsProfileTable, err)
	}
	runtimeTx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal("begin runtime profile self-approval probe: ", err)
	}
	if _, err := runtimeTx.ExecContext(ctx, "SELECT set_config('qg.tenant_id', $1, true)", tenantA); err != nil {
		_ = runtimeTx.Rollback()
		t.Fatal("set tenant scope for runtime profile self-approval probe: ", err)
	}
	_, runtimeMutationErr := runtimeTx.ExecContext(ctx, `UPDATE algorithm_profiles SET lifecycle = 'approved', reviewed_by = submitted_by,
		reviewed_at = clock_timestamp(), review_reference = 'https://security.example/self', lifecycle_version = lifecycle_version + 1
		WHERE tenant_id = $1 AND id = $2`, tenantA, profileReview.ID)
	_ = runtimeTx.Rollback()
	if runtimeMutationErr == nil {
		t.Fatal("runtime role must not bypass the database self-approval guard")
	}
	if err := withIntegrationTenant(ctx, conn, tenantA, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE algorithm_profiles SET lifecycle = 'approved', reviewed_by = submitted_by,
			reviewed_at = clock_timestamp(), review_reference = 'https://security.example/self', lifecycle_version = lifecycle_version + 1
			WHERE tenant_id = $1 AND id = $2`, tenantA, profileReview.ID)
		return err
	}); err == nil {
		t.Fatal("database must reject self-approval even if a caller bypasses the HTTP authorization check")
	}
	response = profileRequestAs("other-tenant-reviewer", tenantB, http.MethodPost,
		"/v1/tenants/"+tenantB+"/algorithm-profile-reviews/"+profileReview.ID+"/approve", approvalBody, profileReviewETag, nextKey())
	if response.Code != http.StatusNotFound {
		t.Fatalf("another tenant must not access the review record: %d %s", response.Code, response.Body.String())
	}
	response = profileRequestAs("admin-3", tenantA, http.MethodPost, reviewActionPath+"/approve", approvalBody, profileReviewETag, nextKey())
	if response.Code != http.StatusForbidden {
		t.Fatalf("tenant administrator without security-engineer role must not approve a profile: %d %s", response.Code, response.Body.String())
	}
	reviewer := "profile-reviewer"
	response = profileRequestAs(reviewer, tenantA, http.MethodPost, reviewActionPath+"/approve", approvalBody, profileReviewETag, nextKey())
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"state":"approved"`) {
		t.Fatalf("independent security engineer should approve the profile: %d %s", response.Code, response.Body.String())
	}
	approvedETag := response.Header().Get("ETag")
	setGatewayApplicationMode("sdk")
	sdkAPIServer := httptest.NewUnstartedServer(server.Handler())
	sdkCertificate := integrationGatewayCertificate(t, gatewayRoute.Host)
	sdkAPIServer.TLS = &tls.Config{
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{tls.X25519},
		Certificates: []tls.Certificate{sdkCertificate},
	}
	sdkAPIServer.StartTLS()
	defer sdkAPIServer.Close()
	sdkRoots := x509.NewCertPool()
	sdkRoots.AddCert(sdkCertificate.Leaf)
	sdkClient := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{tls.X25519},
		ServerName: gatewayRoute.Host, RootCAs: sdkRoots,
	}}}
	defer sdkClient.CloseIdleConnections()
	allowedSDKRequest, err := http.NewRequest(http.MethodPost, sdkAPIServer.URL+"/v1/applications/"+gatewayApplicationID+"/decisions",
		strings.NewReader(decisionJSON("GET", "/api/items")))
	if err != nil {
		t.Fatal("create TLS SDK decision request: ", err)
	}
	allowedSDKRequest.Header.Set("Authorization", "Bearer "+decisionToken)
	allowedSDKRequest.Header.Set("Content-Type", "application/json")
	allowedSDKHTTP, err := sdkClient.Do(allowedSDKRequest)
	if err != nil {
		t.Fatal("send TLS SDK decision request: ", err)
	}
	allowedSDKBody, readSDKErr := io.ReadAll(allowedSDKHTTP.Body)
	_ = allowedSDKHTTP.Body.Close()
	var allowedDecision decisionResponse
	classicalProfileHash := profileDefinitionHash("tls13-classical")
	if allowedSDKHTTP.StatusCode != http.StatusOK || readSDKErr != nil || json.Unmarshal(allowedSDKBody, &allowedDecision) != nil ||
		allowedDecision.Decision != "allow" || allowedDecision.TenantID != tenantA || allowedDecision.ApplicationID != gatewayApplicationID ||
		allowedDecision.ProfileID != "tls13-classical" || allowedDecision.ProfileRegistryVersion != policyRegistryVersion ||
		allowedDecision.ProfileHash != hex.EncodeToString(classicalProfileHash[:]) || allowedDecision.PolicyRevisionID != profileGatePolicyID ||
		allowedDecision.RequestID == "" || allowedDecision.RequestID != allowedSDKHTTP.Header.Get("X-Request-ID") {
		t.Fatalf("approved SDK decision should return the server-bound allow context: %d %s err=%v", allowedSDKHTTP.StatusCode, allowedSDKBody, readSDKErr)
	}
	deniedSDK := decisionHTTP(decisionToken, gatewayApplicationID, decisionJSON("POST", "/api/items"), tls.X25519)
	var deniedDecision decisionResponse
	if deniedSDK.Code != http.StatusOK || json.Unmarshal(deniedSDK.Body.Bytes(), &deniedDecision) != nil || deniedDecision.Decision != "deny" ||
		deniedDecision.Method != "POST" || deniedDecision.Path != "/api/items" {
		t.Fatalf("policy denial should be returned as an explicit server decision: %d %s", deniedSDK.Code, deniedSDK.Body.String())
	}
	var sdkDecisionActor, sdkDecisionIntegration, sdkDecisionPolicyRevision, sdkDecisionProfileHash, sdkDecisionSource string
	if err := withIntegrationTenant(ctx, conn, tenantA, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT actor, source_context->>'integration', source_context->>'policy_revision_id',
			source_context->>'profile_hash', source_context::text FROM audit_events
			WHERE tenant_id = $1 AND correlation_id = $2 AND action = 'authorization.decision'`,
			tenantA, allowedDecision.RequestID).Scan(&sdkDecisionActor, &sdkDecisionIntegration,
			&sdkDecisionPolicyRevision, &sdkDecisionProfileHash, &sdkDecisionSource)
	}); err != nil || sdkDecisionIntegration != "sdk" || sdkDecisionPolicyRevision != allowedDecision.PolicyRevisionID ||
		sdkDecisionProfileHash != allowedDecision.ProfileHash ||
		strings.Contains(sdkDecisionSource, gatewayRequest.IdentityToken) || strings.Contains(sdkDecisionActor, "gateway-user-secret") {
		t.Fatalf("SDK decision audit must correlate the profile and policy without identity secrets: actor=%q source=%q err=%v", sdkDecisionActor, sdkDecisionSource, err)
	}
	setGatewayApplicationMode("gateway")
	checkGatewayProfileGate(true)
	originalClassicalProfile := policyProfiles["tls13-classical"]
	changedClassicalProfile := originalClassicalProfile
	changedClassicalProfile.ProviderVersion += "-registry-change"
	policyProfiles["tls13-classical"] = changedClassicalProfile
	checkProfileGate(false)
	checkGatewayProfileGate(false)
	policyProfiles["tls13-classical"] = originalClassicalProfile
	checkProfileGate(true)
	checkGatewayProfileGate(true)
	response = profileRequest(tenantA, http.MethodGet, reviewActionPath, "", "", "")
	var reviewDetail struct {
		SubmittedBy     string `json:"submitted_by"`
		ReviewedBy      string `json:"reviewed_by"`
		ReviewReference string `json:"review_reference"`
		DesignRecord    struct {
			DowngradeDetection string `json:"downgrade_detection"`
		} `json:"design_record"`
	}
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &reviewDetail) != nil ||
		reviewDetail.SubmittedBy == "" || reviewDetail.SubmittedBy == reviewDetail.ReviewedBy ||
		reviewDetail.ReviewReference != "https://security.example/reviews/classical-profile" ||
		reviewDetail.DesignRecord.DowngradeDetection != "SENSITIVE-REVIEW-DETAIL-DO-NOT-AUDIT" {
		t.Fatalf("authorized reviewer should be able to verify immutable approval evidence: %d %s", response.Code, response.Body.String())
	}
	response = profileRequestAs("profile-tenant-admin", tenantA, http.MethodGet, reviewActionPath, "", "", "")
	if response.Code != http.StatusForbidden {
		t.Fatalf("profile evidence reads should be restricted to security engineers and auditors: %d %s", response.Code, response.Body.String())
	}
	runtimeTx, err = db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal("begin runtime profile evidence mutation probe: ", err)
	}
	if _, err := runtimeTx.ExecContext(ctx, "SELECT set_config('qg.tenant_id', $1, true)", tenantA); err != nil {
		_ = runtimeTx.Rollback()
		t.Fatal("set tenant scope for runtime profile evidence mutation probe: ", err)
	}
	_, runtimeMutationErr = runtimeTx.ExecContext(ctx, `UPDATE algorithm_profiles SET source_reference = 'https://attacker.example/changed'
		WHERE tenant_id = $1 AND id = $2`, tenantA, profileReview.ID)
	_ = runtimeTx.Rollback()
	if runtimeMutationErr == nil {
		t.Fatal("runtime role must not bypass database immutability for profile evidence")
	}
	runtimeTx, err = db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal("begin runtime profile deletion probe: ", err)
	}
	if _, err := runtimeTx.ExecContext(ctx, "SELECT set_config('qg.tenant_id', $1, true)", tenantA); err != nil {
		_ = runtimeTx.Rollback()
		t.Fatal("set tenant scope for runtime profile deletion probe: ", err)
	}
	_, runtimeMutationErr = runtimeTx.ExecContext(ctx, `DELETE FROM algorithm_profiles WHERE tenant_id = $1 AND id = $2`, tenantA, profileReview.ID)
	_ = runtimeTx.Rollback()
	if runtimeMutationErr == nil {
		t.Fatal("runtime role must not delete immutable profile review evidence")
	}
	if _, err := db.ExecContext(ctx, "ALTER TABLE public.algorithm_profiles DISABLE TRIGGER algorithm_profiles_immutable_review"); err == nil {
		t.Fatal("runtime role must not be able to disable the profile review trigger")
	}
	replayKey := nextKey()
	replay := profileRequest(tenantA, http.MethodPost, reviewActionPath+"/approve", approvalBody, profileReviewETag, replayKey)
	if replay.Code != http.StatusOK || replay.Header().Get("Idempotency-Replayed") != "true" || replay.Body.String() != response.Body.String() {
		t.Fatalf("same approval retry should replay its committed response: %d %s", replay.Code, replay.Body.String())
	}
	response = profileRequest(tenantA, http.MethodPost, reviewActionPath+"/approve", approvalBody, profileReviewETag, nextKey())
	if response.Code != http.StatusPreconditionFailed {
		t.Fatalf("stale approval ETag must be rejected: %d %s", response.Code, response.Body.String())
	}
	response = profileRequest(tenantA, http.MethodPost, reviewActionPath+"/reject", approvalBody, approvedETag, nextKey())
	if response.Code != http.StatusConflict {
		t.Fatalf("an approved profile cannot transition directly to rejected: %d %s", response.Code, response.Body.String())
	}
	if err := withIntegrationTenant(ctx, conn, tenantA, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE algorithm_profiles SET source_reference = 'https://attacker.example/changed'
			WHERE tenant_id = $1 AND id = $2`, tenantA, profileReview.ID)
		return err
	}); err == nil {
		t.Fatal("database must reject changes to profile evidence after approval")
	}
	if err := withIntegrationTenant(ctx, conn, tenantA, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE algorithm_profiles SET lifecycle = 'pending_review', lifecycle_version = lifecycle_version + 1
			WHERE tenant_id = $1 AND id = $2`, tenantA, profileReview.ID)
		return err
	}); err == nil {
		t.Fatal("database must reject reactivation or rollback of an approved profile lifecycle")
	}
	var profileAudit string
	if err := withIntegrationTenant(ctx, conn, tenantA, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT COALESCE(string_agg(action || ':' || outcome || ':' || reason_code || ':' || source_context::text, E'\n'), '')
			FROM audit_events WHERE tenant_id = $1 AND target_type = 'algorithm_profile_review' AND target_id = $2`, tenantA, profileReview.ID).Scan(&profileAudit)
	}); err != nil {
		t.Fatal("read profile review audit evidence: ", err)
	}
	if !strings.Contains(profileAudit, "algorithm_profile.review_submitted:success:REVIEW_SUBMITTED") ||
		!strings.Contains(profileAudit, "algorithm_profile.approved:success:PROFILE_APPROVED") ||
		!strings.Contains(profileAudit, "algorithm_profile.review_denied:denied:SELF_REVIEW_REJECTED") ||
		strings.Contains(profileAudit, "SENSITIVE-REVIEW-DETAIL-DO-NOT-AUDIT") || strings.Contains(profileAudit, "security.example/reviews") {
		t.Fatalf("profile audit must be correlated and omit submitted or review payloads: %q", profileAudit)
	}
	checkProfileGate(true)
	response = profileRequest(tenantA, http.MethodPost, reviewActionPath+"/disable", "", approvedETag, nextKey())
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"state":"disabled"`) {
		t.Fatalf("security engineer should disable an approved profile with its current ETag: %d %s", response.Code, response.Body.String())
	}
	checkProfileGate(false)
	checkGatewayProfileGate(false)
	profileList := profileRequest(tenantA, http.MethodGet, "/v1/tenants/"+tenantA+"/algorithm-profiles", "", "", "")
	if profileList.Code != http.StatusOK || !strings.Contains(profileList.Body.String(), `"status":"disabled"`) {
		t.Fatalf("profile list should expose the current tenant lifecycle: %d %s", profileList.Code, profileList.Body.String())
	}
	response = profileRequestAs("profile-author", tenantA, http.MethodPost, profilePath, validEvidence, "", nextKey())
	if response.Code != http.StatusCreated {
		t.Fatalf("disabled profiles should require a new independent review revision before reuse: %d %s", response.Code, response.Body.String())
	}
	if err := json.Unmarshal(response.Body.Bytes(), &profileReview); err != nil || profileReview.State != "pending_review" {
		t.Fatalf("new profile review revision was invalid: %v %s", err, response.Body.String())
	}
	rejectedPath := "/v1/tenants/" + tenantA + "/algorithm-profile-reviews/" + profileReview.ID
	response = profileRequestAs(reviewer, tenantA, http.MethodPost, rejectedPath+"/reject",
		`{"review_reference":"https://security.example/reviews/classical-rejection"}`, response.Header().Get("ETag"), nextKey())
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"state":"rejected"`) {
		t.Fatalf("independent reviewer should be able to reject a profile: %d %s", response.Code, response.Body.String())
	}
	response = profileRequest(tenantA, http.MethodPost, rejectedPath+"/approve", approvalBody, response.Header().Get("ETag"), nextKey())
	if response.Code != http.StatusConflict {
		t.Fatalf("rejected reviews cannot later be approved: %d %s", response.Code, response.Body.String())
	}
	response = profileRequestAs("profile-author", tenantA, http.MethodPost, profilePath, validEvidence, "", nextKey())
	if response.Code != http.StatusCreated {
		t.Fatalf("a rejected snapshot should permit a new immutable review revision: %d %s", response.Code, response.Body.String())
	}
	if err := json.Unmarshal(response.Body.Bytes(), &profileReview); err != nil {
		t.Fatal("decode replacement profile review: ", err)
	}
	response = profileRequestAs(reviewer, tenantA, http.MethodPost,
		"/v1/tenants/"+tenantA+"/algorithm-profile-reviews/"+profileReview.ID+"/approve", approvalBody, response.Header().Get("ETag"), nextKey())
	if response.Code != http.StatusOK {
		t.Fatalf("replacement profile evidence should require a new independent approval: %d %s", response.Code, response.Body.String())
	}
	checkProfileGate(true)
	response = profileRequest(tenantA, http.MethodPost,
		"/v1/tenants/"+tenantA+"/algorithm-profile-reviews/"+profileReview.ID+"/deprecate", "", response.Header().Get("ETag"), nextKey())
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"state":"deprecated"`) {
		t.Fatalf("security engineer should deprecate an approved profile with its current ETag: %d %s", response.Code, response.Body.String())
	}
	checkProfileGate(false)
	checkGatewayProfileGate(false)

	response = profileRequestAs("profile-author", tenantA, http.MethodPost,
		"/v1/tenants/"+tenantA+"/algorithm-profiles/tls13-x25519-mlkem768/reviews", profileEvidence(true), "", nextKey())
	if response.Code != http.StatusCreated {
		t.Fatalf("hybrid profile review submission should accept complete PQC evidence: %d %s", response.Code, response.Body.String())
	}
	if err := json.Unmarshal(response.Body.Bytes(), &profileReview); err != nil {
		t.Fatal("decode hybrid profile review: ", err)
	}
	hybridReviewPath := "/v1/tenants/" + tenantA + "/algorithm-profile-reviews/" + profileReview.ID
	hybridETag := response.Header().Get("ETag")
	adminServer.Auth = integrationTokenVerifier{principal: auth.Principal{Issuer: "https://id.example", Subject: reviewer}}
	concurrentResults := make(chan *httptest.ResponseRecorder, 2)
	var concurrent sync.WaitGroup
	concurrent.Add(2)
	go func(key string) {
		defer concurrent.Done()
		concurrentResults <- profileRequest(tenantA, http.MethodPost, hybridReviewPath+"/approve", approvalBody, hybridETag, key)
	}(nextKey())
	go func(key string) {
		defer concurrent.Done()
		concurrentResults <- profileRequest(tenantA, http.MethodPost, hybridReviewPath+"/reject",
			`{"review_reference":"https://security.example/reviews/hybrid-profile"}`, hybridETag, key)
	}(nextKey())
	concurrent.Wait()
	close(concurrentResults)
	concurrentSuccesses, concurrentStale := 0, 0
	for result := range concurrentResults {
		switch result.Code {
		case http.StatusOK:
			concurrentSuccesses++
		case http.StatusPreconditionFailed:
			concurrentStale++
		default:
			t.Errorf("concurrent profile transition should succeed once and reject the stale operation, got %d %s", result.Code, result.Body.String())
		}
	}
	if concurrentSuccesses != 1 || concurrentStale != 1 {
		t.Fatalf("concurrent profile review transitions must serialize to one success and one stale result, success=%d stale=%d", concurrentSuccesses, concurrentStale)
	}
	tenantBProfilePath := "/v1/tenants/" + tenantB + "/algorithm-profiles/tls13-classical/reviews"
	response = profileRequestAs("other-tenant-author", tenantB, http.MethodPost, tenantBProfilePath, validEvidence, "", nextKey())
	if response.Code != http.StatusCreated {
		t.Fatalf("second tenant should submit its own profile review: %d %s", response.Code, response.Body.String())
	}
	var tenantBReview struct {
		ID    string `json:"id"`
		State string `json:"state"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &tenantBReview); err != nil || !validUUID(tenantBReview.ID) {
		t.Fatalf("second-tenant profile review is invalid: %v %s", err, response.Body.String())
	}
	tenantBReviewPath := "/v1/tenants/" + tenantB + "/algorithm-profile-reviews/" + tenantBReview.ID
	response = profileRequestAs("other-tenant-reviewer", tenantB, http.MethodPost, tenantBReviewPath+"/approve", approvalBody, response.Header().Get("ETag"), nextKey())
	if response.Code != http.StatusOK {
		t.Fatalf("second tenant should independently approve its profile: %d %s", response.Code, response.Body.String())
	}
	checkProfileGateFor(tenantB, "tls13-classical", true)
	originalClassicalProfile = policyProfiles["tls13-classical"]
	changedClassicalProfile = originalClassicalProfile
	changedClassicalProfile.ProviderVersion += "-new-registry-content"
	policyProfiles["tls13-classical"] = changedClassicalProfile
	checkProfileGateFor(tenantB, "tls13-classical", false)
	response = profileRequestAs("other-tenant-author", tenantB, http.MethodPost, tenantBProfilePath, validEvidence, "", nextKey())
	if response.Code != http.StatusCreated {
		policyProfiles["tls13-classical"] = originalClassicalProfile
		t.Fatalf("changed canonical profile should require a new review: %d %s", response.Code, response.Body.String())
	}
	var tenantBReplacement struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &tenantBReplacement); err != nil || !validUUID(tenantBReplacement.ID) {
		policyProfiles["tls13-classical"] = originalClassicalProfile
		t.Fatalf("replacement tenant profile review is invalid: %v %s", err, response.Body.String())
	}
	policyProfiles["tls13-classical"] = originalClassicalProfile
	var invalidatedState string
	if err := withIntegrationTenant(ctx, conn, tenantB, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT lifecycle FROM algorithm_profiles WHERE tenant_id = $1 AND id = $2`, tenantB, tenantBReview.ID).Scan(&invalidatedState)
	}); err != nil || invalidatedState != "disabled" {
		t.Fatalf("registry change must disable the prior approval, state=%q err=%v", invalidatedState, err)
	}
	var invalidationCount int
	if err := withIntegrationTenant(ctx, conn, tenantB, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE tenant_id = $1 AND target_id = $2
			AND action = 'algorithm_profile.invalidated' AND reason_code = 'PROFILE_DEFINITION_CHANGED'`, tenantB, tenantBReview.ID).Scan(&invalidationCount)
	}); err != nil || invalidationCount != 1 {
		t.Fatalf("registry change should audit the invalidation, count=%d err=%v", invalidationCount, err)
	}
	checkProfileGateFor(tenantB, "tls13-classical", false)
	staleApprovalETag := response.Header().Get("ETag")
	response = profileRequestAs("other-tenant-reviewer", tenantB, http.MethodPost,
		"/v1/tenants/"+tenantB+"/algorithm-profile-reviews/"+tenantBReplacement.ID+"/approve", approvalBody, staleApprovalETag, nextKey())
	if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "PROFILE_VERSION_STALE") {
		t.Fatalf("stale canonical evidence must not be approved: %d %s", response.Code, response.Body.String())
	}
	response = profileRequestAs("other-tenant-reviewer", tenantB, http.MethodPost,
		"/v1/tenants/"+tenantB+"/algorithm-profile-reviews/"+tenantBReplacement.ID+"/reject",
		`{"review_reference":"https://security.example/reviews/stale-profile"}`, staleApprovalETag, nextKey())
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"state":"rejected"`) {
		t.Fatalf("stale pending profile evidence should be rejectable but never approvable: %d %s", response.Code, response.Body.String())
	}
	checkProfileGateFor(tenantB, "tls13-classical", false)

	for index, limiter := range []*Server{server, adminServer, server} {
		allowed, retryAfter, err := limiter.checkRateLimit(ctx, "integration-shared", "same-principal", 2)
		if err != nil {
			t.Fatal("check distributed rate limit: ", err)
		}
		if index < 2 && !allowed {
			t.Fatalf("request %d should fit within the shared rate limit", index+1)
		}
		if index == 2 && (allowed || retryAfter < 1 || retryAfter > 60) {
			t.Fatalf("limit should be enforced across API instances with a safe retry time, allowed=%v retry=%d", allowed, retryAfter)
		}
	}
}

func createControlPlaneFixture(t *testing.T, ctx context.Context, conn *pgx.Conn, tenantID, tenantName, role, environmentID, applicationID string) {
	t.Helper()
	err := withIntegrationTenant(ctx, conn, tenantID, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO tenants(id, display_name, status) VALUES ($1, $2, 'active')`, tenantID, tenantName); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO tenant_members(tenant_id, issuer, subject, role) VALUES ($1, 'https://id.example', 'admin-1', $2)`, tenantID, role); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO environments(id, tenant_id, name, lifecycle) VALUES ($1, $2, 'production', 'production')`, environmentID, tenantID); err != nil {
			return err
		}
		if applicationID != "" {
			_, err := tx.Exec(ctx, `INSERT INTO applications(id, tenant_id, environment_id, external_id, display_name, integration_mode, status)
				VALUES ($1, $2, $3, 'existing-app', 'Existing app', 'sdk', 'active')`, applicationID, tenantID, environmentID)
			return err
		}
		return nil
	})
	if err != nil {
		t.Fatal("create tenant fixture: ", err)
	}
}

func integrationGatewayCertificate(t *testing.T, hostname string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal("generate test gateway certificate key: ", err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: hostname}, DNSNames: []string{hostname},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal("create test gateway certificate: ", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal("parse test gateway certificate: ", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

func withIntegrationTenant(ctx context.Context, conn *pgx.Conn, tenantID string, operation func(pgx.Tx) error) error {
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
