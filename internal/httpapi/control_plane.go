package httpapi

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/jackc/pgx/v5/pgconn"

	"quantumgate/internal/auth"
	"quantumgate/internal/webhook"
)

const maxControlBodyBytes = 64 << 10
const maxBearerTokenBytes = 16 << 10

type controlContextKey uint8

const (
	tenantContextKey controlContextKey = iota + 1
	roleContextKey
	principalContextKey
	transactionContextKey
)

type tenantPrincipal struct {
	Issuer   string
	Subject  string
	Role     string
	TenantID string
}

func (s *Server) withTenantAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.Store == nil {
			writeProblem(w, r, http.StatusServiceUnavailable, "CONTROL_PLANE_UNAVAILABLE", "Service unavailable", "The control plane is not configured.", true)
			return
		}
		var identity auth.Principal
		var csrfHash []byte
		browserSession := hasCookie(r, sessionCookieName)
		if browserSession {
			var ok bool
			identity, csrfHash, _, ok = s.loadBrowserSession(r)
			if !ok {
				writeProblem(w, r, http.StatusUnauthorized, "UNAUTHENTICATED", "Authentication required", "Valid administrator authentication is required.", false)
				return
			}
			if unsafeMethod(r.Method) && !s.validCSRFRequest(r, csrfHash) {
				writeProblem(w, r, http.StatusForbidden, "CSRF_REJECTED", "Request denied", "The request could not be validated.", false)
				return
			}
		} else {
			token, ok := bearerToken(r)
			if !ok || s.Auth == nil {
				writeProblem(w, r, http.StatusUnauthorized, "UNAUTHENTICATED", "Authentication required", "Valid administrator authentication is required.", false)
				return
			}
			var err error
			identity, err = s.Auth.Verify(r.Context(), token)
			if err != nil {
				writeProblem(w, r, http.StatusUnauthorized, "UNAUTHENTICATED", "Authentication required", "Valid administrator authentication is required.", false)
				return
			}
		}
		tenantID := r.Header.Get("X-QG-Tenant-ID")
		if !validUUID(tenantID) || len(r.Header.Values("X-QG-Tenant-ID")) != 1 {
			writeProblem(w, r, http.StatusBadRequest, "INVALID_TENANT_CONTEXT", "Invalid request", "A valid tenant context is required.", false)
			return
		}
		clientIP := clientIPDimension(r.RemoteAddr)
		if !s.enforceRateLimit(w, r, "control-plane:ip", clientIP, 300) ||
			!s.enforceRateLimit(w, r, "control-plane:tenant", tenantID, 600) ||
			!s.enforceRateLimit(w, r, "control-plane:principal", identity.Issuer+"\x00"+identity.Subject+"\x00"+tenantID, 120) {
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		tx, err := s.Store.BeginTx(ctx, nil)
		if err != nil {
			writeProblem(w, r, http.StatusServiceUnavailable, "CONTROL_PLANE_UNAVAILABLE", "Service unavailable", "The request could not be processed safely.", true)
			return
		}
		defer tx.Rollback()
		if _, err := tx.ExecContext(ctx, "SELECT set_config('qg.tenant_id', $1, true)", tenantID); err != nil {
			writeProblem(w, r, http.StatusServiceUnavailable, "CONTROL_PLANE_UNAVAILABLE", "Service unavailable", "The request could not be processed safely.", true)
			return
		}
		var role string
		err = tx.QueryRowContext(ctx, `SELECT role FROM tenant_members
			WHERE tenant_id = $1 AND issuer = $2 AND subject = $3`, tenantID, identity.Issuer, identity.Subject).Scan(&role)
		if errors.Is(err, sql.ErrNoRows) {
			writeProblem(w, r, http.StatusNotFound, "TENANT_NOT_FOUND", "Not found", "The requested resource was not found.", false)
			return
		}
		if err != nil {
			writeProblem(w, r, http.StatusServiceUnavailable, "CONTROL_PLANE_UNAVAILABLE", "Service unavailable", "The request could not be processed safely.", true)
			return
		}
		principal := tenantPrincipal{Issuer: identity.Issuer, Subject: identity.Subject, Role: role, TenantID: tenantID}
		r = r.WithContext(context.WithValue(r.Context(), tenantContextKey, tenantID))
		r = r.WithContext(context.WithValue(r.Context(), roleContextKey, role))
		r = r.WithContext(context.WithValue(r.Context(), principalContextKey, principal))
		r = r.WithContext(context.WithValue(r.Context(), transactionContextKey, tx))
		var idempotencyHash []byte
		if unsafeMethod(r.Method) {
			key, valid := validateIdempotencyKey(r.Header.Values(idempotencyKeyHeader))
			if !valid {
				writeProblem(w, r, http.StatusBadRequest, "IDEMPOTENCY_KEY_REQUIRED", "Invalid request", "A single 16 to 128 character Idempotency-Key is required for state-changing requests.", false)
				return
			}
			body, bodyErr := readMutationBody(w, r)
			if bodyErr != nil {
				status := http.StatusBadRequest
				code := "INVALID_REQUEST"
				title := "Invalid request"
				detail := "The request body could not be read."
				var tooLarge *http.MaxBytesError
				if errors.As(bodyErr, &tooLarge) {
					status, code, title, detail = http.StatusRequestEntityTooLarge, "REQUEST_TOO_LARGE", "Request too large", "The request body exceeds the allowed size."
				}
				writeProblem(w, r, status, code, title, detail, false)
				return
			}
			var replay *idempotentResponse
			idempotencyHash, replay, err = s.reserveIdempotency(ctx, tx, r, principal, key, body)
			if errors.Is(err, errIdempotencyKeyReused) {
				writeProblem(w, r, http.StatusConflict, "IDEMPOTENCY_KEY_REUSED", "Conflict", "The idempotency key was already used for a different request.", false)
				return
			}
			if err != nil {
				writeProblem(w, r, http.StatusServiceUnavailable, "IDEMPOTENCY_UNAVAILABLE", "Service unavailable", "The request could not be processed safely.", true)
				return
			}
			if replay != nil {
				replayIdempotentResponse(w, replay)
				return
			}
		} else {
			r.Body = http.MaxBytesReader(w, r.Body, maxControlBodyBytes)
		}
		recorder := httptest.NewRecorder()
		next.ServeHTTP(recorder, r)
		if recorder.Code >= http.StatusInternalServerError || recorder.Code >= http.StatusBadRequest && recorder.Code != http.StatusForbidden {
			writeRecorded(w, recorder)
			return
		}
		if recorder.Code == http.StatusForbidden {
			if auditErr := insertAudit(ctx, tx, principal, requestID(r.Context()), "authorization.denied", "route", r.Method, "denied", "ROLE_REQUIRED"); auditErr != nil {
				writeProblem(w, r, http.StatusServiceUnavailable, "AUDIT_UNAVAILABLE", "Service unavailable", "The request could not be processed safely.", true)
				return
			}
		}
		if len(idempotencyHash) != 0 {
			status := recorder.Code
			if status == 0 {
				status = http.StatusOK
			}
			if err := s.saveIdempotentResponse(ctx, tx, tenantID, idempotencyHash, status, recorder.Header(), recorder.Body.Bytes()); err != nil {
				writeProblem(w, r, http.StatusServiceUnavailable, "IDEMPOTENCY_UNAVAILABLE", "Service unavailable", "The request could not be processed safely.", true)
				return
			}
		}
		if err := tx.Commit(); err != nil {
			writeProblem(w, r, http.StatusServiceUnavailable, "CONTROL_PLANE_UNAVAILABLE", "Service unavailable", "The request could not be processed safely.", true)
			return
		}
		writeRecorded(w, recorder)
	})
}

func hasCookie(r *http.Request, name string) bool {
	for _, cookie := range r.Cookies() {
		if cookie.Name == name {
			return true
		}
	}
	return false
}

func unsafeMethod(method string) bool {
	return method != http.MethodGet && method != http.MethodHead && method != http.MethodOptions
}

func bearerToken(r *http.Request) (string, bool) {
	values := r.Header.Values("Authorization")
	if len(values) != 1 {
		return "", false
	}
	parts := strings.SplitN(values[0], " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || len(parts[1]) == 0 || len(parts[1]) > maxBearerTokenBytes || strings.ContainsAny(parts[1], " \t\r\n") {
		return "", false
	}
	return parts[1], true
}

func writeRecorded(w http.ResponseWriter, recorder *httptest.ResponseRecorder) {
	for key, values := range recorder.Header() {
		w.Header()[key] = append([]string(nil), values...)
	}
	status := recorder.Code
	if status == 0 {
		status = http.StatusOK
	}
	w.WriteHeader(status)
	_, _ = w.Write(recorder.Body.Bytes())
}

func contextTransaction(r *http.Request) *sql.Tx {
	tx, _ := r.Context().Value(transactionContextKey).(*sql.Tx)
	return tx
}

func contextTenant(r *http.Request) string {
	tenantID, _ := r.Context().Value(tenantContextKey).(string)
	return tenantID
}

func contextRole(r *http.Request) string {
	role, _ := r.Context().Value(roleContextKey).(string)
	return role
}

func contextPrincipal(r *http.Request) tenantPrincipal {
	principal, _ := r.Context().Value(principalContextKey).(tenantPrincipal)
	return principal
}

func (s *Server) requireRole(w http.ResponseWriter, r *http.Request, allowed ...string) bool {
	for _, role := range allowed {
		if contextRole(r) == role {
			return true
		}
	}
	writeProblem(w, r, http.StatusForbidden, "FORBIDDEN", "Access denied", "The requested action is not permitted.", false)
	return false
}

func (s *Server) getTenant(w http.ResponseWriter, r *http.Request) {
	if r.PathValue("tenant_id") != contextTenant(r) {
		s.notFound(w, r)
		return
	}
	var tenant struct {
		ID          string    `json:"id"`
		DisplayName string    `json:"display_name"`
		Status      string    `json:"status"`
		CreatedAt   time.Time `json:"created_at"`
		UpdatedAt   time.Time `json:"updated_at"`
		RequestID   string    `json:"request_id"`
	}
	err := contextTransaction(r).QueryRowContext(r.Context(), `SELECT id::text, display_name, status, created_at, updated_at
		FROM tenants WHERE id = $1`, contextTenant(r)).Scan(&tenant.ID, &tenant.DisplayName, &tenant.Status, &tenant.CreatedAt, &tenant.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		s.notFound(w, r)
		return
	}
	if err != nil {
		writeProblem(w, r, http.StatusServiceUnavailable, "CONTROL_PLANE_UNAVAILABLE", "Service unavailable", "The request could not be processed safely.", true)
		return
	}
	tenant.RequestID = requestID(r.Context())
	w.Header().Set("ETag", tenantETag(tenant.UpdatedAt))
	writeJSON(w, http.StatusOK, tenant)
}

func (s *Server) updateTenant(w http.ResponseWriter, r *http.Request) {
	tenantID := r.PathValue("tenant_id")
	if tenantID != contextTenant(r) {
		s.notFound(w, r)
		return
	}
	if !s.requireRole(w, r, "tenant_admin") {
		return
	}
	if len(r.Header.Values("If-Match")) != 1 {
		writeProblem(w, r, http.StatusPreconditionRequired, "PRECONDITION_REQUIRED", "Update requires a version", "Fetch the tenant and send its ETag in If-Match.", false)
		return
	}
	expected, ok := parseTenantETag(r.Header.Get("If-Match"))
	if !ok {
		writeProblem(w, r, http.StatusPreconditionRequired, "PRECONDITION_REQUIRED", "Update requires a version", "Fetch the tenant and send its ETag in If-Match.", false)
		return
	}
	var input struct {
		DisplayName *string `json:"display_name"`
	}
	if err := decodeControlJSON(w, r, &input); err != nil || input.DisplayName == nil || !validLabel(*input.DisplayName, 120) {
		writeProblem(w, r, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request", "The request body is invalid.", false)
		return
	}
	var tenant struct {
		ID          string    `json:"id"`
		DisplayName string    `json:"display_name"`
		Status      string    `json:"status"`
		CreatedAt   time.Time `json:"created_at"`
		UpdatedAt   time.Time `json:"updated_at"`
		RequestID   string    `json:"request_id"`
	}
	err := contextTransaction(r).QueryRowContext(r.Context(), `UPDATE tenants
		SET display_name = $2, updated_at = GREATEST(clock_timestamp(), updated_at + interval '1 microsecond')
		WHERE id = $1 AND updated_at = $3
		RETURNING id::text, display_name, status, created_at, updated_at`, tenantID, *input.DisplayName, expected).
		Scan(&tenant.ID, &tenant.DisplayName, &tenant.Status, &tenant.CreatedAt, &tenant.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		writeProblem(w, r, http.StatusPreconditionFailed, "ETAG_MISMATCH", "Tenant changed", "Fetch the tenant again before retrying the update.", false)
		return
	}
	if err != nil {
		writeProblem(w, r, http.StatusServiceUnavailable, "CONTROL_PLANE_UNAVAILABLE", "Service unavailable", "The request could not be processed safely.", true)
		return
	}
	if err := insertAudit(r.Context(), contextTransaction(r), contextPrincipal(r), requestID(r.Context()), "tenant.updated", "tenant", tenantID, "success", "DISPLAY_NAME_UPDATED"); err != nil {
		writeProblem(w, r, http.StatusServiceUnavailable, "AUDIT_UNAVAILABLE", "Service unavailable", "The request could not be processed safely.", true)
		return
	}
	tenant.RequestID = requestID(r.Context())
	w.Header().Set("ETag", tenantETag(tenant.UpdatedAt))
	writeJSON(w, http.StatusOK, tenant)
}

func tenantETag(updatedAt time.Time) string {
	return `"` + updatedAt.UTC().Format(time.RFC3339Nano) + `"`
}

func parseTenantETag(value string) (time.Time, bool) {
	if len(value) < 3 || value[0] != '"' || value[len(value)-1] != '"' {
		return time.Time{}, false
	}
	parsed, err := time.Parse(time.RFC3339Nano, value[1:len(value)-1])
	return parsed, err == nil
}

func (s *Server) listAuditEvents(w http.ResponseWriter, r *http.Request) {
	if r.PathValue("tenant_id") != contextTenant(r) {
		s.notFound(w, r)
		return
	}
	if !s.requireRole(w, r, "tenant_admin", "security_engineer", "auditor") {
		return
	}
	limit := 50
	if raw := r.URL.Query().Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 100 {
			writeProblem(w, r, http.StatusBadRequest, "INVALID_LIMIT", "Invalid request", "The page size is invalid.", false)
			return
		}
		limit = parsed
	}
	var after any
	if cursor := r.URL.Query().Get("cursor"); cursor != "" {
		decoded, err := base64.RawURLEncoding.DecodeString(cursor)
		if err != nil || !validUUID(string(decoded)) {
			writeProblem(w, r, http.StatusBadRequest, "INVALID_CURSOR", "Invalid request", "The pagination cursor is invalid.", false)
			return
		}
		after = string(decoded)
	}
	rows, err := contextTransaction(r).QueryContext(r.Context(), `SELECT id::text, occurred_at, actor, action, target_type,
		target_id, outcome, correlation_id, reason_code FROM audit_events
		WHERE tenant_id = $1 AND ($2::uuid IS NULL OR (occurred_at, id) < (
			SELECT occurred_at, id FROM audit_events WHERE tenant_id = $1 AND id = $2::uuid))
		ORDER BY occurred_at DESC, id DESC LIMIT $3`, contextTenant(r), after, limit+1)
	if err != nil {
		writeProblem(w, r, http.StatusServiceUnavailable, "CONTROL_PLANE_UNAVAILABLE", "Service unavailable", "The request could not be processed safely.", true)
		return
	}
	defer rows.Close()
	type auditView struct {
		ID            string    `json:"id"`
		OccurredAt    time.Time `json:"occurred_at"`
		Actor         string    `json:"actor"`
		Action        string    `json:"action"`
		TargetType    string    `json:"target_type"`
		TargetID      string    `json:"target_id,omitempty"`
		Outcome       string    `json:"outcome"`
		CorrelationID string    `json:"correlation_id"`
		ReasonCode    string    `json:"reason_code"`
	}
	items := make([]auditView, 0, limit)
	for rows.Next() {
		var item auditView
		if err := rows.Scan(&item.ID, &item.OccurredAt, &item.Actor, &item.Action, &item.TargetType, &item.TargetID,
			&item.Outcome, &item.CorrelationID, &item.ReasonCode); err != nil {
			writeProblem(w, r, http.StatusServiceUnavailable, "CONTROL_PLANE_UNAVAILABLE", "Service unavailable", "The request could not be processed safely.", true)
			return
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		writeProblem(w, r, http.StatusServiceUnavailable, "CONTROL_PLANE_UNAVAILABLE", "Service unavailable", "The request could not be processed safely.", true)
		return
	}
	response := map[string]any{"items": items, "next_cursor": "", "request_id": requestID(r.Context())}
	if len(items) > limit {
		items = items[:limit]
		response["items"] = items
		response["next_cursor"] = base64.RawURLEncoding.EncodeToString([]byte(items[len(items)-1].ID))
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) createEnvironment(w http.ResponseWriter, r *http.Request) {
	if !s.requireRole(w, r, "tenant_admin") || r.PathValue("tenant_id") != contextTenant(r) {
		if r.PathValue("tenant_id") != contextTenant(r) {
			s.notFound(w, r)
		}
		return
	}
	var input struct {
		Name      string `json:"name"`
		Lifecycle string `json:"lifecycle"`
	}
	if err := decodeControlJSON(w, r, &input); err != nil || !validLabel(input.Name, 80) || !oneOf(input.Lifecycle, "development", "staging", "production") {
		writeProblem(w, r, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request", "The request body is invalid.", false)
		return
	}
	var environment struct {
		ID        string    `json:"id"`
		Name      string    `json:"name"`
		Lifecycle string    `json:"lifecycle"`
		CreatedAt time.Time `json:"created_at"`
		RequestID string    `json:"request_id"`
	}
	err := contextTransaction(r).QueryRowContext(r.Context(), `INSERT INTO environments(tenant_id, name, lifecycle)
		VALUES ($1, $2, $3) RETURNING id::text, name, lifecycle, created_at`, contextTenant(r), input.Name, input.Lifecycle).
		Scan(&environment.ID, &environment.Name, &environment.Lifecycle, &environment.CreatedAt)
	if err != nil {
		writeDatabaseProblem(w, r, err, "ENVIRONMENT_CONFLICT")
		return
	}
	if err := insertAudit(r.Context(), contextTransaction(r), contextPrincipal(r), requestID(r.Context()), "environment.created", "environment", environment.ID, "success", "CREATED"); err != nil {
		writeProblem(w, r, http.StatusServiceUnavailable, "AUDIT_UNAVAILABLE", "Service unavailable", "The request could not be processed safely.", true)
		return
	}
	environment.RequestID = requestID(r.Context())
	writeJSON(w, http.StatusCreated, environment)
}

type applicationView struct {
	ID              string    `json:"id"`
	EnvironmentID   string    `json:"environment_id"`
	ExternalID      string    `json:"external_id"`
	DisplayName     string    `json:"display_name"`
	IntegrationMode string    `json:"integration_mode"`
	Status          string    `json:"status"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
	ETag            string    `json:"etag"`
	RequestID       string    `json:"request_id"`
}

func (s *Server) listApplications(w http.ResponseWriter, r *http.Request) {
	if r.PathValue("tenant_id") != contextTenant(r) {
		s.notFound(w, r)
		return
	}
	limit := 50
	if raw := r.URL.Query().Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 100 {
			writeProblem(w, r, http.StatusBadRequest, "INVALID_LIMIT", "Invalid request", "The page size is invalid.", false)
			return
		}
		limit = parsed
	}
	var after any
	if cursor := r.URL.Query().Get("cursor"); cursor != "" {
		decoded, err := base64.RawURLEncoding.DecodeString(cursor)
		if err != nil || !validUUID(string(decoded)) {
			writeProblem(w, r, http.StatusBadRequest, "INVALID_CURSOR", "Invalid request", "The pagination cursor is invalid.", false)
			return
		}
		after = string(decoded)
	}
	rows, err := contextTransaction(r).QueryContext(r.Context(), `SELECT id::text, environment_id::text, external_id,
		display_name, integration_mode, status, created_at, updated_at FROM applications
		WHERE tenant_id = $1 AND ($2::uuid IS NULL OR id > $2::uuid)
		ORDER BY id LIMIT $3`, contextTenant(r), after, limit+1)
	if err != nil {
		writeProblem(w, r, http.StatusServiceUnavailable, "CONTROL_PLANE_UNAVAILABLE", "Service unavailable", "The request could not be processed safely.", true)
		return
	}
	defer rows.Close()
	items := make([]applicationView, 0, limit)
	for rows.Next() {
		var item applicationView
		if err := rows.Scan(&item.ID, &item.EnvironmentID, &item.ExternalID, &item.DisplayName, &item.IntegrationMode, &item.Status, &item.CreatedAt, &item.UpdatedAt); err != nil {
			writeProblem(w, r, http.StatusServiceUnavailable, "CONTROL_PLANE_UNAVAILABLE", "Service unavailable", "The request could not be processed safely.", true)
			return
		}
		item.ETag = tenantETag(item.UpdatedAt)
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		writeProblem(w, r, http.StatusServiceUnavailable, "CONTROL_PLANE_UNAVAILABLE", "Service unavailable", "The request could not be processed safely.", true)
		return
	}
	response := map[string]any{"items": items, "next_cursor": "", "request_id": requestID(r.Context())}
	if len(items) > limit {
		items = items[:limit]
		response["items"] = items
		response["next_cursor"] = base64.RawURLEncoding.EncodeToString([]byte(items[len(items)-1].ID))
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) createApplication(w http.ResponseWriter, r *http.Request) {
	if r.PathValue("tenant_id") != contextTenant(r) {
		s.notFound(w, r)
		return
	}
	if !s.requireRole(w, r, "tenant_admin", "security_engineer", "developer") {
		return
	}
	var input struct {
		EnvironmentID   string `json:"environment_id"`
		ExternalID      string `json:"external_id"`
		DisplayName     string `json:"display_name"`
		IntegrationMode string `json:"integration_mode"`
	}
	if err := decodeControlJSON(w, r, &input); err != nil || !validUUID(input.EnvironmentID) || !validExternalID(input.ExternalID) || !validLabel(input.DisplayName, 120) || !oneOf(input.IntegrationMode, "sdk", "gateway", "control-plane") {
		writeProblem(w, r, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request", "The request body is invalid.", false)
		return
	}
	var item applicationView
	err := contextTransaction(r).QueryRowContext(r.Context(), `INSERT INTO applications
		(tenant_id, environment_id, external_id, display_name, integration_mode, status)
		VALUES ($1, $2, $3, $4, $5, 'active')
		RETURNING id::text, environment_id::text, external_id, display_name, integration_mode, status, created_at, updated_at`,
		contextTenant(r), input.EnvironmentID, input.ExternalID, input.DisplayName, input.IntegrationMode).
		Scan(&item.ID, &item.EnvironmentID, &item.ExternalID, &item.DisplayName, &item.IntegrationMode, &item.Status, &item.CreatedAt, &item.UpdatedAt)
	if err != nil {
		writeDatabaseProblem(w, r, err, "APPLICATION_CONFLICT")
		return
	}
	if err := insertAudit(r.Context(), contextTransaction(r), contextPrincipal(r), requestID(r.Context()), "application.created", "application", item.ID, "success", "CREATED"); err != nil {
		writeProblem(w, r, http.StatusServiceUnavailable, "AUDIT_UNAVAILABLE", "Service unavailable", "The request could not be processed safely.", true)
		return
	}
	item.RequestID = requestID(r.Context())
	item.ETag = tenantETag(item.UpdatedAt)
	w.Header().Set("ETag", item.ETag)
	writeJSON(w, http.StatusCreated, item)
}

func (s *Server) getApplication(w http.ResponseWriter, r *http.Request) {
	applicationID := r.PathValue("application_id")
	if !validUUID(applicationID) {
		s.notFound(w, r)
		return
	}
	var item applicationView
	err := contextTransaction(r).QueryRowContext(r.Context(), `SELECT id::text, environment_id::text, external_id,
		display_name, integration_mode, status, created_at, updated_at FROM applications
		WHERE tenant_id = $1 AND id = $2`, contextTenant(r), applicationID).
		Scan(&item.ID, &item.EnvironmentID, &item.ExternalID, &item.DisplayName, &item.IntegrationMode, &item.Status, &item.CreatedAt, &item.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		s.notFound(w, r)
		return
	}
	if err != nil {
		writeProblem(w, r, http.StatusServiceUnavailable, "CONTROL_PLANE_UNAVAILABLE", "Service unavailable", "The request could not be processed safely.", true)
		return
	}
	item.RequestID = requestID(r.Context())
	item.ETag = tenantETag(item.UpdatedAt)
	w.Header().Set("ETag", item.ETag)
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) updateApplication(w http.ResponseWriter, r *http.Request) {
	if !s.requireRole(w, r, "tenant_admin", "security_engineer") {
		return
	}
	applicationID := r.PathValue("application_id")
	if !validUUID(applicationID) {
		s.notFound(w, r)
		return
	}
	if len(r.Header.Values("If-Match")) != 1 {
		writeProblem(w, r, http.StatusPreconditionRequired, "PRECONDITION_REQUIRED", "Update requires a version", "Fetch the application and send its ETag in If-Match.", false)
		return
	}
	expected, ok := parseTenantETag(r.Header.Get("If-Match"))
	if !ok {
		writeProblem(w, r, http.StatusPreconditionRequired, "PRECONDITION_REQUIRED", "Update requires a version", "Fetch the application and send its ETag in If-Match.", false)
		return
	}
	var input struct {
		DisplayName     *string `json:"display_name"`
		IntegrationMode *string `json:"integration_mode"`
	}
	if err := decodeControlJSON(w, r, &input); err != nil || input.DisplayName == nil && input.IntegrationMode == nil ||
		input.DisplayName != nil && !validLabel(*input.DisplayName, 120) ||
		input.IntegrationMode != nil && !oneOf(*input.IntegrationMode, "sdk", "gateway", "control-plane") {
		writeProblem(w, r, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request", "The application update is invalid.", false)
		return
	}
	var item applicationView
	err := contextTransaction(r).QueryRowContext(r.Context(), `UPDATE applications
		SET display_name = COALESCE($3, display_name), integration_mode = COALESCE($4, integration_mode),
			updated_at = GREATEST(clock_timestamp(), updated_at + interval '1 microsecond')
		WHERE tenant_id = $1 AND id = $2 AND updated_at = $5
		RETURNING id::text, environment_id::text, external_id, display_name, integration_mode, status, created_at, updated_at`,
		contextTenant(r), applicationID, input.DisplayName, input.IntegrationMode, expected).
		Scan(&item.ID, &item.EnvironmentID, &item.ExternalID, &item.DisplayName, &item.IntegrationMode, &item.Status, &item.CreatedAt, &item.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		var exists bool
		if checkErr := contextTransaction(r).QueryRowContext(r.Context(), `SELECT EXISTS(
			SELECT 1 FROM applications WHERE tenant_id = $1 AND id = $2)`, contextTenant(r), applicationID).Scan(&exists); checkErr != nil {
			controlPlaneUnavailable(w, r)
			return
		}
		if !exists {
			s.notFound(w, r)
			return
		}
		writeProblem(w, r, http.StatusPreconditionFailed, "ETAG_MISMATCH", "Application changed", "Fetch the application again before retrying the update.", false)
		return
	}
	if err != nil {
		controlPlaneUnavailable(w, r)
		return
	}
	if err := insertAudit(r.Context(), contextTransaction(r), contextPrincipal(r), requestID(r.Context()), "application.updated", "application", applicationID, "success", "METADATA_UPDATED"); err != nil {
		writeProblem(w, r, http.StatusServiceUnavailable, "AUDIT_UNAVAILABLE", "Service unavailable", "The request could not be processed safely.", true)
		return
	}
	item.RequestID = requestID(r.Context())
	item.ETag = tenantETag(item.UpdatedAt)
	w.Header().Set("ETag", item.ETag)
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) disableApplication(w http.ResponseWriter, r *http.Request) {
	if !s.requireRole(w, r, "tenant_admin", "security_engineer") {
		return
	}
	applicationID := r.PathValue("application_id")
	if !validUUID(applicationID) {
		s.notFound(w, r)
		return
	}
	if len(r.Header.Values("If-Match")) != 1 {
		writeProblem(w, r, http.StatusPreconditionRequired, "PRECONDITION_REQUIRED", "Update requires a version", "Fetch the application and send its ETag in If-Match.", false)
		return
	}
	expected, ok := parseTenantETag(r.Header.Get("If-Match"))
	if !ok {
		writeProblem(w, r, http.StatusPreconditionRequired, "PRECONDITION_REQUIRED", "Update requires a version", "Fetch the application and send its ETag in If-Match.", false)
		return
	}
	var item applicationView
	err := contextTransaction(r).QueryRowContext(r.Context(), `UPDATE applications
		SET status = 'disabled', updated_at = GREATEST(clock_timestamp(), updated_at + interval '1 microsecond')
		WHERE tenant_id = $1 AND id = $2 AND status = 'active' AND updated_at = $3
		RETURNING id::text, environment_id::text, external_id, display_name, integration_mode, status, created_at, updated_at`,
		contextTenant(r), applicationID, expected).
		Scan(&item.ID, &item.EnvironmentID, &item.ExternalID, &item.DisplayName, &item.IntegrationMode, &item.Status, &item.CreatedAt, &item.UpdatedAt)
	wasAlreadyDisabled := false
	if errors.Is(err, sql.ErrNoRows) {
		err = contextTransaction(r).QueryRowContext(r.Context(), `SELECT id::text, environment_id::text, external_id,
			display_name, integration_mode, status, created_at, updated_at FROM applications WHERE tenant_id = $1 AND id = $2`,
			contextTenant(r), applicationID).
			Scan(&item.ID, &item.EnvironmentID, &item.ExternalID, &item.DisplayName, &item.IntegrationMode, &item.Status, &item.CreatedAt, &item.UpdatedAt)
		if errors.Is(err, sql.ErrNoRows) {
			s.notFound(w, r)
			return
		}
		if err != nil {
			controlPlaneUnavailable(w, r)
			return
		}
		if !item.UpdatedAt.Equal(expected) {
			writeProblem(w, r, http.StatusPreconditionFailed, "ETAG_MISMATCH", "Application changed", "Fetch the application again before retrying the update.", false)
			return
		}
		if item.Status != "disabled" {
			controlPlaneUnavailable(w, r)
			return
		}
		wasAlreadyDisabled = true
	} else if err != nil {
		controlPlaneUnavailable(w, r)
		return
	}
	action, reason := "application.disabled", "DISABLED"
	if wasAlreadyDisabled {
		action, reason = "application.disable_noop", "ALREADY_DISABLED"
	}
	if err := insertAudit(r.Context(), contextTransaction(r), contextPrincipal(r), requestID(r.Context()), action, "application", applicationID, "success", reason); err != nil {
		writeProblem(w, r, http.StatusServiceUnavailable, "AUDIT_UNAVAILABLE", "Service unavailable", "The request could not be processed safely.", true)
		return
	}
	item.RequestID = requestID(r.Context())
	item.ETag = tenantETag(item.UpdatedAt)
	w.Header().Set("ETag", item.ETag)
	writeJSON(w, http.StatusOK, item)
}

func controlPlaneUnavailable(w http.ResponseWriter, r *http.Request) {
	writeProblem(w, r, http.StatusServiceUnavailable, "CONTROL_PLANE_UNAVAILABLE", "Service unavailable", "The request could not be processed safely.", true)
}

func decodeControlJSON(w http.ResponseWriter, r *http.Request, target any) error {
	contentTypes := r.Header.Values("Content-Type")
	if len(contentTypes) != 1 {
		return errors.New("content type is required")
	}
	mediaType, _, err := mime.ParseMediaType(contentTypes[0])
	if err != nil || mediaType != "application/json" {
		return errors.New("content type must be application/json")
	}
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("request body must contain one JSON value")
	}
	return nil
}

func validUUID(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return false
	}
	for i, r := range value {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			continue
		}
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return true
}

func validLabel(value string, max int) bool {
	if strings.TrimSpace(value) != value || len(value) == 0 || len(value) > max {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func validExternalID(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for _, r := range value {
		if !(unicode.IsLetter(r) || unicode.IsDigit(r) || strings.ContainsRune("._:-", r)) {
			return false
		}
	}
	return true
}

func oneOf(value string, choices ...string) bool {
	for _, choice := range choices {
		if value == choice {
			return true
		}
	}
	return false
}

func insertAudit(ctx context.Context, tx *sql.Tx, principal tenantPrincipal, correlationID, action, targetType, targetID, outcome, reason string) error {
	actor := auditActor(principal)
	source, _ := json.Marshal(map[string]string{"role": principal.Role})
	var eventID string
	if err := tx.QueryRowContext(ctx, `INSERT INTO audit_events
		(tenant_id, schema_version, actor, action, target_type, target_id, outcome, correlation_id, reason_code, source_context)
		VALUES ($1, 1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb) RETURNING id::text`, principal.TenantID, actor,
		action, targetType, targetID, outcome, correlationID, reason, source).Scan(&eventID); err != nil {
		return err
	}
	eventType, eventReason, shouldQueue := webhook.EventForAudit(action, targetType, targetID, outcome, reason)
	if !shouldQueue {
		return nil
	}
	var applicationID string
	var err error
	switch targetType {
	case "policy_revision":
		err = tx.QueryRowContext(ctx, `SELECT application_id::text FROM policy_revisions WHERE tenant_id = $1 AND id = $2`, principal.TenantID, targetID).Scan(&applicationID)
	case "key_reference":
		err = tx.QueryRowContext(ctx, `SELECT application_id::text FROM key_references WHERE tenant_id = $1 AND id = $2`, principal.TenantID, targetID).Scan(&applicationID)
	case "identity_adapter":
		err = tx.QueryRowContext(ctx, `SELECT application_id::text FROM identity_adapters WHERE tenant_id = $1 AND id = $2`, principal.TenantID, targetID).Scan(&applicationID)
	case "migration_observation":
		err = tx.QueryRowContext(ctx, `SELECT application_id::text FROM migration_observations WHERE tenant_id = $1 AND id = $2`, principal.TenantID, targetID).Scan(&applicationID)
	default:
		return errors.New("webhook event source is invalid")
	}
	if err != nil {
		return err
	}
	return webhook.QueueTx(ctx, tx, eventID, principal.TenantID, applicationID, eventType, targetType, targetID,
		eventReason, correlationID, actor, principal.Role)
}

func writeDatabaseProblem(w http.ResponseWriter, r *http.Request, err error, conflictCode string) {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "23505":
			writeProblem(w, r, http.StatusConflict, conflictCode, "Conflict", "A resource with the same identifier already exists.", false)
			return
		case "23503", "23514", "22001", "22P02":
			writeProblem(w, r, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request", "The request references an invalid resource or value.", false)
			return
		}
	}
	writeProblem(w, r, http.StatusServiceUnavailable, "CONTROL_PLANE_UNAVAILABLE", "Service unavailable", "The request could not be processed safely.", true)
}
