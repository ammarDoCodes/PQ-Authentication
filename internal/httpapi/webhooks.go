package httpapi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"quantumgate/internal/keyprovider"
	"quantumgate/internal/webhook"
)

type webhookDestinationView struct {
	ID            string    `json:"id"`
	ApplicationID string    `json:"application_id"`
	URL           string    `json:"url"`
	EventTypes    []string  `json:"event_types"`
	SigningKeyID  string    `json:"signing_key_id"`
	Enabled       bool      `json:"enabled"`
	Revision      int64     `json:"revision"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
	ETag          string    `json:"etag"`
	RequestID     string    `json:"request_id"`
}

const webhookDestinationColumns = `id::text, application_id::text, endpoint_url, event_types,
	signing_key_id::text, enabled, revision, created_at, updated_at`

type webhookDestinationScanner interface{ Scan(...any) error }

func (s *Server) createWebhookDestination(w http.ResponseWriter, r *http.Request) {
	if !s.requireRole(w, r, "tenant_admin", "security_engineer") {
		return
	}
	applicationID := r.PathValue("application_id")
	if !validUUID(applicationID) {
		s.notFound(w, r)
		return
	}
	if !s.enforceRateLimit(w, r, "webhook:create", applicationID, 10) {
		return
	}
	if s.WebhookSigner == nil || s.WebhookSender == nil || !validProviderEnvironment(s.WebhookEnvironment) {
		writeProblem(w, r, http.StatusServiceUnavailable, "WEBHOOK_DELIVERY_UNAVAILABLE", "Service unavailable", "Signed webhook delivery is not configured.", true)
		return
	}
	var input struct {
		URL        string              `json:"url"`
		EventTypes []webhook.EventType `json:"event_types"`
	}
	if err := decodeControlJSON(w, r, &input); err != nil || !validWebhookEventTypes(input.EventTypes) ||
		s.WebhookSender.ValidateDestination(input.URL) != nil {
		writeProblem(w, r, http.StatusBadRequest, "INVALID_WEBHOOK_DESTINATION", "Invalid request", "The HTTPS destination or event subscriptions are invalid.", false)
		return
	}
	tx := contextTransaction(r)
	var lockedApplication string
	err := tx.QueryRowContext(r.Context(), `SELECT id::text FROM applications
		WHERE tenant_id = $1 AND id = $2 AND status = 'active'`, contextTenant(r), applicationID).Scan(&lockedApplication)
	if errors.Is(err, sql.ErrNoRows) {
		s.notFound(w, r)
		return
	}
	if err != nil {
		controlPlaneUnavailable(w, r)
		return
	}
	var count int
	if err := tx.QueryRowContext(r.Context(), `SELECT count(*) FROM webhook_destinations
		WHERE tenant_id = $1 AND application_id = $2`, contextTenant(r), applicationID).Scan(&count); err != nil {
		controlPlaneUnavailable(w, r)
		return
	}
	if count >= 20 {
		writeProblem(w, r, http.StatusConflict, "WEBHOOK_DESTINATION_LIMIT", "Conflict", "The application has reached its webhook destination limit.", false)
		return
	}
	key, publicMaterial, err := s.generateWebhookSigningKey(r.Context(), contextPrincipal(r), applicationID)
	if err != nil {
		writeProblem(w, r, http.StatusServiceUnavailable, "WEBHOOK_SIGNING_UNAVAILABLE", "Service unavailable", "A signing key could not be created safely.", true)
		return
	}
	keyID, err := registerWebhookSigningKey(r.Context(), tx, contextTenant(r), applicationID, key, publicMaterial)
	if err != nil {
		controlPlaneUnavailable(w, r)
		return
	}
	var eventTypes []string
	for _, eventType := range input.EventTypes {
		eventTypes = append(eventTypes, string(eventType))
	}
	item, err := scanWebhookDestination(tx.QueryRowContext(r.Context(), `INSERT INTO webhook_destinations
		(tenant_id, application_id, endpoint_url, event_types, signing_key_id)
		VALUES ($1, $2, $3, $4, $5) RETURNING `+webhookDestinationColumns,
		contextTenant(r), applicationID, input.URL, eventTypes, keyID))
	if err != nil {
		writeDatabaseProblem(w, r, err, "WEBHOOK_DESTINATION_CONFLICT")
		return
	}
	if err := insertAudit(r.Context(), tx, contextPrincipal(r), requestID(r.Context()),
		"webhook.destination_created", "webhook_destination", item.ID, "success", "DESTINATION_CREATED"); err != nil {
		controlPlaneUnavailable(w, r)
		return
	}
	item.RequestID = requestID(r.Context())
	w.Header().Set("ETag", item.ETag)
	w.Header().Set("Location", "/v1/webhooks/"+item.ID)
	writeJSON(w, http.StatusCreated, item)
}

func (s *Server) listWebhookDestinations(w http.ResponseWriter, r *http.Request) {
	applicationID := r.PathValue("application_id")
	if !validUUID(applicationID) {
		s.notFound(w, r)
		return
	}
	if !s.requireRole(w, r, "tenant_admin", "security_engineer", "auditor") {
		return
	}
	var exists bool
	if err := contextTransaction(r).QueryRowContext(r.Context(), `SELECT EXISTS(
		SELECT 1 FROM applications WHERE tenant_id = $1 AND id = $2)`, contextTenant(r), applicationID).Scan(&exists); err != nil {
		controlPlaneUnavailable(w, r)
		return
	}
	if !exists {
		s.notFound(w, r)
		return
	}
	rows, err := contextTransaction(r).QueryContext(r.Context(), `SELECT `+webhookDestinationColumns+
		` FROM webhook_destinations WHERE tenant_id = $1 AND application_id = $2 ORDER BY created_at DESC, id LIMIT 20`, contextTenant(r), applicationID)
	if err != nil {
		controlPlaneUnavailable(w, r)
		return
	}
	defer rows.Close()
	items := make([]webhookDestinationView, 0, 20)
	for rows.Next() {
		item, err := scanWebhookDestination(rows)
		if err != nil {
			controlPlaneUnavailable(w, r)
			return
		}
		item.RequestID = requestID(r.Context())
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		controlPlaneUnavailable(w, r)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "request_id": requestID(r.Context())})
}

func (s *Server) updateWebhookDestination(w http.ResponseWriter, r *http.Request) {
	if !s.requireRole(w, r, "tenant_admin", "security_engineer") {
		return
	}
	destinationID := r.PathValue("webhook_id")
	if !validUUID(destinationID) {
		s.notFound(w, r)
		return
	}
	if !s.enforceRateLimit(w, r, "webhook:update", destinationID, 30) {
		return
	}
	if len(r.Header.Values("If-Match")) != 1 {
		writeProblem(w, r, http.StatusPreconditionRequired, "PRECONDITION_REQUIRED", "Update requires a version", "Fetch the webhook destination and send its ETag in If-Match.", false)
		return
	}
	var input struct {
		URL        *string              `json:"url"`
		EventTypes *[]webhook.EventType `json:"event_types"`
		Enabled    *bool                `json:"enabled"`
	}
	if err := decodeControlJSON(w, r, &input); err != nil || input.URL == nil && input.EventTypes == nil && input.Enabled == nil {
		writeProblem(w, r, http.StatusBadRequest, "INVALID_WEBHOOK_DESTINATION", "Invalid request", "At least one supported destination setting is required.", false)
		return
	}
	tx := contextTransaction(r)
	item, err := scanWebhookDestination(tx.QueryRowContext(r.Context(), `SELECT `+webhookDestinationColumns+
		` FROM webhook_destinations WHERE tenant_id = $1 AND id = $2 FOR UPDATE`, contextTenant(r), destinationID))
	if errors.Is(err, sql.ErrNoRows) {
		s.notFound(w, r)
		return
	}
	if err != nil {
		controlPlaneUnavailable(w, r)
		return
	}
	if r.Header.Get("If-Match") != item.ETag {
		writeProblem(w, r, http.StatusPreconditionFailed, "ETAG_MISMATCH", "Destination changed", "Fetch the current destination version and retry the update.", false)
		return
	}
	endpoint := item.URL
	if input.URL != nil {
		if s.WebhookSender == nil || s.WebhookSender.ValidateDestination(*input.URL) != nil {
			writeProblem(w, r, http.StatusBadRequest, "INVALID_WEBHOOK_DESTINATION", "Invalid request", "The HTTPS destination is invalid.", false)
			return
		}
		endpoint = *input.URL
	}
	eventTypes := item.EventTypes
	if input.EventTypes != nil {
		if !validWebhookEventTypes(*input.EventTypes) {
			writeProblem(w, r, http.StatusBadRequest, "INVALID_WEBHOOK_DESTINATION", "Invalid request", "The event subscriptions are invalid.", false)
			return
		}
		eventTypes = eventTypeStrings(*input.EventTypes)
	}
	enabled := item.Enabled
	if input.Enabled != nil {
		enabled = *input.Enabled
	}
	if endpoint == item.URL && sameStrings(eventTypes, item.EventTypes) && enabled == item.Enabled {
		item.RequestID = requestID(r.Context())
		w.Header().Set("ETag", item.ETag)
		writeJSON(w, http.StatusOK, item)
		return
	}
	updated, err := scanWebhookDestination(tx.QueryRowContext(r.Context(), `UPDATE webhook_destinations
		SET endpoint_url = $3, event_types = $4, enabled = $5, revision = revision + 1,
			updated_at = GREATEST(clock_timestamp(), updated_at + interval '1 microsecond')
		WHERE tenant_id = $1 AND id = $2 RETURNING `+webhookDestinationColumns,
		contextTenant(r), destinationID, endpoint, eventTypes, enabled))
	if err != nil {
		controlPlaneUnavailable(w, r)
		return
	}
	action, reason := "webhook.destination_updated", "DESTINATION_UPDATED"
	if item.Enabled && !enabled {
		action, reason = "webhook.destination_disabled", "DESTINATION_DISABLED"
		if _, err := tx.ExecContext(r.Context(), `UPDATE webhook_deliveries SET state = 'cancelled', last_error_code = 'DESTINATION_DISABLED',
			updated_at = GREATEST(clock_timestamp(), updated_at + interval '1 microsecond')
			WHERE tenant_id = $1 AND destination_id = $2 AND state IN ('pending','retry')`, contextTenant(r), destinationID); err != nil {
			controlPlaneUnavailable(w, r)
			return
		}
	} else if !item.Enabled && enabled {
		action, reason = "webhook.destination_enabled", "DESTINATION_ENABLED"
	}
	if err := insertAudit(r.Context(), tx, contextPrincipal(r), requestID(r.Context()), action,
		"webhook_destination", destinationID, "success", reason); err != nil {
		controlPlaneUnavailable(w, r)
		return
	}
	updated.RequestID = requestID(r.Context())
	w.Header().Set("ETag", updated.ETag)
	writeJSON(w, http.StatusOK, updated)
}

func (s *Server) listWebhookDeliveries(w http.ResponseWriter, r *http.Request) {
	if !s.requireRole(w, r, "tenant_admin", "security_engineer", "auditor") {
		return
	}
	destinationID := r.PathValue("webhook_id")
	if !validUUID(destinationID) {
		s.notFound(w, r)
		return
	}
	limit := 50
	if raw := r.URL.Query().Get("limit"); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 1 || value > 100 {
			writeProblem(w, r, http.StatusBadRequest, "INVALID_LIMIT", "Invalid request", "The page size is invalid.", false)
			return
		}
		limit = value
	}
	var exists bool
	if err := contextTransaction(r).QueryRowContext(r.Context(), `SELECT EXISTS(
		SELECT 1 FROM webhook_destinations WHERE tenant_id = $1 AND id = $2)`, contextTenant(r), destinationID).Scan(&exists); err != nil {
		controlPlaneUnavailable(w, r)
		return
	}
	if !exists {
		s.notFound(w, r)
		return
	}
	rows, err := contextTransaction(r).QueryContext(r.Context(), `SELECT d.id::text, d.event_id::text, e.event_type, d.state,
		d.attempts, d.cycle_attempts, d.manual_retries, d.last_status_code, d.last_error_code,
		d.next_attempt_at, d.created_at, d.updated_at, d.delivered_at
		FROM webhook_deliveries d JOIN webhook_events e ON e.tenant_id = d.tenant_id AND e.id = d.event_id
		WHERE d.tenant_id = $1 AND d.destination_id = $2 ORDER BY d.created_at DESC, d.id LIMIT $3`,
		contextTenant(r), destinationID, limit)
	if err != nil {
		controlPlaneUnavailable(w, r)
		return
	}
	defer rows.Close()
	items := make([]map[string]any, 0, limit)
	for rows.Next() {
		var item struct {
			ID, EventID, EventType, State          string
			Attempts, CycleAttempts, ManualRetries int
			Status                                 sql.NullInt64
			Error                                  sql.NullString
			NextAttemptAt, CreatedAt, UpdatedAt    time.Time
			DeliveredAt                            sql.NullTime
		}
		if err := rows.Scan(&item.ID, &item.EventID, &item.EventType, &item.State, &item.Attempts,
			&item.CycleAttempts, &item.ManualRetries, &item.Status, &item.Error,
			&item.NextAttemptAt, &item.CreatedAt, &item.UpdatedAt, &item.DeliveredAt); err != nil {
			controlPlaneUnavailable(w, r)
			return
		}
		row := map[string]any{"id": item.ID, "event_id": item.EventID, "event_type": item.EventType,
			"state": item.State, "attempts": item.Attempts, "cycle_attempts": item.CycleAttempts,
			"manual_retries": item.ManualRetries, "next_attempt_at": item.NextAttemptAt.UTC(),
			"created_at": item.CreatedAt.UTC(), "updated_at": item.UpdatedAt.UTC()}
		if item.Status.Valid {
			row["last_status_code"] = item.Status.Int64
		}
		if item.Error.Valid {
			row["last_error_code"] = item.Error.String
		}
		if item.DeliveredAt.Valid {
			row["delivered_at"] = item.DeliveredAt.Time.UTC()
		}
		items = append(items, row)
	}
	if err := rows.Err(); err != nil {
		controlPlaneUnavailable(w, r)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "request_id": requestID(r.Context())})
}

func (s *Server) retryWebhookDelivery(w http.ResponseWriter, r *http.Request) {
	if !s.requireRole(w, r, "tenant_admin", "security_engineer") {
		return
	}
	deliveryID := r.PathValue("delivery_id")
	if !validUUID(deliveryID) {
		s.notFound(w, r)
		return
	}
	if !s.enforceRateLimit(w, r, "webhook:retry", deliveryID, 10) {
		return
	}
	tx := contextTransaction(r)
	var state string
	var enabled bool
	var manualRetries int
	err := tx.QueryRowContext(r.Context(), `SELECT d.state, dest.enabled, d.manual_retries
		FROM webhook_deliveries d JOIN webhook_destinations dest
		  ON dest.tenant_id = d.tenant_id AND dest.application_id = d.application_id AND dest.id = d.destination_id
		WHERE d.tenant_id = $1 AND d.id = $2 FOR UPDATE OF d, dest`, contextTenant(r), deliveryID).
		Scan(&state, &enabled, &manualRetries)
	if errors.Is(err, sql.ErrNoRows) {
		s.notFound(w, r)
		return
	}
	if err != nil {
		controlPlaneUnavailable(w, r)
		return
	}
	if state != "dead" || !enabled || manualRetries >= 5 {
		writeProblem(w, r, http.StatusConflict, "WEBHOOK_RETRY_UNAVAILABLE", "Conflict", "Only enabled, dead-lettered deliveries within the retry limit can be replayed.", false)
		return
	}
	if _, err := tx.ExecContext(r.Context(), `UPDATE webhook_deliveries SET state = 'pending',
		cycle_attempts = 0, manual_retries = manual_retries + 1, next_attempt_at = clock_timestamp(),
		last_status_code = NULL, last_error_code = NULL, updated_at = GREATEST(clock_timestamp(), updated_at + interval '1 microsecond')
		WHERE tenant_id = $1 AND id = $2 AND state = 'dead'`, contextTenant(r), deliveryID); err != nil {
		controlPlaneUnavailable(w, r)
		return
	}
	if err := insertAudit(r.Context(), tx, contextPrincipal(r), requestID(r.Context()),
		"webhook.delivery_manual_retry", "webhook_delivery", deliveryID, "success", "MANUAL_RETRY_QUEUED"); err != nil {
		controlPlaneUnavailable(w, r)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"delivery_id": deliveryID, "state": "pending", "request_id": requestID(r.Context())})
}

func (s *Server) rotateWebhookKey(w http.ResponseWriter, r *http.Request) {
	if !s.requireRole(w, r, "tenant_admin", "security_engineer") {
		return
	}
	destinationID := r.PathValue("webhook_id")
	if !validUUID(destinationID) {
		s.notFound(w, r)
		return
	}
	if !s.enforceRateLimit(w, r, "webhook:rotate-key", destinationID, 5) {
		return
	}
	if s.WebhookSigner == nil || !validProviderEnvironment(s.WebhookEnvironment) {
		writeProblem(w, r, http.StatusServiceUnavailable, "WEBHOOK_SIGNING_UNAVAILABLE", "Service unavailable", "Webhook signing is not configured.", true)
		return
	}
	if len(r.Header.Values("If-Match")) != 1 {
		writeProblem(w, r, http.StatusPreconditionRequired, "PRECONDITION_REQUIRED", "Update requires a version", "Fetch the webhook destination and send its ETag in If-Match.", false)
		return
	}
	tx := contextTransaction(r)
	item, err := scanWebhookDestination(tx.QueryRowContext(r.Context(), `SELECT `+webhookDestinationColumns+
		` FROM webhook_destinations WHERE tenant_id = $1 AND id = $2 FOR UPDATE`, contextTenant(r), destinationID))
	if errors.Is(err, sql.ErrNoRows) {
		s.notFound(w, r)
		return
	}
	if err != nil {
		controlPlaneUnavailable(w, r)
		return
	}
	if r.Header.Get("If-Match") != item.ETag {
		writeProblem(w, r, http.StatusPreconditionFailed, "ETAG_MISMATCH", "Destination changed", "Fetch the current destination version and retry the rotation.", false)
		return
	}
	var tenantID, appID, provider, providerRef, oldState string
	var oldKeyID string
	if err := tx.QueryRowContext(r.Context(), `SELECT tenant_id::text, application_id::text, provider, provider_reference, state
		FROM webhook_signing_keys WHERE tenant_id = $1 AND application_id = $2 AND id = $3`,
		contextTenant(r), item.ApplicationID, item.SigningKeyID).Scan(&tenantID, &appID, &provider, &providerRef, &oldState); err != nil {
		controlPlaneUnavailable(w, r)
		return
	}
	oldKeyID = item.SigningKeyID
	newKey, publicMaterial, err := s.generateWebhookSigningKey(r.Context(), contextPrincipal(r), appID)
	if err != nil {
		writeProblem(w, r, http.StatusServiceUnavailable, "WEBHOOK_SIGNING_UNAVAILABLE", "Service unavailable", "A signing key could not be rotated safely.", true)
		return
	}
	scope := keyprovider.Scope{TenantID: tenantID, ApplicationID: appID, Environment: s.WebhookEnvironment}
	providerCtx := keyprovider.WithAuditContext(r.Context(), keyprovider.AuditContext{Actor: auditActor(contextPrincipal(r)), CorrelationID: requestID(r.Context())})
	retiredState := keyprovider.State(oldState)
	if retiredState == keyprovider.StateActive {
		if _, err := s.WebhookSigner.Transition(providerCtx, scope, providerRef, keyprovider.StateRotationDue); err != nil {
			writeProblem(w, r, http.StatusServiceUnavailable, "WEBHOOK_SIGNING_UNAVAILABLE", "Service unavailable", "The previous signing key could not be retired safely.", true)
			return
		}
		retiredState = keyprovider.StateRotationDue
	}
	newKeyID, err := registerWebhookSigningKey(r.Context(), tx, tenantID, appID, newKey, publicMaterial)
	if err != nil {
		controlPlaneUnavailable(w, r)
		return
	}
	if _, err := tx.ExecContext(r.Context(), `UPDATE webhook_signing_keys SET state = $4,
		retired_at = COALESCE(retired_at, clock_timestamp()), updated_at = GREATEST(clock_timestamp(), updated_at + interval '1 microsecond')
		WHERE tenant_id = $1 AND application_id = $2 AND id = $3`, tenantID, appID, oldKeyID, retiredState); err != nil {
		controlPlaneUnavailable(w, r)
		return
	}
	updated, err := scanWebhookDestination(tx.QueryRowContext(r.Context(), `UPDATE webhook_destinations
		SET signing_key_id = $3, revision = revision + 1, updated_at = GREATEST(clock_timestamp(), updated_at + interval '1 microsecond')
		WHERE tenant_id = $1 AND id = $2 RETURNING `+webhookDestinationColumns,
		tenantID, destinationID, newKeyID))
	if err != nil {
		controlPlaneUnavailable(w, r)
		return
	}
	if err := insertAudit(r.Context(), tx, contextPrincipal(r), requestID(r.Context()),
		"webhook.signing_key_rotated", "webhook_destination", destinationID, "success", "SIGNING_KEY_ROTATED"); err != nil {
		controlPlaneUnavailable(w, r)
		return
	}
	updated.RequestID = requestID(r.Context())
	w.Header().Set("ETag", updated.ETag)
	writeJSON(w, http.StatusOK, updated)
}

func (s *Server) getWebhookPublicKey(w http.ResponseWriter, r *http.Request) {
	keyID := r.PathValue("key_id")
	if !validUUID(keyID) {
		s.notFound(w, r)
		return
	}
	if s.Store == nil || !s.enforceRateLimit(w, r, "webhook-key:ip", clientIPDimension(r.RemoteAddr), 120) {
		if s.Store == nil {
			controlPlaneUnavailable(w, r)
		}
		return
	}
	var algorithm string
	var publicMaterial []byte
	var createdAt, expiresAt time.Time
	var retiredAt sql.NullTime
	err := s.Store.QueryRowContext(r.Context(), `SELECT algorithm, public_material, created_at, expires_at, retired_at
		FROM public.qg_get_webhook_public_key($1)`, keyID).Scan(&algorithm, &publicMaterial, &createdAt, &expiresAt, &retiredAt)
	if errors.Is(err, sql.ErrNoRows) {
		s.notFound(w, r)
		return
	}
	if err != nil {
		controlPlaneUnavailable(w, r)
		return
	}
	w.Header().Set("Cache-Control", "public, max-age=300")
	response := map[string]any{"key_id": keyID, "algorithm": algorithm, "public_key": base64.StdEncoding.EncodeToString(publicMaterial),
		"created_at": createdAt.UTC(), "expires_at": expiresAt.UTC()}
	if retiredAt.Valid {
		response["retired_at"] = retiredAt.Time.UTC()
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) generateWebhookSigningKey(ctx context.Context, principal tenantPrincipal, applicationID string) (keyprovider.Metadata, []byte, error) {
	if s.WebhookSigner == nil || !validUUID(principal.TenantID) || !validUUID(applicationID) || !validProviderEnvironment(s.WebhookEnvironment) {
		return keyprovider.Metadata{}, nil, errors.New("webhook signing is not configured")
	}
	scope := keyprovider.Scope{TenantID: principal.TenantID, ApplicationID: applicationID, Environment: s.WebhookEnvironment}
	ctx = keyprovider.WithAuditContext(ctx, keyprovider.AuditContext{Actor: auditActor(principal), CorrelationID: requestID(ctx)})
	metadata, err := s.WebhookSigner.Generate(ctx, scope, keyprovider.KeySpec{
		Purpose: keyprovider.PurposeSigning, Algorithm: keyprovider.AlgorithmEd25519, ExpiresAt: time.Now().UTC().AddDate(4, 0, 0),
	})
	if err != nil {
		return keyprovider.Metadata{}, nil, err
	}
	metadata, err = s.WebhookSigner.Transition(ctx, scope, metadata.Reference, keyprovider.StateActive)
	if err != nil {
		return keyprovider.Metadata{}, nil, err
	}
	publicMaterial, err := s.WebhookSigner.PublicKey(ctx, scope, metadata.Reference)
	if err != nil {
		return keyprovider.Metadata{}, nil, err
	}
	parsed, err := x509.ParsePKIXPublicKey(publicMaterial)
	public, ok := parsed.(ed25519.PublicKey)
	if err != nil || !ok || len(public) != ed25519.PublicKeySize || metadata.Algorithm != keyprovider.AlgorithmEd25519 || metadata.State != keyprovider.StateActive {
		return keyprovider.Metadata{}, nil, errors.New("webhook provider returned invalid signing material")
	}
	return metadata, publicMaterial, nil
}

func registerWebhookSigningKey(ctx context.Context, tx *sql.Tx, tenantID, applicationID string,
	metadata keyprovider.Metadata, publicMaterial []byte) (string, error) {
	if tx == nil || !validUUID(tenantID) || !validUUID(applicationID) || metadata.Provider == "" ||
		metadata.Purpose != keyprovider.PurposeSigning || metadata.Algorithm != keyprovider.AlgorithmEd25519 ||
		metadata.State != keyprovider.StateActive || metadata.Version == 0 || len(metadata.Reference) < 16 ||
		len(publicMaterial) == 0 || len(publicMaterial) > 128 {
		return "", errors.New("webhook signing key metadata is invalid")
	}
	var keyID, provider, state string
	var version int64
	var existing []byte
	err := tx.QueryRowContext(ctx, `SELECT id::text, provider, state, version, public_material
		FROM webhook_signing_keys WHERE tenant_id = $1 AND application_id = $2 AND provider_reference = $3 FOR UPDATE`,
		tenantID, applicationID, metadata.Reference).Scan(&keyID, &provider, &state, &version, &existing)
	if errors.Is(err, sql.ErrNoRows) {
		err = tx.QueryRowContext(ctx, `INSERT INTO webhook_signing_keys
			(tenant_id, application_id, provider, provider_reference, algorithm, public_material, version, state, created_at, updated_at, expires_at)
			VALUES ($1, $2, $3, $4, 'Ed25519', $5, $6, 'active', $7, $8, $9) RETURNING id::text`,
			tenantID, applicationID, metadata.Provider, metadata.Reference, publicMaterial, metadata.Version,
			metadata.CreatedAt.UTC(), metadata.UpdatedAt.UTC(), metadata.ExpiresAt.UTC()).Scan(&keyID)
		return keyID, err
	}
	if err != nil || provider != metadata.Provider || version != int64(metadata.Version) || state != string(keyprovider.StateActive) {
		return "", errors.New("webhook signing key metadata does not match the provider")
	}
	if existing != nil {
		if !bytes.Equal(existing, publicMaterial) {
			return "", errors.New("webhook public key does not match immutable metadata")
		}
		return keyID, nil
	}
	if _, err := tx.ExecContext(ctx, `UPDATE webhook_signing_keys SET public_material = $4,
		updated_at = GREATEST(clock_timestamp(), updated_at + interval '1 microsecond')
		WHERE tenant_id = $1 AND application_id = $2 AND id = $3 AND public_material IS NULL AND state = 'active'`,
		tenantID, applicationID, keyID, publicMaterial); err != nil {
		return "", err
	}
	return keyID, nil
}

func scanWebhookDestination(row webhookDestinationScanner) (webhookDestinationView, error) {
	var item webhookDestinationView
	if err := row.Scan(&item.ID, &item.ApplicationID, &item.URL, &item.EventTypes, &item.SigningKeyID,
		&item.Enabled, &item.Revision, &item.CreatedAt, &item.UpdatedAt); err != nil {
		return item, err
	}
	item.CreatedAt, item.UpdatedAt = item.CreatedAt.UTC(), item.UpdatedAt.UTC()
	item.ETag = webhookDestinationETag(item.ID, item.Revision)
	return item, nil
}

func webhookDestinationETag(id string, revision int64) string {
	return fmt.Sprintf("\"wh-%s-r%d\"", id, revision)
}

func validProviderEnvironment(value string) bool {
	return value == "development" || value == "test" || value == "production"
}

func validWebhookEventTypes(values []webhook.EventType) bool { return webhook.ValidEventTypes(values) }

func eventTypeStrings(values []webhook.EventType) []string {
	result := make([]string, len(values))
	for i := range values {
		result[i] = string(values[i])
	}
	return result
}

func sameStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
