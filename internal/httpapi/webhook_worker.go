package httpapi

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"time"

	"quantumgate/internal/keyprovider"
	"quantumgate/internal/webhook"
)

type claimedWebhookDelivery struct {
	ID, TenantID, LeaseToken string
	Attempt, CycleAttempt    int
}

type webhookDeliveryRecord struct {
	ID, TenantID, ApplicationID, EventID, DestinationID string
	State, LeaseToken, Endpoint, SigningKeyID           string
	ProviderReference, EventType, CorrelationID         string
	ResourceType, ResourceID, ReasonCode                string
	Attempt, CycleAttempt                               int
	OccurredAt                                          time.Time
	Enabled                                             bool
}

// ProcessWebhookDeliveries claims a small batch durably, then sends each item
// outside the claim transaction. Expired leases are reclaimed by PostgreSQL.
func ProcessWebhookDeliveries(ctx context.Context, db *sql.DB, signer *keyprovider.Broker,
	sender webhook.Sender, environment string) (int, error) {
	if db == nil || signer == nil || sender == nil || !validProviderEnvironment(environment) {
		return 0, errors.New("webhook worker configuration is invalid")
	}
	claimTx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0, errors.New("webhook delivery claim could not start")
	}
	rows, err := claimTx.QueryContext(ctx, `SELECT delivery_id::text, tenant_id::text, lease_token::text, attempt, cycle_attempt
		FROM public.qg_claim_webhook_deliveries(5)`)
	if err != nil {
		_ = claimTx.Rollback()
		return 0, errors.New("webhook delivery queue is unavailable")
	}
	claimed := make([]claimedWebhookDelivery, 0, 5)
	for rows.Next() {
		var item claimedWebhookDelivery
		if err := rows.Scan(&item.ID, &item.TenantID, &item.LeaseToken, &item.Attempt, &item.CycleAttempt); err != nil {
			_ = rows.Close()
			_ = claimTx.Rollback()
			return 0, errors.New("webhook delivery claim is invalid")
		}
		claimed = append(claimed, item)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		_ = claimTx.Rollback()
		return 0, errors.New("webhook delivery claim could not be read")
	}
	if err := rows.Close(); err != nil {
		_ = claimTx.Rollback()
		return 0, errors.New("webhook delivery claim could not be closed")
	}
	if err := claimTx.Commit(); err != nil {
		return 0, errors.New("webhook delivery claim could not be committed")
	}
	processed := 0
	for _, item := range claimed {
		if err := processWebhookDelivery(ctx, db, signer, sender, environment, item); err != nil {
			return processed, err
		}
		processed++
	}
	return processed, nil
}

func processWebhookDelivery(ctx context.Context, db *sql.DB, signer *keyprovider.Broker,
	sender webhook.Sender, environment string, claim claimedWebhookDelivery) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return errors.New("webhook delivery transaction could not start")
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `SELECT set_config('qg.tenant_id', $1, true)`, claim.TenantID); err != nil {
		return errors.New("webhook delivery tenant scope could not be set")
	}
	var item webhookDeliveryRecord
	err = tx.QueryRowContext(ctx, `SELECT d.id::text, d.tenant_id::text, d.application_id::text,
		d.event_id::text, d.destination_id::text, d.state, d.lease_token::text,
		e.event_type, e.occurred_at, e.correlation_id, e.resource_type, e.resource_id::text, e.reason_code,
		d.attempts, d.cycle_attempts, dest.endpoint_url, dest.enabled,
		k.id::text, k.provider_reference
		FROM public.webhook_deliveries d
		JOIN public.webhook_events e ON e.tenant_id = d.tenant_id AND e.application_id = d.application_id AND e.id = d.event_id
		JOIN public.webhook_destinations dest ON dest.tenant_id = d.tenant_id AND dest.application_id = d.application_id AND dest.id = d.destination_id
		JOIN public.webhook_signing_keys k ON k.tenant_id = dest.tenant_id AND k.application_id = dest.application_id AND k.id = dest.signing_key_id
		WHERE d.tenant_id = $1 AND d.id = $2 AND d.state = 'delivering' AND d.lease_token = $3`,
		claim.TenantID, claim.ID, claim.LeaseToken).Scan(&item.ID, &item.TenantID, &item.ApplicationID,
		&item.EventID, &item.DestinationID, &item.State, &item.LeaseToken,
		&item.EventType, &item.OccurredAt, &item.CorrelationID, &item.ResourceType, &item.ResourceID, &item.ReasonCode,
		&item.Attempt, &item.CycleAttempt, &item.Endpoint, &item.Enabled, &item.SigningKeyID, &item.ProviderReference)
	if errors.Is(err, sql.ErrNoRows) {
		return nil // The lease expired and another worker owns this item.
	}
	if err != nil {
		return errors.New("webhook delivery state could not be loaded")
	}
	if err := tx.Commit(); err != nil {
		return errors.New("webhook delivery snapshot could not be closed")
	}
	if !item.Enabled {
		return completeWebhookDelivery(ctx, db, item, webhook.SendResult{ErrorCode: "DESTINATION_DISABLED"}, "cancelled", 0)
	}
	if item.CycleAttempt > webhook.MaxAttempts {
		return completeWebhookDelivery(ctx, db, item, webhook.SendResult{ErrorCode: "ATTEMPTS_EXHAUSTED"}, "dead", 0)
	}
	var eventType webhook.EventType
	eventType = webhook.EventType(item.EventType)
	job := webhook.DeliveryJob{
		Event: webhook.Event{ID: item.EventID, Type: eventType, TenantID: item.TenantID,
			ApplicationID: item.ApplicationID, OccurredAt: item.OccurredAt.UTC(), CorrelationID: item.CorrelationID,
			ResourceType: item.ResourceType, ResourceID: item.ResourceID, ReasonCode: item.ReasonCode},
		Destination: item.Endpoint, DestinationID: item.DestinationID, KeyID: item.SigningKeyID,
		KeyReference: item.ProviderReference,
		Scope:        keyprovider.Scope{TenantID: item.TenantID, ApplicationID: item.ApplicationID, Environment: environment},
		Attempt:      item.CycleAttempt, SentAt: time.Now().UTC(),
	}
	providerCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	providerCtx = keyprovider.WithAuditContext(providerCtx, keyprovider.AuditContext{
		Actor: "service:webhook-delivery-worker", CorrelationID: item.CorrelationID,
	})
	result, executeErr := webhook.Execute(providerCtx, job, signer, sender)
	cancel()
	if executeErr != nil {
		result = webhook.SendResult{ErrorCode: "DELIVERY_CONFIGURATION_INVALID"}
	}
	state := webhook.DeliveryDisposition(result, item.CycleAttempt)
	var delay time.Duration
	if state == "retry" {
		delay = webhook.RetryDelay(item.CycleAttempt)
	}
	return completeWebhookDelivery(ctx, db, item, result, state, delay)
}

func completeWebhookDelivery(ctx context.Context, db *sql.DB, item webhookDeliveryRecord,
	result webhook.SendResult, state string, delay time.Duration) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return errors.New("webhook delivery completion transaction could not start")
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `SELECT set_config('qg.tenant_id', $1, true)`, item.TenantID); err != nil {
		return errors.New("webhook delivery completion tenant scope could not be set")
	}
	var status any
	if result.StatusCode != 0 {
		status = result.StatusCode
	}
	var errorCode any
	if result.ErrorCode != "" {
		errorCode = result.ErrorCode
	}
	var deliveredAt any
	if state == "delivered" {
		deliveredAt = time.Now().UTC()
	}
	updated, err := tx.ExecContext(ctx, `UPDATE webhook_deliveries SET state = $4,
		next_attempt_at = CASE WHEN $4 = 'retry' THEN clock_timestamp() + ($5 * interval '1 second') ELSE clock_timestamp() END,
		lease_token = NULL, lease_until = NULL, last_status_code = $6, last_error_code = $7,
		delivered_at = $8, updated_at = GREATEST(clock_timestamp(), updated_at + interval '1 microsecond')
		WHERE tenant_id = $1 AND id = $2 AND state = 'delivering' AND lease_token = $3`,
		item.TenantID, item.ID, item.LeaseToken, state, int64(delay/time.Second), status, errorCode, deliveredAt)
	if err != nil {
		return errors.New("webhook delivery state could not be saved")
	}
	count, err := updated.RowsAffected()
	if err != nil || count != 1 {
		return errors.New("webhook delivery lease was lost")
	}
	action, outcome, reason := webhookAuditOutcome(state, result.ErrorCode)
	principal := tenantPrincipal{Issuer: "urn:quantumgate:service", Subject: "webhook-delivery-worker", Role: "system", TenantID: item.TenantID}
	if err := insertAudit(ctx, tx, principal, item.CorrelationID, action, "webhook_delivery", item.ID, outcome, reason); err != nil {
		return errors.New("webhook delivery audit could not be saved")
	}
	if err := tx.Commit(); err != nil {
		return errors.New("webhook delivery transaction could not commit")
	}
	return nil
}

func webhookAuditOutcome(state, errorCode string) (action, outcome, reason string) {
	switch state {
	case "delivered":
		return "webhook.delivery_succeeded", "success", "DELIVERED"
	case "retry":
		return "webhook.delivery_retry_scheduled", "failure", safeWebhookReason(errorCode)
	case "cancelled":
		return "webhook.delivery_cancelled", "success", safeWebhookReason(errorCode)
	default:
		return "webhook.delivery_dead_lettered", "failure", safeWebhookReason(errorCode)
	}
}

func safeWebhookReason(value string) string {
	if len(value) == 0 || len(value) > 64 {
		return "DELIVERY_FAILED"
	}
	for _, char := range value {
		if !(char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || char == '_') {
			return "DELIVERY_FAILED"
		}
	}
	return value
}

// RunWebhookDeliveryWorker stops promptly at shutdown; an unfinished lease is
// recovered by the next process after PostgreSQL's bounded lease expires.
func RunWebhookDeliveryWorker(ctx context.Context, db *sql.DB, signer *keyprovider.Broker,
	sender webhook.Sender, environment string, logger *slog.Logger) {
	if db == nil || signer == nil || sender == nil {
		return
	}
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		workerCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
		count, err := ProcessWebhookDeliveries(workerCtx, db, signer, sender, environment)
		cancel()
		if err != nil && ctx.Err() == nil && logger != nil {
			logger.Warn("webhook delivery processing failed", "code", "WEBHOOK_DELIVERY_UNAVAILABLE")
		}
		if count > 0 && logger != nil {
			logger.Info("webhook deliveries processed", "count", count)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
