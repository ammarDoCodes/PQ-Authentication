package webhook

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
)

// EventForAudit maps only successful, explicitly approved control-plane audit
// actions into outbound events. Raw audit source/context is never copied.
func EventForAudit(action, targetType, targetID, outcome, reason string) (EventType, string, bool) {
	if !validUUID(targetID) {
		return "", "", false
	}
	if action == "identity_adapter.verification_failed" && targetType == "identity_adapter" && outcome == "failure" {
		return AdapterFailure, "ADAPTER_VERIFICATION_FAILED", true
	}
	if outcome != "success" {
		return "", "", false
	}
	switch {
	case oneOf(action, "policy.activated", "policy.scheduled_activated") && targetType == "policy_revision":
		return PolicyActivated, "POLICY_ACTIVATED", true
	case action == "policy.rolled_back" && targetType == "policy_revision":
		if !oneOf(reason, "ROLLBACK_COMPATIBILITY", "ROLLBACK_SECURITY", "ROLLBACK_INCIDENT", "ROLLBACK_OTHER") {
			return PolicyRollback, "POLICY_ROLLED_BACK", true
		}
		return PolicyRollback, reason, true
	case action == "key_reference.rotation_due" && targetType == "key_reference":
		return KeyRotationDue, "KEY_ROTATION_DUE", true
	case action == "key_reference.revoked" && targetType == "key_reference":
		return KeyRevoked, "KEY_REVOKED", true
	case action == "posture.blocker_found" && targetType == "migration_observation":
		return PostureBlocker, "POSTURE_BLOCKER_FOUND", true
	default:
		return "", "", false
	}
}

func oneOf(value string, values ...string) bool {
	for _, candidate := range values {
		if value == candidate {
			return true
		}
	}
	return false
}

// QueueTx persists one immutable event and its fan-out in the caller's source
// transaction. If no enabled destination subscribes, no event row is needed.
func QueueTx(ctx context.Context, tx *sql.Tx, eventID, tenantID, applicationID string, eventType EventType,
	targetType, targetID, reason, correlationID, actor, role string) error {
	if tx == nil || !validUUID(eventID) || !validUUID(tenantID) || !validUUID(applicationID) || !validUUID(targetID) ||
		!validEventType(eventType) || len(correlationID) < 1 || len(correlationID) > 128 {
		return errors.New("webhook event context is invalid")
	}
	err := tx.QueryRowContext(ctx, `INSERT INTO public.webhook_events
		(id, tenant_id, application_id, event_type, correlation_id, resource_type, resource_id, reason_code)
		SELECT $1, $2, $3, $4, $5, $6, $7, $8
		WHERE EXISTS (SELECT 1 FROM public.webhook_destinations
			WHERE tenant_id = $2 AND application_id = $3 AND enabled AND event_types @> ARRAY[$4]::TEXT[])
		RETURNING id::text`, eventID, tenantID, applicationID, string(eventType), correlationID,
		targetType, targetID, reason).Scan(&eventID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO public.webhook_deliveries
		(tenant_id, application_id, event_id, destination_id)
		SELECT $1, $2, $3, id FROM public.webhook_destinations
		WHERE tenant_id = $1 AND application_id = $2 AND enabled AND event_types @> ARRAY[$4]::TEXT[]`,
		tenantID, applicationID, eventID, string(eventType)); err != nil {
		return err
	}
	source, err := json.Marshal(map[string]string{"role": role})
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO public.audit_events
		(tenant_id, schema_version, actor, action, target_type, target_id, outcome, correlation_id, reason_code, source_context)
		VALUES ($1, 1, $2, 'webhook.event_queued', 'webhook_event', $3, 'success', $4, $5, $6::jsonb)`,
		tenantID, actor, eventID, correlationID, string(eventType), source)
	return err
}

func validEventType(value EventType) bool {
	_, ok := allowedEventTypes[value]
	return ok
}
