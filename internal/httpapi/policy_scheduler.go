package httpapi

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"time"
)

// ProcessDuePolicySchedules activates due revisions in bounded batches. Candidate rows
// are only hints; each application row is locked before its policy lifecycle is changed.
func ProcessDuePolicySchedules(ctx context.Context, db *sql.DB) (int, error) {
	if db == nil {
		return 0, errors.New("database is required")
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0, errors.New("policy scheduler transaction could not start")
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, "SELECT tenant_id::text, policy_id::text FROM qg_claim_due_policy_schedules($1)", 50)
	if err != nil {
		return 0, errors.New("policy schedule queue is unavailable")
	}
	type candidate struct{ tenantID, policyID string }
	candidates := make([]candidate, 0, 50)
	for rows.Next() {
		var item candidate
		if err := rows.Scan(&item.tenantID, &item.policyID); err != nil {
			rows.Close()
			return 0, errors.New("policy schedule queue is invalid")
		}
		candidates = append(candidates, item)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, errors.New("policy schedule queue could not be read")
	}
	if err := rows.Close(); err != nil {
		return 0, errors.New("policy schedule queue could not be closed")
	}
	activated := 0
	for _, candidate := range candidates {
		if _, err := tx.ExecContext(ctx, "SELECT set_config('qg.tenant_id', $1, true)", candidate.tenantID); err != nil {
			return 0, errors.New("policy tenant scope could not be set")
		}
		var applicationID string
		err := tx.QueryRowContext(ctx, `SELECT application_id::text FROM policy_revisions
			WHERE tenant_id = $1 AND id = $2`, candidate.tenantID, candidate.policyID).Scan(&applicationID)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return 0, errors.New("scheduled policy could not be located")
		}
		var applicationStatus string
		if err := tx.QueryRowContext(ctx, `SELECT status FROM applications
			WHERE tenant_id = $1 AND id = $2 FOR UPDATE`, candidate.tenantID, applicationID).Scan(&applicationStatus); err != nil {
			return 0, errors.New("scheduled policy application could not be locked")
		}
		var state string
		var effectiveAt sql.NullTime
		var documentJSON string
		var contentHash []byte
		err = tx.QueryRowContext(ctx, `SELECT state, effective_at, document::text, content_hash FROM policy_revisions
			WHERE tenant_id = $1 AND id = $2 FOR UPDATE`, candidate.tenantID, candidate.policyID).
			Scan(&state, &effectiveAt, &documentJSON, &contentHash)
		if err != nil {
			return 0, errors.New("scheduled policy lifecycle could not be locked")
		}
		if state != "scheduled" {
			if err := cancelPolicyScheduleTx(ctx, tx, candidate.tenantID, candidate.policyID); err != nil {
				return 0, errors.New("stale policy schedule could not be cleared")
			}
			continue
		}
		if !effectiveAt.Valid {
			return 0, errors.New("scheduled policy has no activation time")
		}
		if effectiveAt.Time.After(time.Now().UTC()) {
			if err := schedulePolicyTx(ctx, tx, candidate.tenantID, candidate.policyID, effectiveAt.Time.UTC()); err != nil {
				return 0, errors.New("policy schedule time could not be repaired")
			}
			continue
		}
		var document policyDocument
		decodeErr := json.Unmarshal([]byte(documentJSON), &document)
		canonical, marshalErr := json.Marshal(document)
		computedHash := sha256.Sum256(canonical)
		documentIntact := decodeErr == nil && marshalErr == nil && document.EffectiveWindow != nil && len(contentHash) == sha256.Size &&
			bytes.Equal(contentHash, computedHash[:])
		now := time.Now().UTC()
		windowExpired := document.EffectiveWindow != nil && document.EffectiveWindow.EndsAt != nil && !document.EffectiveWindow.EndsAt.After(now)
		if applicationStatus != "active" || !documentIntact || windowExpired {
			if _, err := tx.ExecContext(ctx, `UPDATE policy_revisions SET state = 'retired', retired_at = now(), lifecycle_updated_at = clock_timestamp(), lifecycle_version = lifecycle_version + 1
				WHERE tenant_id = $1 AND id = $2 AND state = 'scheduled'`, candidate.tenantID, candidate.policyID); err != nil {
				return 0, errors.New("scheduled policy for disabled application could not be retired")
			}
			if err := cancelPolicyScheduleTx(ctx, tx, candidate.tenantID, candidate.policyID); err != nil {
				return 0, errors.New("disabled policy schedule could not be cleared")
			}
			reason := "APPLICATION_DISABLED"
			if !documentIntact {
				reason = "POLICY_DOCUMENT_INTEGRITY_FAILURE"
			} else if windowExpired {
				reason = "POLICY_WINDOW_EXPIRED"
			}
			if err := insertSchedulerAudit(ctx, tx, candidate.tenantID, candidate.policyID, "policy.schedule_retired", reason); err != nil {
				return 0, errors.New("retired policy schedule audit could not be recorded")
			}
			continue
		}
		if document.EffectiveWindow.StartsAt != nil && document.EffectiveWindow.StartsAt.After(now) {
			if err := schedulePolicyTx(ctx, tx, candidate.tenantID, candidate.policyID, document.EffectiveWindow.StartsAt.UTC()); err != nil {
				return 0, errors.New("policy effective window could not be respected")
			}
			continue
		}
		if _, err := tx.ExecContext(ctx, `UPDATE policy_revisions
			SET state = 'retired', retired_at = now(), lifecycle_updated_at = clock_timestamp(), lifecycle_version = lifecycle_version + 1
			WHERE tenant_id = $1 AND application_id = $2 AND state = 'active' AND id <> $3`,
			candidate.tenantID, applicationID, candidate.policyID); err != nil {
			return 0, errors.New("previous active policy could not be retired")
		}
		if _, err := tx.ExecContext(ctx, `UPDATE policy_revisions
			SET state = 'active', retired_at = NULL, lifecycle_updated_at = clock_timestamp(), lifecycle_version = lifecycle_version + 1
			WHERE tenant_id = $1 AND id = $2 AND state = 'scheduled'`, candidate.tenantID, candidate.policyID); err != nil {
			return 0, errors.New("scheduled policy could not be activated")
		}
		if err := cancelPolicyScheduleTx(ctx, tx, candidate.tenantID, candidate.policyID); err != nil {
			return 0, errors.New("activated policy schedule could not be cleared")
		}
		if err := insertSchedulerAudit(ctx, tx, candidate.tenantID, candidate.policyID, "policy.scheduled_activated", "SCHEDULED_ACTIVATION"); err != nil {
			return 0, errors.New("scheduled policy audit could not be recorded")
		}
		activated++
	}
	if err := tx.Commit(); err != nil {
		return 0, errors.New("policy scheduler transaction could not commit")
	}
	return activated, nil
}

func insertSchedulerAudit(ctx context.Context, tx *sql.Tx, tenantID, policyID, action, reason string) error {
	var correlationBytes [18]byte
	if _, err := rand.Read(correlationBytes[:]); err != nil {
		return errors.New("policy scheduler correlation could not be generated")
	}
	actor := tenantPrincipal{Issuer: "urn:quantumgate:service", Subject: "policy-scheduler", Role: "system", TenantID: tenantID}
	return insertAudit(ctx, tx, actor, "schedule:"+base64.RawURLEncoding.EncodeToString(correlationBytes[:]),
		action, "policy_revision", policyID, "success", reason)
}

func RunPolicyScheduleWorker(ctx context.Context, db *sql.DB, logger *slog.Logger) {
	if db == nil {
		return
	}
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		workerCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		activated, err := ProcessDuePolicySchedules(workerCtx, db)
		cancel()
		if err != nil && ctx.Err() == nil && logger != nil {
			logger.Warn("policy schedule processing failed", "code", "POLICY_SCHEDULER_UNAVAILABLE")
		}
		if activated > 0 && logger != nil {
			logger.Info("scheduled policies activated", "count", activated)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func schedulePolicyTx(ctx context.Context, tx *sql.Tx, tenantID, policyID string, effectiveAt time.Time) error {
	_, err := tx.ExecContext(ctx, "SELECT qg_schedule_policy($1, $2, $3)", tenantID, policyID, effectiveAt)
	return err
}

func cancelPolicyScheduleTx(ctx context.Context, tx *sql.Tx, tenantID, policyID string) error {
	_, err := tx.ExecContext(ctx, "SELECT qg_cancel_policy_schedule($1, $2)", tenantID, policyID)
	return err
}
