package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"log/slog"
	"os"
	"strings"
	"time"
	"unicode"

	"github.com/jackc/pgx/v5"

	"quantumgate/internal/config"
	"quantumgate/internal/storage"
)

func main() {
	if err := run(); err != nil {
		slog.Error("bootstrap command failed", "code", "BOOTSTRAP_FAILURE")
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.LoadBootstrap()
	if err != nil {
		return errors.New("configuration is invalid")
	}
	tenantID := strings.TrimSpace(os.Getenv("BOOTSTRAP_TENANT_ID"))
	tenantName := strings.TrimSpace(os.Getenv("BOOTSTRAP_TENANT_NAME"))
	issuer := strings.TrimSpace(os.Getenv("BOOTSTRAP_ADMIN_ISSUER"))
	subject := strings.TrimSpace(os.Getenv("BOOTSTRAP_ADMIN_SUBJECT"))
	environmentName := strings.TrimSpace(os.Getenv("BOOTSTRAP_ENVIRONMENT_NAME"))
	if environmentName == "" {
		environmentName = "default"
	}
	if !isUUID(tenantID) || !validLabel(tenantName, 120) || !validIdentityPart(issuer, 2048) ||
		issuer != cfg.OIDCIssuer || !validIdentityPart(subject, 512) || !validLabel(environmentName, 80) {
		return errors.New("bootstrap tenant and administrator settings are invalid")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, cfg.DatabaseURL)
	if err != nil {
		return errors.New("database connection failed")
	}
	defer conn.Close(context.Background())
	if err := storage.VerifyTenantSafePGXRole(ctx, conn); err != nil {
		return errors.New("bootstrap database role is not permitted")
	}
	tx, err := conn.Begin(ctx)
	if err != nil {
		return errors.New("bootstrap transaction could not be started")
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, "SELECT set_config('qg.tenant_id', $1, true)", tenantID); err != nil {
		return errors.New("tenant scope could not be initialized")
	}
	var createdTenantID string
	err = tx.QueryRow(ctx, `INSERT INTO tenants(id, display_name, status) VALUES ($1, $2, 'active')
		ON CONFLICT (id) DO NOTHING RETURNING id::text`, tenantID, tenantName).Scan(&createdTenantID)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return errors.New("tenant could not be created")
	}
	tenantCreated := err == nil
	var storedName, status string
	if err := tx.QueryRow(ctx, "SELECT display_name, status FROM tenants WHERE id = $1", tenantID).Scan(&storedName, &status); err != nil || storedName != tenantName || status != "active" {
		return errors.New("configured tenant does not match the existing tenant")
	}
	var environmentCreated string
	err = tx.QueryRow(ctx, `INSERT INTO environments(tenant_id, name, lifecycle) VALUES ($1, $2, 'development')
		ON CONFLICT (tenant_id, name) DO NOTHING RETURNING id::text`, tenantID, environmentName).Scan(&environmentCreated)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return errors.New("default environment could not be created")
	}
	var memberCreated string
	err = tx.QueryRow(ctx, `INSERT INTO tenant_members(tenant_id, issuer, subject, role) VALUES ($1, $2, $3, 'tenant_admin')
		ON CONFLICT (tenant_id, issuer, subject) DO NOTHING RETURNING id::text`, tenantID, issuer, subject).Scan(&memberCreated)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return errors.New("bootstrap administrator could not be added")
	}
	var role string
	if err := tx.QueryRow(ctx, `SELECT role FROM tenant_members WHERE tenant_id = $1 AND issuer = $2 AND subject = $3`, tenantID, issuer, subject).Scan(&role); err != nil || role != "tenant_admin" {
		return errors.New("existing bootstrap identity is not a tenant administrator")
	}
	if tenantCreated {
		if err := writeBootstrapAudit(ctx, tx, tenantID, issuer, subject, "tenant.bootstrapped", "tenant", tenantID); err != nil {
			return err
		}
	}
	if environmentCreated != "" {
		if err := writeBootstrapAudit(ctx, tx, tenantID, issuer, subject, "environment.created", "environment", environmentCreated); err != nil {
			return err
		}
	}
	if memberCreated != "" {
		if err := writeBootstrapAudit(ctx, tx, tenantID, issuer, subject, "tenant.member_added", "tenant_member", memberCreated); err != nil {
			return err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return errors.New("bootstrap transaction could not be committed")
	}
	slog.Info("QuantumGate tenant bootstrap completed", "tenant_id", tenantID)
	return nil
}

func writeBootstrapAudit(ctx context.Context, tx pgx.Tx, tenantID, issuer, subject, action, targetType, targetID string) error {
	var correlationBytes [18]byte
	if _, err := rand.Read(correlationBytes[:]); err != nil {
		return errors.New("audit correlation identifier could not be generated")
	}
	identity := sha256.Sum256([]byte(issuer + "\x00" + subject))
	actor := "oidc:" + base64.RawURLEncoding.EncodeToString(identity[:])
	_, err := tx.Exec(ctx, `INSERT INTO audit_events
		(tenant_id, schema_version, actor, action, target_type, target_id, outcome, correlation_id, reason_code, source_context)
		VALUES ($1, 1, $2, $3, $4, $5, 'success', $6, 'BOOTSTRAP', '{"tool":"qg-bootstrap"}'::jsonb)`,
		tenantID, actor, action, targetType, targetID, hex.EncodeToString(correlationBytes[:]))
	if err != nil {
		return errors.New("bootstrap audit event could not be written")
	}
	return nil
}

func isUUID(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return false
	}
	for i, char := range value {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			continue
		}
		if !((char >= '0' && char <= '9') || (char >= 'a' && char <= 'f') || (char >= 'A' && char <= 'F')) {
			return false
		}
	}
	return true
}

func validIdentityPart(value string, max int) bool {
	if len(value) == 0 || len(value) > max {
		return false
	}
	for _, char := range value {
		if unicode.IsControl(char) {
			return false
		}
	}
	return true
}

func validLabel(value string, max int) bool {
	if strings.TrimSpace(value) != value || !validIdentityPart(value, max) {
		return false
	}
	return true
}
