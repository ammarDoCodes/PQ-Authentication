package storage

import (
	"context"
	"database/sql"
	"errors"

	"github.com/jackc/pgx/v5"
)

// VerifyTenantSafeRole rejects service credentials that can bypass PostgreSQL
// row-level security, including membership in an elevated role.
func VerifyTenantSafeRole(ctx context.Context, db *sql.DB) error {
	if db == nil {
		return errors.New("database is required")
	}
	var unsafe bool
	err := db.QueryRowContext(ctx, `SELECT EXISTS (
		SELECT 1 FROM pg_roles r
		WHERE (r.rolsuper OR r.rolbypassrls)
		AND (r.rolname = current_user OR pg_has_role(current_user, r.oid, 'MEMBER'))
	)`).Scan(&unsafe)
	if err != nil {
		return errors.New("database role safety could not be verified")
	}
	if unsafe {
		return errors.New("service database role can bypass tenant row-level security")
	}
	return nil
}

func VerifyTenantSafePGXRole(ctx context.Context, conn *pgx.Conn) error {
	if conn == nil {
		return errors.New("database is required")
	}
	var unsafe bool
	err := conn.QueryRow(ctx, `SELECT EXISTS (
		SELECT 1 FROM pg_roles r
		WHERE (r.rolsuper OR r.rolbypassrls)
		AND (r.rolname = current_user OR pg_has_role(current_user, r.oid, 'MEMBER'))
	)`).Scan(&unsafe)
	if err != nil {
		return errors.New("database role safety could not be verified")
	}
	if unsafe {
		return errors.New("database role can bypass tenant row-level security")
	}
	return nil
}
