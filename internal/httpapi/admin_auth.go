package httpapi

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"quantumgate/internal/auth"
)

const (
	loginCookieName   = "__Host-qg_login"
	sessionCookieName = "__Host-qg_admin"
	csrfCookieName    = "__Host-qg_csrf"
	loginTTL          = 5 * time.Minute
	sessionTTL        = 8 * time.Hour
	sessionIdleTTL    = 30 * time.Minute
)

type loginTransaction struct {
	nonce        string
	codeVerifier string
}

func (s *Server) startAdminLogin(w http.ResponseWriter, r *http.Request) {
	if s.Store == nil || s.OIDC == nil {
		writeProblem(w, r, http.StatusServiceUnavailable, "ADMIN_LOGIN_UNAVAILABLE", "Sign-in unavailable", "Administrator sign-in is not configured.", true)
		return
	}
	if !s.enforceRateLimit(w, r, "admin-login:ip", clientIPDimension(r.RemoteAddr), 10) {
		return
	}
	state, err := randomURLToken(32)
	if err != nil {
		writeProblem(w, r, http.StatusServiceUnavailable, "ADMIN_LOGIN_UNAVAILABLE", "Sign-in unavailable", "The sign-in request could not be created safely.", true)
		return
	}
	browser, err := randomURLToken(32)
	if err != nil {
		writeProblem(w, r, http.StatusServiceUnavailable, "ADMIN_LOGIN_UNAVAILABLE", "Sign-in unavailable", "The sign-in request could not be created safely.", true)
		return
	}
	nonce, err := randomURLToken(32)
	if err != nil {
		writeProblem(w, r, http.StatusServiceUnavailable, "ADMIN_LOGIN_UNAVAILABLE", "Sign-in unavailable", "The sign-in request could not be created safely.", true)
		return
	}
	verifier, err := randomURLToken(32)
	if err != nil {
		writeProblem(w, r, http.StatusServiceUnavailable, "ADMIN_LOGIN_UNAVAILABLE", "Sign-in unavailable", "The sign-in request could not be created safely.", true)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	if _, err := s.Store.ExecContext(ctx, `DELETE FROM oidc_login_transactions WHERE expires_at <= now()`); err != nil {
		writeProblem(w, r, http.StatusServiceUnavailable, "ADMIN_LOGIN_UNAVAILABLE", "Sign-in unavailable", "The sign-in request could not be created safely.", true)
		return
	}
	_, err = s.Store.ExecContext(ctx, `INSERT INTO oidc_login_transactions
		(state_hash, browser_hash, nonce, code_verifier, expires_at)
		VALUES ($1, $2, $3, $4, now() + ($5 * interval '1 second'))`,
		hashToken(state), hashToken(browser), nonce, verifier, int64(loginTTL.Seconds()))
	if err != nil {
		writeProblem(w, r, http.StatusServiceUnavailable, "ADMIN_LOGIN_UNAVAILABLE", "Sign-in unavailable", "The sign-in request could not be created safely.", true)
		return
	}
	setAuthCookie(w, loginCookieName, browser, loginTTL, true)
	w.Header().Set("Location", s.OIDC.AuthorizationURL(state, nonce, verifier))
	w.WriteHeader(http.StatusFound)
}

func (s *Server) finishAdminLogin(w http.ResponseWriter, r *http.Request) {
	if s.Store == nil || s.OIDC == nil {
		writeProblem(w, r, http.StatusServiceUnavailable, "ADMIN_LOGIN_UNAVAILABLE", "Sign-in unavailable", "Administrator sign-in is not configured.", true)
		return
	}
	if !s.enforceRateLimit(w, r, "admin-callback:ip", clientIPDimension(r.RemoteAddr), 60) {
		return
	}
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		s.denyAdminLogin(w, r, "INVALID_PROVIDER_RESPONSE")
		return
	}
	state, stateOK := exactlyOneQueryValue(query, "state")
	code, codeOK := exactlyOneQueryValue(query, "code")
	browser, cookieOK := uniqueCookie(r, loginCookieName)
	if !stateOK || !codeOK || !cookieOK || len(state) > 256 || len(code) > 4096 || len(browser) > 128 || query.Has("error") {
		s.denyAdminLogin(w, r, "INVALID_PROVIDER_RESPONSE")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	var tx loginTransaction
	err = s.Store.QueryRowContext(ctx, `DELETE FROM oidc_login_transactions
		WHERE state_hash = $1 AND browser_hash = $2 AND expires_at > now()
		RETURNING nonce, code_verifier`, hashToken(state), hashToken(browser)).Scan(&tx.nonce, &tx.codeVerifier)
	clearAuthCookie(w, loginCookieName)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			writeProblem(w, r, http.StatusServiceUnavailable, "ADMIN_LOGIN_UNAVAILABLE", "Sign-in unavailable", "The sign-in request could not be validated safely.", true)
		} else {
			s.denyAdminLogin(w, r, "LOGIN_TRANSACTION_INVALID")
		}
		return
	}
	identity, err := s.OIDC.Exchange(ctx, code, tx.codeVerifier, tx.nonce)
	if err != nil {
		s.denyAdminLogin(w, r, "IDENTITY_VALIDATION_FAILED")
		return
	}
	session, err := randomURLToken(32)
	if err != nil {
		writeProblem(w, r, http.StatusServiceUnavailable, "ADMIN_LOGIN_UNAVAILABLE", "Sign-in unavailable", "The sign-in session could not be created safely.", true)
		return
	}
	csrf, err := randomURLToken(32)
	if err != nil {
		writeProblem(w, r, http.StatusServiceUnavailable, "ADMIN_LOGIN_UNAVAILABLE", "Sign-in unavailable", "The sign-in session could not be created safely.", true)
		return
	}
	actor := hashedActor(identity.Issuer, identity.Subject)
	dbtx, err := s.Store.BeginTx(ctx, nil)
	if err != nil {
		writeProblem(w, r, http.StatusServiceUnavailable, "ADMIN_LOGIN_UNAVAILABLE", "Sign-in unavailable", "The sign-in session could not be created safely.", true)
		return
	}
	defer dbtx.Rollback()
	_, err = dbtx.ExecContext(ctx, `INSERT INTO admin_sessions
		(token_hash, issuer, subject, auth_time, csrf_hash, acr, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, now() + ($7 * interval '1 second'))`,
		hashToken(session), identity.Issuer, identity.Subject, identity.AuthTime, hashToken(csrf), identity.ACR, int64(sessionTTL.Seconds()))
	if err != nil || !insertAuthEvent(ctx, dbtx, actor, "admin.login", "success", "LOGIN_ACCEPTED", requestID(r.Context())) {
		writeProblem(w, r, http.StatusServiceUnavailable, "ADMIN_LOGIN_UNAVAILABLE", "Sign-in unavailable", "The sign-in session could not be created safely.", true)
		return
	}
	if err := dbtx.Commit(); err != nil {
		writeProblem(w, r, http.StatusServiceUnavailable, "ADMIN_LOGIN_UNAVAILABLE", "Sign-in unavailable", "The sign-in session could not be created safely.", true)
		return
	}
	setAuthCookie(w, sessionCookieName, session, sessionTTL, true)
	setAuthCookie(w, csrfCookieName, csrf, sessionTTL, false)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) denyAdminLogin(w http.ResponseWriter, r *http.Request, reason string) {
	clearAuthCookie(w, loginCookieName)
	if !s.recordAuthEvent(r.Context(), "anonymous", "admin.login", "denied", reason, requestID(r.Context())) {
		writeProblem(w, r, http.StatusServiceUnavailable, "AUDIT_UNAVAILABLE", "Sign-in unavailable", "The sign-in result could not be recorded safely.", true)
		return
	}
	writeProblem(w, r, http.StatusUnauthorized, "LOGIN_FAILED", "Sign-in failed", "Administrator sign-in could not be completed.", false)
}

func (s *Server) adminSessionInfo(w http.ResponseWriter, r *http.Request) {
	if s.Store == nil {
		writeProblem(w, r, http.StatusServiceUnavailable, "ADMIN_LOGIN_UNAVAILABLE", "Sign-in unavailable", "Administrator sign-in is not configured.", true)
		return
	}
	if !s.enforceRateLimit(w, r, "admin-session:ip", clientIPDimension(r.RemoteAddr), 120) {
		return
	}
	principal, csrfHash, sessionToken, ok := s.loadBrowserSession(r)
	if !ok {
		writeJSON(w, http.StatusOK, map[string]any{"authenticated": false, "request_id": requestID(r.Context())})
		return
	}
	csrf, csrfOK := uniqueCookie(r, csrfCookieName)
	if !csrfOK || subtle.ConstantTimeCompare(hashToken(csrf), csrfHash) != 1 {
		csrf, err := randomURLToken(32)
		if err != nil {
			writeProblem(w, r, http.StatusServiceUnavailable, "ADMIN_LOGIN_UNAVAILABLE", "Sign-in unavailable", "The session could not be validated safely.", true)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		if _, err := s.Store.ExecContext(ctx, `UPDATE admin_sessions SET csrf_hash = $1 WHERE token_hash = $2 AND revoked_at IS NULL`, hashToken(csrf), hashToken(sessionToken)); err != nil {
			writeProblem(w, r, http.StatusServiceUnavailable, "ADMIN_LOGIN_UNAVAILABLE", "Sign-in unavailable", "The session could not be validated safely.", true)
			return
		}
		setAuthCookie(w, csrfCookieName, csrf, sessionTTL, false)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"authenticated": true, "auth_time": principal.AuthTime.UTC().Format(time.RFC3339),
		"csrf_token": csrf, "request_id": requestID(r.Context()),
	})
}

func (s *Server) endAdminSession(w http.ResponseWriter, r *http.Request) {
	if !s.enforceRateLimit(w, r, "admin-logout:ip", clientIPDimension(r.RemoteAddr), 30) {
		return
	}
	principal, csrfHash, token, ok := s.loadBrowserSession(r)
	if !ok {
		clearSessionCookies(w)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if !s.validCSRFRequest(r, csrfHash) {
		writeProblem(w, r, http.StatusForbidden, "CSRF_REJECTED", "Request denied", "The request could not be validated.", false)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	tx, err := s.Store.BeginTx(ctx, nil)
	if err != nil {
		writeProblem(w, r, http.StatusServiceUnavailable, "ADMIN_LOGOUT_UNAVAILABLE", "Sign-out unavailable", "The session could not be revoked safely.", true)
		return
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `UPDATE admin_sessions SET revoked_at = now() WHERE token_hash = $1 AND revoked_at IS NULL`, hashToken(token)); err != nil || !insertAuthEvent(ctx, tx, hashedActor(principal.Issuer, principal.Subject), "admin.logout", "success", "SESSION_REVOKED", requestID(r.Context())) {
		writeProblem(w, r, http.StatusServiceUnavailable, "ADMIN_LOGOUT_UNAVAILABLE", "Sign-out unavailable", "The session could not be revoked safely.", true)
		return
	}
	if err := tx.Commit(); err != nil {
		writeProblem(w, r, http.StatusServiceUnavailable, "ADMIN_LOGOUT_UNAVAILABLE", "Sign-out unavailable", "The session could not be revoked safely.", true)
		return
	}
	clearSessionCookies(w)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) loadBrowserSession(r *http.Request) (auth.Principal, []byte, string, bool) {
	if s.Store == nil {
		return auth.Principal{}, nil, "", false
	}
	token, ok := uniqueCookie(r, sessionCookieName)
	if !ok || len(token) > 128 {
		return auth.Principal{}, nil, "", false
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	var principal auth.Principal
	var csrfHash []byte
	err := s.Store.QueryRowContext(ctx, `UPDATE admin_sessions
		SET last_seen_at = now()
		WHERE token_hash = $1 AND revoked_at IS NULL AND expires_at > now()
		AND last_seen_at > now() - ($2 * interval '1 second')
		RETURNING issuer, subject, auth_time, csrf_hash, acr`, hashToken(token), int64(sessionIdleTTL.Seconds())).Scan(
		&principal.Issuer, &principal.Subject, &principal.AuthTime, &csrfHash, &principal.ACR)
	if err != nil || principal.Issuer == "" || principal.Subject == "" || len(csrfHash) != sha256.Size {
		return auth.Principal{}, nil, "", false
	}
	return principal, csrfHash, token, true
}

func (s *Server) validCSRFRequest(r *http.Request, expectedHash []byte) bool {
	if len(r.Header.Values("Origin")) != 1 || r.Header.Get("Origin") != s.PublicOrigin || s.PublicOrigin == "" {
		return false
	}
	headerValues := r.Header.Values("X-QG-CSRF-Token")
	if len(headerValues) != 1 {
		return false
	}
	cookie, ok := uniqueCookie(r, csrfCookieName)
	if !ok || len(cookie) > 128 || headerValues[0] != cookie {
		return false
	}
	actualHash := hashToken(cookie)
	return len(expectedHash) == sha256.Size && subtle.ConstantTimeCompare(actualHash, expectedHash) == 1
}

func insertAuthEvent(ctx context.Context, tx *sql.Tx, actor, action, outcome, reason, correlationID string) bool {
	_, err := tx.ExecContext(ctx, `INSERT INTO admin_auth_events(actor, action, outcome, reason_code, correlation_id)
		VALUES ($1, $2, $3, $4, $5)`, actor, action, outcome, reason, correlationID)
	return err == nil
}

func (s *Server) recordAuthEvent(ctx context.Context, actor, action, outcome, reason, correlationID string) bool {
	if s.Store == nil {
		return false
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	tx, err := s.Store.BeginTx(ctx, nil)
	if err != nil {
		return false
	}
	defer tx.Rollback()
	if !insertAuthEvent(ctx, tx, actor, action, outcome, reason, correlationID) {
		return false
	}
	return tx.Commit() == nil
}

func randomURLToken(size int) (string, error) {
	if size < 32 || size > 128 {
		return "", errors.New("token size is outside the supported range")
	}
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func hashToken(value string) []byte {
	hash := sha256.Sum256([]byte(value))
	return hash[:]
}

func hashedActor(issuer, subject string) string {
	hash := sha256.Sum256([]byte(issuer + "\x00" + subject))
	return "oidc:" + base64.RawURLEncoding.EncodeToString(hash[:])
}

func exactlyOneQueryValue(values url.Values, key string) (string, bool) {
	items := values[key]
	if len(items) != 1 || items[0] == "" || strings.ContainsAny(items[0], "\r\n\x00") {
		return "", false
	}
	return items[0], true
}

func uniqueCookie(r *http.Request, name string) (string, bool) {
	if len(r.Header.Values("Cookie")) != 1 {
		return "", false
	}
	var found string
	count := 0
	for _, cookie := range r.Cookies() {
		if cookie.Name == name {
			found = cookie.Value
			count++
		}
	}
	return found, count == 1 && found != ""
}

func setAuthCookie(w http.ResponseWriter, name, value string, ttl time.Duration, httpOnly bool) {
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: value, Path: "/", MaxAge: int(ttl.Seconds()),
		Expires: time.Now().Add(ttl).UTC(), HttpOnly: httpOnly, Secure: true,
		SameSite: http.SameSiteLaxMode,
	})
}

func clearAuthCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: "", Path: "/", MaxAge: -1, Expires: time.Unix(1, 0).UTC(), HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
}

func clearSessionCookies(w http.ResponseWriter) {
	clearAuthCookie(w, sessionCookieName)
	clearAuthCookie(w, csrfCookieName)
}
