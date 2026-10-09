package httpapi

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"quantumgate/internal/auth"
	"quantumgate/internal/config"
	"quantumgate/internal/gateway"
	"quantumgate/internal/keyprovider"
	"quantumgate/internal/webhook"
)

type Pinger interface{ PingContext(context.Context) error }

type KeyProviderHealth interface{ Health(context.Context) error }

type Server struct {
	DB                   Pinger
	Store                *sql.DB
	Auth                 auth.TokenVerifier
	OIDC                 *auth.OIDCFlow
	OIDCIssuer           string
	IdentityAllowedHosts []string
	PublicOrigin         string
	RateLimitKey         []byte
	CryptoMode           config.CryptoMode
	Logger               *slog.Logger
	Gateway              *gateway.Gateway
	KeyProvider          KeyProviderHealth
	KeyProviderRequired  bool
	WebhookSigner        *keyprovider.Broker
	WebhookSender        *webhook.SenderClient
	WebhookEnvironment   string
	identityVerifierMu   sync.Mutex
	identityVerifiers    map[string]identityVerifierEntry
	lastRateLimitCleanup atomic.Int64
}

type problem struct {
	Type      string "json:\"type\""
	Title     string "json:\"title\""
	Status    int    "json:\"status\""
	Code      string "json:\"code\""
	Detail    string "json:\"detail\""
	Instance  string "json:\"instance\""
	RequestID string "json:\"request_id\""
	Retryable bool   "json:\"retryable\""
}

type requestIDKey struct{}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health/live", s.live)
	mux.HandleFunc("GET /health/ready", s.ready)
	mux.HandleFunc("GET /auth/login", s.startAdminLogin)
	mux.HandleFunc("GET /auth/callback", s.finishAdminLogin)
	mux.HandleFunc("GET /auth/session", s.adminSessionInfo)
	mux.HandleFunc("POST /auth/logout", s.endAdminSession)
	mux.HandleFunc("POST /oauth/token", s.issueServiceAccessToken)
	mux.HandleFunc("POST /oauth/introspect", s.introspectServiceAccessToken)
	mux.HandleFunc("GET /.well-known/qg-webhook-keys/{key_id}", s.getWebhookPublicKey)
	mux.Handle("POST /v1/applications/{application_id}/observations", s.withServiceTokenAuth(http.HandlerFunc(s.ingestObservation)))
	mux.Handle("POST /v1/applications/{application_id}/decisions", s.withDecisionServiceTokenAuth(http.HandlerFunc(s.evaluateDecision)))
	mux.HandleFunc("GET /{$}", s.dashboard)
	mux.HandleFunc("GET /dashboard.js", s.dashboardAsset)
	mux.HandleFunc("GET /dashboard.css", s.dashboardAsset)
	api := http.NewServeMux()
	api.HandleFunc("GET /v1/tenants/{tenant_id}", s.getTenant)
	api.HandleFunc("PATCH /v1/tenants/{tenant_id}", s.updateTenant)
	api.HandleFunc("GET /v1/tenants/{tenant_id}/members", s.listMembers)
	api.HandleFunc("POST /v1/tenants/{tenant_id}/members", s.createMember)
	api.HandleFunc("DELETE /v1/tenants/{tenant_id}/members/{member_id}", s.removeMember)
	api.HandleFunc("GET /v1/tenants/{tenant_id}/audit-events", s.listAuditEvents)
	api.HandleFunc("POST /v1/tenants/{tenant_id}/exports", s.createAuditExport)
	api.HandleFunc("GET /v1/exports/{export_id}", s.getAuditExport)
	api.HandleFunc("GET /v1/exports/{export_id}/download", s.downloadAuditExport)
	api.HandleFunc("POST /v1/tenants/{tenant_id}/environments", s.createEnvironment)
	api.HandleFunc("GET /v1/tenants/{tenant_id}/algorithm-profiles", s.listAlgorithmProfiles)
	api.HandleFunc("POST /v1/tenants/{tenant_id}/algorithm-profiles/{profile_id}/reviews", s.submitProfileReview)
	api.HandleFunc("GET /v1/tenants/{tenant_id}/algorithm-profile-reviews/{review_id}", s.getProfileReview)
	api.HandleFunc("POST /v1/tenants/{tenant_id}/algorithm-profile-reviews/{review_id}/approve", s.approveProfileReview)
	api.HandleFunc("POST /v1/tenants/{tenant_id}/algorithm-profile-reviews/{review_id}/reject", s.rejectProfileReview)
	api.HandleFunc("POST /v1/tenants/{tenant_id}/algorithm-profile-reviews/{review_id}/disable", s.disableProfileReview)
	api.HandleFunc("POST /v1/tenants/{tenant_id}/algorithm-profile-reviews/{review_id}/deprecate", s.deprecateProfileReview)
	api.HandleFunc("GET /v1/tenants/{tenant_id}/applications", s.listApplications)
	api.HandleFunc("POST /v1/tenants/{tenant_id}/applications", s.createApplication)
	api.HandleFunc("GET /v1/applications/{application_id}/policies", s.listApplicationPolicies)
	api.HandleFunc("POST /v1/applications/{application_id}/policies", s.createPolicy)
	api.HandleFunc("GET /v1/applications/{application_id}/identity-adapters", s.listIdentityAdapters)
	api.HandleFunc("POST /v1/applications/{application_id}/identity-adapters", s.createIdentityAdapter)
	api.HandleFunc("PATCH /v1/identity-adapters/{adapter_id}", s.updateIdentityAdapter)
	api.HandleFunc("POST /v1/identity-adapters/{adapter_id}/verify", s.verifyIdentityAdapter)
	api.HandleFunc("POST /v1/identity-adapters/{adapter_id}/disable", s.disableIdentityAdapter)
	api.HandleFunc("GET /v1/applications/{application_id}/keys", s.listApplicationKeys)
	api.HandleFunc("POST /v1/applications/{application_id}/keys/rotate", s.createKeyReference)
	api.HandleFunc("GET /v1/applications/{application_id}/webhooks", s.listWebhookDestinations)
	api.HandleFunc("POST /v1/applications/{application_id}/webhooks", s.createWebhookDestination)
	api.HandleFunc("PATCH /v1/webhooks/{webhook_id}", s.updateWebhookDestination)
	api.HandleFunc("POST /v1/webhooks/{webhook_id}/rotate-key", s.rotateWebhookKey)
	api.HandleFunc("GET /v1/webhooks/{webhook_id}/deliveries", s.listWebhookDeliveries)
	api.HandleFunc("POST /v1/webhook-deliveries/{delivery_id}/retry", s.retryWebhookDelivery)
	api.HandleFunc("POST /v1/keys/{key_id}/activate", s.activateKeyReference)
	api.HandleFunc("POST /v1/keys/{key_id}/disable", s.disableKeyReference)
	api.HandleFunc("POST /v1/keys/{key_id}/revoke", s.revokeKeyReference)
	api.HandleFunc("GET /v1/keys/{key_id}/public-material", s.getKeyPublicMaterial)
	api.HandleFunc("GET /v1/applications/{application_id}", s.getApplication)
	api.HandleFunc("PATCH /v1/applications/{application_id}", s.updateApplication)
	api.HandleFunc("POST /v1/applications/{application_id}/credentials/rotate", s.rotateApplicationCredential)
	api.HandleFunc("GET /v1/applications/{application_id}/posture", s.getApplicationPosture)
	api.HandleFunc("GET /v1/applications/{application_id}/observations", s.listApplicationObservations)
	api.HandleFunc("POST /v1/applications/{application_id}/disable", s.disableApplication)
	api.HandleFunc("GET /v1/policies/{policy_id}", s.getPolicy)
	api.HandleFunc("POST /v1/policies/{policy_id}/simulate", s.simulatePolicy)
	api.HandleFunc("POST /v1/policies/{policy_id}/activate", s.activatePolicy)
	api.HandleFunc("POST /v1/policies/{policy_id}/schedule", s.schedulePolicy)
	api.HandleFunc("POST /v1/policies/{policy_id}/rollback", s.rollbackPolicy)
	api.HandleFunc("POST /v1/policies/{policy_id}/retire", s.retirePolicy)
	api.HandleFunc("/", s.notFound)
	tenantAPI := s.withTenantAuth(api)
	postureService := s.withServiceTokenScope("posture:read", http.HandlerFunc(s.getApplicationPosture))
	mux.Handle("GET /v1/applications/{application_id}/posture", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, ok := bearerToken(r)
		if ok && validOpaqueAccessToken(token) {
			postureService.ServeHTTP(w, r)
			return
		}
		tenantAPI.ServeHTTP(w, r)
	}))
	mux.Handle("/v1/", tenantAPI)
	mux.HandleFunc("/", s.notFound)
	return s.withCommonMiddleware(mux)
}

// GatewayHandler serves only operator-configured application routes. Its
// fallback is a not-found response, never the control-plane mux.
func (s *Server) GatewayHandler() http.Handler {
	var handler http.Handler = http.HandlerFunc(s.notFound)
	if s.Gateway != nil {
		handler = s.Gateway.Middleware(handler)
	}
	return s.withCommonMiddleware(handler)
}

func (s *Server) withCommonMiddleware(handler http.Handler) http.Handler {
	handler = s.withCryptoPolicy(handler)
	handler = s.withSecurityHeaders(handler)
	handler = s.withRecovery(handler)
	return s.withRequestID(handler)
}

func (s *Server) live(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "live", "request_id": requestID(r.Context())})
}

func (s *Server) ready(w http.ResponseWriter, r *http.Request) {
	if s.DB == nil {
		writeProblem(w, r, http.StatusServiceUnavailable, "NOT_READY", "Service not ready", "A required dependency is unavailable.", true)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := s.DB.PingContext(ctx); err != nil {
		if s.Logger != nil {
			s.Logger.Warn("readiness check failed", "request_id", requestID(r.Context()), "dependency", "database")
		}
		writeProblem(w, r, http.StatusServiceUnavailable, "NOT_READY", "Service not ready", "A required dependency is unavailable.", true)
		return
	}
	if s.KeyProviderRequired && s.KeyProvider == nil {
		writeProblem(w, r, http.StatusServiceUnavailable, "NOT_READY", "Service not ready", "A required dependency is unavailable.", true)
		return
	}
	if s.KeyProvider != nil {
		if err := s.KeyProvider.Health(ctx); err != nil {
			if s.Logger != nil {
				s.Logger.Warn("readiness check failed", "request_id", requestID(r.Context()), "dependency", "key-provider")
			}
			writeProblem(w, r, http.StatusServiceUnavailable, "NOT_READY", "Service not ready", "A required dependency is unavailable.", true)
			return
		}
	}
	if s.Store != nil {
		var rateLimitsReady bool
		if err := s.Store.QueryRowContext(ctx, `SELECT to_regclass('public.rate_limit_buckets') IS NOT NULL
			AND to_regclass('public.idempotency_records') IS NOT NULL
			AND to_regclass('public.export_jobs') IS NOT NULL
			AND to_regprocedure('public.qg_purge_expired_exports(uuid,integer)') IS NOT NULL
			AND has_table_privilege(current_user, 'public.export_jobs', 'SELECT')
			AND has_table_privilege(current_user, 'public.export_jobs', 'INSERT')
			AND NOT has_table_privilege(current_user, 'public.export_jobs', 'UPDATE')
			AND NOT has_table_privilege(current_user, 'public.export_jobs', 'DELETE')
			AND has_function_privilege(current_user, 'public.qg_purge_expired_exports(uuid,integer)', 'EXECUTE')
			AND to_regclass('public.policy_revisions') IS NOT NULL
			AND EXISTS (SELECT 1 FROM pg_catalog.pg_attribute
				WHERE attrelid = 'public.application_credentials'::regclass AND attname = 'scopes' AND NOT attisdropped)
			AND EXISTS (SELECT 1 FROM pg_catalog.pg_attribute
				WHERE attrelid = 'public.identity_adapters'::regclass AND attname = 'last_verified_at' AND NOT attisdropped)
			AND to_regprocedure('public.qg_claim_due_policy_schedules(integer)') IS NOT NULL
			AND to_regprocedure('public.qg_authenticate_application_credential(uuid,bytea)') IS NOT NULL
			AND to_regprocedure('public.qg_validate_service_access_token(bytea)') IS NOT NULL
			AND to_regclass('public.migration_observations_application_id') IS NOT NULL
			AND to_regclass('public.key_references_application_id') IS NOT NULL
			AND EXISTS (SELECT 1 FROM pg_catalog.pg_attribute
				WHERE attrelid = 'public.key_references'::regclass AND attname = 'updated_at' AND NOT attisdropped)
			AND to_regclass('public.algorithm_profiles') IS NOT NULL
			AND to_regprocedure('public.qg_guard_algorithm_profile_review()') IS NOT NULL
			AND EXISTS (SELECT 1 FROM pg_catalog.pg_attribute
				WHERE attrelid = 'public.algorithm_profiles'::regclass AND attname = 'lifecycle_version' AND NOT attisdropped)
			AND EXISTS (SELECT 1 FROM pg_catalog.pg_attribute
				WHERE attrelid = 'public.algorithm_profiles'::regclass AND attname = 'profile_hash' AND NOT attisdropped)`).Scan(&rateLimitsReady); err != nil || !rateLimitsReady {
			writeProblem(w, r, http.StatusServiceUnavailable, "NOT_READY", "Service not ready", "A required database migration is not available.", true)
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready", "request_id": requestID(r.Context())})
}

func (s *Server) notFound(w http.ResponseWriter, r *http.Request) {
	writeProblem(w, r, http.StatusNotFound, "NOT_FOUND", "Not found", "The requested resource was not found.", false)
}

func (s *Server) withRequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(r.RequestURI) > 8192 {
			writeProblem(w, r, http.StatusRequestURITooLong, "REQUEST_TOO_LARGE", "Request URI too long", "The request could not be processed safely.", false)
			return
		}
		idBytes := make([]byte, 18)
		if _, err := rand.Read(idBytes); err != nil {
			writeProblem(w, r, http.StatusServiceUnavailable, "REQUEST_ID_UNAVAILABLE", "Service unavailable", "The request could not be processed safely.", true)
			return
		}
		id := base64.RawURLEncoding.EncodeToString(idBytes)
		ctx := context.WithValue(r.Context(), requestIDKey{}, id)
		w.Header().Set("X-Request-ID", id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (s *Server) withSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		if r.TLS != nil {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) withCryptoPolicy(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.CryptoMode == config.CryptoHybrid && (r.TLS == nil || r.TLS.Version < tls.VersionTLS13 || r.TLS.CurveID != tls.X25519MLKEM768) {
			writeProblem(w, r, http.StatusForbidden, "HYBRID_REQUIRED", "Request denied", "The connection does not meet the required protection profile.", false)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) withRecovery(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if recovered := recover(); recovered != nil {
				if s.Logger != nil {
					s.Logger.Error("request handler panic", "request_id", requestID(r.Context()), "panic_type", fmt.Sprintf("%T", recovered))
				}
				writeProblem(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Internal server error", "The request could not be processed.", false)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func requestID(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey{}).(string)
	return id
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeProblem(w http.ResponseWriter, r *http.Request, status int, code, title, detail string, retryable bool) {
	instance := r.URL.Path
	if len(instance) > 2048 {
		instance = instance[:2048]
	}
	p := problem{Type: "about:blank", Title: title, Status: status, Code: code, Detail: detail,
		Instance: instance, RequestID: requestID(r.Context()), Retryable: retryable}
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(p)
}

func NewHTTPServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr: addr, Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second,
		WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 64 << 10,
	}
}
