package httpapi

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"quantumgate/internal/config"
	"quantumgate/internal/gateway"
)

type fakePinger struct{ err error }

func (f fakePinger) PingContext(context.Context) error { return f.err }

type fakeKeyProvider struct{ err error }

func (p fakeKeyProvider) Health(context.Context) error { return p.err }

type gatewayRuntimeFunc func(context.Context, gateway.Route, gateway.Request) (gateway.Decision, error)

func (f gatewayRuntimeFunc) Evaluate(ctx context.Context, route gateway.Route, request gateway.Request) (gateway.Decision, error) {
	return f(ctx, route, request)
}

func TestLiveHealthReturnsRequestIDAndSecurityHeaders(t *testing.T) {
	server := &Server{CryptoMode: config.CryptoObserve}
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/health/live", nil))
	if response.Code != http.StatusOK || response.Header().Get("X-Request-ID") == "" {
		t.Fatalf("unexpected health response: %d %+v", response.Code, response.Header())
	}
	if response.Header().Get("X-Content-Type-Options") != "nosniff" || response.Header().Get("Cross-Origin-Resource-Policy") != "same-origin" || !strings.Contains(response.Body.String(), "live") {
		t.Fatal("health response is missing required headers or status")
	}
}

func TestGatewayHandlerCannotFallThroughToControlPlane(t *testing.T) {
	route := gateway.Route{
		Host: "app.customer.example", TenantID: "10000000-0000-4000-8000-000000000001",
		ApplicationID: "20000000-0000-4000-8000-000000000002", UpstreamURL: "http://127.0.0.1:8081",
	}
	proxy, err := gateway.New([]gateway.Route{route}, gatewayRuntimeFunc(func(context.Context, gateway.Route, gateway.Request) (gateway.Decision, error) {
		return gateway.Decision{Outcome: "allow"}, nil
	}), nil, nil, "development")
	if err != nil {
		t.Fatal("create gateway:", err)
	}
	server := &Server{Gateway: proxy, CryptoMode: config.CryptoObserve}
	request := httptest.NewRequest(http.MethodGet, "/health/live", nil)
	request.Host = "control.customer.example"
	response := httptest.NewRecorder()
	server.GatewayHandler().ServeHTTP(response, request)
	if response.Code != http.StatusNotFound || strings.Contains(response.Body.String(), `"status":"live"`) {
		t.Fatalf("gateway listener exposed a control-plane route: status=%d body=%s", response.Code, response.Body.String())
	}
	response = httptest.NewRecorder()
	server.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/health/live", nil))
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"status":"live"`) {
		t.Fatalf("control-plane listener failed its own liveness route: status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestReadyFailsClosedWhenDatabaseIsUnavailable(t *testing.T) {
	server := &Server{DB: fakePinger{err: errors.New("secret-bearing driver detail")}}
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/health/ready", nil))
	if response.Code != http.StatusServiceUnavailable || strings.Contains(response.Body.String(), "secret-bearing") {
		t.Fatalf("readiness did not fail safely: %d %s", response.Code, response.Body.String())
	}
}

func TestReadyFailsClosedWhenRequiredKeyProviderIsMissingOrUnavailable(t *testing.T) {
	for _, test := range []struct {
		name     string
		provider KeyProviderHealth
		required bool
	}{
		{name: "required provider missing", required: true},
		{name: "configured provider unavailable", provider: fakeKeyProvider{err: errors.New("credential-canary")}},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := &Server{DB: fakePinger{}, KeyProvider: test.provider, KeyProviderRequired: test.required}
			response := httptest.NewRecorder()
			server.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/health/ready", nil))
			if response.Code != http.StatusServiceUnavailable || strings.Contains(response.Body.String(), "credential-canary") {
				t.Fatalf("key provider failure should block readiness without leaking details: %d %s", response.Code, response.Body.String())
			}
		})
	}
}

func TestHybridModeRejectsClassicalOrPlaintextConnection(t *testing.T) {
	server := &Server{CryptoMode: config.CryptoHybrid}
	request := httptest.NewRequest(http.MethodGet, "/health/live", nil)
	request.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, CurveID: tls.X25519}
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), "HYBRID_REQUIRED") || response.Header().Get("X-Request-ID") == "" {
		t.Fatalf("expected identified hybrid-profile rejection, got %d %s", response.Code, response.Body.String())
	}
	request = httptest.NewRequest(http.MethodGet, "/health/live", nil)
	response = httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("expected plaintext request rejection, got %d", response.Code)
	}
}

func TestHybridModeAcceptsHybridTLSConnection(t *testing.T) {
	server := &Server{CryptoMode: config.CryptoHybrid}
	request := httptest.NewRequest(http.MethodGet, "/health/live", nil)
	request.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, CurveID: tls.X25519MLKEM768}
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("expected hybrid profile to pass, got %d: %s", response.Code, response.Body.String())
	}
}

func TestReadinessFailureLogsNoDriverError(t *testing.T) {
	var logOutput strings.Builder
	logger := slog.New(slog.NewTextHandler(&logOutput, nil))
	server := &Server{DB: fakePinger{err: errors.New("do-not-log-this")}, Logger: logger}
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/health/ready", nil))
	if strings.Contains(logOutput.String(), "do-not-log-this") {
		t.Fatal("driver detail leaked to logs")
	}
}
