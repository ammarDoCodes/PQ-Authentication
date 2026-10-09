package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"quantumgate/internal/config"
)

func TestDashboardUsesLocalAssetsAndRestrictiveContentPolicy(t *testing.T) {
	server := &Server{CryptoMode: config.CryptoObserve}
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", nil))
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `src="/dashboard.js"`) {
		t.Fatalf("dashboard did not render its local application: %d %s", response.Code, response.Body.String())
	}
	policy := response.Header().Get("Content-Security-Policy")
	if !strings.Contains(policy, "script-src 'self'") || strings.Contains(policy, "unsafe-inline") || strings.Contains(policy, "https:") {
		t.Fatalf("dashboard CSP is too permissive: %q", policy)
	}
	for _, path := range []string{"/dashboard.js", "/dashboard.css"} {
		asset := httptest.NewRecorder()
		server.Handler().ServeHTTP(asset, httptest.NewRequest(http.MethodGet, path, nil))
		if asset.Code != http.StatusOK || strings.Contains(asset.Header().Get("Content-Type"), "text/html") {
			t.Fatalf("dashboard asset %s was not served with its own type: %d %s", path, asset.Code, asset.Header().Get("Content-Type"))
		}
	}
}
