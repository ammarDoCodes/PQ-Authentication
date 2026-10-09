package quantumgate

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const testApplicationID = "40000000-0000-4000-8000-000000000004"

func TestClientUsesScopedCachedTokensAndIdempotentObservationWrites(t *testing.T) {
	var tokenRequests atomic.Int32
	var observationRequests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/oauth/token":
			tokenRequests.Add(1)
			clientID, secret, ok := r.BasicAuth()
			if !ok || clientID != testApplicationID || !validClientSecret(secret) || r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
				t.Errorf("token request did not use the expected client credentials: %#v", r.Header)
				http.Error(w, "bad auth", http.StatusUnauthorized)
				return
			}
			formBody, readErr := io.ReadAll(r.Body)
			form, err := url.ParseQuery(string(formBody))
			if readErr != nil || err != nil || form.Get("grant_type") != "client_credentials" || form.Get("scope") != "observations:write" {
				t.Errorf("unexpected OAuth form: %#v, %v, %v", form, readErr, err)
				http.Error(w, "bad form", http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": testOpaque("qgt_", 1), "token_type": "Bearer", "expires_in": 300, "scope": "observations:write",
			})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/applications/"+testApplicationID+"/observations":
			observationRequests.Add(1)
			if r.Header.Get("Authorization") != "Bearer "+testOpaque("qgt_", 1) || !validIdempotencyKey(r.Header.Get("Idempotency-Key")) {
				t.Errorf("observation request is missing its access token or idempotency key")
				http.Error(w, "bad auth", http.StatusUnauthorized)
				return
			}
			var body struct {
				Source string `json:"source"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Source != "test-sdk" {
				t.Errorf("unexpected observation JSON: %+v, %v", body, err)
				http.Error(w, "bad observation", http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(Accepted{
				ObservationID: fmt.Sprintf("60000000-0000-4000-8000-%012d", observationRequests.Load()),
				ApplicationID: testApplicationID,
				ObservedAt:    time.Now().UTC(),
				RequestID:     "test-request",
			})
		case r.Method == http.MethodGet && r.URL.Path == "/health/ready":
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "ready"})
		default:
			t.Errorf("unexpected SDK request: %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := NewClient(Config{
		Endpoint: server.URL, ApplicationID: testApplicationID,
		ClientSecret: testOpaque("qgc_", 2),
	})
	if err != nil {
		t.Fatal("create client:", err)
	}
	observation := Observation{
		Source: "test-sdk", Protocol: "TLS 1.3", AlgorithmProfile: "tls13-classical", Confidence: "high",
		Evidence: ObservationEvidence{KeyExchange: "X25519"},
	}
	for range 2 {
		accepted, err := client.Observe(context.Background(), observation)
		if err != nil || accepted.ApplicationID != testApplicationID || accepted.ObservationID == "" {
			t.Fatalf("observation was not accepted: %+v, %v", accepted, err)
		}
	}
	if tokenRequests.Load() != 1 || observationRequests.Load() != 2 {
		t.Fatalf("expected cached token and two telemetry writes, got tokens=%d observations=%d", tokenRequests.Load(), observationRequests.Load())
	}
	if err := client.Health(context.Background()); err != nil {
		t.Fatalf("health request failed: %v", err)
	}
}

func TestNewClientRejectsInsecureRemoteEndpointAndUnsafeCredentials(t *testing.T) {
	secret := testOpaque("qgc_", 7)
	if _, err := NewClient(Config{Endpoint: "http://api.example", ApplicationID: testApplicationID, ClientSecret: secret}); err == nil {
		t.Fatal("remote plaintext endpoint should be rejected")
	}
	if _, err := NewClient(Config{Endpoint: "https://api.example", TenantID: "not-a-tenant", ApplicationID: testApplicationID, ClientSecret: secret}); err == nil {
		t.Fatal("malformed tenant configuration should be rejected")
	}
	if _, err := NewClient(Config{Endpoint: "https://api.example", TenantID: testTenantID, ApplicationID: "not-an-application", ClientSecret: secret}); err == nil {
		t.Fatal("malformed application configuration should be rejected")
	}
	if _, err := NewClient(Config{Endpoint: "https://api.example", ApplicationID: testApplicationID, ClientSecret: "qgc_short"}); err == nil {
		t.Fatal("malformed client secret should be rejected")
	}
	if _, err := NewClient(Config{Endpoint: "https://user:pass@api.example", ApplicationID: testApplicationID, ClientSecret: secret}); err == nil {
		t.Fatal("endpoint credentials should be rejected")
	}
}

func TestIdempotencyKeyValidation(t *testing.T) {
	if !validIdempotencyKey("observation-key-0001") {
		t.Fatal("safe idempotency key was rejected")
	}
	for _, key := range []string{"short", strings.Repeat("a", 129), "has space 123456789"} {
		if validIdempotencyKey(key) {
			t.Errorf("unsafe idempotency key accepted: %q", key)
		}
	}
}

func TestProtectUsesScopedTokenAndReturnsServerDecisionWithoutLocalPolicy(t *testing.T) {
	var tokenRequests, decisionRequests atomic.Int32
	client := newProtectTestClient(t, func(request *http.Request) (*http.Response, error) {
		switch request.URL.Path {
		case "/oauth/token":
			tokenRequests.Add(1)
			user, secret, ok := request.BasicAuth()
			body, readErr := io.ReadAll(request.Body)
			form, parseErr := url.ParseQuery(string(body))
			if !ok || user != testApplicationID || !validClientSecret(secret) || readErr != nil || parseErr != nil || form.Get("scope") != "decisions:evaluate" {
				t.Errorf("decision token request was not correctly scoped: basic=%v form=%v", ok, form)
				return testHTTPResponse(request, http.StatusBadRequest, `{"code":"BAD_TOKEN_REQUEST"}`, nil), nil
			}
			return testHTTPResponse(request, http.StatusOK, `{"access_token":"`+testOpaque("qgt_", 4)+`","token_type":"Bearer","expires_in":300,"scope":"decisions:evaluate"}`, nil), nil
		case "/v1/applications/" + testApplicationID + "/decisions":
			call := decisionRequests.Add(1)
			body, err := io.ReadAll(request.Body)
			var input map[string]any
			if err := json.Unmarshal(body, &input); err != nil || input["method"] != "GET" || input["path"] != "/api/items" || input["identity_token"] != "existing-id-token" || len(input) != 3 {
				t.Errorf("decision request must contain only the validated action and existing identity token: %s (%v)", body, err)
			}
			if err != nil || request.Header.Get("Authorization") != "Bearer "+testOpaque("qgt_", 4) ||
				request.Header.Get("Content-Type") != "application/json" || request.Header.Get("Idempotency-Key") != "" {
				t.Errorf("decision call has invalid authentication or replay behavior: body_error=%v headers=%v", err, request.Header)
			}
			if strings.Contains(string(body), "tenant_id") || strings.Contains(string(body), "application_id") {
				t.Error("tenant and application must be derived from SDK configuration and the scoped token")
			}
			outcome := "allow"
			if call == 2 {
				outcome = "deny"
			}
			requestID := fmt.Sprintf("server-request-%03d", call)
			response := testHTTPResponse(request, http.StatusOK, testDecisionJSON(outcome, requestID), map[string]string{
				"X-Request-ID": requestID, "X-QG-Transport-Profile": "tls13-classical",
				"X-QG-Policy-Revision": "90000000-0000-4000-8000-000000000009",
			})
			return response, nil
		default:
			t.Errorf("unexpected Protect request: %s %s", request.Method, request.URL.Path)
			return testHTTPResponse(request, http.StatusNotFound, "{}", nil), nil
		}
	})
	defer client.httpClient.CloseIdleConnections()
	input := DecisionRequest{Method: "GET", Path: "/api/items", IdentityToken: "existing-id-token"}
	for index, expected := range []string{"allow", "deny"} {
		decision, err := client.Protect(context.Background(), input)
		if err != nil || decision.Decision != expected || decision.RequestID == "" || decision.ApplicationID != testApplicationID || decision.TenantID != testTenantID {
			t.Fatalf("Protect result %d = %+v, %v; want server outcome %q", index, decision, err, expected)
		}
	}
	if tokenRequests.Load() != 1 || decisionRequests.Load() != 2 {
		t.Fatalf("scope token should be cached while every decision is freshly evaluated, tokens=%d decisions=%d", tokenRequests.Load(), decisionRequests.Load())
	}
}

func TestProtectFailsClosedOnConfigurationAndContextErrors(t *testing.T) {
	var calls atomic.Int32
	client := newProtectTestClient(t, func(request *http.Request) (*http.Response, error) {
		calls.Add(1)
		if request.URL.Path == "/oauth/token" {
			return testHTTPResponse(request, http.StatusOK, `{"access_token":"`+testOpaque("qgt_", 9)+`","token_type":"Bearer","expires_in":300,"scope":"decisions:evaluate"}`, nil), nil
		}
		return testHTTPResponse(request, http.StatusOK, `{}`, nil), nil
	})
	defer client.httpClient.CloseIdleConnections()
	if _, err := client.Protect(context.Background(), DecisionRequest{Method: "GET", Path: "/api/items", IdentityToken: "token"}); err == nil {
		t.Fatal("malformed decision response must fail closed")
	}
	if calls.Load() != 2 {
		t.Fatalf("request should fetch one access token and one decision, got %d calls", calls.Load())
	}
	client.tenantID = ""
	if _, err := client.Protect(context.Background(), DecisionRequest{Method: "GET", Path: "/api/items", IdentityToken: "token"}); err == nil {
		t.Fatal("Protect must require an expected tenant binding")
	}
	if calls.Load() != 2 {
		t.Fatal("invalid configuration should fail before network access")
	}
	for _, request := range []DecisionRequest{
		{Method: "TRACE", Path: "/api/items", IdentityToken: "token"},
		{Method: "GET", Path: "/api/items?tenant=other", IdentityToken: "token"},
		{Method: "GET", Path: "/api/items", IdentityToken: ""},
	} {
		client.tenantID = testTenantID
		if _, err := client.Protect(context.Background(), request); err == nil {
			t.Errorf("invalid request context should fail closed: %+v", request)
		}
	}
	plainHTTP, err := NewClient(Config{Endpoint: "http://localhost:8080", TenantID: testTenantID, ApplicationID: testApplicationID, ClientSecret: testOpaque("qgc_", 5)})
	if err != nil {
		t.Fatal("construct allowed loopback development client:", err)
	}
	if _, err := plainHTTP.Protect(context.Background(), DecisionRequest{Method: "GET", Path: "/api/items", IdentityToken: "token"}); err == nil {
		t.Fatal("Protect must reject a plaintext endpoint")
	}
}

func TestProtectRejectsMalformedOrMismatchedResponses(t *testing.T) {
	for name, body := range map[string]string{
		"wrong tenant":       strings.Replace(testDecisionJSON("allow", "server-request-001"), testTenantID, "50000000-0000-4000-8000-000000000005", 1),
		"wrong application":  strings.Replace(testDecisionJSON("allow", "server-request-001"), testApplicationID, "50000000-0000-4000-8000-000000000005", 1),
		"wrong action":       strings.Replace(testDecisionJSON("allow", "server-request-001"), `"path":"/api/items"`, `"path":"/api/admin"`, 1),
		"unknown decision":   strings.Replace(testDecisionJSON("allow", "server-request-001"), `"decision":"allow"`, `"decision":"permit"`, 1),
		"missing reason":     strings.Replace(testDecisionJSON("allow", "server-request-001"), `"reason_codes":["POLICY_MATCH"]`, `"reason_codes":[]`, 1),
		"malformed profile":  strings.Replace(testDecisionJSON("allow", "server-request-001"), strings.Repeat("a", 64), "not-a-profile-hash", 1),
		"missing revision":   strings.Replace(testDecisionJSON("allow", "server-request-001"), "90000000-0000-4000-8000-000000000009", "bad", 1),
		"mismatched request": strings.Replace(testDecisionJSON("allow", "server-request-001"), `"method":"GET"`, `"method":"POST"`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			client := newProtectTestClient(t, func(request *http.Request) (*http.Response, error) {
				if request.URL.Path == "/oauth/token" {
					return testHTTPResponse(request, http.StatusOK, `{"access_token":"`+testOpaque("qgt_", 6)+`","token_type":"Bearer","expires_in":300,"scope":"decisions:evaluate"}`, nil), nil
				}
				return testHTTPResponse(request, http.StatusOK, body, map[string]string{
					"X-Request-ID": "server-request-001", "X-QG-Transport-Profile": "tls13-classical",
					"X-QG-Policy-Revision": "90000000-0000-4000-8000-000000000009",
				}), nil
			})
			defer client.httpClient.CloseIdleConnections()
			if _, err := client.Protect(context.Background(), DecisionRequest{Method: "GET", Path: "/api/items", IdentityToken: "existing-id-token"}); err == nil {
				t.Fatal("mismatched response must fail closed")
			}
		})
	}

	t.Run("mismatched response transport headers", func(t *testing.T) {
		client := newProtectTestClient(t, func(request *http.Request) (*http.Response, error) {
			if request.URL.Path == "/oauth/token" {
				return testHTTPResponse(request, http.StatusOK, `{"access_token":"`+testOpaque("qgt_", 6)+`","token_type":"Bearer","expires_in":300,"scope":"decisions:evaluate"}`, nil), nil
			}
			return testHTTPResponse(request, http.StatusOK, testDecisionJSON("allow", "server-request-001"), map[string]string{
				"X-Request-ID": "server-request-001", "X-QG-Transport-Profile": "tls13-x25519-mlkem768",
				"X-QG-Policy-Revision": "90000000-0000-4000-8000-000000000009",
			}), nil
		})
		defer client.httpClient.CloseIdleConnections()
		if _, err := client.Protect(context.Background(), DecisionRequest{Method: "GET", Path: "/api/items", IdentityToken: "existing-id-token"}); err == nil {
			t.Fatal("response profile mismatch must fail closed")
		}
	})
}

func TestProtectFailsClosedForTimeoutAndUnapprovedProfile(t *testing.T) {
	secret := "identity-token-canary-should-not-appear-in-errors"
	client := newProtectTestClient(t, func(request *http.Request) (*http.Response, error) {
		if request.URL.Path == "/oauth/token" {
			return testHTTPResponse(request, http.StatusOK, `{"access_token":"`+testOpaque("qgt_", 7)+`","token_type":"Bearer","expires_in":300,"scope":"decisions:evaluate"}`, nil), nil
		}
		body, readErr := io.ReadAll(request.Body)
		var input DecisionRequest
		if readErr != nil || json.Unmarshal(body, &input) != nil {
			t.Errorf("read decision body: %v", readErr)
		}
		if input.Path == "/slow" {
			<-request.Context().Done()
			return nil, request.Context().Err()
		}
		return testHTTPResponse(request, http.StatusServiceUnavailable,
			`{"status":503,"code":"PROFILE_NOT_APPROVED","detail":"`+secret+`"}`, nil), nil
	})
	defer client.httpClient.CloseIdleConnections()
	client.httpClient.Timeout = 15 * time.Millisecond
	if _, err := client.Protect(context.Background(), DecisionRequest{Method: "GET", Path: "/slow", IdentityToken: secret}); err == nil {
		t.Fatal("decision timeout must fail closed")
	}
	client.httpClient.Timeout = time.Second
	_, err := client.Protect(context.Background(), DecisionRequest{Method: "GET", Path: "/api/items", IdentityToken: secret})
	var apiError *APIError
	if !errors.As(err, &apiError) || apiError.Code != "PROFILE_NOT_APPROVED" || apiError.Detail != "" || strings.Contains(err.Error(), secret) {
		t.Fatalf("unapproved profile must be a safe API error without decision or secret: %#v, %v", apiError, err)
	}
}

func testOpaque(prefix string, seed byte) string {
	decoded := make([]byte, 32)
	for index := range decoded {
		decoded[index] = seed
	}
	return prefix + base64.RawURLEncoding.EncodeToString(decoded)
}

const testTenantID = "30000000-0000-4000-8000-000000000003"

type testRoundTripper func(*http.Request) (*http.Response, error)

func (roundTrip testRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	return roundTrip(request)
}

func newProtectTestClient(t *testing.T, roundTrip testRoundTripper) *Client {
	t.Helper()
	client, err := NewClient(Config{
		Endpoint: "https://quantumgate.test", TenantID: testTenantID, ApplicationID: testApplicationID,
		ClientSecret: testOpaque("qgc_", 8),
	})
	if err != nil {
		t.Fatal("create Protect test client:", err)
	}
	client.httpClient = &http.Client{Transport: roundTrip, Timeout: defaultTimeout}
	return client
}

func testHTTPResponse(request *http.Request, status int, body string, headers map[string]string) *http.Response {
	responseHeaders := make(http.Header)
	responseHeaders.Set("Content-Type", "application/json")
	for name, value := range headers {
		responseHeaders.Set(name, value)
	}
	return &http.Response{
		StatusCode: status, Header: responseHeaders, Body: io.NopCloser(strings.NewReader(body)), Request: request,
		TLS: &tls.ConnectionState{Version: tls.VersionTLS13, CurveID: tls.X25519},
	}
}

func testDecisionJSON(outcome, requestID string) string {
	return `{"request_id":"` + requestID + `","tenant_id":"` + testTenantID + `","application_id":"` + testApplicationID +
		`","method":"GET","path":"/api/items","profile_id":"tls13-classical","profile_registry_version":1,"profile_hash":"` + strings.Repeat("a", 64) +
		`","policy_revision_id":"90000000-0000-4000-8000-000000000009","mode":"classical-approved","decision":"` + outcome +
		`","reason_codes":["POLICY_MATCH"]}`
}
