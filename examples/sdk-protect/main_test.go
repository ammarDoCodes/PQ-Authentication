package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"quantumgate/internal/auth"
	"quantumgate/sdk/go/quantumgate"
)

type testIdentityVerifier struct {
	err   error
	calls int
}

func (v *testIdentityVerifier) Verify(_ context.Context, _ string) (auth.Principal, error) {
	v.calls++
	return auth.Principal{Issuer: "https://id.example", Subject: "existing-user"}, v.err
}

type testProtector struct {
	decision quantumgate.Decision
	err      error
	request  quantumgate.DecisionRequest
	calls    int
}

func (p *testProtector) Protect(_ context.Context, request quantumgate.DecisionRequest) (quantumgate.Decision, error) {
	p.calls++
	p.request = request
	return p.decision, p.err
}

func TestProtectedActionUsesExistingIdentityAndHonorsServerOutcome(t *testing.T) {
	for _, test := range []struct {
		name       string
		outcome    string
		wantStatus int
	}{
		{name: "allow", outcome: "allow", wantStatus: http.StatusOK},
		{name: "configured observe", outcome: "observe", wantStatus: http.StatusOK},
		{name: "configured degraded allowance", outcome: "degraded_allowed", wantStatus: http.StatusOK},
		{name: "deny", outcome: "deny", wantStatus: http.StatusForbidden},
		{name: "step up", outcome: "step_up", wantStatus: http.StatusUnauthorized},
		{name: "unknown response", outcome: "permit", wantStatus: http.StatusForbidden},
	} {
		t.Run(test.name, func(t *testing.T) {
			verifier := &testIdentityVerifier{}
			client := &testProtector{decision: quantumgate.Decision{Decision: test.outcome}}
			handler := newHandler(verifier, client)
			request := httptest.NewRequest(http.MethodGet, "/api/items", nil)
			request.Header.Set("Authorization", "Bearer existing-user-id-token")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.wantStatus || verifier.calls != 1 || client.calls != 1 {
				t.Fatalf("status=%d verifier_calls=%d protect_calls=%d, want %d/1/1", response.Code, verifier.calls, client.calls, test.wantStatus)
			}
			if client.request.Method != http.MethodGet || client.request.Path != "/api/items" || client.request.IdentityToken != "existing-user-id-token" {
				t.Fatalf("Protect received the wrong existing request context: %+v", client.request)
			}
		})
	}
}

func TestProtectedActionFailsClosedBeforeAndAfterDecisionCall(t *testing.T) {
	verifier := &testIdentityVerifier{err: errors.New("invalid identity")}
	client := &testProtector{decision: quantumgate.Decision{Decision: "allow"}}
	handler := newHandler(verifier, client)
	request := httptest.NewRequest(http.MethodGet, "/api/items", nil)
	request.Header.Set("Authorization", "Bearer existing-user-id-token")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized || client.calls != 0 {
		t.Fatalf("existing app authentication failure should stop before Protect: status=%d protect_calls=%d", response.Code, client.calls)
	}

	verifier.err = nil
	client.err = &quantumgate.APIError{StatusCode: http.StatusServiceUnavailable, Code: "PROFILE_NOT_APPROVED"}
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable || response.Body.String() == "" {
		t.Fatalf("unavailable or stale profile decision must block the protected action: status=%d body=%q", response.Code, response.Body.String())
	}
	if response.Code == http.StatusOK {
		t.Fatal("failed Protect call must never execute the protected action")
	}
}
