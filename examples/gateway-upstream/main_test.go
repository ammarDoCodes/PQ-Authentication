package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"quantumgate/internal/auth"
)

type exampleVerifier struct {
	token string
}

func (v exampleVerifier) Verify(_ context.Context, token string) (auth.Principal, error) {
	if token != v.token {
		return auth.Principal{}, auth.ErrUnauthenticated
	}
	return auth.Principal{Issuer: "https://id.example", Subject: "user-1"}, nil
}

func TestItemsRequireApplicationIdentityAndReturnExistingResponse(t *testing.T) {
	handler := newHandler(exampleVerifier{token: "valid-test-token"})
	request := httptest.NewRequest(http.MethodGet, "/api/items", nil)
	request.Header.Set("Authorization", "Bearer valid-test-token")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"item-1"`) {
		t.Fatalf("valid application identity should reach the existing handler: %d %s", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), "valid-test-token") || strings.Contains(response.Body.String(), "user-1") {
		t.Fatal("example response must not expose the bearer token or raw subject")
	}
}

func TestItemsRejectMissingMalformedAndInvalidIdentity(t *testing.T) {
	handler := newHandler(exampleVerifier{token: "valid-test-token"})
	cases := []struct {
		name           string
		authorizations []string
	}{
		{name: "missing"},
		{name: "wrong scheme", authorizations: []string{"Basic valid-test-token"}},
		{name: "invalid token", authorizations: []string{"Bearer invalid-test-token"}},
		{name: "duplicate headers", authorizations: []string{"Bearer valid-test-token", "Bearer valid-test-token"}},
		{name: "oversized token", authorizations: []string{"Bearer " + strings.Repeat("x", 16<<10+1)}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/api/items", nil)
			for _, value := range testCase.authorizations {
				request.Header.Add("Authorization", value)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusUnauthorized || response.Header().Get("WWW-Authenticate") != "Bearer" {
				t.Fatalf("invalid application identity must fail closed: %d %v %s", response.Code, response.Header(), response.Body.String())
			}
		})
	}
	request := httptest.NewRequest(http.MethodGet, "/api/items", nil)
	request.Header.Set("Authorization", "Bearer valid-test-token")
	response := httptest.NewRecorder()
	newHandler(nil).ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("missing application verifier must fail closed: %d %s", response.Code, response.Body.String())
	}
}

func TestHealthDoesNotRequireIdentityAndAppListenAddressIsLoopbackOnly(t *testing.T) {
	response := httptest.NewRecorder()
	newHandler(nil).ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if response.Code != http.StatusNoContent {
		t.Fatalf("health endpoint should be available without an identity: %d", response.Code)
	}
	for _, address := range []string{"0.0.0.0:8081", "example.com:8081", "127.0.0.1:0", "127.0.0.1:not-a-port"} {
		if err := requireLoopbackAddress(address); err == nil {
			t.Errorf("unsafe listen address %q was accepted", address)
		}
	}
	if err := requireLoopbackAddress("127.0.0.1:8081"); err != nil {
		t.Fatalf("loopback listen address should be accepted: %v", err)
	}
}
