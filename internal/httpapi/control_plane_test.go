package httpapi

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestValidUUIDRejectsMalformedIdentifiers(t *testing.T) {
	for _, value := range []string{
		"10000000-0000-4000-8000-000000000001",
		"ffffffff-ffff-ffff-ffff-ffffffffffff",
	} {
		if !validUUID(value) {
			t.Errorf("valid UUID rejected: %q", value)
		}
	}
	for _, value := range []string{
		"", "10000000-0000-4000-8000-00000000000g", "10000000-0000-4000-8000-000000000001/extra",
		"10000000000040008000000000000001", " 10000000-0000-4000-8000-000000000001",
	} {
		if validUUID(value) {
			t.Errorf("malformed UUID accepted: %q", value)
		}
	}
}

func TestExternalIDsAndLabelsAreBoundedAndRejectControls(t *testing.T) {
	if !validExternalID("legacy.api:v2") || !validLabel("Existing application", 120) {
		t.Fatal("expected ordinary application metadata to be valid")
	}
	for _, value := range []string{"x\r\nheader", "bad/path", strings.Repeat("a", 129), "\x00"} {
		if validExternalID(value) {
			t.Errorf("unsafe external ID accepted: %q", value)
		}
	}
	for _, value := range []string{" padded", "line\nfeed", strings.Repeat("a", 121)} {
		if validLabel(value, 120) {
			t.Errorf("unsafe label accepted: %q", value)
		}
	}
}

func TestBearerTokenRequiresSingleBoundedBearerHeader(t *testing.T) {
	tests := []struct {
		name   string
		values []string
		valid  bool
	}{
		{name: "valid", values: []string{"Bearer signed.jwt.value"}, valid: true},
		{name: "wrong scheme", values: []string{"Basic signed.jwt.value"}},
		{name: "extra spaces", values: []string{"Bearer signed.jwt.value more"}},
		{name: "empty", values: []string{"Bearer "}},
		{name: "duplicate", values: []string{"Bearer one", "Bearer two"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/v1/tenants/10000000-0000-4000-8000-000000000001", nil)
			for _, value := range test.values {
				r.Header.Add("Authorization", value)
			}
			_, valid := bearerToken(r)
			if valid != test.valid {
				t.Fatalf("bearer validity = %v, want %v", valid, test.valid)
			}
		})
	}
	tooLong := httptest.NewRequest(http.MethodGet, "/v1/tenants/10000000-0000-4000-8000-000000000001", nil)
	tooLong.Header.Set("Authorization", "Bearer "+strings.Repeat("x", maxBearerTokenBytes+1))
	if _, ok := bearerToken(tooLong); ok {
		t.Fatal("oversized bearer token accepted")
	}
}

func TestIdempotencyKeysAreSingleBoundedAndHeaderSafe(t *testing.T) {
	valid := "request-key-00000001"
	if key, ok := validateIdempotencyKey([]string{valid}); !ok || key != valid {
		t.Fatalf("valid idempotency key rejected: %q, %v", key, ok)
	}
	for _, values := range [][]string{
		{}, {valid, valid}, {"short"}, {strings.Repeat("a", 129)}, {"request key 0000001"}, {"request-key-0000001\r\n"},
	} {
		if _, ok := validateIdempotencyKey(values); ok {
			t.Errorf("invalid idempotency key accepted: %#v", values)
		}
	}
}

func TestIdempotencyHashesAreScopedAndLengthDelimited(t *testing.T) {
	principal := tenantPrincipal{TenantID: "tenant", Issuer: "issuer", Subject: "subject"}
	one := idempotencyKeyDigest(principal, "client-key")
	principal.TenantID = "other-tenant"
	if string(one) == string(idempotencyKeyDigest(principal, "client-key")) {
		t.Fatal("idempotency key hash must be tenant scoped")
	}
	if string(encodeHashFields([]byte("ab"), []byte("c"))) == string(encodeHashFields([]byte("a"), []byte("bc"))) {
		t.Fatal("hash field encoding must preserve field boundaries")
	}
}

func TestIdempotencyBodiesAreEncryptedAndBoundToTheirRecord(t *testing.T) {
	server := &Server{RateLimitKey: []byte(strings.Repeat("k", 32))}
	plain := []byte(`{"client_secret":"credential-secret"}`)
	keyHash := bytes.Repeat([]byte{0x42}, 32)
	stored, err := server.sealIdempotentBody(plain, "tenant-a", keyHash)
	if err != nil {
		t.Fatal("seal idempotency response:", err)
	}
	if !bytes.HasPrefix(stored, idempotencyBodyPrefix) || bytes.Contains(stored, []byte("credential-secret")) {
		t.Fatal("idempotency response was not stored as ciphertext")
	}
	opened, err := server.openIdempotentBody(stored, "tenant-a", keyHash)
	if err != nil || !bytes.Equal(opened, plain) {
		t.Fatalf("encrypted response did not round-trip: %q, %v", opened, err)
	}
	if _, err := server.openIdempotentBody(stored, "tenant-b", keyHash); err == nil {
		t.Fatal("ciphertext was accepted under another tenant")
	}
	tampered := append([]byte(nil), stored...)
	tampered[len(tampered)-1] ^= 1
	if _, err := server.openIdempotentBody(tampered, "tenant-a", keyHash); err == nil {
		t.Fatal("tampered ciphertext was accepted")
	}
	legacy := []byte(`{"status":"ok"}`)
	opened, err = server.openIdempotentBody(legacy, "tenant-a", keyHash)
	if err != nil || !bytes.Equal(opened, legacy) {
		t.Fatalf("pre-encryption response compatibility failed: %q, %v", opened, err)
	}
}

func TestApplicationCredentialScopesAreNarrowAndUnique(t *testing.T) {
	if !validApplicationCredentialScopes([]string{"decisions:evaluate", "posture:read"}) {
		t.Fatal("allowed credential scopes were rejected")
	}
	for _, scopes := range [][]string{
		{}, {"unknown:admin"}, {"decisions:evaluate", "decisions:evaluate"}, {"events:write", "posture:read", "observations:write", "decisions:evaluate", "extra"},
	} {
		if validApplicationCredentialScopes(scopes) {
			t.Errorf("invalid credential scopes accepted: %#v", scopes)
		}
	}
	if scopes, ok := parseOAuthScope("decisions:evaluate posture:read"); !ok || len(scopes) != 2 {
		t.Fatalf("valid OAuth scope string was rejected: %#v, %v", scopes, ok)
	}
	if _, ok := parseOAuthScope("decisions:evaluate  posture:read"); ok {
		t.Fatal("duplicate separators in OAuth scope string were accepted")
	}
}

func TestOAuthCredentialAndScopeParsing(t *testing.T) {
	secret := "qgc_" + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0}, 32))
	token := "qgt_" + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	if !validOpaqueCredential(secret) || validOpaqueCredential("qgc_short") || validOpaqueCredential("bad_"+strings.Repeat("a", 43)) ||
		!validOpaqueAccessToken(token) || validOpaqueAccessToken("qgt_short") {
		t.Fatal("opaque credential shape validation failed")
	}
	form := url.Values{"grant_type": {"client_credentials"}, "scope": {"decisions:evaluate"}}
	if !onlyOAuthFormFields(form) || onlyOAuthFormFields(url.Values{"grant_type": {"client_credentials"}, "scope": {"decisions:evaluate"}, "client_secret": {"leak"}}) {
		t.Fatal("OAuth form field allowlist validation failed")
	}
	if !scopesSubset([]string{"decisions:evaluate"}, []string{"decisions:evaluate", "posture:read"}) ||
		scopesSubset([]string{"events:write"}, []string{"decisions:evaluate"}) {
		t.Fatal("OAuth scope grant subset validation failed")
	}
}

func TestCookieMutationRequiresSameOriginDoubleSubmitCSRF(t *testing.T) {
	csrf := strings.Repeat("c", 43)
	request := httptest.NewRequest(http.MethodPost, "/v1/resource", nil)
	request.AddCookie(&http.Cookie{Name: csrfCookieName, Value: csrf})
	request.Header.Set("Origin", "https://console.example")
	request.Header.Set("X-QG-CSRF-Token", csrf)
	server := &Server{PublicOrigin: "https://console.example"}
	if !server.validCSRFRequest(request, hashToken(csrf)) {
		t.Fatal("valid same-origin CSRF token was rejected")
	}
	request.Header.Set("Origin", "https://attacker.example")
	if server.validCSRFRequest(request, hashToken(csrf)) {
		t.Fatal("cross-origin request was accepted")
	}
	request.Header.Set("Origin", "https://console.example")
	request.Header.Set("X-QG-CSRF-Token", strings.Repeat("x", 43))
	if server.validCSRFRequest(request, hashToken(csrf)) {
		t.Fatal("mismatched CSRF header was accepted")
	}
}

func TestSessionCookieRejectsDuplicateCookieHeaders(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Add("Cookie", sessionCookieName+"=one")
	request.Header.Add("Cookie", sessionCookieName+"=two")
	if !hasCookie(request, sessionCookieName) {
		t.Fatal("expected duplicated session cookie to be detected")
	}
	if _, ok := uniqueCookie(request, sessionCookieName); ok {
		t.Fatal("duplicated session cookie was accepted")
	}
}

func TestControlJSONRequiresOneJSONContentTypeBody(t *testing.T) {
	target := struct {
		Name string `json:"name"`
	}{}
	tests := []struct {
		name        string
		contentType []string
		body        string
		wantErr     bool
	}{
		{name: "valid", contentType: []string{"application/json"}, body: `{"name":"api"}`},
		{name: "unknown field", contentType: []string{"application/json"}, body: `{"name":"api","role":"admin"}`, wantErr: true},
		{name: "multiple documents", contentType: []string{"application/json"}, body: `{"name":"api"}{"name":"other"}`, wantErr: true},
		{name: "wrong media type", contentType: []string{"text/plain"}, body: `{"name":"api"}`, wantErr: true},
		{name: "duplicate media type", contentType: []string{"application/json", "application/json"}, body: `{"name":"api"}`, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/v1/tenants/id/applications", strings.NewReader(test.body))
			for _, value := range test.contentType {
				r.Header.Add("Content-Type", value)
			}
			err := decodeControlJSON(httptest.NewRecorder(), r, &target)
			if (err != nil) != test.wantErr {
				t.Fatalf("decode error = %v, wantErr %v", err, test.wantErr)
			}
		})
	}
}

func TestControlPlaneFailsClosedWhenDependenciesAreAbsent(t *testing.T) {
	server := &Server{}
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/v1/tenants/10000000-0000-4000-8000-000000000001", nil)
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), "CONTROL_PLANE_UNAVAILABLE") {
		t.Fatalf("control plane did not fail closed: %d %s", response.Code, response.Body.String())
	}
}
