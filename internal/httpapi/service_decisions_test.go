package httpapi

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestValidDecisionRequestRequiresBoundedIdentityAndActionContext(t *testing.T) {
	valid := decisionRequest{
		Method: "GET", Path: "/api/items", IdentityToken: "existing-application-id-token",
	}
	if !validDecisionRequest(valid) {
		t.Fatal("well-formed protected action context should be accepted")
	}
	for name, mutate := range map[string]func(*decisionRequest){
		"missing method":      func(input *decisionRequest) { input.Method = "" },
		"unknown method":      func(input *decisionRequest) { input.Method = "TRACE" },
		"missing path":        func(input *decisionRequest) { input.Path = "" },
		"query string":        func(input *decisionRequest) { input.Path = "/api/items?tenant=other" },
		"encoded path":        func(input *decisionRequest) { input.Path = "/api/%2fitems" },
		"path traversal":      func(input *decisionRequest) { input.Path = "/api/../admin" },
		"control in path":     func(input *decisionRequest) { input.Path = "/api/\r\nitems" },
		"missing identity":    func(input *decisionRequest) { input.IdentityToken = "" },
		"whitespace identity": func(input *decisionRequest) { input.IdentityToken = "token with spaces" },
		"oversized identity":  func(input *decisionRequest) { input.IdentityToken = strings.Repeat("t", (16<<10)+1) },
	} {
		t.Run(name, func(t *testing.T) {
			input := valid
			mutate(&input)
			if validDecisionRequest(input) {
				t.Fatal("malformed decision request should be rejected")
			}
		})
	}
}

func TestDecodeDecisionControlJSONRejectsMalformedEnvelopes(t *testing.T) {
	validBody := `{"method":"GET","path":"/api/items","identity_token":"existing-application-id-token"}`
	tests := []struct {
		name        string
		contentType string
		body        string
	}{
		{name: "valid JSON media type parameters", contentType: "application/json; charset=utf-8", body: validBody},
		{name: "missing media type", body: validBody},
		{name: "multiple media types", contentType: "application/json, application/json", body: validBody},
		{name: "wrong media type", contentType: "text/plain", body: validBody},
		{name: "unknown field", contentType: "application/json", body: `{"method":"GET","path":"/api/items","identity_token":"existing-application-id-token","tenant_id":"forged"}`},
		{name: "trailing JSON value", contentType: "application/json", body: validBody + ` {}`},
		{name: "truncated JSON", contentType: "application/json", body: `{"method":`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest("POST", "/", strings.NewReader(test.body))
			if test.contentType != "" {
				request.Header.Set("Content-Type", test.contentType)
			}
			var decoded decisionRequest
			err := decodeControlJSON(httptest.NewRecorder(), request, &decoded)
			if test.name == "valid JSON media type parameters" {
				if err != nil || decoded.Method != "GET" || decoded.Path != "/api/items" {
					t.Fatalf("well-formed decision body should decode: %+v, %v", decoded, err)
				}
				return
			}
			if err == nil {
				t.Fatal("malformed decision envelope must be rejected")
			}
		})
	}
}
