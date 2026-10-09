package httpapi

import (
	"testing"
	"time"
)

func validClassicalPolicy() policyDocument {
	return policyDocument{
		Mode: "classical-approved", AllowedProfiles: []string{"tls13-classical"}, Fallback: "deny", StaleBehavior: "observe",
		RouteRules:           []policyRouteRule{{Method: "GET", PathPrefix: "/api/", AllowedProfiles: []string{"tls13-classical"}}},
		IdentityRequirements: policyIdentityRequirements{RequiredACRs: []string{"urn:example:mfa"}},
		Exceptions:           []policyException{}, EffectiveWindow: &policyWindow{},
	}
}

func TestValidatePolicyDocumentAcceptsOnlyCuratedModeProfiles(t *testing.T) {
	now := time.Now().UTC()
	document := validClassicalPolicy()
	if err := validatePolicyDocument(document, now); err != nil {
		t.Fatalf("valid policy rejected: %v", err)
	}
	document.AllowedProfiles = []string{"tls13-x25519-mlkem768"}
	if err := validatePolicyDocument(document, now); err == nil {
		t.Fatal("classical policy accepted the hybrid profile")
	}
	document = validClassicalPolicy()
	document.AllowedProfiles = []string{"unreviewed-custom-profile"}
	if err := validatePolicyDocument(document, now); err == nil {
		t.Fatal("policy accepted a profile outside the curated registry")
	}
	document = validClassicalPolicy()
	document.Mode = "pqc-approved"
	document.AllowedProfiles = []string{"tls13-classical"}
	if err := validatePolicyDocument(document, now); err == nil {
		t.Fatal("policy accepted unsupported pure-PQC mode")
	}
}

func TestValidatePolicyDocumentRequiresExplicitCollectionsAndBoundaries(t *testing.T) {
	now := time.Now().UTC()
	document := validClassicalPolicy()
	document.IdentityRequirements.RequiredACRs = nil
	if err := validatePolicyDocument(document, now); err == nil {
		t.Fatal("missing identity_requirements.required_acrs was accepted")
	}
	document = validClassicalPolicy()
	document.RouteRules = []policyRouteRule{{Method: "GET", PathPrefix: "/api/?tenant=*", AllowedProfiles: []string{"tls13-classical"}}}
	if err := validatePolicyDocument(document, now); err == nil {
		t.Fatal("route rule accepted query syntax")
	}
	document = validClassicalPolicy()
	document.EffectiveWindow = &policyWindow{StartsAt: timePointer(now.Add(time.Hour)), EndsAt: timePointer(now)}
	if err := validatePolicyDocument(document, now); err == nil {
		t.Fatal("empty effective window was accepted")
	}
	document = validClassicalPolicy()
	document.Exceptions = []policyException{{Method: "POST", PathPrefix: "/api/legacy", AllowedProfiles: []string{"tls13-classical"},
		Owner: "team", Reason: "migration", ExpiresAt: now.Add(time.Hour), CompensatingControl: "manual approval"}}
	if err := validatePolicyDocument(document, now); err != nil {
		t.Fatalf("valid bounded migration exception rejected: %v", err)
	}
}

func TestEvaluatePolicyUsesExplicitFallbackStepUpAndExceptionDecisions(t *testing.T) {
	document := validClassicalPolicy()
	now := time.Now().UTC()
	decision, reasons := evaluatePolicy(document, "GET", "/api/items", "tls13-classical", "urn:example:mfa", now)
	if decision != "allow" || len(reasons) != 1 || reasons[0] != "POLICY_MATCH" {
		t.Fatalf("valid policy context got %q %v", decision, reasons)
	}
	decision, reasons = evaluatePolicy(document, "GET", "/api/items", "tls13-classical", "urn:example:password", now)
	if decision != "step_up" || reasons[0] != "IDENTITY_STEP_UP_REQUIRED" {
		t.Fatalf("weak identity context got %q %v", decision, reasons)
	}
	decision, reasons = evaluatePolicy(document, "POST", "/api/items", "tls13-classical", "urn:example:mfa", now)
	if decision != "deny" || reasons[0] != "NO_ROUTE_RULE" {
		t.Fatalf("unmatched route got %q %v", decision, reasons)
	}
	document.Exceptions = []policyException{{Method: "POST", PathPrefix: "/api/legacy", AllowedProfiles: []string{"tls13-x25519-mlkem768"},
		Owner: "team", Reason: "migration", ExpiresAt: now.Add(time.Hour), CompensatingControl: "manual approval"}}
	decision, reasons = evaluatePolicy(document, "POST", "/api/legacy", "tls13-x25519-mlkem768", "urn:example:mfa", now)
	if decision != "degraded_allowed" || reasons[0] != "MIGRATION_EXCEPTION_ACTIVE" {
		t.Fatalf("bounded exception got %q %v", decision, reasons)
	}
	document.Mode = "observe-only"
	decision, reasons = evaluatePolicy(document, "POST", "/unlisted", "tls13-x25519-mlkem768", "", now)
	if decision != "observe" || reasons[0] != "OBSERVE_ONLY" {
		t.Fatalf("observe-only policy got %q %v", decision, reasons)
	}
}

func TestPolicyPathAndIdentityInputsRejectAmbiguousValues(t *testing.T) {
	for _, path := range []string{"", "api/items", "/api/items?x=1", "/api/%2fadmin", "/api/../admin", "/api/with space", "/api\\admin"} {
		if validPolicyPath(path) {
			t.Errorf("ambiguous policy path accepted: %q", path)
		}
	}
	if !validPolicyPath("/api/v1/items") || !validBoundedToken("urn:example:mfa", 512) {
		t.Fatal("ordinary route and ACR values should be accepted")
	}
	if validBoundedToken("urn:example:bad\ncontext", 512) {
		t.Fatal("invalid policy identity context was accepted")
	}
}

func TestPolicyETagChangesWithLifecycleVersion(t *testing.T) {
	id := "10000000-0000-4000-8000-000000000001"
	first := policyETag(id, 1)
	second := policyETag(id, 2)
	if first == second || first == "" || first[0] != '"' || first[len(first)-1] != '"' {
		t.Fatalf("policy ETag must be quoted and advance with lifecycle version: %q %q", first, second)
	}
}

func timePointer(value time.Time) *time.Time { return &value }
