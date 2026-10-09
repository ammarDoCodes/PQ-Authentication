package httpapi

import "testing"

func TestValidOIDCIssuerRequiresExactAllowlistedHTTPSHost(t *testing.T) {
	allowed := []string{"login.example", "keys.login.example"}
	valid := []string{
		"https://login.example",
		"https://LOGIN.EXAMPLE/tenant/one",
		"https://login.example:443/tenant/one",
	}
	for _, issuer := range valid {
		if !validOIDCIssuer(issuer, allowed) {
			t.Errorf("expected issuer to pass allowlist validation: %q", issuer)
		}
	}
	invalid := []string{
		"http://login.example",
		"https://evil-login.example",
		"https://login.example.evil.test",
		"https://login.example:444",
		"https://127.0.0.1",
		"https://user@login.example",
		"https://login.example?next=https://evil.test",
		"https://login.example?",
		"https://login.example/#fragment",
		"https://login.example#",
		"https://*.example",
	}
	for _, issuer := range invalid {
		if validOIDCIssuer(issuer, allowed) {
			t.Errorf("issuer escaped the configured host policy: %q", issuer)
		}
	}
}
