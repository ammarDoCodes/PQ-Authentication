package auth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

type fakeResolver struct {
	ips []net.IPAddr
	err error
}

func (r fakeResolver) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) {
	return r.ips, r.err
}

func TestPublicUnicastRejectsPrivateAndSpecialPurposeAddresses(t *testing.T) {
	for _, raw := range []string{"127.0.0.1", "10.0.0.8", "169.254.169.254", "100.64.0.1", "192.0.2.1", "198.18.0.1", "2001:db8::1", "fc00::1"} {
		addr := netip.MustParseAddr(raw)
		if publicUnicast(addr) {
			t.Errorf("unsafe address accepted: %s", addr)
		}
	}
	for _, raw := range []string{"8.8.8.8", "2606:4700:4700::1111"} {
		addr := netip.MustParseAddr(raw)
		if !publicUnicast(addr) {
			t.Errorf("public unicast address rejected: %s", addr)
		}
	}
}

func TestRestrictedTransportRejectsUnlistedOrNonHTTPSURLs(t *testing.T) {
	client := newRestrictedHTTPClient([]string{"id.example"})
	rt := client.Transport.(*restrictedTransport)
	for _, target := range []string{"http://id.example/.well-known/openid-configuration", "https://evil.example/jwks", "https://127.0.0.1/jwks", "https://id.example:8443/token"} {
		req := httptest.NewRequest(http.MethodGet, target, nil)
		if _, err := rt.RoundTrip(req); !errors.Is(err, errEgressDenied) {
			t.Errorf("expected egress denial for %s, got %v", target, err)
		}
	}
}

func TestRestrictedDialerRejectsPrivateDNSAnswer(t *testing.T) {
	rt := newRestrictedHTTPClient([]string{"id.example"}).Transport.(*restrictedTransport)
	rt.resolver = fakeResolver{ips: []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}}
	_, err := rt.dialContext(context.Background(), "tcp", "id.example:443")
	if !errors.Is(err, errEgressDenied) {
		t.Fatalf("expected private DNS answer to be denied, got %v", err)
	}
}

func TestRestrictedDialerRejectsMixedPublicAndPrivateDNSAnswers(t *testing.T) {
	rt := newRestrictedHTTPClient([]string{"id.example"}).Transport.(*restrictedTransport)
	rt.resolver = fakeResolver{ips: []net.IPAddr{{IP: net.ParseIP("8.8.8.8")}, {IP: net.ParseIP("10.0.0.1")}}}
	_, err := rt.dialContext(context.Background(), "tcp", "id.example:443")
	if !errors.Is(err, errEgressDenied) {
		t.Fatalf("expected mixed DNS answer set to be denied, got %v", err)
	}
}

func TestOIDCAuthorizationURLUsesStateNonceAndS256PKCE(t *testing.T) {
	flow := &OIDCFlow{requiredACR: "urn:test:mfa", maxTokenAge: 15 * time.Minute, config: oauth2.Config{
		ClientID: "qg-client", RedirectURL: "https://console.example/auth/callback",
		Endpoint: oauth2.Endpoint{AuthURL: "https://id.example/authorize"},
	}}
	state := strings.Repeat("s", 43)
	nonce := strings.Repeat("n", 43)
	verifier := strings.Repeat("v", 43)
	parsed, err := url.Parse(flow.AuthorizationURL(state, nonce, verifier))
	if err != nil {
		t.Fatal(err)
	}
	query := parsed.Query()
	challengeHash := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(challengeHash[:])
	if query.Get("state") != state || query.Get("nonce") != nonce || query.Get("code_challenge_method") != "S256" || query.Get("code_challenge") != challenge ||
		query.Get("acr_values") != "urn:test:mfa" || query.Get("max_age") != "900" {
		t.Fatalf("authorization URL omitted required OIDC protections: %s", parsed.Redacted())
	}
}

func TestOIDCProviderEndpointMustUseHTTPSAndExactConfiguredHost(t *testing.T) {
	allowed := []string{"login.example"}
	for _, endpoint := range []string{
		"http://login.example/authorize",
		"https://evil.example/authorize",
		"https://login.example:8443/authorize",
		"https://user@login.example/authorize",
		"https://login.example/authorize#fragment",
	} {
		if allowedProviderEndpoint(endpoint, allowed) {
			t.Errorf("unsafe OIDC endpoint accepted: %s", endpoint)
		}
	}
	if !allowedProviderEndpoint("https://login.example/authorize", allowed) || !allowedProviderEndpoint("https://login.example:443/authorize", allowed) {
		t.Fatal("valid OIDC endpoint was rejected")
	}
}
