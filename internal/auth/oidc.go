package auth

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const maxIDTokenBytes = 16 << 10

var ErrUnauthenticated = errors.New("authentication required")

type Principal struct {
	Issuer   string
	Subject  string
	ACR      string
	AuthTime time.Time
}

type TokenVerifier interface {
	Verify(context.Context, string) (Principal, error)
}

type OIDCSettings struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	AllowedHosts []string
	RequiredACR  string
	SigningAlgs  []string
	MaxTokenAge  time.Duration
}

// OIDCFlow owns the provider discovery, authorization-code exchange, and
// ID-token validation for the administrator login flow.
type OIDCFlow struct {
	issuer      string
	clientID    string
	requiredACR string
	maxTokenAge time.Duration
	client      *http.Client
	config      oauth2.Config
	verifier    *oidc.IDTokenVerifier
}

type OIDCVerifier struct {
	issuer      string
	clientID    string
	requiredACR string
	requireACR  bool
	maxTokenAge time.Duration
	verifier    *oidc.IDTokenVerifier
}

func NewOIDCVerifier(ctx context.Context, settings OIDCSettings) (*OIDCVerifier, error) {
	if settings.RequiredACR == "" {
		return nil, errors.New("a required OIDC ACR is required")
	}
	return newOIDCVerifier(ctx, settings, true)
}

// NewOIDCIdentityVerifier validates a signed, audience-bound ID token but
// leaves the policy engine to compare the verified ACR against active policy.
func NewOIDCIdentityVerifier(ctx context.Context, settings OIDCSettings) (*OIDCVerifier, error) {
	return newOIDCVerifier(ctx, settings, false)
}

func newOIDCVerifier(ctx context.Context, settings OIDCSettings, requireACR bool) (*OIDCVerifier, error) {
	if settings.Issuer == "" || settings.ClientID == "" || len(settings.AllowedHosts) == 0 || len(settings.SigningAlgs) == 0 {
		return nil, errors.New("complete OIDC verification settings are required")
	}
	if settings.MaxTokenAge < time.Minute || settings.MaxTokenAge > time.Hour {
		return nil, errors.New("OIDC token age is outside the supported range")
	}
	client := newRestrictedHTTPClient(settings.AllowedHosts)
	providerCtx := oidc.ClientContext(ctx, client)
	provider, err := oidc.NewProvider(providerCtx, settings.Issuer)
	if err != nil {
		return nil, errors.New("OIDC provider metadata could not be verified")
	}
	verifier := provider.VerifierContext(providerCtx, &oidc.Config{
		ClientID:             settings.ClientID,
		SupportedSigningAlgs: append([]string(nil), settings.SigningAlgs...),
	})
	return &OIDCVerifier{
		issuer: settings.Issuer, clientID: settings.ClientID,
		requiredACR: settings.RequiredACR, requireACR: requireACR, maxTokenAge: settings.MaxTokenAge,
		verifier: verifier,
	}, nil
}

func NewOIDCFlow(ctx context.Context, settings OIDCSettings) (*OIDCFlow, error) {
	if settings.RedirectURL == "" {
		return nil, errors.New("OIDC redirect URL is required")
	}
	if settings.Issuer == "" || settings.ClientID == "" || settings.RequiredACR == "" || len(settings.AllowedHosts) == 0 || len(settings.SigningAlgs) == 0 {
		return nil, errors.New("complete OIDC flow settings are required")
	}
	if settings.MaxTokenAge < time.Minute || settings.MaxTokenAge > time.Hour {
		return nil, errors.New("OIDC token age is outside the supported range")
	}
	client := newRestrictedHTTPClient(settings.AllowedHosts)
	providerCtx := oidc.ClientContext(ctx, client)
	provider, err := oidc.NewProvider(providerCtx, settings.Issuer)
	if err != nil {
		return nil, errors.New("OIDC provider metadata could not be verified")
	}
	endpoint := provider.Endpoint()
	if !allowedProviderEndpoint(endpoint.AuthURL, settings.AllowedHosts) || !allowedProviderEndpoint(endpoint.TokenURL, settings.AllowedHosts) {
		return nil, errors.New("OIDC provider endpoints are outside the configured host policy")
	}
	return &OIDCFlow{
		issuer: settings.Issuer, clientID: settings.ClientID,
		requiredACR: settings.RequiredACR, maxTokenAge: settings.MaxTokenAge, client: client,
		config: oauth2.Config{
			ClientID: settings.ClientID, ClientSecret: settings.ClientSecret,
			Endpoint: endpoint, RedirectURL: settings.RedirectURL,
			Scopes: []string{oidc.ScopeOpenID, "profile", "email"},
		},
		verifier: provider.VerifierContext(providerCtx, &oidc.Config{
			ClientID: settings.ClientID, SupportedSigningAlgs: append([]string(nil), settings.SigningAlgs...),
		}),
	}, nil
}

func allowedProviderEndpoint(raw string, allowedHosts []string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Fragment != "" || u.Opaque != "" || u.Hostname() == "" {
		return false
	}
	if port := u.Port(); port != "" && port != "443" {
		return false
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if net.ParseIP(host) != nil {
		return false
	}
	for _, allowed := range allowedHosts {
		if host == strings.ToLower(strings.TrimSuffix(allowed, ".")) {
			return true
		}
	}
	return false
}

// AuthorizationURL builds the provider redirect. The caller must persist
// state, nonce, and verifier before redirecting the browser.
func (f *OIDCFlow) AuthorizationURL(state, nonce, verifier string) string {
	return f.config.AuthCodeURL(state,
		oidc.Nonce(nonce),
		oauth2.S256ChallengeOption(verifier),
		oauth2.SetAuthURLParam("acr_values", f.requiredACR),
		oauth2.SetAuthURLParam("max_age", strconv.Itoa(int(f.maxTokenAge.Seconds()))),
	)
}

// Exchange validates the ID token returned by the code exchange, including
// the nonce associated with the one-time server-side login transaction.
func (f *OIDCFlow) Exchange(ctx context.Context, code, verifier, expectedNonce string) (Principal, error) {
	if f == nil || f.verifier == nil || code == "" || verifier == "" || expectedNonce == "" {
		return Principal{}, ErrUnauthenticated
	}
	ctx = oidc.ClientContext(ctx, f.client)
	token, err := f.config.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		return Principal{}, ErrUnauthenticated
	}
	raw, ok := token.Extra("id_token").(string)
	if !ok || raw == "" || len(raw) > maxIDTokenBytes {
		return Principal{}, ErrUnauthenticated
	}
	idToken, err := f.verifier.Verify(ctx, raw)
	if err != nil || idToken == nil || idToken.Issuer != f.issuer || idToken.Subject == "" || len(idToken.Subject) > 512 || strings.ContainsAny(idToken.Subject, "\r\n\x00") || idToken.Nonce != expectedNonce {
		return Principal{}, ErrUnauthenticated
	}
	var claims struct {
		ACR             string `json:"acr"`
		AuthTime        int64  `json:"auth_time"`
		AuthorizedParty string `json:"azp"`
	}
	if err := idToken.Claims(&claims); err != nil || claims.ACR != f.requiredACR || claims.AuthTime <= 0 {
		return Principal{}, ErrUnauthenticated
	}
	if claims.AuthorizedParty != "" && claims.AuthorizedParty != f.clientID || len(idToken.Audience) > 1 && claims.AuthorizedParty != f.clientID {
		return Principal{}, ErrUnauthenticated
	}
	now := time.Now()
	if idToken.IssuedAt.After(now.Add(30*time.Second)) || now.Sub(idToken.IssuedAt) > f.maxTokenAge+30*time.Second {
		return Principal{}, ErrUnauthenticated
	}
	authTime := time.Unix(claims.AuthTime, 0)
	if authTime.After(now.Add(30*time.Second)) || authTime.After(idToken.IssuedAt.Add(30*time.Second)) || now.Sub(authTime) > f.maxTokenAge+30*time.Second {
		return Principal{}, ErrUnauthenticated
	}
	return Principal{Issuer: idToken.Issuer, Subject: idToken.Subject, ACR: claims.ACR, AuthTime: authTime}, nil
}

func (v *OIDCVerifier) Verify(ctx context.Context, raw string) (Principal, error) {
	if v == nil || v.verifier == nil || len(raw) == 0 || len(raw) > maxIDTokenBytes || strings.ContainsAny(raw, " \t\r\n") {
		return Principal{}, ErrUnauthenticated
	}
	token, err := v.verifier.Verify(ctx, raw)
	if err != nil || token == nil || token.Issuer != v.issuer || token.Subject == "" || len(token.Subject) > 512 || strings.ContainsAny(token.Subject, "\r\n\x00") {
		return Principal{}, ErrUnauthenticated
	}
	var claims struct {
		ACR             string `json:"acr"`
		AuthTime        int64  `json:"auth_time"`
		AuthorizedParty string `json:"azp"`
	}
	if err := token.Claims(&claims); err != nil || v.requireACR && claims.ACR != v.requiredACR || claims.AuthTime <= 0 || token.Nonce == "" {
		return Principal{}, ErrUnauthenticated
	}
	if claims.AuthorizedParty != "" && claims.AuthorizedParty != v.clientID || len(token.Audience) > 1 && claims.AuthorizedParty != v.clientID {
		return Principal{}, ErrUnauthenticated
	}
	now := time.Now()
	if token.IssuedAt.After(now.Add(30*time.Second)) || now.Sub(token.IssuedAt) > v.maxTokenAge+30*time.Second {
		return Principal{}, ErrUnauthenticated
	}
	authTime := time.Unix(claims.AuthTime, 0)
	if authTime.After(now.Add(30*time.Second)) || authTime.After(token.IssuedAt.Add(30*time.Second)) || now.Sub(authTime) > v.maxTokenAge+30*time.Second {
		return Principal{}, ErrUnauthenticated
	}
	return Principal{Issuer: token.Issuer, Subject: token.Subject, ACR: claims.ACR, AuthTime: authTime}, nil
}
