package gateway

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type runtimeFunc func(context.Context, Route, Request) (Decision, error)

func (f runtimeFunc) Evaluate(ctx context.Context, route Route, request Request) (Decision, error) {
	return f(ctx, route, request)
}

func TestTLSProfileRequiresTLS13AndRecognizedGroup(t *testing.T) {
	for _, test := range []struct {
		name    string
		state   *tls.ConnectionState
		profile string
		valid   bool
	}{
		{name: "nil", valid: false},
		{name: "tls12", state: &tls.ConnectionState{Version: tls.VersionTLS12, CurveID: tls.X25519}, valid: false},
		{name: "unknown group", state: &tls.ConnectionState{Version: tls.VersionTLS13, CurveID: tls.CurveID(65000)}, valid: false},
		{name: "classical x25519", state: &tls.ConnectionState{Version: tls.VersionTLS13, CurveID: tls.X25519}, profile: "tls13-classical", valid: true},
		{name: "classical p256", state: &tls.ConnectionState{Version: tls.VersionTLS13, CurveID: tls.CurveP256}, profile: "tls13-classical", valid: true},
		{name: "hybrid", state: &tls.ConnectionState{Version: tls.VersionTLS13, CurveID: tls.X25519MLKEM768}, profile: "tls13-x25519-mlkem768", valid: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			profile, ok := TLSProfile(test.state)
			if ok != test.valid || profile != test.profile {
				t.Fatalf("TLSProfile() = %q, %v; want %q, %v", profile, ok, test.profile, test.valid)
			}
		})
	}
}

func TestValidateServerCertificateCoversEveryRoute(t *testing.T) {
	certificate := gatewayTestCertificate(t, "app.customer.example")
	routes := []Route{{Host: "app.customer.example"}}
	if err := ValidateServerCertificate(certificate, routes); err != nil {
		t.Fatalf("certificate with matching DNS SAN rejected: %v", err)
	}
	certificate.Leaf = nil
	if err := ValidateServerCertificate(certificate, routes); err != nil {
		t.Fatalf("certificate without a cached parsed leaf was rejected: %v", err)
	}
	routes = append(routes, Route{Host: "other.customer.example"})
	if err := ValidateServerCertificate(certificate, routes); err == nil {
		t.Fatal("certificate missing a configured route hostname was accepted")
	}
	certificate.Leaf = nil
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		t.Fatal("parse test certificate:", err)
	}
	leaf.NotAfter = time.Now().Add(-time.Minute)
	certificate.Leaf = leaf
	if err := ValidateServerCertificate(certificate, routes[:1]); err == nil {
		t.Fatal("expired gateway certificate was accepted")
	}
}

func TestLoadRoutesFileRequiresExactAllowedHTTPSUpstream(t *testing.T) {
	valid := `{"routes":[{"host":"app.customer.example","tenant_id":"10000000-0000-4000-8000-000000000001","application_id":"20000000-0000-4000-8000-000000000002","upstream_url":"https://orders.service.example"}]}`
	writeRouteFile := func(content string) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "gateway-routes.json")
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	path := writeRouteFile(valid)
	routes, err := LoadRoutesFile(path, []string{"orders.service.example"}, "production")
	if err != nil || len(routes) != 1 {
		t.Fatalf("valid gateway routes rejected: routes=%v err=%v", routes, err)
	}
	for name, content := range map[string]string{
		"unknown field":         strings.Replace(valid, `"host":`, `"extra":"x","host":`, 1),
		"unauthorized upstream": strings.Replace(valid, "orders.service.example", "other.service.example", 1),
		"url credentials":       strings.Replace(valid, "https://orders", "https://user:pass@orders", 1),
		"query string":          strings.Replace(valid, `"upstream_url":"https://orders.service.example"`, `"upstream_url":"https://orders.service.example?x=1"`, 1),
		"duplicate host":        strings.Replace(valid, `}]}`, `},{"host":"app.customer.example","tenant_id":"10000000-0000-4000-8000-000000000001","application_id":"20000000-0000-4000-8000-000000000002","upstream_url":"https://orders.service.example"}]}`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadRoutesFile(writeRouteFile(content), []string{"orders.service.example"}, "production"); err == nil {
				t.Fatal("invalid route configuration was accepted")
			}
		})
	}
}

func TestLoadRoutesFileOnlyAllowsLoopbackHTTPInDevelopment(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gateway-routes.json")
	route := Route{
		Host: "app.customer.example", TenantID: "10000000-0000-4000-8000-000000000001",
		ApplicationID: "20000000-0000-4000-8000-000000000002", UpstreamURL: "http://127.0.0.1:8081",
	}
	body, _ := json.Marshal(routeFile{Routes: []Route{route}})
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRoutesFile(path, nil, "production"); err == nil {
		t.Fatal("production configuration accepted an HTTP upstream")
	}
	if _, err := LoadRoutesFile(path, nil, "development"); err != nil {
		t.Fatalf("development should permit an explicit loopback test upstream: %v", err)
	}
}

func TestGatewayDerivesContextStripsSpoofedHeadersAndProxiesAllowedRequest(t *testing.T) {
	var upstreamCalls int
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls++
		if r.Header.Get("X-Forwarded-For") != "203.0.113.9" || r.Header.Get("X-Forwarded-Proto") != "https" || r.Header.Get("X-Forwarded-Host") != "app.customer.example" {
			t.Errorf("forwarded headers were not replaced safely: %v", r.Header)
		}
		if r.Header.Get("X-QG-Transport-Profile") != "tls13-classical" || r.Header.Get("X-QG-Policy-Revision") != "30000000-0000-4000-8000-000000000003" || r.Header.Get("X-QG-Request-ID") != "request-1" {
			t.Errorf("trusted gateway context was not propagated: %v", r.Header)
		}
		if r.Header.Get("Authorization") != "Bearer end-user-id-token" {
			t.Errorf("end-user identity token was not preserved for the application")
		}
		w.Header().Set("X-QG-Upstream-Forgery", "discard")
		w.Header().Set("X-Request-ID", "upstream-forgery")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	parsedUpstream, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	route := Route{
		Host: "app.customer.example", TenantID: "10000000-0000-4000-8000-000000000001",
		ApplicationID: "20000000-0000-4000-8000-000000000002", UpstreamURL: upstream.URL,
	}
	runtimeCalls := 0
	decisionRuntime := runtimeFunc(func(_ context.Context, receivedRoute Route, request Request) (Decision, error) {
		runtimeCalls++
		if receivedRoute.TenantID != route.TenantID || receivedRoute.ApplicationID != route.ApplicationID {
			t.Errorf("untrusted request changed its registered tenant/application: %+v", receivedRoute)
		}
		if request.Method != http.MethodGet || request.Path != "/orders/1" || request.ProfileID != "tls13-classical" ||
			request.IdentityToken != "end-user-id-token" || request.RequestID != "request-1" || request.ClientIP != "203.0.113.9" {
			t.Errorf("unexpected trusted decision context: %+v", request)
		}
		return Decision{Outcome: "allow", PolicyRevisionID: "30000000-0000-4000-8000-000000000003"}, nil
	})
	gateway, err := New([]Route{route}, decisionRuntime, nil, nil, "development")
	if err != nil {
		t.Fatal("create gateway:", err)
	}
	if gateway.routes[route.Host].target.Host != parsedUpstream.Host {
		t.Fatal("gateway did not bind the configured upstream host")
	}
	request := httptest.NewRequest(http.MethodGet, "/orders/1?sort=asc", nil)
	request.Host = "app.customer.example"
	request.RemoteAddr = "203.0.113.9:41234"
	request.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, CurveID: tls.X25519, ServerName: route.Host}
	request.Header.Set("Authorization", "Bearer end-user-id-token")
	request.Header.Set("X-Forwarded-For", "192.0.2.10")
	request.Header.Set("X-QG-Transport-Profile", "tls13-x25519-mlkem768")
	response := httptest.NewRecorder()
	response.Header().Set("X-Request-ID", "request-1")
	gateway.Middleware(http.NotFoundHandler()).ServeHTTP(response, request)
	if response.Code != http.StatusNoContent || runtimeCalls != 1 || upstreamCalls != 1 {
		t.Fatalf("allowed gateway request failed: status=%d runtime=%d upstream=%d body=%s", response.Code, runtimeCalls, upstreamCalls, response.Body.String())
	}
	if response.Header().Get("X-QG-Upstream-Forgery") != "" {
		t.Fatal("upstream spoofed a QuantumGate response header")
	}
	if got := response.Header().Get("X-Request-ID"); got != "request-1" {
		t.Fatalf("upstream spoofed the response request ID: got %q", got)
	}
}

func TestGatewayEndToEndDerivesHybridProfileFromLiveTLS(t *testing.T) {
	upstreamCalls := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls++
		if r.URL.Path != "/checkout" {
			t.Errorf("upstream received unexpected path %q", r.URL.Path)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	route := Route{
		Host: "app.customer.example", TenantID: "10000000-0000-4000-8000-000000000001",
		ApplicationID: "20000000-0000-4000-8000-000000000002", UpstreamURL: upstream.URL,
	}
	runtimeCalls := 0
	gateway, err := New([]Route{route}, runtimeFunc(func(_ context.Context, _ Route, request Request) (Decision, error) {
		runtimeCalls++
		if request.ProfileID != "tls13-x25519-mlkem768" {
			t.Errorf("gateway did not derive the live hybrid profile: %q", request.ProfileID)
		}
		return Decision{Outcome: "allow", PolicyRevisionID: "30000000-0000-4000-8000-000000000003"}, nil
	}), nil, nil, "development")
	if err != nil {
		t.Fatal("create gateway:", err)
	}
	certificate := gatewayTestCertificate(t, route.Host)
	server := httptest.NewUnstartedServer(gateway.Middleware(http.NotFoundHandler()))
	server.TLS = &tls.Config{
		MinVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{tls.X25519MLKEM768},
		Certificates: []tls.Certificate{certificate},
	}
	server.StartTLS()
	defer server.Close()

	roots := x509.NewCertPool()
	roots.AddCert(certificate.Leaf)
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{tls.X25519MLKEM768},
		ServerName: route.Host, RootCAs: roots,
	}}}
	defer client.CloseIdleConnections()
	request, err := http.NewRequest(http.MethodGet, server.URL+"/checkout", nil)
	if err != nil {
		t.Fatal("create request:", err)
	}
	request.Host = route.Host
	request.Header.Set("Authorization", "Bearer end-user-id-token")
	request.Header.Set("X-QG-Transport-Profile", "tls13-classical")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal("send end-to-end request:", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent || runtimeCalls != 1 || upstreamCalls != 1 {
		t.Fatalf("end-to-end gateway request status=%d runtime=%d upstream=%d", response.StatusCode, runtimeCalls, upstreamCalls)
	}
}

func gatewayTestCertificate(t *testing.T, hostname string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal("generate test certificate key:", err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: hostname}, DNSNames: []string{hostname},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal("create test certificate:", err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal("parse test certificate:", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: parsed, SupportedSignatureAlgorithms: []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256}}
}

func TestGatewayRejectsMisdirectedAndUnprotectedRequestsBeforeEvaluation(t *testing.T) {
	upstream := httptest.NewServer(http.NotFoundHandler())
	defer upstream.Close()
	route := Route{
		Host: "app.customer.example", TenantID: "10000000-0000-4000-8000-000000000001",
		ApplicationID: "20000000-0000-4000-8000-000000000002", UpstreamURL: upstream.URL,
	}
	evaluations := 0
	gateway, err := New([]Route{route}, runtimeFunc(func(context.Context, Route, Request) (Decision, error) {
		evaluations++
		return Decision{Outcome: "allow"}, nil
	}), nil, nil, "development")
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		host string
		tls  *tls.ConnectionState
		want int
	}{
		{name: "SNI mismatch", host: "app.customer.example", tls: &tls.ConnectionState{Version: tls.VersionTLS13, CurveID: tls.X25519, ServerName: "other.customer.example"}, want: http.StatusMisdirectedRequest},
		{name: "TLS missing", host: "app.customer.example", want: http.StatusMisdirectedRequest},
		{name: "TLS 1.2", host: "app.customer.example", tls: &tls.ConnectionState{Version: tls.VersionTLS12, CurveID: tls.X25519, ServerName: route.Host}, want: http.StatusForbidden},
		{name: "gateway SNI with control-plane Host", host: "admin.example", tls: &tls.ConnectionState{Version: tls.VersionTLS13, CurveID: tls.X25519, ServerName: route.Host}, want: http.StatusMisdirectedRequest},
		{name: "spoofed host", host: "other.customer.example", tls: &tls.ConnectionState{Version: tls.VersionTLS13, CurveID: tls.X25519, ServerName: "other.customer.example"}, want: http.StatusNotFound},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/orders", nil)
			request.Host = test.host
			request.TLS = test.tls
			request.Header.Set("Authorization", "Bearer token")
			response := httptest.NewRecorder()
			gateway.Middleware(http.NotFoundHandler()).ServeHTTP(response, request)
			if response.Code != test.want || evaluations != 0 {
				t.Fatalf("request status=%d evaluations=%d; want status=%d and no decision", response.Code, evaluations, test.want)
			}
		})
	}
}

func TestGatewayDoesNotForwardWhenPolicyDeniesOrRuntimeFails(t *testing.T) {
	upstreamCalls := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { upstreamCalls++ }))
	defer upstream.Close()
	route := Route{
		Host: "app.customer.example", TenantID: "10000000-0000-4000-8000-000000000001",
		ApplicationID: "20000000-0000-4000-8000-000000000002", UpstreamURL: upstream.URL,
	}
	for _, test := range []struct {
		name     string
		decision Decision
		err      error
		want     int
	}{
		{name: "deny", decision: Decision{Outcome: "deny"}, want: http.StatusForbidden},
		{name: "step up", decision: Decision{Outcome: "step_up"}, want: http.StatusUnauthorized},
		{name: "unavailable", err: &Failure{StatusCode: http.StatusServiceUnavailable, Code: "DATA_PLANE_UNAVAILABLE"}, want: http.StatusServiceUnavailable},
		{name: "unknown outcome", decision: Decision{Outcome: "unknown"}, want: http.StatusForbidden},
	} {
		t.Run(test.name, func(t *testing.T) {
			gateway, err := New([]Route{route}, runtimeFunc(func(context.Context, Route, Request) (Decision, error) { return test.decision, test.err }), nil, nil, "development")
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(http.MethodGet, "/orders", nil)
			request.Host = route.Host
			request.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, CurveID: tls.X25519, ServerName: route.Host}
			request.Header.Set("Authorization", "Bearer token")
			response := httptest.NewRecorder()
			gateway.Middleware(http.NotFoundHandler()).ServeHTTP(response, request)
			if response.Code != test.want || upstreamCalls != 0 {
				t.Fatalf("request status=%d upstream=%d; want status=%d and no forwarding", response.Code, upstreamCalls, test.want)
			}
		})
	}
}
