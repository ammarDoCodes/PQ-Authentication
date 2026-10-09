package gateway

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	maxRouteFileBytes = 1 << 20
	maxGatewayRoutes  = 1000
	maxGatewayRequest = 64 << 10
)

type Route struct {
	Host          string `json:"host"`
	TenantID      string `json:"tenant_id"`
	ApplicationID string `json:"application_id"`
	UpstreamURL   string `json:"upstream_url"`
}

type routeFile struct {
	Routes []Route `json:"routes"`
}

type Request struct {
	RequestID     string
	Method        string
	Path          string
	ProfileID     string
	IdentityToken string
	ClientIP      string
}

type Decision struct {
	Outcome          string
	Mode             string
	PolicyRevisionID string
	ReasonCodes      []string
	ExpiresAt        *time.Time
}

type Failure struct {
	StatusCode int
	Code       string
	RetryAfter int
}

func (f *Failure) Error() string { return "gateway request could not be evaluated" }

type Runtime interface {
	Evaluate(context.Context, Route, Request) (Decision, error)
}

type configuredRoute struct {
	config Route
	target *url.URL
	proxy  *httputil.ReverseProxy
}

type Gateway struct {
	routes  map[string]*configuredRoute
	runtime Runtime
	logger  *slog.Logger
}

func LoadRoutesFile(path string, allowedUpstreamHosts []string, environment string) ([]Route, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("gateway route configuration could not be opened")
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxRouteFileBytes+1))
	if err != nil || len(data) > maxRouteFileBytes {
		return nil, errors.New("gateway route configuration exceeds the size limit")
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	var config routeFile
	if err := decoder.Decode(&config); err != nil {
		return nil, errors.New("gateway route configuration is invalid")
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("gateway route configuration must contain one JSON document")
	}
	if len(config.Routes) == 0 || len(config.Routes) > maxGatewayRoutes {
		return nil, errors.New("gateway route count is outside the supported range")
	}
	if err := validateRoutes(config.Routes, allowedUpstreamHosts, environment); err != nil {
		return nil, err
	}
	return config.Routes, nil
}

func New(routes []Route, runtime Runtime, logger *slog.Logger, allowedUpstreamHosts []string, environment string) (*Gateway, error) {
	if len(routes) == 0 || len(routes) > maxGatewayRoutes || runtime == nil {
		return nil, errors.New("gateway requires routes and a decision runtime")
	}
	if err := validateRoutes(routes, allowedUpstreamHosts, environment); err != nil {
		return nil, err
	}
	configured := make(map[string]*configuredRoute, len(routes))
	for _, route := range routes {
		host := normalizeHostname(route.Host)
		target, err := url.Parse(route.UpstreamURL)
		if !validHost(host) || host != route.Host || !validUUID(route.TenantID) || !validUUID(route.ApplicationID) ||
			err != nil || target == nil || target.User != nil || target.RawQuery != "" || target.Fragment != "" ||
			(target.Scheme != "https" && !localHTTPUpstream(target)) ||
			(target.Path != "" && target.Path != "/") || target.Hostname() == "" || strings.EqualFold(host, target.Hostname()) {
			return nil, errors.New("gateway route contains an invalid host, tenant, application, or upstream")
		}
		if target.Scheme == "https" && target.Port() != "" && target.Port() != "443" {
			return nil, errors.New("gateway HTTPS upstreams must use port 443")
		}
		if _, exists := configured[host]; exists {
			return nil, errors.New("gateway route hosts must be unique")
		}
		target.Path = ""
		target.RawPath = ""
		target.RawQuery = ""
		transport := &http.Transport{
			Proxy:             nil,
			DialContext:       (&net.Dialer{Timeout: 3 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			ForceAttemptHTTP2: true, MaxConnsPerHost: 200, MaxIdleConns: 100,
			IdleConnTimeout: 30 * time.Second, TLSHandshakeTimeout: 5 * time.Second,
			ResponseHeaderTimeout: 5 * time.Second, MaxResponseHeaderBytes: 64 << 10,
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13},
		}
		proxy := &httputil.ReverseProxy{
			Transport: transport,
			Rewrite: func(request *httputil.ProxyRequest) {
				request.SetURL(target)
				request.Out.Host = target.Host
				stripForwardedHeaders(request.Out.Header)
				request.Out.Header.Set("X-Forwarded-For", clientIP(request.In.RemoteAddr))
				request.Out.Header.Set("X-Forwarded-Proto", "https")
				request.Out.Header.Set("X-Forwarded-Host", host)
				request.Out.Header.Set("X-QG-Request-ID", request.In.Header.Get("X-Request-ID"))
				request.Out.Header.Set("X-QG-Transport-Profile", request.In.Header.Get("X-QG-Transport-Profile"))
				request.Out.Header.Set("X-QG-Policy-Revision", request.In.Header.Get("X-QG-Policy-Revision"))
				request.Out.Header.Set("X-QG-Decision-Expires-At", request.In.Header.Get("X-QG-Decision-Expires-At"))
			},
			ModifyResponse: func(response *http.Response) error {
				stripQGHeaders(response.Header)
				if response.Request != nil {
					response.Header.Set("X-Request-ID", response.Request.Header.Get("X-QG-Request-ID"))
				}
				return nil
			},
			ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
				if logger != nil {
					logger.Error("gateway upstream request failed", "request_id", w.Header().Get("X-Request-ID"), "code", "GATEWAY_UPSTREAM_FAILURE")
				}
				writeProblem(w, http.StatusBadGateway, "UPSTREAM_UNAVAILABLE", "The application could not be reached.", w.Header().Get("X-Request-ID"), false, 0)
			},
		}
		configured[host] = &configuredRoute{config: route, target: target, proxy: proxy}
	}
	return &Gateway{routes: configured, runtime: runtime, logger: logger}, nil
}

func (g *Gateway) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		route := g.routeForRequest(r)
		if route == nil {
			next.ServeHTTP(w, r)
			return
		}
		g.serveRoute(w, r, route)
	})
}

func (g *Gateway) CloseIdleConnections() {
	for _, route := range g.routes {
		if transport, ok := route.proxy.Transport.(*http.Transport); ok {
			transport.CloseIdleConnections()
		}
	}
}

func (g *Gateway) routeForRequest(r *http.Request) *configuredRoute {
	host := requestHostname(r.Host)
	if route := g.routes[host]; route != nil {
		return route
	}
	if r.TLS != nil {
		return g.routes[normalizeHostname(r.TLS.ServerName)]
	}
	return nil
}

func (g *Gateway) serveRoute(w http.ResponseWriter, r *http.Request, route *configuredRoute) {
	requestID := w.Header().Get("X-Request-ID")
	if r.TLS == nil || requestHostname(r.Host) != route.config.Host || normalizeHostname(r.TLS.ServerName) != route.config.Host {
		writeProblem(w, http.StatusMisdirectedRequest, "GATEWAY_HOST_MISMATCH", "The request host does not match its TLS server name.", requestID, false, 0)
		return
	}
	profileID, ok := TLSProfile(r.TLS)
	if !ok || !validGatewayRequest(r) {
		writeProblem(w, http.StatusForbidden, "GATEWAY_CONTEXT_REJECTED", "The request does not have an accepted transport or route context.", requestID, false, 0)
		return
	}
	identityToken, ok := bearerToken(r.Header.Values("Authorization"))
	if !ok {
		w.Header().Set("WWW-Authenticate", "Bearer")
		writeProblem(w, http.StatusUnauthorized, "IDENTITY_REQUIRED", "A verified application identity is required.", requestID, false, 0)
		return
	}
	clientAddress := clientIP(r.RemoteAddr)
	request := Request{
		RequestID: requestID, Method: r.Method, Path: r.URL.Path, ProfileID: profileID,
		IdentityToken: identityToken, ClientIP: clientAddress,
	}
	ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
	defer cancel()
	decision, err := g.runtime.Evaluate(ctx, route.config, request)
	if err != nil {
		var failure *Failure
		if errors.As(err, &failure) {
			if failure.StatusCode == http.StatusUnauthorized {
				w.Header().Set("WWW-Authenticate", "Bearer")
			}
			if failure.RetryAfter > 0 {
				w.Header().Set("Retry-After", fmt.Sprintf("%d", failure.RetryAfter))
			}
			writeProblem(w, failure.StatusCode, failure.Code, safeFailureDetail(failure.StatusCode), requestID, failure.StatusCode >= 500, failure.RetryAfter)
			return
		}
		if g.logger != nil {
			g.logger.Error("gateway decision evaluation failed", "request_id", requestID, "code", "DATA_PLANE_UNAVAILABLE")
		}
		writeProblem(w, http.StatusServiceUnavailable, "DATA_PLANE_UNAVAILABLE", "The request could not be evaluated safely.", requestID, true, 0)
		return
	}
	if decision.Outcome != "allow" && decision.Outcome != "observe" && decision.Outcome != "degraded_allowed" {
		if decision.Outcome == "step_up" {
			w.Header().Set("WWW-Authenticate", "Bearer")
			writeProblem(w, http.StatusUnauthorized, "STEP_UP_REQUIRED", "Additional authentication is required.", requestID, false, 0)
			return
		}
		writeProblem(w, http.StatusForbidden, "POLICY_DENIED", "The request is not allowed by the active policy.", requestID, false, 0)
		return
	}
	r = r.Clone(ctx)
	r.Header = r.Header.Clone()
	stripForwardedHeaders(r.Header)
	r.Header.Set("X-Request-ID", requestID)
	r.Header.Set("X-QG-Transport-Profile", profileID)
	r.Header.Set("X-QG-Policy-Revision", decision.PolicyRevisionID)
	if decision.ExpiresAt != nil {
		r.Header.Set("X-QG-Decision-Expires-At", decision.ExpiresAt.UTC().Format(time.RFC3339Nano))
	}
	route.proxy.ServeHTTP(w, r)
}

func TLSProfile(state *tls.ConnectionState) (string, bool) {
	if state == nil || state.Version != tls.VersionTLS13 {
		return "", false
	}
	switch state.CurveID {
	case tls.X25519MLKEM768:
		return "tls13-x25519-mlkem768", true
	case tls.X25519, tls.CurveP256, tls.CurveP384, tls.CurveP521:
		return "tls13-classical", true
	default:
		return "", false
	}
}

func ValidateServerCertificate(certificate tls.Certificate, routes []Route) error {
	if len(certificate.Certificate) == 0 || len(routes) == 0 {
		return errors.New("gateway TLS certificate and routes are required")
	}
	leaf := certificate.Leaf
	if leaf == nil {
		var err error
		leaf, err = x509.ParseCertificate(certificate.Certificate[0])
		if err != nil {
			return errors.New("gateway TLS certificate is invalid")
		}
	}
	now := time.Now()
	if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return errors.New("gateway TLS certificate is not currently valid")
	}
	for _, route := range routes {
		if !validHost(route.Host) || leaf.VerifyHostname(route.Host) != nil {
			return errors.New("gateway TLS certificate does not cover a configured hostname")
		}
	}
	return nil
}

func validGatewayRequest(r *http.Request) bool {
	if r.URL == nil || r.URL.IsAbs() || r.URL.Host != "" || r.URL.RawPath != "" || !validMethod(r.Method) {
		return false
	}
	path := r.URL.Path
	if len(path) == 0 || len(path) > 1024 || path[0] != '/' || strings.ContainsAny(path, "?#%\\") || strings.Contains(path, "..") || strings.TrimSpace(path) != path {
		return false
	}
	for _, ch := range path {
		if ch < 0x21 || ch > 0x7e {
			return false
		}
	}
	return len(r.RequestURI) <= maxGatewayRequest
}

func validateRoutes(routes []Route, allowedUpstreamHosts []string, environment string) error {
	if environment != "development" && environment != "production" {
		return errors.New("gateway environment is invalid")
	}
	allowed := make(map[string]struct{}, len(allowedUpstreamHosts))
	for _, host := range allowedUpstreamHosts {
		canonical := normalizeHostname(host)
		if !validHost(canonical) || canonical != host {
			return errors.New("gateway upstream host allowlist is invalid")
		}
		allowed[canonical] = struct{}{}
	}
	seen := make(map[string]struct{}, len(routes))
	for _, route := range routes {
		host := normalizeHostname(route.Host)
		target, err := url.Parse(route.UpstreamURL)
		if !validHost(host) || host != route.Host || !validUUID(route.TenantID) || !validUUID(route.ApplicationID) ||
			err != nil || target == nil || target.User != nil || target.RawQuery != "" || target.Fragment != "" || target.Opaque != "" ||
			(target.Path != "" && target.Path != "/") || strings.EqualFold(host, target.Hostname()) {
			return errors.New("gateway route contains an invalid host, tenant, application, or upstream")
		}
		if target.Scheme == "https" {
			if !validHost(strings.ToLower(target.Hostname())) || target.Port() != "" && target.Port() != "443" {
				return errors.New("gateway HTTPS upstream must use an allowlisted DNS host and port 443")
			}
			if _, ok := allowed[strings.ToLower(target.Hostname())]; !ok {
				return errors.New("gateway HTTPS upstream host is not allowlisted")
			}
		} else if !(environment == "development" && localHTTPUpstream(target)) {
			return errors.New("gateway upstream must use HTTPS; loopback HTTP is development-only")
		}
		if _, exists := seen[host]; exists {
			return errors.New("gateway route hosts must be unique")
		}
		seen[host] = struct{}{}
	}
	return nil
}

func localHTTPUpstream(target *url.URL) bool {
	if target == nil || target.Scheme != "http" || target.User != nil || target.RawQuery != "" || target.Fragment != "" || target.Opaque != "" {
		return false
	}
	address := net.ParseIP(target.Hostname())
	return address != nil && address.IsLoopback()
}

func bearerToken(values []string) (string, bool) {
	if len(values) != 1 {
		return "", false
	}
	parts := strings.SplitN(values[0], " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || len(parts[1]) == 0 || len(parts[1]) > 16<<10 || strings.ContainsAny(parts[1], " \t\r\n") {
		return "", false
	}
	return parts[1], true
}

func requestHostname(value string) string {
	host := strings.TrimSpace(value)
	if strings.Contains(host, ":") {
		if parsed, _, err := net.SplitHostPort(host); err == nil {
			host = parsed
		}
	}
	return normalizeHostname(host)
}

func normalizeHostname(host string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
}

func validHost(host string) bool {
	if len(host) == 0 || len(host) > 253 || net.ParseIP(host) != nil {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, ch := range label {
			if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-') {
				return false
			}
		}
	}
	return true
}

func validUUID(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return false
	}
	for index, ch := range value {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			continue
		}
		if !(ch >= '0' && ch <= '9' || ch >= 'a' && ch <= 'f' || ch >= 'A' && ch <= 'F') {
			return false
		}
	}
	return true
}

func validMethod(value string) bool {
	switch value {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}

func clientIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(strings.TrimSpace(remoteAddr))
	if err != nil {
		return "unknown"
	}
	address := net.ParseIP(host)
	if address == nil {
		return "unknown"
	}
	return address.String()
}

func stripForwardedHeaders(header http.Header) {
	for name := range header {
		lower := strings.ToLower(name)
		if lower == "forwarded" || lower == "x-real-ip" || lower == "x-forwarded-for" ||
			strings.HasPrefix(lower, "x-forwarded-") || strings.HasPrefix(lower, "x-original-") ||
			strings.HasPrefix(lower, "x-qg-") || lower == "x-envoy-external-address" || lower == "x-forwarded-client-cert" {
			header.Del(name)
		}
	}
}

func stripQGHeaders(header http.Header) {
	for name := range header {
		if strings.HasPrefix(strings.ToLower(name), "x-qg-") {
			header.Del(name)
		}
	}
}

func safeFailureDetail(status int) string {
	if status == http.StatusUnauthorized {
		return "The request identity could not be verified."
	}
	if status == http.StatusTooManyRequests {
		return "The request rate exceeds the configured limit."
	}
	return "The request could not be evaluated safely."
}

type gatewayProblem struct {
	Type      string `json:"type"`
	Title     string `json:"title"`
	Status    int    `json:"status"`
	Code      string `json:"code"`
	Detail    string `json:"detail"`
	RequestID string `json:"request_id"`
	Retryable bool   `json:"retryable"`
}

func writeProblem(w http.ResponseWriter, status int, code, detail, requestID string, retryable bool, retryAfter int) {
	w.Header().Set("Content-Type", "application/problem+json")
	if retryAfter > 0 {
		w.Header().Set("Retry-After", fmt.Sprintf("%d", retryAfter))
	}
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(gatewayProblem{
		Type: "about:blank", Title: http.StatusText(status), Status: status,
		Code: code, Detail: detail, RequestID: requestID, Retryable: retryable,
	})
}
