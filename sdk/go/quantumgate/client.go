package quantumgate

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	defaultTimeout = 5 * time.Second
	maxTimeout     = 30 * time.Second
	maxResponse    = 64 << 10
)

type Config struct {
	Endpoint      string
	TenantID      string
	ApplicationID string
	ClientSecret  string
	Timeout       time.Duration
}

type Client struct {
	baseURL       url.URL
	tenantID      string
	applicationID string
	clientSecret  string
	httpClient    *http.Client
	tokenMu       sync.Mutex
	tokens        map[string]cachedToken
}

type cachedToken struct {
	value     string
	expiresAt time.Time
}

type Observation struct {
	Source           string              `json:"source"`
	Protocol         string              `json:"protocol"`
	AlgorithmProfile string              `json:"algorithm_profile"`
	Blocker          *string             `json:"blocker,omitempty"`
	Confidence       string              `json:"confidence"`
	ObservedAt       *time.Time          `json:"observed_at,omitempty"`
	Evidence         ObservationEvidence `json:"evidence,omitempty"`
	IdempotencyKey   string              `json:"-"`
}

type ObservationEvidence struct {
	KeyExchange     string `json:"key_exchange,omitempty"`
	SignatureScheme string `json:"signature_scheme,omitempty"`
	EndpointRole    string `json:"endpoint_role,omitempty"`
}

type Accepted struct {
	ObservationID string    `json:"observation_id"`
	ApplicationID string    `json:"application_id"`
	ObservedAt    time.Time `json:"observed_at"`
	RequestID     string    `json:"request_id"`
}

type DecisionRequest struct {
	Method        string `json:"method"`
	Path          string `json:"path"`
	IdentityToken string `json:"identity_token"`
}

type Decision struct {
	RequestID              string     `json:"request_id"`
	TenantID               string     `json:"tenant_id"`
	ApplicationID          string     `json:"application_id"`
	Method                 string     `json:"method"`
	Path                   string     `json:"path"`
	ProfileID              string     `json:"profile_id"`
	ProfileRegistryVersion int64      `json:"profile_registry_version"`
	ProfileHash            string     `json:"profile_hash"`
	PolicyRevisionID       string     `json:"policy_revision_id"`
	Mode                   string     `json:"mode"`
	Decision               string     `json:"decision"`
	ReasonCodes            []string   `json:"reason_codes"`
	ExpiresAt              *time.Time `json:"expires_at,omitempty"`
}

type APIError struct {
	StatusCode int    `json:"status"`
	Code       string `json:"code"`
	Detail     string `json:"detail"`
	RequestID  string `json:"request_id"`
}

func (e *APIError) Error() string {
	if e == nil {
		return "QuantumGate request failed"
	}
	if e.Code != "" {
		return fmt.Sprintf("QuantumGate request failed (%d %s)", e.StatusCode, e.Code)
	}
	return fmt.Sprintf("QuantumGate request failed (%d)", e.StatusCode)
}

func NewClient(config Config) (*Client, error) {
	if !validUUID(config.ApplicationID) || !validClientSecret(config.ClientSecret) {
		return nil, errors.New("a valid application ID and QuantumGate client secret are required")
	}
	if config.TenantID != "" && !validUUID(config.TenantID) {
		return nil, errors.New("tenant ID must be a valid UUID")
	}
	rawEndpoint := strings.TrimSpace(config.Endpoint)
	base, err := url.Parse(rawEndpoint)
	if err != nil || base.Host == "" || base.User != nil || base.RawQuery != "" || base.ForceQuery || base.Fragment != "" || base.Opaque != "" || strings.ContainsAny(rawEndpoint, "?# \t\r\n") {
		return nil, errors.New("endpoint must be an absolute HTTPS URL without credentials, query, or fragment")
	}
	if base.Scheme != "https" && !(base.Scheme == "http" && isLoopbackHost(base.Hostname())) {
		return nil, errors.New("endpoint must use HTTPS except for a localhost development endpoint")
	}
	base.Path = strings.TrimSuffix(base.Path, "/")
	base.RawPath = ""
	timeout := config.Timeout
	if timeout == 0 {
		timeout = defaultTimeout
	}
	if timeout < 100*time.Millisecond || timeout > maxTimeout {
		return nil, errors.New("timeout must be between 100ms and 30s")
	}
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   timeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ExpectContinueTimeout: time.Second,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS13},
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return &Client{
		baseURL:       *base,
		tenantID:      strings.ToLower(config.TenantID),
		applicationID: strings.ToLower(config.ApplicationID),
		clientSecret:  config.ClientSecret,
		httpClient:    client,
	}, nil
}

func (c *Client) Observe(ctx context.Context, observation Observation) (Accepted, error) {
	if c == nil || c.httpClient == nil {
		return Accepted{}, errors.New("QuantumGate client is not configured")
	}
	token, err := c.serviceToken(ctx, "observations:write")
	if err != nil {
		return Accepted{}, err
	}
	body, err := json.Marshal(observation)
	if err != nil {
		return Accepted{}, errors.New("observation could not be encoded")
	}
	idempotencyKey := observation.IdempotencyKey
	if idempotencyKey == "" {
		idempotencyKey, err = newIdempotencyKey()
		if err != nil {
			return Accepted{}, errors.New("idempotency key could not be generated safely")
		}
	}
	if !validIdempotencyKey(idempotencyKey) {
		return Accepted{}, errors.New("idempotency key must contain 16 to 128 safe ASCII characters")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.endpoint("/v1/applications/"+c.applicationID+"/observations"), strings.NewReader(string(body)))
	if err != nil {
		return Accepted{}, errors.New("observation request could not be created")
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", idempotencyKey)
	response, err := c.httpClient.Do(request)
	if err != nil {
		return Accepted{}, fmt.Errorf("send QuantumGate observation: %w", err)
	}
	defer response.Body.Close()
	responseBody, err := readBounded(response.Body)
	if err != nil {
		return Accepted{}, err
	}
	if response.StatusCode != http.StatusCreated {
		return Accepted{}, decodeAPIError(response.StatusCode, responseBody)
	}
	var accepted Accepted
	if err := json.Unmarshal(responseBody, &accepted); err != nil || accepted.ObservationID == "" || accepted.ApplicationID != c.applicationID {
		return Accepted{}, errors.New("QuantumGate returned an invalid observation response")
	}
	return accepted, nil
}

// Protect requests a fresh server-side policy decision for an existing
// application's authenticated action context. It returns policy outcomes,
// including deny and step_up, without interpreting them locally.
func (c *Client) Protect(ctx context.Context, decisionRequest DecisionRequest) (Decision, error) {
	if c == nil || c.httpClient == nil {
		return Decision{}, errors.New("QuantumGate client is not configured")
	}
	if c.baseURL.Scheme != "https" {
		return Decision{}, errors.New("QuantumGate decisions require an HTTPS endpoint")
	}
	if !validUUID(c.tenantID) || !validDecisionRequest(decisionRequest) {
		return Decision{}, errors.New("a tenant ID and valid protected request context are required")
	}
	token, err := c.serviceToken(ctx, "decisions:evaluate")
	if err != nil {
		return Decision{}, err
	}
	body, err := json.Marshal(decisionRequest)
	if err != nil || len(body) > maxResponse {
		return Decision{}, errors.New("decision request could not be encoded safely")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.endpoint("/v1/applications/"+c.applicationID+"/decisions"), strings.NewReader(string(body)))
	if err != nil {
		return Decision{}, errors.New("decision request could not be created")
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	response, err := c.httpClient.Do(request)
	if err != nil {
		return Decision{}, fmt.Errorf("send QuantumGate decision request: %w", err)
	}
	defer response.Body.Close()
	responseBody, err := readBounded(response.Body)
	if err != nil {
		return Decision{}, err
	}
	if response.StatusCode != http.StatusOK {
		apiError := decodeAPIError(response.StatusCode, responseBody)
		if parsed, ok := apiError.(*APIError); ok {
			parsed.Detail = ""
		}
		return Decision{}, apiError
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return Decision{}, errors.New("QuantumGate returned an invalid decision response")
	}
	var decision Decision
	if err := json.Unmarshal(responseBody, &decision); err != nil || !validDecisionResponse(decision, decisionRequest, c, response) {
		return Decision{}, errors.New("QuantumGate returned an invalid decision response")
	}
	return decision, nil
}

func (c *Client) Health(ctx context.Context) error {
	if c == nil || c.httpClient == nil {
		return errors.New("QuantumGate client is not configured")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint("/health/ready"), nil)
	if err != nil {
		return errors.New("health request could not be created")
	}
	response, err := c.httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("check QuantumGate health: %w", err)
	}
	defer response.Body.Close()
	responseBody, err := readBounded(response.Body)
	if err != nil {
		return err
	}
	if response.StatusCode != http.StatusOK {
		return decodeAPIError(response.StatusCode, responseBody)
	}
	return nil
}

func (c *Client) serviceToken(ctx context.Context, scope string) (string, error) {
	if scope != "observations:write" && scope != "decisions:evaluate" {
		return "", errors.New("QuantumGate token scope is not supported")
	}
	c.tokenMu.Lock()
	defer c.tokenMu.Unlock()
	if c.tokens == nil {
		c.tokens = make(map[string]cachedToken)
	}
	if cached, ok := c.tokens[scope]; ok && time.Now().Add(15*time.Second).Before(cached.expiresAt) {
		return cached.value, nil
	}
	form := url.Values{"grant_type": {"client_credentials"}, "scope": {scope}}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint("/oauth/token"), strings.NewReader(form.Encode()))
	if err != nil {
		return "", errors.New("token request could not be created")
	}
	request.SetBasicAuth(c.applicationID, c.clientSecret)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "application/json")
	response, err := c.httpClient.Do(request)
	if err != nil {
		return "", fmt.Errorf("request QuantumGate access token: %w", err)
	}
	defer response.Body.Close()
	responseBody, err := readBounded(response.Body)
	if err != nil {
		return "", err
	}
	if response.StatusCode != http.StatusOK {
		return "", decodeAPIError(response.StatusCode, responseBody)
	}
	var tokenResponse struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
		Scope       string `json:"scope"`
	}
	if err := json.Unmarshal(responseBody, &tokenResponse); err != nil || !validAccessToken(tokenResponse.AccessToken) ||
		!strings.EqualFold(tokenResponse.TokenType, "Bearer") || tokenResponse.ExpiresIn < 1 || tokenResponse.ExpiresIn > 300 ||
		tokenResponse.Scope != scope {
		return "", errors.New("QuantumGate returned an invalid access token")
	}
	cached := cachedToken{value: tokenResponse.AccessToken, expiresAt: time.Now().Add(time.Duration(tokenResponse.ExpiresIn) * time.Second)}
	c.tokens[scope] = cached
	return cached.value, nil
}

func validDecisionRequest(request DecisionRequest) bool {
	if request.Method != "GET" && request.Method != "HEAD" && request.Method != "POST" && request.Method != "PUT" && request.Method != "PATCH" && request.Method != "DELETE" {
		return false
	}
	if len(request.Path) == 0 || len(request.Path) > 1024 || request.Path[0] != '/' ||
		strings.ContainsAny(request.Path, "?#%\\") || strings.Contains(request.Path, "..") || strings.TrimSpace(request.Path) != request.Path {
		return false
	}
	for _, char := range request.Path {
		if char < 0x21 || char > 0x7e {
			return false
		}
	}
	parsed, err := url.ParseRequestURI(request.Path)
	return err == nil && parsed.Path == request.Path && parsed.RawQuery == "" && parsed.Fragment == "" && validBoundedText(request.IdentityToken, 16<<10)
}

func validDecisionResponse(decision Decision, request DecisionRequest, client *Client, response *http.Response) bool {
	if client == nil || response == nil || response.TLS == nil || !validUUID(decision.TenantID) || decision.TenantID != client.tenantID ||
		!validUUID(decision.ApplicationID) || decision.ApplicationID != client.applicationID ||
		decision.Method != request.Method || decision.Path != request.Path || !validUUID(decision.PolicyRevisionID) ||
		!validCorrelationID(decision.RequestID) || decision.RequestID != response.Header.Get("X-Request-ID") ||
		decision.ProfileID != tlsProfile(response.TLS) || decision.ProfileID == "" ||
		response.Header.Get("X-QG-Transport-Profile") != decision.ProfileID ||
		response.Header.Get("X-QG-Policy-Revision") != decision.PolicyRevisionID ||
		decision.ProfileRegistryVersion < 1 || !validProfileHash(decision.ProfileHash) ||
		!oneOf(decision.Mode, "classical-approved", "hybrid-approved", "pqc-approved", "observe-only") ||
		!oneOf(decision.Decision, "allow", "deny", "step_up", "observe", "degraded_allowed") ||
		len(decision.ReasonCodes) == 0 || len(decision.ReasonCodes) > 16 {
		return false
	}
	for _, reason := range decision.ReasonCodes {
		if !validReasonCode(reason) {
			return false
		}
	}
	return decision.ExpiresAt == nil || (!decision.ExpiresAt.IsZero() && decision.ExpiresAt.After(time.Now()))
}

func tlsProfile(state *tls.ConnectionState) string {
	if state == nil || state.Version != tls.VersionTLS13 {
		return ""
	}
	switch state.CurveID {
	case tls.X25519MLKEM768:
		return "tls13-x25519-mlkem768"
	case tls.X25519, tls.CurveP256, tls.CurveP384, tls.CurveP521:
		return "tls13-classical"
	default:
		return ""
	}
}

func validProfileHash(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && hex.EncodeToString(decoded) == value
}

func validCorrelationID(value string) bool { return validBoundedText(value, 128) }

func validReasonCode(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for _, char := range value {
		if !(char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || char == '_') {
			return false
		}
	}
	return true
}

func oneOf(value string, options ...string) bool {
	for _, option := range options {
		if value == option {
			return true
		}
	}
	return false
}

func validBoundedText(value string, maximum int) bool {
	if len(value) == 0 || len(value) > maximum || strings.TrimSpace(value) != value {
		return false
	}
	for _, char := range value {
		if char < 0x21 || char > 0x7e {
			return false
		}
	}
	return true
}

func (c *Client) endpoint(path string) string {
	endpoint := c.baseURL
	endpoint.Path = strings.TrimSuffix(endpoint.Path, "/") + path
	return endpoint.String()
}

func readBounded(reader io.Reader) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(reader, maxResponse+1))
	if err != nil || len(body) > maxResponse {
		return nil, errors.New("QuantumGate response exceeded the size limit or could not be read")
	}
	return body, nil
}

func decodeAPIError(status int, body []byte) error {
	var apiError APIError
	if err := json.Unmarshal(body, &apiError); err != nil {
		return &APIError{StatusCode: status}
	}
	apiError.StatusCode = status
	if apiError.Code != "" && !validReasonCode(apiError.Code) {
		apiError.Code = ""
	}
	return &apiError
}

func newIdempotencyKey() (string, error) {
	bytes := make([]byte, 24)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return "qg-observation-" + base64.RawURLEncoding.EncodeToString(bytes), nil
}

func validIdempotencyKey(value string) bool {
	if len(value) < 16 || len(value) > 128 {
		return false
	}
	for _, char := range value {
		if !(char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || strings.ContainsRune("._~-", char)) {
			return false
		}
	}
	return true
}

func validClientSecret(value string) bool { return validOpaqueValue(value, "qgc_") }
func validAccessToken(value string) bool  { return validOpaqueValue(value, "qgt_") }

func validOpaqueValue(value, prefix string) bool {
	if !strings.HasPrefix(value, prefix) {
		return false
	}
	encoded := strings.TrimPrefix(value, prefix)
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	return err == nil && len(decoded) == 32 && base64.RawURLEncoding.EncodeToString(decoded) == encoded
}

func validUUID(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return false
	}
	for index, char := range value {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			continue
		}
		if !(char >= '0' && char <= '9' || char >= 'a' && char <= 'f' || char >= 'A' && char <= 'F') {
			return false
		}
	}
	return true
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	address := net.ParseIP(host)
	return address != nil && address.IsLoopback()
}
