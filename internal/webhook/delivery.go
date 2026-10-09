// Package webhook implements QuantumGate's small, signed HTTP event transport.
package webhook

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"quantumgate/internal/keyprovider"
)

const (
	SchemaVersion   = 1
	MaxAttempts     = 8
	MaxBodyBytes    = 16 << 10
	signatureDomain = "QuantumGate-Webhook-Event-v1\x00"
)

type EventType string

const (
	PolicyActivated EventType = "policy.activated"
	PolicyRollback  EventType = "policy.rollback"
	KeyRotationDue  EventType = "key.rotation_due"
	KeyRevoked      EventType = "key.revoked"
	AdapterFailure  EventType = "adapter.failure"
	PostureBlocker  EventType = "posture.blocker_found"
)

var allowedEventTypes = map[EventType]struct{}{
	PolicyActivated: {}, PolicyRollback: {}, KeyRotationDue: {}, KeyRevoked: {},
	AdapterFailure: {}, PostureBlocker: {},
}

// Event contains only bounded, non-secret audit metadata. ReasonCode values
// are produced by QuantumGate's event mapper, never copied from request data.
type Event struct {
	ID            string
	Type          EventType
	TenantID      string
	ApplicationID string
	OccurredAt    time.Time
	CorrelationID string
	ResourceType  string
	ResourceID    string
	ReasonCode    string
}

// Envelope is serialized once and those exact bytes are signed and sent. Its
// fixed field order plus exact-byte verification avoids a second canonicalizer.
type Envelope struct {
	SchemaVersion int       `json:"schema_version"`
	EventID       string    `json:"event_id"`
	EventType     EventType `json:"event_type"`
	TenantID      string    `json:"tenant_id"`
	ApplicationID string    `json:"application_id"`
	OccurredAt    time.Time `json:"occurred_at"`
	SentAt        time.Time `json:"sent_at"`
	Attempt       int       `json:"attempt"`
	CorrelationID string    `json:"correlation_id"`
	DestinationID string    `json:"destination_id"`
	KeyID         string    `json:"key_id"`
	Algorithm     string    `json:"algorithm"`
	ResourceType  string    `json:"resource_type"`
	ResourceID    string    `json:"resource_id"`
	ReasonCode    string    `json:"reason_code"`
}

type Signer interface {
	Sign(context.Context, keyprovider.Scope, string, []byte, crypto.SignerOpts) ([]byte, error)
}

type SendResult struct {
	Delivered  bool
	Retryable  bool
	StatusCode int
	ErrorCode  string
}

type Sender interface {
	Send(context.Context, string, []byte, []byte) SendResult
}

type DeliveryJob struct {
	Event         Event
	Destination   string
	DestinationID string
	KeyID         string
	KeyReference  string
	Scope         keyprovider.Scope
	Attempt       int
	SentAt        time.Time
}

// Execute signs before sending. Any signer error or malformed signature stops
// delivery; the sender never has an unsigned-event path.
func Execute(ctx context.Context, job DeliveryJob, signer Signer, sender Sender) (SendResult, error) {
	if signer == nil || sender == nil || !validJob(job) {
		return SendResult{ErrorCode: "DELIVERY_CONFIGURATION_INVALID"}, errors.New("webhook delivery configuration is invalid")
	}
	envelope := Envelope{
		SchemaVersion: SchemaVersion, EventID: job.Event.ID, EventType: job.Event.Type,
		TenantID: job.Event.TenantID, ApplicationID: job.Event.ApplicationID,
		OccurredAt: job.Event.OccurredAt.UTC(), SentAt: job.SentAt.UTC(), Attempt: job.Attempt,
		CorrelationID: job.Event.CorrelationID, DestinationID: job.DestinationID,
		KeyID: job.KeyID, Algorithm: string(keyprovider.AlgorithmEd25519),
		ResourceType: job.Event.ResourceType, ResourceID: job.Event.ResourceID,
		ReasonCode: job.Event.ReasonCode,
	}
	body, err := json.Marshal(envelope)
	if err != nil || len(body) > MaxBodyBytes {
		return SendResult{ErrorCode: "EVENT_ENVELOPE_INVALID"}, errors.New("webhook event envelope is invalid")
	}
	signed := SigningBytes(body)
	signature, err := signer.Sign(ctx, job.Scope, job.KeyReference, signed, crypto.Hash(0))
	if err != nil {
		return classifySigningFailure(err), nil
	}
	if len(signature) != ed25519.SignatureSize {
		return SendResult{ErrorCode: "SIGNATURE_INVALID"}, nil
	}
	return sender.Send(ctx, job.Destination, body, signature), nil
}

func VerifyBody(body, signature []byte, publicKey ed25519.PublicKey) bool {
	if len(body) == 0 || len(body) > MaxBodyBytes || len(signature) != ed25519.SignatureSize || len(publicKey) != ed25519.PublicKeySize {
		return false
	}
	return ed25519.Verify(publicKey, SigningBytes(body), signature)
}

func SigningBytes(body []byte) []byte {
	result := make([]byte, 0, len(signatureDomain)+len(body))
	result = append(result, signatureDomain...)
	return append(result, body...)
}

func validJob(job DeliveryJob) bool {
	_, eventTypeOK := allowedEventTypes[job.Event.Type]
	return eventTypeOK && validUUID(job.Event.ID) && validUUID(job.Event.TenantID) &&
		validUUID(job.Event.ApplicationID) && validUUID(job.Event.ResourceID) && validUUID(job.DestinationID) &&
		validUUID(job.KeyID) && job.Event.OccurredAt.After(time.Time{}) && job.SentAt.After(time.Time{}) &&
		job.Attempt > 0 && job.Attempt <= 1_000_000 && len(job.Event.CorrelationID) >= 1 && len(job.Event.CorrelationID) <= 128 &&
		len(job.Event.ResourceType) >= 1 && len(job.Event.ResourceType) <= 64 &&
		len(job.Event.ReasonCode) >= 1 && len(job.Event.ReasonCode) <= 64 &&
		validUUID(job.Scope.TenantID) && validUUID(job.Scope.ApplicationID) && job.Scope.TenantID == job.Event.TenantID &&
		job.Scope.ApplicationID == job.Event.ApplicationID &&
		(job.Scope.Environment == "development" || job.Scope.Environment == "test" || job.Scope.Environment == "production") &&
		len(job.KeyReference) >= 16 && len(job.KeyReference) <= 1024
}

func ValidEventTypes(values []EventType) bool {
	if len(values) == 0 || len(values) > len(allowedEventTypes) {
		return false
	}
	seen := make(map[EventType]struct{}, len(values))
	for _, value := range values {
		if _, ok := allowedEventTypes[value]; !ok {
			return false
		}
		if _, ok := seen[value]; ok {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func validUUID(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return false
	}
	for i, char := range value {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			continue
		}
		if !((char >= '0' && char <= '9') || (char >= 'a' && char <= 'f') || (char >= 'A' && char <= 'F')) {
			return false
		}
	}
	return true
}

func classifySigningFailure(err error) SendResult {
	if errors.Is(err, keyprovider.ErrAuditUnavailable) {
		return SendResult{Retryable: true, ErrorCode: "SIGNING_AUDIT_UNAVAILABLE"}
	}
	if errors.Is(err, keyprovider.ErrProviderTimeout) || errors.Is(err, keyprovider.ErrProviderUnavailable) {
		return SendResult{Retryable: true, ErrorCode: "SIGNING_PROVIDER_UNAVAILABLE"}
	}
	return SendResult{ErrorCode: "SIGNING_FAILED"}
}

func RetryDelay(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	if attempt > MaxAttempts {
		attempt = MaxAttempts
	}
	delay := 5 * time.Second * time.Duration(1<<(attempt-1))
	if delay > 15*time.Minute {
		return 15 * time.Minute
	}
	return delay
}

func DeliveryDisposition(result SendResult, cycleAttempt int) string {
	if result.Delivered {
		return "delivered"
	}
	if result.Retryable && cycleAttempt > 0 && cycleAttempt < MaxAttempts {
		return "retry"
	}
	return "dead"
}

func ClassifyStatus(status int) SendResult {
	switch {
	case status >= 200 && status < 300:
		return SendResult{Delivered: true, StatusCode: status}
	case status == http.StatusRequestTimeout || status == http.StatusTooEarly || status == http.StatusTooManyRequests || status >= 500:
		return SendResult{Retryable: true, StatusCode: status, ErrorCode: "HTTP_RETRYABLE"}
	case status >= 300 && status < 400:
		return SendResult{StatusCode: status, ErrorCode: "HTTP_REDIRECT_REJECTED"}
	default:
		return SendResult{StatusCode: status, ErrorCode: "HTTP_PERMANENT_FAILURE"}
	}
}

func ClassifyTransportError(err error) SendResult {
	var unknownAuthority x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var certInvalid x509.CertificateInvalidError
	var verification *tls.CertificateVerificationError
	if errors.As(err, &unknownAuthority) || errors.As(err, &hostname) || errors.As(err, &certInvalid) || errors.As(err, &verification) {
		return SendResult{ErrorCode: "TLS_VERIFICATION_FAILED"}
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return SendResult{Retryable: true, ErrorCode: "DNS_FAILURE"}
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return SendResult{Retryable: true, ErrorCode: "HTTP_TIMEOUT"}
	}
	return SendResult{Retryable: true, ErrorCode: "HTTP_NETWORK_FAILURE"}
}

type resolver interface {
	LookupIPAddr(context.Context, string) ([]net.IPAddr, error)
}

type SenderClient struct {
	allowedHosts map[string]struct{}
	resolver     resolver
	client       *http.Client
}

func NewSender(allowedHosts []string) (*SenderClient, error) {
	allowed := make(map[string]struct{}, len(allowedHosts))
	for _, host := range allowedHosts {
		host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
		if !validDNSName(host) || unsafeWebhookHostname(host) {
			return nil, errors.New("webhook host allow-list is invalid")
		}
		if _, exists := allowed[host]; exists {
			return nil, errors.New("webhook host allow-list contains duplicates")
		}
		allowed[host] = struct{}{}
	}
	if len(allowed) == 0 {
		return nil, errors.New("webhook host allow-list is empty")
	}
	return &SenderClient{allowedHosts: allowed, resolver: net.DefaultResolver, client: &http.Client{Timeout: 6 * time.Second}}, nil
}

// ValidateDestination rejects arbitrary or credential-bearing URLs. Exact
// hostname allow-listing is combined with per-attempt DNS validation below.
func (s *SenderClient) ValidateDestination(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Fragment != "" || u.RawQuery != "" ||
		u.ForceQuery || u.Opaque != "" || u.Hostname() == "" || u.Port() != "" && u.Port() != "443" || len(raw) > 2048 ||
		strings.ContainsAny(raw, "\r\n\x00") {
		return errors.New("webhook destination is invalid")
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if !validDNSName(host) || unsafeWebhookHostname(host) {
		return errors.New("webhook destination is invalid")
	}
	if _, ok := s.allowedHosts[host]; !ok {
		return errors.New("webhook destination host is not allowed")
	}
	return nil
}

func (s *SenderClient) Send(ctx context.Context, destination string, body, signature []byte) SendResult {
	if s == nil || s.resolver == nil || s.client == nil || len(signature) != ed25519.SignatureSize || len(body) == 0 || len(body) > MaxBodyBytes {
		return SendResult{ErrorCode: "DELIVERY_CONFIGURATION_INVALID"}
	}
	if err := s.ValidateDestination(destination); err != nil {
		return SendResult{ErrorCode: "DESTINATION_REJECTED"}
	}
	u, _ := url.Parse(destination)
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	addresses, err := s.resolver.LookupIPAddr(ctx, host)
	if err != nil || len(addresses) == 0 {
		return SendResult{Retryable: true, ErrorCode: "DNS_FAILURE"}
	}
	for _, address := range addresses {
		if !publicDestinationIP(address.IP) {
			return SendResult{ErrorCode: "SSRF_DESTINATION_REJECTED"}
		}
	}
	port := "443"
	if u.Port() != "" {
		port = u.Port()
	}
	transport := &http.Transport{
		Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, DisableKeepAlives: true, TLSHandshakeTimeout: 3 * time.Second,
		ResponseHeaderTimeout: 4 * time.Second, ExpectContinueTimeout: time.Second,
		DialContext: func(dialCtx context.Context, network, address string) (net.Conn, error) {
			requestedHost, requestedPort, splitErr := net.SplitHostPort(address)
			if splitErr != nil || strings.ToLower(strings.TrimSuffix(requestedHost, ".")) != host || requestedPort != port {
				return nil, errors.New("webhook dial target changed")
			}
			dialer := net.Dialer{Timeout: 3 * time.Second, KeepAlive: -1}
			var lastErr error
			for _, ip := range addresses {
				if !publicDestinationIP(ip.IP) {
					return nil, errors.New("webhook DNS result is not public")
				}
				connection, dialErr := dialer.DialContext(dialCtx, network, net.JoinHostPort(ip.IP.String(), port))
				if dialErr == nil {
					return connection, nil
				}
				lastErr = dialErr
			}
			return nil, lastErr
		},
	}
	client := *s.client
	if s.client.Transport == nil {
		client.Transport = transport
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, destination, bytes.NewReader(body))
	if err != nil {
		return SendResult{ErrorCode: "DESTINATION_REJECTED"}
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-QG-Signature", "ed25519="+base64.StdEncoding.EncodeToString(signature))
	request.Header.Set("User-Agent", "QuantumGate-Webhook/1")
	response, err := client.Do(request)
	if err != nil {
		return ClassifyTransportError(err)
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	return ClassifyStatus(response.StatusCode)
}

func validDNSName(host string) bool {
	if host == "" || len(host) > 253 || net.ParseIP(host) != nil {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, char := range label {
			if !(char >= 'a' && char <= 'z' || char >= '0' && char <= '9' || char == '-') {
				return false
			}
		}
	}
	return true
}

var blockedPrefixes = parsePrefixes([]string{
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
	"172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16",
	"198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
	"::/128", "::1/128", "64:ff9b::/96", "64:ff9b:1::/48", "100::/64", "2001::/23", "2001:2::/48", "2001:db8::/32", "2001:10::/28", "2002::/16",
	"fc00::/7", "fe80::/10", "ff00::/8",
})

func parsePrefixes(values []string) []*net.IPNet {
	result := make([]*net.IPNet, 0, len(values))
	for _, value := range values {
		_, subnet, err := net.ParseCIDR(value)
		if err == nil {
			result = append(result, subnet)
		}
	}
	return result
}

func publicDestinationIP(value net.IP) bool {
	if value == nil {
		return false
	}
	if mapped := value.To4(); mapped != nil {
		value = mapped
	}
	if !value.IsGlobalUnicast() || value.IsPrivate() || value.IsLoopback() || value.IsLinkLocalUnicast() ||
		value.IsLinkLocalMulticast() || value.IsMulticast() || value.IsUnspecified() {
		return false
	}
	for _, prefix := range blockedPrefixes {
		if prefix.Contains(value) {
			return false
		}
	}
	return true
}

func unsafeWebhookHostname(host string) bool {
	if !strings.Contains(host, ".") {
		return true
	}
	for _, suffix := range []string{".localhost", ".local", ".internal", ".test", ".invalid"} {
		if strings.HasSuffix(host, suffix) {
			return true
		}
	}
	return false
}
