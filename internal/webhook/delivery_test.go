package webhook

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"quantumgate/internal/keyprovider"
)

const (
	testTenant = "9c0d0c44-1e99-4d15-8c4f-a303d6389890"
	testApp    = "bd3e5672-e07d-4f72-a82d-62a2c4d3e4cc"
	testID     = "ab3e5672-e07d-4f72-a82d-62a2c4d3e4cc"
	testDest   = "cb3e5672-e07d-4f72-a82d-62a2c4d3e4cc"
	testKeyID  = "db3e5672-e07d-4f72-a82d-62a2c4d3e4cc"
)

func testJob() DeliveryJob {
	now := time.Date(2026, 9, 28, 12, 30, 0, 123456000, time.UTC)
	return DeliveryJob{
		Event: Event{ID: testID, Type: PolicyActivated, TenantID: testTenant, ApplicationID: testApp,
			OccurredAt: now.Add(-time.Minute), CorrelationID: "req-123", ResourceType: "policy_revision",
			ResourceID: testID, ReasonCode: "POLICY_ACTIVATED"},
		Destination: "https://hooks.example.com/qg/events", DestinationID: testDest, KeyID: testKeyID,
		KeyReference: "provider-reference-not-public", Scope: keyprovider.Scope{TenantID: testTenant, ApplicationID: testApp, Environment: "test"},
		Attempt: 1, SentAt: now,
	}
}

type testSigner struct {
	private   ed25519.PrivateKey
	signature []byte
	err       error
	called    int
}

func (s *testSigner) Sign(_ context.Context, scope keyprovider.Scope, reference string, message []byte, opts crypto.SignerOpts) ([]byte, error) {
	s.called++
	if scope.TenantID != testTenant || scope.ApplicationID != testApp || reference != "provider-reference-not-public" || opts.HashFunc() != 0 {
		return nil, errors.New("unexpected signer context")
	}
	if s.err != nil {
		return nil, s.err
	}
	if s.signature != nil {
		return append([]byte(nil), s.signature...), nil
	}
	return ed25519.Sign(s.private, message), nil
}

type testSender struct {
	called int
	body   []byte
	sig    []byte
	result SendResult
}

func (s *testSender) Send(_ context.Context, _ string, body, signature []byte) SendResult {
	s.called++
	s.body = append([]byte(nil), body...)
	s.sig = append([]byte(nil), signature...)
	return s.result
}

func TestExecuteSignsExactStableEnvelopeAndSendsOnlySignedEvents(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer := &testSigner{private: private}
	sender := &testSender{result: SendResult{Delivered: true, StatusCode: http.StatusNoContent}}
	result, err := Execute(context.Background(), testJob(), signer, sender)
	if err != nil || !result.Delivered || sender.called != 1 {
		t.Fatalf("Execute() = %+v, %v, send calls %d", result, err, sender.called)
	}
	if !VerifyBody(sender.body, sender.sig, public) {
		t.Fatal("signature did not verify over exact sent body")
	}
	var envelope Envelope
	if err := json.Unmarshal(sender.body, &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.SchemaVersion != 1 || envelope.EventID != testID || envelope.EventType != PolicyActivated ||
		envelope.TenantID != testTenant || envelope.DestinationID != testDest || envelope.KeyID != testKeyID ||
		envelope.Algorithm != "Ed25519" || envelope.Attempt != 1 || envelope.SentAt.IsZero() {
		t.Fatalf("unexpected signed envelope: %+v", envelope)
	}
	changed := testJob()
	changed.Attempt = 2
	second := &testSender{}
	if _, err := Execute(context.Background(), changed, signer, second); err != nil {
		t.Fatal(err)
	}
	if string(sender.body) == string(second.body) || VerifyBody(second.body, sender.sig, public) {
		t.Fatal("attempt changes must be authenticated in the signed bytes")
	}
}

func TestExecuteFailsClosedOnProviderFailureOrBadSignature(t *testing.T) {
	for _, tc := range []struct {
		name      string
		signer    *testSigner
		want      string
		retryable bool
	}{
		{name: "provider outage retries", signer: &testSigner{err: keyprovider.ErrProviderUnavailable}, want: "SIGNING_PROVIDER_UNAVAILABLE", retryable: true},
		{name: "audit outage retries", signer: &testSigner{err: keyprovider.ErrAuditUnavailable}, want: "SIGNING_AUDIT_UNAVAILABLE", retryable: true},
		{name: "disabled key is permanent", signer: &testSigner{err: keyprovider.ErrKeyUnavailable}, want: "SIGNING_FAILED"},
		{name: "malformed signature is permanent", signer: &testSigner{signature: []byte("bad")}, want: "SIGNATURE_INVALID"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sender := &testSender{}
			signer := tc.signer
			result, err := Execute(context.Background(), testJob(), signer, sender)
			if err != nil || sender.called != 0 || result.ErrorCode != tc.want || result.Retryable != tc.retryable {
				t.Fatalf("Execute() = %+v, %v, send calls %d", result, err, sender.called)
			}
		})
	}
}

func TestDestinationValidationRequiresExactHTTPSAllowList(t *testing.T) {
	sender, err := NewSender([]string{"hooks.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if err := sender.ValidateDestination("https://hooks.example.com:443/qg/events"); err != nil {
		t.Fatalf("valid allow-listed HTTPS URL rejected: %v", err)
	}
	for _, raw := range []string{
		"http://hooks.example.com/events", "https://evil.example.com/events",
		"https://hooks.example.com:8443/events", "https://user:pass@hooks.example.com/events",
		"https://hooks.example.com/events?token=secret", "https://127.0.0.1/events",
		"https://hooks.example.com/events#fragment", "https://hooks.example.com/events\r\nX-Evil: yes",
		"https://hooks.example.com/events?", "https://hooks.localhost/events", "https://localhost/events",
	} {
		if err := sender.ValidateDestination(raw); err == nil {
			t.Errorf("unsafe destination accepted: %q", raw)
		}
	}
	if _, err := NewSender([]string{"*.example.com"}); err == nil {
		t.Fatal("wildcard allow-list must be rejected")
	}
	for _, host := range []string{"localhost", "hooks.localhost", "hooks.internal", "hooks.test"} {
		if _, err := NewSender([]string{host}); err == nil {
			t.Errorf("unsafe allow-list host accepted: %s", host)
		}
	}
}

type testResolver struct {
	addresses []net.IPAddr
	err       error
	called    int
}

func (r *testResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	r.called++
	if host != "hooks.example.com" {
		return nil, errors.New("unexpected lookup host")
	}
	return r.addresses, r.err
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }

func TestSenderPinsAndValidatesDNSAndClassifiesHTTPWithoutRedirects(t *testing.T) {
	sender, err := NewSender([]string{"hooks.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	sender.resolver = &testResolver{addresses: []net.IPAddr{{IP: net.ParseIP("8.8.8.8")}}}
	calls := 0
	sender.client.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls++
		if request.URL.Host != "hooks.example.com" || request.URL.Scheme != "https" || request.Header.Get("Content-Type") != "application/json" ||
			!strings.HasPrefix(request.Header.Get("X-QG-Signature"), "ed25519=") {
			t.Fatalf("unexpected outbound request: URL=%s headers=%v", request.URL, request.Header)
		}
		if calls == 1 {
			return &http.Response{StatusCode: http.StatusFound, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("")), Request: request}, nil
		}
		return &http.Response{StatusCode: http.StatusNoContent, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("")), Request: request}, nil
	})
	result := sender.Send(context.Background(), "https://hooks.example.com/qg/events", []byte(`{"event_id":"one"}`), make([]byte, ed25519.SignatureSize))
	if result.Delivered || result.Retryable || result.ErrorCode != "HTTP_REDIRECT_REJECTED" || calls != 1 {
		t.Fatalf("redirect result = %+v, calls=%d", result, calls)
	}
	sender.client.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusNoContent, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("")), Request: request}, nil
	})
	result = sender.Send(context.Background(), "https://hooks.example.com/qg/events", []byte(`{"event_id":"one"}`), make([]byte, ed25519.SignatureSize))
	if !result.Delivered || result.StatusCode != http.StatusNoContent {
		t.Fatalf("2xx result = %+v", result)
	}
}

func TestSenderRejectsPrivateDNSAndRetriesDNSFailure(t *testing.T) {
	sender, err := NewSender([]string{"hooks.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	for _, ip := range []string{"127.0.0.1", "10.2.3.4", "169.254.169.254", "192.168.1.5", "100.64.0.1", "::1", "fd00::1", "fe80::1"} {
		resolver := &testResolver{addresses: []net.IPAddr{{IP: net.ParseIP(ip)}}}
		sender.resolver = resolver
		result := sender.Send(context.Background(), "https://hooks.example.com/events", []byte(`{"event_id":"one"}`), make([]byte, ed25519.SignatureSize))
		if result.ErrorCode != "SSRF_DESTINATION_REJECTED" || result.Retryable {
			t.Errorf("address %s result = %+v", ip, result)
		}
	}
	sender.resolver = &testResolver{err: &net.DNSError{Err: "lookup failed", Name: "hooks.example.com", IsTemporary: true}}
	result := sender.Send(context.Background(), "https://hooks.example.com/events", []byte(`{"event_id":"one"}`), make([]byte, ed25519.SignatureSize))
	if result.ErrorCode != "DNS_FAILURE" || !result.Retryable {
		t.Fatalf("DNS outage result = %+v", result)
	}
}

func TestRetryClassificationAndBackoffAreBounded(t *testing.T) {
	if !ClassifyStatus(200).Delivered || !ClassifyStatus(204).Delivered {
		t.Fatal("2xx statuses must deliver")
	}
	for _, status := range []int{408, 425, 429, 500, 503} {
		if !ClassifyStatus(status).Retryable {
			t.Errorf("%d should be retryable", status)
		}
	}
	for _, status := range []int{301, 302, 400, 401, 404} {
		if result := ClassifyStatus(status); result.Retryable || result.Delivered {
			t.Errorf("%d should be permanent: %+v", status, result)
		}
	}
	if RetryDelay(1) != 5*time.Second || RetryDelay(MaxAttempts) > 15*time.Minute {
		t.Fatal("unexpected retry backoff bounds")
	}
	if RetryDelay(MaxAttempts) <= 0 || RetryDelay(MaxAttempts+1) != RetryDelay(MaxAttempts) {
		t.Fatal("retry backoff must be bounded")
	}
	for _, tc := range []struct {
		result  SendResult
		attempt int
		want    string
	}{
		{SendResult{Delivered: true}, 1, "delivered"},
		{SendResult{Retryable: true}, 1, "retry"},
		{SendResult{Retryable: true}, MaxAttempts, "dead"},
		{SendResult{ErrorCode: "TLS_VERIFICATION_FAILED"}, 1, "dead"},
	} {
		if got := DeliveryDisposition(tc.result, tc.attempt); got != tc.want {
			t.Errorf("DeliveryDisposition(%+v, %d) = %q, want %q", tc.result, tc.attempt, got, tc.want)
		}
	}
	if got := ClassifyTransportError(x509.UnknownAuthorityError{}); got.Retryable || got.ErrorCode != "TLS_VERIFICATION_FAILED" {
		t.Fatalf("TLS failure result = %+v", got)
	}
}

func TestEventMapperAllowsOnlySafeApprovedAuditActions(t *testing.T) {
	cases := []struct {
		action, targetType, outcome, reason string
		want                                EventType
		wantReason                          string
	}{
		{"policy.activated", "policy_revision", "success", "ACTIVATED", PolicyActivated, "POLICY_ACTIVATED"},
		{"policy.scheduled_activated", "policy_revision", "success", "SCHEDULED_ACTIVATION", PolicyActivated, "POLICY_ACTIVATED"},
		{"policy.rolled_back", "policy_revision", "success", "ROLLBACK_SECURITY", PolicyRollback, "ROLLBACK_SECURITY"},
		{"identity_adapter.verification_failed", "identity_adapter", "failure", "raw provider error", AdapterFailure, "ADAPTER_VERIFICATION_FAILED"},
		{"key_reference.revoked", "key_reference", "success", "REVOKED", KeyRevoked, "KEY_REVOKED"},
	}
	for _, tc := range cases {
		got, reason, ok := EventForAudit(tc.action, tc.targetType, testID, tc.outcome, tc.reason)
		if !ok || got != tc.want || reason != tc.wantReason {
			t.Errorf("EventForAudit(%q) = %q, %q, %v", tc.action, got, reason, ok)
		}
	}
	for _, tc := range []struct{ action, targetType, outcome string }{
		{"identity_adapter.verification_failed", "identity_adapter", "success"},
		{"policy.activated", "policy_revision", "failure"},
		{"webhook.event_queued", "webhook_event", "success"},
		{"policy.activated", "key_reference", "success"},
	} {
		if _, _, ok := EventForAudit(tc.action, tc.targetType, testID, tc.outcome, "anything"); ok {
			t.Errorf("unapproved audit action was mapped: %+v", tc)
		}
	}
}
