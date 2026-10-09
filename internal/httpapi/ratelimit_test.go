package httpapi

import (
	"bytes"
	"strings"
	"testing"
)

func TestRateLimitBucketsUseKeyedPseudonyms(t *testing.T) {
	key := bytes.Repeat([]byte("k"), 32)
	first := rateLimitBucketHash(key, "control-plane:ip", "203.0.113.10")
	if len(first) != 32 || !bytes.Equal(first, rateLimitBucketHash(key, "control-plane:ip", "203.0.113.10")) {
		t.Fatal("rate-limit HMAC should be a stable 32-byte digest for one dimension")
	}
	if bytes.Equal(first, rateLimitBucketHash(key, "control-plane:ip", "203.0.113.11")) ||
		bytes.Equal(first, rateLimitBucketHash(bytes.Repeat([]byte("x"), 32), "control-plane:ip", "203.0.113.10")) {
		t.Fatal("different client dimensions or privacy keys must produce different buckets")
	}
	if strings.Contains(string(first), "203.0.113.10") {
		t.Fatal("raw client dimension leaked into the stored bucket key")
	}
}

func TestClientIPDimensionNormalizesOnlySocketAddress(t *testing.T) {
	if got := clientIPDimension("203.0.113.10:443"); got != "203.0.113.10" {
		t.Fatalf("IPv4 socket address was not normalized: %q", got)
	}
	if got := clientIPDimension("[2001:db8::1]:443"); got != "2001:db8::1" {
		t.Fatalf("IPv6 socket address was not normalized: %q", got)
	}
	if got := clientIPDimension("untrusted-proxy-header"); got != "unknown" {
		t.Fatalf("invalid socket address should use a generic bucket: %q", got)
	}
}
