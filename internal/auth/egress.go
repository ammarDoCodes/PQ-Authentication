package auth

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

const maxOIDCResponseBytes = 1 << 20

var errEgressDenied = errors.New("OIDC egress policy denied the request")
var blockedEgressPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"),
}

type ipResolver interface {
	LookupIPAddr(context.Context, string) ([]net.IPAddr, error)
}

type restrictedTransport struct {
	base     *http.Transport
	allowed  map[string]struct{}
	resolver ipResolver
	dialer   net.Dialer
}

func newRestrictedHTTPClient(hosts []string) *http.Client {
	allowed := make(map[string]struct{}, len(hosts))
	for _, host := range hosts {
		allowed[strings.ToLower(strings.TrimSuffix(host, "."))] = struct{}{}
	}
	rt := &restrictedTransport{
		allowed:  allowed,
		resolver: net.DefaultResolver,
		dialer:   net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second},
	}
	rt.base = &http.Transport{
		Proxy:                  nil,
		DialContext:            rt.dialContext,
		TLSClientConfig:        &tlsConfig,
		TLSHandshakeTimeout:    5 * time.Second,
		ResponseHeaderTimeout:  5 * time.Second,
		MaxResponseHeaderBytes: 64 << 10,
		DisableCompression:     true,
	}
	return &http.Client{
		Transport:     rt,
		Timeout:       10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

var tlsConfig = structTLSConfig()

func structTLSConfig() tls.Config {
	return tls.Config{MinVersion: tls.VersionTLS13}
}

func (t *restrictedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL == nil || req.URL.Scheme != "https" || req.URL.User != nil || req.URL.Fragment != "" {
		return nil, errEgressDenied
	}
	host := strings.ToLower(strings.TrimSuffix(req.URL.Hostname(), "."))
	if _, ok := t.allowed[host]; !ok || net.ParseIP(host) != nil {
		return nil, errEgressDenied
	}
	if port := req.URL.Port(); port != "" && port != "443" {
		return nil, errEgressDenied
	}
	resp, err := t.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	if resp.Body == nil {
		return resp, nil
	}
	if resp.ContentLength > maxOIDCResponseBytes {
		_ = resp.Body.Close()
		return nil, errors.New("OIDC response exceeded size limit")
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxOIDCResponseBytes+1))
	_ = resp.Body.Close()
	if err != nil {
		return nil, errors.New("OIDC response could not be read")
	}
	if len(body) > maxOIDCResponseBytes {
		return nil, errors.New("OIDC response exceeded size limit")
	}
	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))
	return resp, nil
}

func (t *restrictedTransport) dialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil || port != "443" {
		return nil, errEgressDenied
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if _, ok := t.allowed[host]; !ok || net.ParseIP(host) != nil {
		return nil, errEgressDenied
	}
	ips, err := t.resolver.LookupIPAddr(ctx, host)
	if err != nil || len(ips) == 0 {
		return nil, errEgressDenied
	}
	candidates := make([]netip.Addr, 0, len(ips))
	for _, candidate := range ips {
		addr, ok := netip.AddrFromSlice(candidate.IP)
		if !ok {
			return nil, errEgressDenied
		}
		addr = addr.Unmap()
		if !publicUnicast(addr) {
			return nil, errEgressDenied
		}
		candidates = append(candidates, addr)
	}
	var lastErr error
	for _, candidate := range candidates {
		conn, dialErr := t.dialer.DialContext(ctx, network, net.JoinHostPort(candidate.String(), port))
		if dialErr == nil {
			return conn, nil
		}
		lastErr = dialErr
	}
	if lastErr != nil {
		return nil, fmt.Errorf("OIDC endpoint connection failed: %w", lastErr)
	}
	return nil, errEgressDenied
}

func publicUnicast(addr netip.Addr) bool {
	if !addr.IsValid() || !addr.IsGlobalUnicast() || addr.IsPrivate() || addr.IsLoopback() ||
		addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsUnspecified() || addr.IsMulticast() {
		return false
	}
	for _, prefix := range blockedEgressPrefixes {
		if prefix.Contains(addr) {
			return false
		}
	}
	return true
}
