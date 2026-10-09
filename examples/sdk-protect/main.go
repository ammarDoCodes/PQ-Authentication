package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"quantumgate/internal/auth"
	"quantumgate/sdk/go/quantumgate"
)

type identityVerifier interface {
	Verify(context.Context, string) (auth.Principal, error)
}

type protector interface {
	Protect(context.Context, quantumgate.DecisionRequest) (quantumgate.Decision, error)
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "SDK protect example: "+err.Error())
		os.Exit(1)
	}
}

func run() error {
	issuer := strings.TrimSpace(os.Getenv("APP_OIDC_ISSUER"))
	audience := strings.TrimSpace(os.Getenv("APP_OIDC_AUDIENCE"))
	allowedHosts := splitHosts(os.Getenv("APP_OIDC_ALLOWED_HOSTS"))
	if issuer == "" || audience == "" || len(allowedHosts) == 0 {
		return fmt.Errorf("APP_OIDC_ISSUER, APP_OIDC_AUDIENCE, and APP_OIDC_ALLOWED_HOSTS are required")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	verifier, err := auth.NewOIDCIdentityVerifier(ctx, auth.OIDCSettings{
		Issuer: issuer, ClientID: audience, AllowedHosts: allowedHosts,
		SigningAlgs: []string{"RS256"}, MaxTokenAge: 15 * time.Minute,
	})
	if err != nil {
		return fmt.Errorf("initialize existing OIDC verification: %w", err)
	}
	client, err := quantumgate.NewClient(quantumgate.Config{
		Endpoint: os.Getenv("QG_API_ENDPOINT"), TenantID: os.Getenv("QG_TENANT_ID"),
		ApplicationID: os.Getenv("QG_APPLICATION_ID"), ClientSecret: os.Getenv("QG_CLIENT_SECRET"),
	})
	if err != nil {
		return fmt.Errorf("configure QuantumGate client: %w", err)
	}
	address := os.Getenv("APP_LISTEN_ADDR")
	if address == "" {
		address = "127.0.0.1:8082"
	}
	if err := requireLoopbackAddress(address); err != nil {
		return err
	}
	server := &http.Server{
		Addr: address, Handler: newHandler(verifier, client),
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second,
		WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second,
		MaxHeaderBytes: 64 << 10,
	}
	fmt.Fprintf(os.Stderr, "listening on %s; this example accepts loopback connections only\n", address)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("serve example: %w", err)
	}
	return nil
}

func newHandler(verifier identityVerifier, client protector) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /api/items", func(w http.ResponseWriter, r *http.Request) {
		token, ok := bearerToken(r.Header.Values("Authorization"))
		if !ok || verifier == nil {
			writeUnauthorized(w)
			return
		}
		if _, err := verifier.Verify(r.Context(), token); err != nil {
			writeUnauthorized(w)
			return
		}
		if client == nil {
			http.Error(w, "protection decision unavailable", http.StatusServiceUnavailable)
			return
		}
		decision, err := client.Protect(r.Context(), quantumgate.DecisionRequest{
			Method: r.Method, Path: r.URL.Path, IdentityToken: token,
		})
		if err != nil {
			http.Error(w, "protection decision unavailable", http.StatusServiceUnavailable)
			return
		}
		switch decision.Decision {
		case "allow", "observe", "degraded_allowed":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string][]map[string]string{
				"items": {{"id": "item-1", "name": "Sample item"}},
			})
		case "step_up":
			w.Header().Set("WWW-Authenticate", "Bearer")
			http.Error(w, "additional authentication is required", http.StatusUnauthorized)
		default:
			http.Error(w, "request denied by policy", http.StatusForbidden)
		}
	})
	return mux
}

func bearerToken(values []string) (string, bool) {
	if len(values) != 1 {
		return "", false
	}
	parts := strings.SplitN(values[0], " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || len(parts[1]) == 0 || len(parts[1]) > 16<<10 ||
		strings.ContainsAny(parts[1], " \t\r\n") {
		return "", false
	}
	return parts[1], true
}

func writeUnauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", "Bearer")
	http.Error(w, "authentication required", http.StatusUnauthorized)
}

func splitHosts(value string) []string {
	parts := strings.Split(value, ",")
	hosts := make([]string, 0, len(parts))
	for _, part := range parts {
		if host := strings.TrimSpace(part); host != "" {
			hosts = append(hosts, host)
		}
	}
	return hosts
}

func requireLoopbackAddress(address string) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		return fmt.Errorf("APP_LISTEN_ADDR must use a loopback IP address")
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return fmt.Errorf("APP_LISTEN_ADDR must contain a valid TCP port")
	}
	return nil
}
