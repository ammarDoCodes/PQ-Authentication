package httpapi

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func (s *Server) checkRateLimit(ctx context.Context, scope, dimension string, maximum int) (bool, int, error) {
	if s.Store == nil || len(s.RateLimitKey) != 32 || scope == "" || dimension == "" || maximum < 1 {
		return false, 0, errors.New("rate limiter is not configured")
	}
	bucket := rateLimitBucketHash(s.RateLimitKey, scope, dimension)
	var count, retryAfter int
	err := s.Store.QueryRowContext(ctx, `INSERT INTO rate_limit_buckets(bucket_hash, window_started_at, request_count)
		VALUES ($1, date_trunc('minute', now()), 1)
		ON CONFLICT (bucket_hash, window_started_at) DO UPDATE
		SET request_count = LEAST(rate_limit_buckets.request_count + 1, $2 + 1)
		RETURNING request_count,
			GREATEST(1, CEIL(EXTRACT(EPOCH FROM (window_started_at + interval '1 minute' - now())))::integer)`,
		bucket, maximum).Scan(&count, &retryAfter)
	if err != nil {
		return false, 0, errors.New("distributed rate limit could not be checked")
	}
	s.pruneRateLimitBuckets(ctx)
	return count <= maximum, retryAfter, nil
}

func (s *Server) pruneRateLimitBuckets(ctx context.Context) {
	now := time.Now().Unix()
	previous := s.lastRateLimitCleanup.Load()
	if now-previous < 300 || !s.lastRateLimitCleanup.CompareAndSwap(previous, now) {
		return
	}
	_, _ = s.Store.ExecContext(ctx, `WITH stale AS (
		SELECT ctid FROM rate_limit_buckets
		WHERE window_started_at < date_trunc('minute', now()) - interval '24 hours'
		LIMIT 10000
	) DELETE FROM rate_limit_buckets AS buckets USING stale WHERE buckets.ctid = stale.ctid`)
}

func rateLimitBucketHash(key []byte, scope, dimension string) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(scope))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(dimension))
	return mac.Sum(nil)
}

func clientIPDimension(remoteAddr string) string {
	host, _, err := net.SplitHostPort(strings.TrimSpace(remoteAddr))
	if err != nil {
		host = strings.TrimSpace(remoteAddr)
	}
	address := net.ParseIP(host)
	if address == nil {
		return "unknown"
	}
	return address.String()
}

func (s *Server) enforceRateLimit(w http.ResponseWriter, r *http.Request, scope, dimension string, maximum int) bool {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	allowed, retryAfter, err := s.checkRateLimit(ctx, scope, dimension, maximum)
	if err != nil {
		if s.Logger != nil {
			s.Logger.Error("distributed rate-limit check failed", "request_id", requestID(r.Context()))
		}
		writeProblem(w, r, 503, "RATE_LIMIT_UNAVAILABLE", "Service unavailable", "The request could not be processed safely.", true)
		return false
	}
	if !allowed {
		w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
		writeProblem(w, r, 429, "RATE_LIMITED", "Too many requests", "The request rate exceeds the current limit.", true)
		return false
	}
	return true
}
