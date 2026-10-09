CREATE TABLE rate_limit_buckets (
    bucket_hash BYTEA NOT NULL CHECK (octet_length(bucket_hash) = 32),
    window_started_at TIMESTAMPTZ NOT NULL,
    request_count INTEGER NOT NULL CHECK (request_count > 0),
    PRIMARY KEY (bucket_hash, window_started_at)
);
