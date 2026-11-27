-- Sprint 5.3: API rate limiting buckets
CREATE TABLE IF NOT EXISTS api_rate_limits (
  bucket_key TEXT PRIMARY KEY,
  window_started_at TEXT NOT NULL,
  request_count INTEGER NOT NULL DEFAULT 0 CHECK(request_count >= 0)
);
CREATE INDEX IF NOT EXISTS idx_api_rate_limits_window
ON api_rate_limits(window_started_at);
