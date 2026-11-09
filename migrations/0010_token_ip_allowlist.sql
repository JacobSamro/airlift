-- Per-token IP allowlist: comma-separated IPs / CIDR ranges the token may be
-- used from (NULL = anywhere). Checked against the same client IP the rate
-- limiter uses (peer address, or the proxy-appended X-Forwarded-For hop when
-- server.trust_proxy is on).
ALTER TABLE personal_access_tokens ADD COLUMN allowed_ips TEXT;
