-- OAuth 2.1 authorization server for MCP clients (agents).
-- Public clients via dynamic registration (RFC 7591); PKCE S256 required.
CREATE TABLE oauth_clients (
    id            TEXT PRIMARY KEY,       -- client_id
    name          TEXT NOT NULL,
    redirect_uris TEXT NOT NULL,          -- JSON array
    created_at    TEXT NOT NULL
);

-- Authorization codes (hashed, single use, 5 minutes). The grant the user
-- consented to (cap + resource scope) travels with the code.
CREATE TABLE oauth_codes (
    code_hash      TEXT PRIMARY KEY,
    client_id      TEXT NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    user_id        TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    redirect_uri   TEXT NOT NULL,
    code_challenge TEXT NOT NULL,
    max_perm       TEXT NOT NULL,
    scope_kind     TEXT NOT NULL,
    scope_org_id   TEXT,
    scope_app_id   TEXT,
    expires_at     TEXT NOT NULL
);

-- Refresh tokens (hashed, rotating). The access token is an expiring PAT
-- row, so the grant shows up (and is revocable) under Access Tokens;
-- revoking it drops its refresh token too.
CREATE TABLE oauth_refresh_tokens (
    token_hash TEXT PRIMARY KEY,
    pat_id     TEXT NOT NULL REFERENCES personal_access_tokens(id) ON DELETE CASCADE,
    client_id  TEXT NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    expires_at TEXT NOT NULL
);
