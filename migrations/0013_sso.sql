-- Enterprise SSO identity providers (generic OIDC or SAML 2.0).
-- org_id NULL = instance-wide (configured by an instance admin, trusted for
-- any account in its domains); otherwise org-scoped (configured by that
-- org's admins, may only sign in that org's members / provision into it).
CREATE TABLE sso_providers (
    id             TEXT PRIMARY KEY,
    org_id         TEXT REFERENCES orgs(id) ON DELETE CASCADE,
    kind           TEXT NOT NULL,                  -- oidc | saml
    name           TEXT NOT NULL,
    enabled        INTEGER NOT NULL DEFAULT 1,
    domains        TEXT NOT NULL DEFAULT '',       -- comma-separated email domains
    auto_provision INTEGER NOT NULL DEFAULT 0,
    default_role   TEXT NOT NULL DEFAULT 'member', -- org role for provisioned users
    config         TEXT NOT NULL,                  -- JSON (see api/sso.rs)
    created_at     TEXT NOT NULL
);

-- In-flight logins: state / RelayState → what we must see come back.
-- Single use; expire after 10 minutes.
CREATE TABLE sso_requests (
    id              TEXT PRIMARY KEY,
    provider_id     TEXT NOT NULL REFERENCES sso_providers(id) ON DELETE CASCADE,
    nonce           TEXT,
    pkce_verifier   TEXT,
    saml_request_id TEXT,
    created_at      TEXT NOT NULL
);
