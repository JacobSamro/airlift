-- airlift initial schema.
-- All ids are UUID strings. Timestamps are RFC3339 TEXT (UTC).

-- Key/value instance settings: signing secret, setup state, storage overrides, etc.
CREATE TABLE settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- ───────────────────────── identity ─────────────────────────

CREATE TABLE users (
    id            TEXT PRIMARY KEY,
    email         TEXT NOT NULL,
    username      TEXT NOT NULL,
    password_hash TEXT NOT NULL,         -- argon2id PHC string
    is_admin      INTEGER NOT NULL DEFAULT 0, -- instance super-admin
    created_at    TEXT NOT NULL
);
CREATE UNIQUE INDEX idx_users_email ON users (lower(email));
CREATE UNIQUE INDEX idx_users_username ON users (lower(username));

-- Personal access tokens used by the publish CLI and API automation.
-- A token is scoped to 'all' (everything the owner can reach), one org, or one
-- app, and capped by max_perm: 'read' | 'publish' | 'admin'. The effective
-- grant is always owner RBAC ∩ scope ∩ cap.
CREATE TABLE personal_access_tokens (
    id           TEXT PRIMARY KEY,
    user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    token_prefix TEXT NOT NULL,          -- first chars, shown in UI for identification
    token_hash   TEXT NOT NULL,          -- sha256(hex) of the full secret
    scope_kind   TEXT NOT NULL DEFAULT 'all', -- all | org | app
    scope_org_id TEXT REFERENCES orgs(id) ON DELETE CASCADE,
    scope_app_id TEXT REFERENCES apps(id) ON DELETE CASCADE,
    max_perm     TEXT NOT NULL DEFAULT 'admin',
    last_used_at TEXT,
    expires_at   TEXT,
    created_at   TEXT NOT NULL
);
CREATE UNIQUE INDEX idx_pat_hash ON personal_access_tokens (token_hash);
CREATE INDEX idx_pat_user ON personal_access_tokens (user_id);

-- Dashboard sessions (signed cookie references this row).
CREATE TABLE sessions (
    id         TEXT PRIMARY KEY,         -- random session id
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);
CREATE INDEX idx_sessions_user ON sessions (user_id);

-- ───────────────────────── tenancy ─────────────────────────

CREATE TABLE orgs (
    id         TEXT PRIMARY KEY,
    slug       TEXT NOT NULL,            -- namespace path segment
    name       TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE UNIQUE INDEX idx_orgs_slug ON orgs (lower(slug));

-- Org-level role: owner | admin | member.
CREATE TABLE org_members (
    org_id  TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role    TEXT NOT NULL DEFAULT 'member',
    PRIMARY KEY (org_id, user_id)
);
CREATE INDEX idx_org_members_user ON org_members (user_id);

CREATE TABLE teams (
    id         TEXT PRIMARY KEY,
    org_id     TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    slug       TEXT NOT NULL,
    name       TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE UNIQUE INDEX idx_teams_org_slug ON teams (org_id, lower(slug));

CREATE TABLE team_members (
    team_id TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role    TEXT NOT NULL DEFAULT 'member', -- maintainer | member
    PRIMARY KEY (team_id, user_id)
);
CREATE INDEX idx_team_members_user ON team_members (user_id);

-- Team → app permission: read | publish | admin.
CREATE TABLE team_app_perms (
    team_id    TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    app_id     TEXT NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    permission TEXT NOT NULL DEFAULT 'read',
    PRIMARY KEY (team_id, app_id)
);

-- ───────────────────────── apps / updates ─────────────────────────

-- An Expo application. The id appears in the public update URL
-- (`/u/<app_id>/manifest`), so it is a UUID rather than a guessable slug.
-- Each app owns an RSA-2048 code-signing keypair; the self-signed certificate
-- is embedded in the app binary (expo-updates `codeSigningCertificate`).
CREATE TABLE apps (
    id              TEXT PRIMARY KEY,
    org_id          TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    slug            TEXT NOT NULL,
    name            TEXT NOT NULL,
    private_key_pem TEXT NOT NULL,
    certificate_pem TEXT NOT NULL,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL
);
CREATE UNIQUE INDEX idx_apps_org_slug ON apps (org_id, lower(slug));

-- A stream of published updates (EAS-style). Auto-created on first publish.
CREATE TABLE branches (
    id         TEXT PRIMARY KEY,
    app_id     TEXT NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    name       TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE UNIQUE INDEX idx_branches_app_name ON branches (app_id, name);

-- What builds point at (`expo-channel-name`). A channel maps to a branch;
-- repointing it promotes that branch's releases instantly. `auto_release`
-- decides whether a new publish on the branch goes live immediately or waits
-- for a manual promote.
CREATE TABLE channels (
    id           TEXT PRIMARY KEY,
    app_id       TEXT NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    branch_id    TEXT REFERENCES branches(id) ON DELETE SET NULL,
    auto_release INTEGER NOT NULL DEFAULT 1,
    created_at   TEXT NOT NULL
);
CREATE UNIQUE INDEX idx_channels_app_name ON channels (app_id, lower(name));

-- One publish event on a branch (covers one or both platforms).
-- group_type 'rollback_to_embedded' emits the protocol directive instead of a
-- manifest.
CREATE TABLE update_groups (
    id              TEXT PRIMARY KEY,
    branch_id       TEXT NOT NULL REFERENCES branches(id) ON DELETE CASCADE,
    runtime_version TEXT NOT NULL,
    message         TEXT,
    git_branch      TEXT,
    git_commit      TEXT,
    group_type      TEXT NOT NULL DEFAULT 'normal', -- normal | rollback_to_embedded
    created_at      TEXT NOT NULL
);
CREATE INDEX idx_groups_branch_runtime ON update_groups (branch_id, runtime_version, created_at);

-- Content-addressed files (bundles + assets), deduplicated per org. Bytes live
-- in object storage at `orgs/<org_id>/assets/sha256/<hex>`.
CREATE TABLE assets (
    id           TEXT PRIMARY KEY,
    org_id       TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    sha256       TEXT NOT NULL,          -- hex digest of the file bytes
    size         INTEGER NOT NULL,
    content_type TEXT NOT NULL,
    created_at   TEXT NOT NULL
);
CREATE UNIQUE INDEX idx_assets_org_sha ON assets (org_id, sha256);

-- The per-platform update inside a group. `id` is the protocol manifest id.
CREATE TABLE updates (
    id              TEXT PRIMARY KEY,
    group_id        TEXT NOT NULL REFERENCES update_groups(id) ON DELETE CASCADE,
    platform        TEXT NOT NULL,       -- ios | android
    launch_asset_id TEXT NOT NULL REFERENCES assets(id),
    metadata_json   TEXT NOT NULL,       -- exported metadata for this platform
    created_at      TEXT NOT NULL
);
CREATE UNIQUE INDEX idx_updates_group_platform ON updates (group_id, platform);

-- Assets referenced by an update, with the manifest-facing key/type.
CREATE TABLE update_assets (
    update_id      TEXT NOT NULL REFERENCES updates(id) ON DELETE CASCADE,
    asset_id       TEXT NOT NULL REFERENCES assets(id),
    key            TEXT NOT NULL,        -- expo asset key (md5 basename in exports)
    file_extension TEXT,
    content_type   TEXT NOT NULL,
    PRIMARY KEY (update_id, key)
);
CREATE INDEX idx_update_assets_asset ON update_assets (asset_id);

-- The release pointer: which update group a channel serves for a runtime
-- version. Advanced automatically (auto_release channels) or by promote.
CREATE TABLE channel_releases (
    channel_id      TEXT NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
    runtime_version TEXT NOT NULL,
    group_id        TEXT NOT NULL REFERENCES update_groups(id) ON DELETE CASCADE,
    released_at     TEXT NOT NULL,
    PRIMARY KEY (channel_id, runtime_version)
);

-- bsdiff patches between two launch bundles (SDK 55+ incremental updates).
CREATE TABLE patches (
    id             TEXT PRIMARY KEY,
    from_update_id TEXT NOT NULL REFERENCES updates(id) ON DELETE CASCADE,
    to_update_id   TEXT NOT NULL REFERENCES updates(id) ON DELETE CASCADE,
    sha256         TEXT,
    size           INTEGER,
    status         TEXT NOT NULL DEFAULT 'queued', -- queued | ready | failed
    detail         TEXT,
    created_at     TEXT NOT NULL
);
CREATE UNIQUE INDEX idx_patches_pair ON patches (from_update_id, to_update_id);

-- ───────────────────────── client monitoring ─────────────────────────

-- Last-known state of every device that checked in (EAS-Client-ID).
CREATE TABLE clients (
    app_id             TEXT NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    client_id          TEXT NOT NULL,
    platform           TEXT,
    runtime_version    TEXT,
    channel            TEXT,
    embedded_update_id TEXT,
    current_update_id  TEXT,
    first_seen         TEXT NOT NULL,
    last_seen          TEXT NOT NULL,
    PRIMARY KEY (app_id, client_id)
);
CREATE INDEX idx_clients_last_seen ON clients (app_id, last_seen);

-- Daily manifest-request rollups per app/platform/served update.
CREATE TABLE checkins_daily (
    app_id    TEXT NOT NULL,
    day       TEXT NOT NULL,             -- YYYY-MM-DD (UTC)
    platform  TEXT NOT NULL,
    update_id TEXT NOT NULL DEFAULT '',  -- '' = no update served (directive)
    count     INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (app_id, day, platform, update_id)
);

-- ───────────────────────── domains / TLS ─────────────────────────

CREATE TABLE domains (
    domain     TEXT PRIMARY KEY,
    org_id     TEXT REFERENCES orgs(id) ON DELETE CASCADE, -- NULL = instance-level
    status     TEXT NOT NULL DEFAULT 'pending',            -- pending | active | failed
    is_primary INTEGER NOT NULL DEFAULT 0,
    detail     TEXT,                                       -- last ACME error, if any
    created_at TEXT NOT NULL
);

-- ───────────────────────── audit ─────────────────────────

CREATE TABLE audit_log (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ts            TEXT NOT NULL,
    actor_user_id TEXT,
    org_id        TEXT,
    action        TEXT NOT NULL,
    target        TEXT,
    detail        TEXT
);
CREATE INDEX idx_audit_org_ts ON audit_log (org_id, ts);
