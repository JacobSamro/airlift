-- Sourcemaps for launch bundles, keyed by the bundle's sha256 (so republished
-- copies and rollbacks of the same bundle share it). Uploaded with publish
-- (`<bundle>.map` in the export); stored privately at
-- orgs/<org>/sourcemaps/<sha256>.map, never served to devices.
CREATE TABLE sourcemaps (
    org_id        TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    bundle_sha256 TEXT NOT NULL,
    size          INTEGER NOT NULL,
    created_at    TEXT NOT NULL,
    PRIMARY KEY (org_id, bundle_sha256)
);

-- JS errors from devices (airlift reporter or OTLP exception logs), grouped
-- by a fingerprint over the error name and its top symbolicated in-app
-- frames.
CREATE TABLE error_groups (
    id          TEXT PRIMARY KEY,
    app_id      TEXT NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    fingerprint TEXT NOT NULL,
    name        TEXT NOT NULL,
    message     TEXT NOT NULL,
    culprit     TEXT,                     -- top symbolicated in-app frame
    fatal       INTEGER NOT NULL DEFAULT 0,
    events      INTEGER NOT NULL DEFAULT 0,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    UNIQUE (app_id, fingerprint)
);
CREATE INDEX idx_error_groups_seen ON error_groups (app_id, last_seen);

CREATE TABLE error_events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    group_id        TEXT NOT NULL REFERENCES error_groups(id) ON DELETE CASCADE,
    app_id          TEXT NOT NULL,
    ts              TEXT NOT NULL,
    update_id       TEXT,
    platform        TEXT,
    runtime_version TEXT,
    channel         TEXT,
    client_id       TEXT,
    fatal           INTEGER NOT NULL DEFAULT 0,
    message         TEXT NOT NULL,
    raw_stack       TEXT,
    frames_json     TEXT,                 -- symbolicated frames
    source          TEXT NOT NULL         -- reporter | otlp
);
CREATE INDEX idx_error_events_group ON error_events (group_id, ts);
CREATE INDEX idx_error_events_app ON error_events (app_id, ts);
CREATE INDEX idx_error_events_update ON error_events (app_id, update_id);

-- OTLP log records (OTLP/HTTP JSON), kept for observability.retention_days.
CREATE TABLE log_records (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    app_id        TEXT NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    ts            TEXT NOT NULL,
    severity      INTEGER NOT NULL DEFAULT 0,   -- OTLP severityNumber (1-24)
    severity_text TEXT,
    body          TEXT NOT NULL,
    attributes    TEXT,                         -- JSON object (record + resource)
    update_id     TEXT,
    platform      TEXT,
    client_id     TEXT,
    trace_id      TEXT
);
CREATE INDEX idx_log_records_app ON log_records (app_id, ts);

-- OTLP metric data points, rolled up per minute and attribute set.
CREATE TABLE metric_points (
    app_id     TEXT NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    name       TEXT NOT NULL,
    minute     TEXT NOT NULL,                   -- YYYY-MM-DDTHH:MM
    attributes TEXT NOT NULL DEFAULT '{}',      -- canonical JSON
    kind       TEXT NOT NULL,                   -- sum | gauge | histogram
    unit       TEXT,
    count      INTEGER NOT NULL DEFAULT 0,
    sum        REAL NOT NULL DEFAULT 0,
    min        REAL,
    max        REAL,
    PRIMARY KEY (app_id, name, minute, attributes)
);
CREATE INDEX idx_metric_points_name ON metric_points (app_id, name, minute);
