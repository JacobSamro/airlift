-- Per-device launch outcome for each update, the basis of per-update health.
-- A row appears when a device reports running the update (launched: its
-- Expo-Current-Update-ID) or lists it in Expo-Recent-Failed-Update-IDs
-- (failed). Failure rate = failed devices / devices that tried the update.
CREATE TABLE client_updates (
    app_id     TEXT NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    update_id  TEXT NOT NULL,            -- lowercase manifest id
    client_id  TEXT NOT NULL,
    launched   INTEGER NOT NULL DEFAULT 0,
    failed     INTEGER NOT NULL DEFAULT 0,
    first_seen TEXT NOT NULL,
    last_seen  TEXT NOT NULL,
    PRIMARY KEY (app_id, update_id, client_id)
);
CREATE INDEX idx_client_updates_update ON client_updates (app_id, update_id);
