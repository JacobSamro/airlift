-- Every release a channel has served, per runtime version, oldest first.
-- Rollback walks THIS history (what the channel actually shipped), not the
-- branch's publish order. A rolled-back release is flagged so a second
-- rollback steps further back instead of toggling.
CREATE TABLE channel_release_history (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    channel_id      TEXT NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
    runtime_version TEXT NOT NULL,
    group_id        TEXT NOT NULL REFERENCES update_groups(id) ON DELETE CASCADE,
    rolled_back     INTEGER NOT NULL DEFAULT 0,
    released_at     TEXT NOT NULL
);
CREATE INDEX idx_release_history_channel
    ON channel_release_history (channel_id, runtime_version, id);

-- Seed with the current pointers so existing channels have a starting point.
INSERT INTO channel_release_history (channel_id, runtime_version, group_id, released_at)
SELECT channel_id, runtime_version, group_id, released_at FROM channel_releases;
