-- A/B splits: a channel can send a stable share of its devices to another
-- channel (which tracks the experiment branch, with its own releases,
-- rollouts and rollbacks). Bucketing is the rollout scheme with its own salt:
-- sha256(EAS-Client-ID ":" split_salt) < split_percent/100 → split channel.
-- Devices without a client id always stay on the channel itself.
ALTER TABLE channels ADD COLUMN split_channel_id TEXT REFERENCES channels(id) ON DELETE SET NULL;
ALTER TABLE channels ADD COLUMN split_percent REAL;
ALTER TABLE channels ADD COLUMN split_salt TEXT;
