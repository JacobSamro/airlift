-- Progressive rollouts. A release pointer may serve its group to only part of
-- the fleet: a device is in when bucket(sha256(EAS-Client-ID ":" salt)) <
-- rollout_percent/100, where bucket maps the digest to [0,1). The salt is
-- fixed for the life of the rollout, so a device inside at N% stays inside at
-- any higher percentage. Devices outside (and devices without a client id)
-- get previous_group_id, the last fully released group (or no update).
-- rollout_percent NULL = fully released. No per-device state is stored.
ALTER TABLE channel_releases ADD COLUMN rollout_percent REAL;
ALTER TABLE channel_releases ADD COLUMN rollout_salt TEXT;
ALTER TABLE channel_releases ADD COLUMN previous_group_id TEXT
    REFERENCES update_groups(id) ON DELETE SET NULL;
