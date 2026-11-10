-- GC for bsdiff patch objects (orgs/<org>/patches/<from>-<to>).
--
-- A ready patch now records the storage key it wrote. Deleting the row
-- (directly, or by cascade when an update/app/org goes away) leaves a
-- tombstone for that key; the GC sweep deletes the object once no other
-- patch row still points at it (two update pairs with the same bundles
-- share one object).

ALTER TABLE patches ADD COLUMN object_key TEXT;

-- Ready patches from before this migration: derive their key the same way
-- Storage::patch_key does.
UPDATE patches
SET object_key = (
    SELECT 'orgs/' || fa.org_id || '/patches/' || fa.sha256 || '-' || ta.sha256
    FROM updates fu
    JOIN assets fa ON fa.id = fu.launch_asset_id
    JOIN updates tu ON tu.id = patches.to_update_id
    JOIN assets ta ON ta.id = tu.launch_asset_id
    WHERE fu.id = patches.from_update_id
)
WHERE status = 'ready';

CREATE INDEX idx_patches_object_key ON patches (object_key);

CREATE TABLE patch_object_tombstones (
    object_key TEXT PRIMARY KEY,
    created_at TEXT NOT NULL
);

CREATE TRIGGER patches_object_tombstone
AFTER DELETE ON patches
WHEN old.object_key IS NOT NULL
BEGIN
    INSERT OR IGNORE INTO patch_object_tombstones (object_key, created_at)
    VALUES (old.object_key, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'));
END;
