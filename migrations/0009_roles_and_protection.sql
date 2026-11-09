-- Custom roles: an org names a set of app capabilities
-- (read, publish, release, channels, keys, protected) and team app grants
-- may use it ("role:<name>") instead of a built-in level (read | publish |
-- admin). Effective access is still owner RBAC ∩ PAT scope ∩ PAT cap.
CREATE TABLE org_roles (
    org_id       TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    capabilities TEXT NOT NULL,           -- comma-separated capability names
    created_at   TEXT NOT NULL,
    PRIMARY KEY (org_id, name)
);

-- Branch protection: publishing to a protected branch, or releasing on a
-- channel that serves one, requires the `protected` capability.
ALTER TABLE branches ADD COLUMN protected INTEGER NOT NULL DEFAULT 0;
