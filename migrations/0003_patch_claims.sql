-- Lease for a `generating` patch job: set when a worker claims it. Stale
-- leases are requeued (instead of every startup resetting ALL generating
-- jobs, which let a second process steal a live job), and a worker's terminal
-- status write only lands while it still holds the lease it claimed.
ALTER TABLE patches ADD COLUMN claimed_at TEXT;
