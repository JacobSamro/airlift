-- Patch generation retries: a failure (often transient, e.g. a storage
-- timeout) requeues the job with exponential backoff until `attempts` hits
-- the cap, instead of marking the pair failed forever on the first error.
ALTER TABLE patches ADD COLUMN attempts INTEGER NOT NULL DEFAULT 0;
ALTER TABLE patches ADD COLUMN not_before TEXT;
