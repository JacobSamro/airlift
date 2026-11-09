//! Queries for the bsdiff patch queue.
//!
//! Status flow: `queued` → `generating` → `ready` | `failed` |
//! `not_beneficial`. A failed attempt is retried with backoff (`attempts`,
//! `not_before`); after the cap the job stays failed (a later request for the same
//! pair won't re-enqueue while the row exists); `generating` rows whose
//! lease (`claimed_at`) went stale are requeued by the worker.

use serde::Serialize;

use crate::error::Result;
use crate::util::now_rfc3339;

use super::Db;

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct PatchRow {
    pub id: String,
    pub from_update_id: String,
    pub to_update_id: String,
    pub sha256: Option<String>,
    pub size: Option<i64>,
    pub status: String,
    pub detail: Option<String>,
    pub created_at: String,
    /// Lease timestamp of the worker currently generating this job.
    pub claimed_at: Option<String>,
    /// Failed generation attempts so far.
    pub attempts: i64,
    /// A retried job isn't claimable before this time (backoff).
    pub not_before: Option<String>,
}

pub async fn find(db: &Db, from_update_id: &str, to_update_id: &str) -> Result<Option<PatchRow>> {
    let p = sqlx::query_as::<_, PatchRow>(
        "SELECT * FROM patches WHERE from_update_id = ? AND to_update_id = ?",
    )
    .bind(from_update_id)
    .bind(to_update_id)
    .fetch_optional(db)
    .await?;
    Ok(p)
}

/// Enqueue a pair for generation (idempotent).
pub async fn enqueue(db: &Db, from_update_id: &str, to_update_id: &str) -> Result<()> {
    sqlx::query(
        "INSERT INTO patches (id, from_update_id, to_update_id, status, created_at)
         VALUES (?, ?, ?, 'queued', ?)
         ON CONFLICT(from_update_id, to_update_id) DO NOTHING",
    )
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(from_update_id)
    .bind(to_update_id)
    .bind(now_rfc3339())
    .execute(db)
    .await?;
    Ok(())
}

/// Atomically claim the oldest queued job (worker concurrency = 1 per
/// process; the single UPDATE keeps multi-process deployments safe too).
pub async fn claim_next(db: &Db) -> Result<Option<PatchRow>> {
    // The lease value doubles as the claim token: a random suffix keeps two
    // claims in the same millisecond distinct.
    let now = now_rfc3339();
    let lease = format!("{now}#{}", uuid::Uuid::new_v4());
    let p = sqlx::query_as::<_, PatchRow>(
        "UPDATE patches SET status = 'generating', claimed_at = ?1
         WHERE id = (SELECT id FROM patches
                     WHERE status = 'queued' AND (not_before IS NULL OR not_before <= ?2)
                     ORDER BY created_at LIMIT 1)
         RETURNING *",
    )
    .bind(lease)
    .bind(now)
    .fetch_optional(db)
    .await?;
    Ok(p)
}

/// A failed attempt that still has retries left: back to the queue, not
/// claimable before `not_before`. Same lease guard as the terminal writes.
pub async fn retry_later(db: &Db, job: &PatchRow, detail: &str, not_before: &str) -> Result<()> {
    sqlx::query(
        "UPDATE patches
         SET status = 'queued', attempts = attempts + 1, detail = ?, not_before = ?,
             claimed_at = NULL
         WHERE id = ? AND status = 'generating' AND claimed_at IS ?",
    )
    .bind(detail)
    .bind(not_before)
    .bind(&job.id)
    .bind(&job.claimed_at)
    .execute(db)
    .await?;
    Ok(())
}

/// Terminal status write, applied only while `job` still holds its lease (a
/// reclaimed job's late result must not overwrite the new owner's outcome).
/// The three terminal states share this guard.
async fn finish(
    db: &Db,
    job: &PatchRow,
    status: &str,
    sha256: Option<&str>,
    size: Option<i64>,
    detail: Option<&str>,
) -> Result<()> {
    sqlx::query(
        "UPDATE patches SET status = ?, sha256 = ?, size = ?, detail = ?
         WHERE id = ? AND status = 'generating' AND claimed_at IS ?",
    )
    .bind(status)
    .bind(sha256)
    .bind(size)
    .bind(detail)
    .bind(&job.id)
    .bind(&job.claimed_at)
    .execute(db)
    .await?;
    Ok(())
}

pub async fn mark_ready(db: &Db, job: &PatchRow, sha256: &str, size: i64) -> Result<()> {
    finish(db, job, "ready", Some(sha256), Some(size), None).await
}

pub async fn mark_failed(db: &Db, job: &PatchRow, detail: &str) -> Result<()> {
    finish(db, job, "failed", None, None, Some(detail)).await
}

/// Terminal: the diff was too close to the full bundle to be worth serving.
pub async fn mark_not_beneficial(db: &Db, job: &PatchRow, size: i64) -> Result<()> {
    finish(db, job, "not_beneficial", None, Some(size), None).await
}

/// Put a ready-but-lost patch back in the queue.
pub async fn requeue(db: &Db, id: &str) -> Result<()> {
    sqlx::query("UPDATE patches SET status = 'queued', sha256 = NULL, size = NULL WHERE id = ?")
        .bind(id)
        .execute(db)
        .await?;
    Ok(())
}

/// Requeue `generating` jobs whose lease is older than `cutoff` (the worker
/// died or restarted mid-job). Live leases held by another process are left
/// alone. Leases are `<rfc3339>#<uuid>`, so text comparison against a bare
/// fixed-width timestamp orders by the time prefix.
pub async fn requeue_stale(db: &Db, cutoff: &str) -> Result<u64> {
    let res = sqlx::query(
        "UPDATE patches SET status = 'queued', claimed_at = NULL
         WHERE status = 'generating' AND (claimed_at IS NULL OR claimed_at < ?)",
    )
    .bind(cutoff)
    .execute(db)
    .await?;
    Ok(res.rows_affected())
}
