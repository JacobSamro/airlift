//! Queries for the bsdiff patch queue.
//!
//! Status flow: `queued` → `generating` → `ready` | `failed` |
//! `not_beneficial`. Failed jobs stay failed (a later request for the same
//! pair won't re-enqueue while the row exists); interrupted `generating` rows
//! are requeued on startup.

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
    let p = sqlx::query_as::<_, PatchRow>(
        "UPDATE patches SET status = 'generating'
         WHERE id = (SELECT id FROM patches WHERE status = 'queued'
                     ORDER BY created_at LIMIT 1)
         RETURNING *",
    )
    .fetch_optional(db)
    .await?;
    Ok(p)
}

pub async fn mark_ready(db: &Db, id: &str, sha256: &str, size: i64) -> Result<()> {
    sqlx::query("UPDATE patches SET status = 'ready', sha256 = ?, size = ? WHERE id = ?")
        .bind(sha256)
        .bind(size)
        .bind(id)
        .execute(db)
        .await?;
    Ok(())
}

pub async fn mark_failed(db: &Db, id: &str, detail: &str) -> Result<()> {
    sqlx::query("UPDATE patches SET status = 'failed', detail = ? WHERE id = ?")
        .bind(detail)
        .bind(id)
        .execute(db)
        .await?;
    Ok(())
}

/// Terminal: the diff was too close to the full bundle to be worth serving.
pub async fn mark_not_beneficial(db: &Db, id: &str, size: i64) -> Result<()> {
    sqlx::query("UPDATE patches SET status = 'not_beneficial', size = ? WHERE id = ?")
        .bind(size)
        .bind(id)
        .execute(db)
        .await?;
    Ok(())
}

/// Put a ready-but-lost patch back in the queue.
pub async fn requeue(db: &Db, id: &str) -> Result<()> {
    sqlx::query("UPDATE patches SET status = 'queued', sha256 = NULL, size = NULL WHERE id = ?")
        .bind(id)
        .execute(db)
        .await?;
    Ok(())
}

/// Requeue jobs a previous process left mid-generation.
pub async fn requeue_interrupted(db: &Db) -> Result<()> {
    sqlx::query("UPDATE patches SET status = 'queued' WHERE status = 'generating'")
        .execute(db)
        .await?;
    Ok(())
}
