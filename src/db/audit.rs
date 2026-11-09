//! Append-only audit log.

use serde::Serialize;

use crate::error::Result;
use crate::util::now_rfc3339;

use super::Db;

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct AuditRow {
    pub id: i64,
    pub ts: String,
    pub actor_user_id: Option<String>,
    pub org_id: Option<String>,
    pub action: String,
    pub target: Option<String>,
    pub detail: Option<String>,
}

/// Record an audit event. Failures are swallowed by callers (auditing must never
/// break the primary operation).
pub async fn record(
    db: &Db,
    actor_user_id: Option<&str>,
    org_id: Option<&str>,
    action: &str,
    target: Option<&str>,
    detail: Option<&str>,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO audit_log (ts, actor_user_id, org_id, action, target, detail)
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(now_rfc3339())
    .bind(actor_user_id)
    .bind(org_id)
    .bind(action)
    .bind(target)
    .bind(detail)
    .execute(db)
    .await?;
    Ok(())
}

pub async fn list(db: &Db, org_id: &str, limit: i64) -> Result<Vec<AuditRow>> {
    let rows = sqlx::query_as::<_, AuditRow>(
        "SELECT id, ts, actor_user_id, org_id, action, target, detail
         FROM audit_log WHERE org_id = ? ORDER BY id DESC LIMIT ?",
    )
    .bind(org_id)
    .bind(limit)
    .fetch_all(db)
    .await?;
    Ok(rows)
}

/// An audit row with the actor resolved, for export.
#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct ExportRow {
    pub id: i64,
    pub ts: String,
    pub actor_user_id: Option<String>,
    pub actor_username: Option<String>,
    pub actor_email: Option<String>,
    pub action: String,
    pub target: Option<String>,
    pub detail: Option<String>,
}

/// Filters for [`export`]; all optional.
#[derive(Debug, Default)]
pub struct ExportFilter<'a> {
    /// Only entries with id > after_id (incremental sync cursor).
    pub after_id: Option<i64>,
    /// ts >= since / ts < until (RFC3339).
    pub since: Option<&'a str>,
    pub until: Option<&'a str>,
    /// Action prefix, e.g. "channel." or "update.publish".
    pub action_prefix: Option<&'a str>,
}

/// An org's audit entries, oldest first (so a cursor can resume).
pub async fn export(
    db: &Db,
    org_id: &str,
    f: &ExportFilter<'_>,
    limit: i64,
) -> Result<Vec<ExportRow>> {
    let rows = sqlx::query_as::<_, ExportRow>(
        "SELECT l.id, l.ts, l.actor_user_id, u.username AS actor_username,
                u.email AS actor_email, l.action, l.target, l.detail
         FROM audit_log l LEFT JOIN users u ON u.id = l.actor_user_id
         WHERE l.org_id = ?1
           AND (?2 IS NULL OR l.id > ?2)
           AND (?3 IS NULL OR l.ts >= ?3)
           AND (?4 IS NULL OR l.ts < ?4)
           AND (?5 IS NULL OR substr(l.action, 1, length(?5)) = ?5)
         ORDER BY l.id LIMIT ?6",
    )
    .bind(org_id)
    .bind(f.after_id)
    .bind(f.since)
    .bind(f.until)
    .bind(f.action_prefix)
    .bind(limit)
    .fetch_all(db)
    .await?;
    Ok(rows)
}
