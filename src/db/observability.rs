//! Queries for sourcemaps, error groups/events, OTLP logs and metric rollups.

use serde::Serialize;

use crate::error::Result;
use crate::util::now_rfc3339;

use super::Db;

// ───────────────────────── sourcemaps ─────────────────────────

pub async fn add_sourcemap(db: &Db, org_id: &str, bundle_sha256: &str, size: i64) -> Result<()> {
    sqlx::query(
        "INSERT INTO sourcemaps (org_id, bundle_sha256, size, created_at) VALUES (?, ?, ?, ?)
         ON CONFLICT(org_id, bundle_sha256) DO UPDATE SET size = excluded.size",
    )
    .bind(org_id)
    .bind(bundle_sha256)
    .bind(size)
    .bind(now_rfc3339())
    .execute(db)
    .await?;
    Ok(())
}

pub async fn has_sourcemap(db: &Db, org_id: &str, bundle_sha256: &str) -> Result<bool> {
    let (n,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM sourcemaps WHERE org_id = ? AND bundle_sha256 = ?")
            .bind(org_id)
            .bind(bundle_sha256)
            .fetch_one(db)
            .await?;
    Ok(n > 0)
}

/// Drop the sourcemap row for a collected bundle; true if there was one.
pub async fn delete_sourcemap(db: &Db, org_id: &str, bundle_sha256: &str) -> Result<bool> {
    let res = sqlx::query("DELETE FROM sourcemaps WHERE org_id = ? AND bundle_sha256 = ?")
        .bind(org_id)
        .bind(bundle_sha256)
        .execute(db)
        .await?;
    Ok(res.rows_affected() > 0)
}

// ───────────────────────── errors ─────────────────────────

/// Fields of one stored error event.
pub struct NewErrorEvent<'a> {
    pub app_id: &'a str,
    pub ts: &'a str,
    pub fingerprint: &'a str,
    pub name: &'a str,
    pub message: &'a str,
    pub culprit: Option<&'a str>,
    pub fatal: bool,
    pub update_id: Option<&'a str>,
    pub platform: Option<&'a str>,
    pub runtime_version: Option<&'a str>,
    pub channel: Option<&'a str>,
    pub client_id: Option<&'a str>,
    pub raw_stack: Option<&'a str>,
    pub frames_json: Option<&'a str>,
    pub source: &'a str,
}

/// Upsert the event's group (by fingerprint) and append the event.
pub async fn record_error(db: &Db, e: &NewErrorEvent<'_>) -> Result<String> {
    let mut tx = db.begin().await?;
    let (group_id,): (String,) = sqlx::query_as(
        "INSERT INTO error_groups
            (id, app_id, fingerprint, name, message, culprit, fatal, events, first_seen, last_seen)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 1, ?8, ?8)
         ON CONFLICT(app_id, fingerprint) DO UPDATE SET
           events = events + 1,
           last_seen = max(last_seen, excluded.last_seen),
           fatal = max(fatal, excluded.fatal),
           culprit = COALESCE(culprit, excluded.culprit)
         RETURNING id",
    )
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(e.app_id)
    .bind(e.fingerprint)
    .bind(e.name)
    .bind(e.message)
    .bind(e.culprit)
    .bind(e.fatal)
    .bind(e.ts)
    .fetch_one(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO error_events
            (group_id, app_id, ts, update_id, platform, runtime_version, channel, client_id,
             fatal, message, raw_stack, frames_json, source)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&group_id)
    .bind(e.app_id)
    .bind(e.ts)
    .bind(e.update_id)
    .bind(e.platform)
    .bind(e.runtime_version)
    .bind(e.channel)
    .bind(e.client_id)
    .bind(e.fatal)
    .bind(e.message)
    .bind(e.raw_stack)
    .bind(e.frames_json)
    .bind(e.source)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(group_id)
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct ErrorGroupRow {
    pub id: String,
    pub name: String,
    pub message: String,
    pub culprit: Option<String>,
    pub fatal: bool,
    /// All-time events.
    pub events: i64,
    /// Events / distinct devices in the requested window.
    pub recent_events: i64,
    pub recent_devices: i64,
    pub updates: i64,
    pub first_seen: String,
    pub last_seen: String,
}

/// Error groups seen since `since`, most recent first; optionally only
/// those hit by one update.
pub async fn error_groups(
    db: &Db,
    app_id: &str,
    since: &str,
    update_id: Option<&str>,
    limit: i64,
) -> Result<Vec<ErrorGroupRow>> {
    let rows = sqlx::query_as::<_, ErrorGroupRow>(
        "SELECT g.id, g.name, g.message, g.culprit, g.fatal, g.events,
                COUNT(e.id) AS recent_events,
                COUNT(DISTINCT e.client_id) AS recent_devices,
                COUNT(DISTINCT e.update_id) AS updates,
                g.first_seen, g.last_seen
         FROM error_groups g JOIN error_events e ON e.group_id = g.id
         WHERE g.app_id = ?1 AND e.ts >= ?2 AND (?3 IS NULL OR e.update_id = ?3)
         GROUP BY g.id ORDER BY g.last_seen DESC LIMIT ?4",
    )
    .bind(app_id)
    .bind(since)
    .bind(update_id)
    .bind(limit)
    .fetch_all(db)
    .await?;
    Ok(rows)
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct ErrorEventRow {
    pub id: i64,
    pub ts: String,
    pub update_id: Option<String>,
    pub platform: Option<String>,
    pub runtime_version: Option<String>,
    pub channel: Option<String>,
    pub client_id: Option<String>,
    pub fatal: bool,
    pub message: String,
    pub raw_stack: Option<String>,
    pub frames_json: Option<String>,
    pub source: String,
}

pub async fn error_group(
    db: &Db,
    app_id: &str,
    group_id: &str,
) -> Result<Option<(ErrorGroupRow, Vec<ErrorEventRow>)>> {
    let group = sqlx::query_as::<_, ErrorGroupRow>(
        "SELECT g.id, g.name, g.message, g.culprit, g.fatal, g.events,
                COUNT(e.id) AS recent_events,
                COUNT(DISTINCT e.client_id) AS recent_devices,
                COUNT(DISTINCT e.update_id) AS updates,
                g.first_seen, g.last_seen
         FROM error_groups g LEFT JOIN error_events e ON e.group_id = g.id
         WHERE g.app_id = ? AND g.id = ? GROUP BY g.id",
    )
    .bind(app_id)
    .bind(group_id)
    .fetch_optional(db)
    .await?;
    let Some(group) = group else { return Ok(None) };
    let events = sqlx::query_as::<_, ErrorEventRow>(
        "SELECT id, ts, update_id, platform, runtime_version, channel, client_id, fatal,
                message, raw_stack, frames_json, source
         FROM error_events WHERE group_id = ? ORDER BY ts DESC LIMIT 50",
    )
    .bind(group_id)
    .fetch_all(db)
    .await?;
    Ok(Some((group, events)))
}

// ───────────────────────── logs ─────────────────────────

pub struct NewLog {
    pub ts: String,
    pub severity: i64,
    pub severity_text: Option<String>,
    pub body: String,
    pub attributes: Option<String>,
    pub update_id: Option<String>,
    pub platform: Option<String>,
    pub client_id: Option<String>,
    pub trace_id: Option<String>,
}

pub async fn insert_logs(db: &Db, app_id: &str, logs: &[NewLog]) -> Result<()> {
    let mut tx = db.begin().await?;
    for l in logs {
        sqlx::query(
            "INSERT INTO log_records
                (app_id, ts, severity, severity_text, body, attributes, update_id, platform,
                 client_id, trace_id)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(app_id)
        .bind(&l.ts)
        .bind(l.severity)
        .bind(&l.severity_text)
        .bind(&l.body)
        .bind(&l.attributes)
        .bind(&l.update_id)
        .bind(&l.platform)
        .bind(&l.client_id)
        .bind(&l.trace_id)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(())
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct LogRow {
    pub id: i64,
    pub ts: String,
    pub severity: i64,
    pub severity_text: Option<String>,
    pub body: String,
    pub attributes: Option<String>,
    pub update_id: Option<String>,
    pub platform: Option<String>,
    pub client_id: Option<String>,
    pub trace_id: Option<String>,
}

/// Log search: newest first; `before_id` pages backwards.
pub struct LogQuery<'a> {
    pub since: &'a str,
    pub min_severity: i64,
    pub text: Option<&'a str>,
    pub update_id: Option<&'a str>,
    pub client_id: Option<&'a str>,
    pub before_id: Option<i64>,
    pub limit: i64,
}

pub async fn query_logs(db: &Db, app_id: &str, q: &LogQuery<'_>) -> Result<Vec<LogRow>> {
    let like = q.text.map(|t| {
        format!(
            "%{}%",
            t.replace('\\', "\\\\")
                .replace('%', "\\%")
                .replace('_', "\\_")
        )
    });
    let rows = sqlx::query_as::<_, LogRow>(
        "SELECT id, ts, severity, severity_text, body, attributes, update_id, platform,
                client_id, trace_id
         FROM log_records
         WHERE app_id = ?1 AND ts >= ?2 AND severity >= ?3
           AND (?4 IS NULL OR body LIKE ?4 ESCAPE '\\' OR attributes LIKE ?4 ESCAPE '\\')
           AND (?5 IS NULL OR update_id = ?5)
           AND (?6 IS NULL OR client_id = ?6)
           AND (?7 IS NULL OR id < ?7)
         ORDER BY id DESC LIMIT ?8",
    )
    .bind(app_id)
    .bind(q.since)
    .bind(q.min_severity)
    .bind(like)
    .bind(q.update_id)
    .bind(q.client_id)
    .bind(q.before_id)
    .bind(q.limit)
    .fetch_all(db)
    .await?;
    Ok(rows)
}

// ───────────────────────── metrics ─────────────────────────

/// One aggregated observation for a minute bucket.
pub struct MetricObs<'a> {
    pub name: &'a str,
    pub minute: &'a str,
    pub attributes: &'a str,
    pub kind: &'a str,
    pub unit: Option<&'a str>,
    pub count: i64,
    pub sum: f64,
    pub min: Option<f64>,
    pub max: Option<f64>,
}

pub async fn add_metric_points(db: &Db, app_id: &str, obs: &[MetricObs<'_>]) -> Result<()> {
    let mut tx = db.begin().await?;
    for o in obs {
        sqlx::query(
            "INSERT INTO metric_points
                (app_id, name, minute, attributes, kind, unit, count, sum, min, max)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(app_id, name, minute, attributes) DO UPDATE SET
               count = count + excluded.count,
               sum = sum + excluded.sum,
               min = CASE WHEN min IS NULL OR excluded.min < min THEN excluded.min ELSE min END,
               max = CASE WHEN max IS NULL OR excluded.max > max THEN excluded.max ELSE max END",
        )
        .bind(app_id)
        .bind(o.name)
        .bind(o.minute)
        .bind(o.attributes)
        .bind(o.kind)
        .bind(o.unit)
        .bind(o.count)
        .bind(o.sum)
        .bind(o.min)
        .bind(o.max)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(())
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct MetricName {
    pub name: String,
    pub kind: String,
    pub unit: Option<String>,
    pub last_minute: String,
}

pub async fn metric_names(db: &Db, app_id: &str, since: &str) -> Result<Vec<MetricName>> {
    let rows = sqlx::query_as::<_, MetricName>(
        "SELECT name, kind, unit, max(minute) AS last_minute FROM metric_points
         WHERE app_id = ? AND minute >= ? GROUP BY name, kind, unit ORDER BY name",
    )
    .bind(app_id)
    .bind(since)
    .fetch_all(db)
    .await?;
    Ok(rows)
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct MetricBucket {
    pub bucket: String,
    pub count: i64,
    pub sum: f64,
    pub min: Option<f64>,
    pub max: Option<f64>,
}

/// A metric's series since `since`, summed across attribute sets, in buckets
/// of `bucket_len` characters of the minute key (16 = minute, 13 = hour,
/// 10 = day).
pub async fn metric_series(
    db: &Db,
    app_id: &str,
    name: &str,
    since: &str,
    bucket_len: i64,
) -> Result<Vec<MetricBucket>> {
    let rows = sqlx::query_as::<_, MetricBucket>(
        "SELECT substr(minute, 1, ?4) AS bucket, SUM(count) AS count, SUM(sum) AS sum,
                MIN(min) AS min, MAX(max) AS max
         FROM metric_points WHERE app_id = ?1 AND name = ?2 AND minute >= ?3
         GROUP BY bucket ORDER BY bucket",
    )
    .bind(app_id)
    .bind(name)
    .bind(since)
    .bind(bucket_len)
    .fetch_all(db)
    .await?;
    Ok(rows)
}

// ───────────────────────── retention ─────────────────────────

/// Drop raw events/logs/metric points older than `cutoff` (RFC3339), and
/// error groups with no remaining events. Returns rows removed.
pub async fn prune(db: &Db, cutoff: &str) -> Result<u64> {
    let minute_cutoff: String = cutoff.chars().take(16).collect();
    let mut n = 0;
    n += sqlx::query("DELETE FROM error_events WHERE ts < ?")
        .bind(cutoff)
        .execute(db)
        .await?
        .rows_affected();
    n += sqlx::query(
        "DELETE FROM error_groups WHERE last_seen < ?
           AND NOT EXISTS (SELECT 1 FROM error_events e WHERE e.group_id = error_groups.id)",
    )
    .bind(cutoff)
    .execute(db)
    .await?
    .rows_affected();
    n += sqlx::query("DELETE FROM log_records WHERE ts < ?")
        .bind(cutoff)
        .execute(db)
        .await?
        .rows_affected();
    n += sqlx::query("DELETE FROM metric_points WHERE minute < ?")
        .bind(minute_cutoff)
        .execute(db)
        .await?
        .rows_affected();
    Ok(n)
}
