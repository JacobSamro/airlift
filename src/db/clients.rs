//! Queries for device check-ins and adoption stats.

use serde::Serialize;

use crate::analytics::ClientCheckin;
use crate::error::Result;
use crate::util::{now_rfc3339, rfc3339_in, utc_day_offset};

use super::Db;

pub async fn upsert_client(
    db: &Db,
    app_id: &str,
    client_id: &str,
    c: &ClientCheckin,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO clients (app_id, client_id, platform, runtime_version, channel,
                              embedded_update_id, current_update_id, first_seen, last_seen)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(app_id, client_id) DO UPDATE SET
           platform = excluded.platform,
           runtime_version = excluded.runtime_version,
           channel = excluded.channel,
           embedded_update_id = excluded.embedded_update_id,
           current_update_id = excluded.current_update_id,
           last_seen = excluded.last_seen",
    )
    .bind(app_id)
    .bind(client_id)
    .bind(&c.platform)
    .bind(&c.runtime_version)
    .bind(&c.channel)
    .bind(&c.embedded_update_id)
    .bind(&c.current_update_id)
    .bind(now_rfc3339())
    .bind(&c.last_seen)
    .execute(db)
    .await?;
    Ok(())
}

pub async fn add_checkins(
    db: &Db,
    app_id: &str,
    day: &str,
    platform: &str,
    update_id: &str,
    n: u64,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO checkins_daily (app_id, day, platform, update_id, count)
         VALUES (?, ?, ?, ?, ?)
         ON CONFLICT(app_id, day, platform, update_id)
           DO UPDATE SET count = count + excluded.count",
    )
    .bind(app_id)
    .bind(day)
    .bind(platform)
    .bind(update_id)
    .bind(n as i64)
    .execute(db)
    .await?;
    Ok(())
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct ClientRow {
    pub client_id: String,
    pub platform: Option<String>,
    pub runtime_version: Option<String>,
    pub channel: Option<String>,
    pub embedded_update_id: Option<String>,
    pub current_update_id: Option<String>,
    pub first_seen: String,
    pub last_seen: String,
}

/// Devices seen most recently, newest first.
pub async fn list_clients(db: &Db, app_id: &str, limit: i64) -> Result<Vec<ClientRow>> {
    let rows = sqlx::query_as::<_, ClientRow>(
        "SELECT client_id, platform, runtime_version, channel, embedded_update_id,
                current_update_id, first_seen, last_seen
         FROM clients WHERE app_id = ? ORDER BY last_seen DESC LIMIT ?",
    )
    .bind(app_id)
    .bind(limit)
    .fetch_all(db)
    .await?;
    Ok(rows)
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct AdoptionRow {
    pub current_update_id: Option<String>,
    pub platform: Option<String>,
    pub runtime_version: Option<String>,
    pub devices: i64,
}

/// How many recently-seen devices run each update (14-day activity window).
pub async fn adoption(db: &Db, app_id: &str) -> Result<Vec<AdoptionRow>> {
    let cutoff = rfc3339_in(-14 * 86400);
    let rows = sqlx::query_as::<_, AdoptionRow>(
        "SELECT current_update_id, platform, runtime_version, COUNT(*) AS devices
         FROM clients WHERE app_id = ? AND last_seen > ?
         GROUP BY current_update_id, platform, runtime_version
         ORDER BY devices DESC",
    )
    .bind(app_id)
    .bind(cutoff)
    .fetch_all(db)
    .await?;
    Ok(rows)
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct CheckinDay {
    pub day: String,
    pub platform: String,
    pub count: i64,
}

/// Daily manifest-request series over a trailing window.
pub async fn checkin_series(db: &Db, app_id: &str, days: i64) -> Result<Vec<CheckinDay>> {
    let since = utc_day_offset(days);
    let rows = sqlx::query_as::<_, CheckinDay>(
        "SELECT day, platform, SUM(count) AS count
         FROM checkins_daily WHERE app_id = ? AND day >= ?
         GROUP BY day, platform ORDER BY day",
    )
    .bind(app_id)
    .bind(since)
    .fetch_all(db)
    .await?;
    Ok(rows)
}
