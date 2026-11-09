//! Read APIs for device telemetry: error groups (symbolicated), OTLP logs and
//! metric series. All require `read` on the app.

use axum::extract::{Path, Query, State};
use axum::response::Response;
use serde::Deserialize;
use serde_json::json;

use super::apps::resolve_app;
use super::json_ok;
use crate::auth::ApiUser;
use crate::db;
use crate::error::{Error, Result};
use crate::models::Capability;
use crate::state::AppState;

/// "1h" | "24h" | "7d" | "14d" … → RFC3339 lower bound (default 24h).
fn since(window: Option<&str>) -> Result<String> {
    let w = window.unwrap_or("24h").trim();
    let (n, unit) = w.split_at(w.len().saturating_sub(1));
    let n: i64 = n
        .parse()
        .map_err(|_| Error::bad_request("window like 1h, 24h, 7d"))?;
    let secs = match unit {
        "m" => n * 60,
        "h" => n * 3600,
        "d" => n * 86_400,
        _ => return Err(Error::bad_request("window like 1h, 24h, 7d")),
    };
    Ok(crate::util::rfc3339_in(-secs.clamp(60, 90 * 86_400)))
}

#[derive(Deserialize)]
pub struct ErrorsQuery {
    window: Option<String>,
    update: Option<String>,
    limit: Option<i64>,
}

pub async fn list_errors(
    State(state): State<AppState>,
    caller: ApiUser,
    Path((slug, app_slug)): Path<(String, String)>,
    Query(q): Query<ErrorsQuery>,
) -> Result<Response> {
    let (_org, app) = resolve_app(&state, &caller, &slug, &app_slug, Capability::Read).await?;
    let since = since(q.window.as_deref())?;
    let update = q.update.as_deref().map(str::to_ascii_lowercase);
    let groups = db::observability::error_groups(
        state.db(),
        &app.id,
        &since,
        update.as_deref(),
        q.limit.unwrap_or(100).clamp(1, 500),
    )
    .await?;
    Ok(json_ok(json!({ "groups": groups })))
}

pub async fn get_error(
    State(state): State<AppState>,
    caller: ApiUser,
    Path((slug, app_slug, group)): Path<(String, String, String)>,
) -> Result<Response> {
    let (_org, app) = resolve_app(&state, &caller, &slug, &app_slug, Capability::Read).await?;
    let (group, events) = db::observability::error_group(state.db(), &app.id, &group)
        .await?
        .ok_or(Error::NotFound)?;
    let events: Vec<_> = events
        .into_iter()
        .map(|e| {
            let frames: serde_json::Value = e
                .frames_json
                .as_deref()
                .and_then(|f| serde_json::from_str(f).ok())
                .unwrap_or(serde_json::Value::Null);
            json!({
                "id": e.id, "ts": e.ts, "update_id": e.update_id, "platform": e.platform,
                "runtime_version": e.runtime_version, "channel": e.channel,
                "client_id": e.client_id, "fatal": e.fatal, "message": e.message,
                "raw_stack": e.raw_stack, "frames": frames, "source": e.source,
            })
        })
        .collect();
    Ok(json_ok(json!({ "group": group, "events": events })))
}

#[derive(Deserialize)]
pub struct LogsQuery {
    window: Option<String>,
    /// Minimum OTLP severityNumber (9 = INFO, 13 = WARN, 17 = ERROR).
    severity: Option<i64>,
    q: Option<String>,
    update: Option<String>,
    client: Option<String>,
    before_id: Option<i64>,
    limit: Option<i64>,
}

pub async fn list_logs(
    State(state): State<AppState>,
    caller: ApiUser,
    Path((slug, app_slug)): Path<(String, String)>,
    Query(q): Query<LogsQuery>,
) -> Result<Response> {
    let (_org, app) = resolve_app(&state, &caller, &slug, &app_slug, Capability::Read).await?;
    let since = since(q.window.as_deref())?;
    let update = q.update.as_deref().map(str::to_ascii_lowercase);
    let logs = db::observability::query_logs(
        state.db(),
        &app.id,
        &db::observability::LogQuery {
            since: &since,
            min_severity: q.severity.unwrap_or(0),
            text: q.q.as_deref().filter(|t| !t.is_empty()),
            update_id: update.as_deref(),
            client_id: q.client.as_deref().filter(|c| !c.is_empty()),
            before_id: q.before_id,
            limit: q.limit.unwrap_or(200).clamp(1, 1000),
        },
    )
    .await?;
    Ok(json_ok(json!({ "logs": logs })))
}

#[derive(Deserialize)]
pub struct MetricsQuery {
    window: Option<String>,
}

pub async fn list_metrics(
    State(state): State<AppState>,
    caller: ApiUser,
    Path((slug, app_slug)): Path<(String, String)>,
    Query(q): Query<MetricsQuery>,
) -> Result<Response> {
    let (_org, app) = resolve_app(&state, &caller, &slug, &app_slug, Capability::Read).await?;
    let since = since(Some(q.window.as_deref().unwrap_or("7d")))?;
    let names = db::observability::metric_names(state.db(), &app.id, &since).await?;
    Ok(json_ok(json!({ "metrics": names })))
}

#[derive(Deserialize)]
pub struct SeriesQuery {
    name: String,
    window: Option<String>,
    /// minute | hour | day (default: chosen from the window)
    bucket: Option<String>,
}

pub async fn metric_series(
    State(state): State<AppState>,
    caller: ApiUser,
    Path((slug, app_slug)): Path<(String, String)>,
    Query(q): Query<SeriesQuery>,
) -> Result<Response> {
    let (_org, app) = resolve_app(&state, &caller, &slug, &app_slug, Capability::Read).await?;
    let window = q.window.as_deref().unwrap_or("24h");
    let since = since(Some(window))?;
    let bucket_len = match q.bucket.as_deref() {
        Some("minute") => 16,
        Some("hour") => 13,
        Some("day") => 10,
        Some(_) => return Err(Error::bad_request("bucket: minute|hour|day")),
        None if window.ends_with('m') || window == "1h" => 16,
        None if window.ends_with('h') => 13,
        None => 10,
    };
    let series =
        db::observability::metric_series(state.db(), &app.id, &q.name, &since, bucket_len).await?;
    Ok(json_ok(json!({ "name": q.name, "series": series })))
}
