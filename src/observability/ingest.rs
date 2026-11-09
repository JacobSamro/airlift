//! Public (device-facing) telemetry endpoints:
//!
//!   POST /u/{app_id}/errors          JS error reports (airlift reporter)
//!   POST /u/{app_id}/otlp/v1/logs    OTLP/HTTP JSON logs
//!   POST /u/{app_id}/otlp/v1/metrics OTLP/HTTP JSON metrics
//!
//! Unauthenticated like the manifest endpoint, so: small body limits, a
//! per-IP+app rate limit, strict size caps per field, and the work is only
//! enqueued (202) — symbolication and writes happen in the background.

use std::num::NonZeroU32;
use std::sync::LazyLock;

use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use governor::{clock::DefaultClock, state::keyed::DefaultKeyedStateStore, Quota, RateLimiter};
use serde::Deserialize;
use serde_json::{json, Value};

use super::{otlp, submit, ErrorReport, Item};
use crate::db;
use crate::error::{Error, Result};
use crate::geo::ClientAddr;
use crate::state::AppState;

type Limiter = RateLimiter<String, DefaultKeyedStateStore<String>, DefaultClock>;

/// Per (client IP, app): 10 requests/s sustained, bursts of 60 — generous
/// for real devices (batching), hostile to a flood.
static LIMITER: LazyLock<Limiter> = LazyLock::new(|| {
    RateLimiter::keyed(
        Quota::per_second(NonZeroU32::new(10).unwrap()).allow_burst(NonZeroU32::new(60).unwrap()),
    )
});

const MAX_ERRORS_PER_REQUEST: usize = 20;
const MAX_MESSAGE: usize = 4 * 1024;
const MAX_STACK: usize = 64 * 1024;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/u/{app_id}/errors",
            post(errors).layer(DefaultBodyLimit::max(256 * 1024)),
        )
        .route(
            "/u/{app_id}/otlp/v1/logs",
            post(otlp_logs).layer(DefaultBodyLimit::max(1024 * 1024)),
        )
        .route(
            "/u/{app_id}/otlp/v1/metrics",
            post(otlp_metrics).layer(DefaultBodyLimit::max(1024 * 1024)),
        )
}

/// Resolve the app and apply the rate limit.
async fn admit(
    state: &AppState,
    app_id: &str,
    ip: Option<std::net::IpAddr>,
) -> Result<db::apps::App> {
    let key = format!("{}|{app_id}", ip.map(|i| i.to_string()).unwrap_or_default());
    if LIMITER.check_key(&key).is_err() {
        return Err(Error::bad_request("rate limit exceeded"));
    }
    db::apps::find_by_id(state.db(), app_id)
        .await?
        .ok_or(Error::NotFound)
}

fn clip(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &s[..end])
}

/// One report from the airlift reporter (or any client).
#[derive(Deserialize)]
struct ReportedError {
    #[serde(default)]
    name: Option<String>,
    message: String,
    #[serde(default)]
    stack: Option<String>,
    #[serde(default)]
    fatal: bool,
    #[serde(default)]
    update_id: Option<String>,
    #[serde(default)]
    platform: Option<String>,
    #[serde(default)]
    runtime_version: Option<String>,
    #[serde(default)]
    channel: Option<String>,
    #[serde(default)]
    client_id: Option<String>,
    /// RFC3339; defaults to receipt time. Clamped to "not in the future".
    #[serde(default)]
    timestamp: Option<String>,
}

async fn errors(
    State(state): State<AppState>,
    Path(app_id): Path<String>,
    ClientAddr(ip): ClientAddr,
    Json(body): Json<Value>,
) -> Result<Response> {
    let app = admit(&state, &app_id, ip).await?;
    let items: Vec<Value> = match body {
        Value::Array(a) => a,
        one => vec![one],
    };
    if items.len() > MAX_ERRORS_PER_REQUEST {
        return Err(Error::bad_request(format!(
            "at most {MAX_ERRORS_PER_REQUEST} errors per request"
        )));
    }
    let now = crate::util::now_rfc3339();
    let mut accepted = 0;
    for v in items {
        let e: ReportedError = serde_json::from_value(v)
            .map_err(|e| Error::bad_request(format!("invalid error report: {e}")))?;
        let ts = e
            .timestamp
            .as_deref()
            .filter(|t| {
                time::OffsetDateTime::parse(t, &time::format_description::well_known::Rfc3339)
                    .is_ok()
            })
            .map(crate::util::normalize_rfc3339)
            .filter(|t| *t <= now)
            .unwrap_or_else(|| now.clone());
        let platform = e
            .platform
            .map(|p| p.to_ascii_lowercase())
            .filter(|p| p == "ios" || p == "android");
        let report = ErrorReport {
            app_id: app.id.clone(),
            org_id: app.org_id.clone(),
            ts,
            name: clip(e.name.as_deref().unwrap_or("Error"), 200),
            message: clip(&e.message, MAX_MESSAGE),
            stack: e.stack.map(|s| clip(&s, MAX_STACK)),
            fatal: e.fatal,
            update_id: e.update_id.map(|u| clip(&u.to_ascii_lowercase(), 64)),
            platform,
            runtime_version: e.runtime_version.map(|r| clip(&r, 100)),
            channel: e.channel.map(|c| clip(&c, 100)),
            client_id: e.client_id.map(|c| clip(&c, 200)),
            source: "reporter",
        };
        if submit(Item::Error(Box::new(report))) {
            accepted += 1;
        }
    }
    Ok((StatusCode::ACCEPTED, Json(json!({ "accepted": accepted }))).into_response())
}

fn require_json(headers: &HeaderMap) -> Result<()> {
    let ct = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if ct.starts_with("application/json") {
        Ok(())
    } else {
        Err(Error::bad_request(
            "OTLP/HTTP JSON only (Content-Type: application/json); protobuf is not supported",
        ))
    }
}

/// OTLP success: an empty Export*ServiceResponse.
fn otlp_ok() -> Response {
    (StatusCode::OK, Json(json!({}))).into_response()
}

async fn otlp_logs(
    State(state): State<AppState>,
    Path(app_id): Path<String>,
    ClientAddr(ip): ClientAddr,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Result<Response> {
    require_json(&headers)?;
    let app = admit(&state, &app_id, ip).await?;
    let (mut logs, errors) = otlp::parse_logs(&body, &app.id, &app.org_id);
    for l in &mut logs {
        l.body = clip(&l.body, MAX_STACK);
    }
    for mut e in errors {
        e.message = clip(&e.message, MAX_MESSAGE);
        e.stack = e.stack.map(|s| clip(&s, MAX_STACK));
        submit(Item::Error(Box::new(e)));
    }
    if !logs.is_empty() {
        submit(Item::Logs {
            app_id: app.id,
            logs,
        });
    }
    Ok(otlp_ok())
}

async fn otlp_metrics(
    State(state): State<AppState>,
    Path(app_id): Path<String>,
    ClientAddr(ip): ClientAddr,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Result<Response> {
    require_json(&headers)?;
    let app = admit(&state, &app_id, ip).await?;
    let points = otlp::parse_metrics(&body);
    if !points.is_empty() {
        submit(Item::Metrics {
            app_id: app.id,
            points,
        });
    }
    Ok(otlp_ok())
}
