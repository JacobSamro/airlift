//! Device observability: JS error reports (airlift reporter, OTLP exception
//! logs) symbolicated with the bundle's sourcemap and grouped; OTLP logs and
//! per-minute metric rollups. All in SQLite, pruned after
//! `observability.retention_days`.
//!
//! Ingestion is unauthenticated (devices, like the manifest endpoint), so the
//! HTTP handlers only validate and enqueue; a background worker does the
//! sourcemap fetch, symbolication and writes. The queue is bounded: under
//! overload, telemetry is dropped rather than slowing devices or the server.

pub mod ingest;
pub mod otlp;
pub mod stack;

use std::sync::{Arc, Mutex, OnceLock};

use tokio::sync::mpsc;

use crate::db;
use crate::state::AppState;
use crate::storage::Storage;

/// One error to symbolicate and store.
#[derive(Debug, Clone)]
pub struct ErrorReport {
    pub app_id: String,
    pub org_id: String,
    pub ts: String,
    pub name: String,
    pub message: String,
    pub stack: Option<String>,
    pub fatal: bool,
    pub update_id: Option<String>,
    pub platform: Option<String>,
    pub runtime_version: Option<String>,
    pub channel: Option<String>,
    pub client_id: Option<String>,
    pub source: &'static str,
}

/// Work for the background writer.
pub enum Item {
    Error(Box<ErrorReport>),
    Logs {
        app_id: String,
        logs: Vec<db::observability::NewLog>,
    },
    Metrics {
        app_id: String,
        points: Vec<otlp::MetricPoint>,
    },
}

const QUEUE_DEPTH: usize = 4096;
static QUEUE: OnceLock<mpsc::Sender<Item>> = OnceLock::new();

/// Enqueue telemetry; false (dropped) when the worker is backed up or not
/// running.
pub fn submit(item: Item) -> bool {
    match QUEUE.get() {
        Some(tx) => match tx.try_send(item) {
            Ok(()) => true,
            Err(_) => {
                metrics::counter!("airlift_telemetry_dropped_total").increment(1);
                false
            }
        },
        None => false,
    }
}

/// Start the writer (and the retention loop).
pub fn spawn(state: AppState) {
    let (tx, mut rx) = mpsc::channel::<Item>(QUEUE_DEPTH);
    if QUEUE.set(tx).is_err() {
        return;
    }
    let worker = state.clone();
    tokio::spawn(async move {
        while let Some(item) = rx.recv().await {
            let res = match item {
                Item::Error(e) => store_error(&worker, *e).await,
                Item::Logs { app_id, logs } => {
                    db::observability::insert_logs(worker.db(), &app_id, &logs).await
                }
                Item::Metrics { app_id, points } => {
                    otlp::store_metrics(worker.db(), &app_id, &points).await
                }
            };
            if let Err(e) = res {
                tracing::warn!(error = %e, "telemetry write failed");
            }
        }
    });
    tokio::spawn(retention_loop(state));
}

/// Symbolicate (when the bundle has a sourcemap), fingerprint, store.
async fn store_error(state: &AppState, e: ErrorReport) -> crate::error::Result<()> {
    let mut frames = e.stack.as_deref().map(stack::parse).unwrap_or_default();
    if let Some(map) = sourcemap_for(state, &e).await {
        stack::symbolicate(&mut frames, &map);
    }
    let fingerprint = stack::fingerprint(&e.name, &e.message, &frames);
    let culprit = stack::culprit(&frames);
    let frames_json = serde_json::to_string(&frames).ok();
    db::observability::record_error(
        state.db(),
        &db::observability::NewErrorEvent {
            app_id: &e.app_id,
            ts: &e.ts,
            fingerprint: &fingerprint,
            name: &e.name,
            message: &e.message,
            culprit: culprit.as_deref(),
            fatal: e.fatal,
            update_id: e.update_id.as_deref(),
            platform: e.platform.as_deref(),
            runtime_version: e.runtime_version.as_deref(),
            channel: e.channel.as_deref(),
            client_id: e.client_id.as_deref(),
            raw_stack: e.stack.as_deref(),
            frames_json: frames_json.as_deref(),
            source: e.source,
        },
    )
    .await?;
    metrics::counter!("airlift_device_errors_total", "source" => e.source).increment(1);
    Ok(())
}

/// Parsed sourcemaps, most recently used last; a handful is plenty (one per
/// live bundle per platform).
type MapCache = Mutex<Vec<(String, Arc<sourcemap::DecodedMap>)>>;
static MAPS: OnceLock<MapCache> = OnceLock::new();
const MAX_MAPS: usize = 8;

/// The sourcemap of the bundle the error's update runs, if uploaded.
async fn sourcemap_for(state: &AppState, e: &ErrorReport) -> Option<Arc<sourcemap::DecodedMap>> {
    let update_id = e.update_id.as_deref()?;
    let update = db::updates::find_update_in_app(state.db(), &e.app_id, update_id)
        .await
        .ok()??;
    let launch = db::updates::launch_asset(state.db(), &update.id)
        .await
        .ok()??;
    let sha = launch.sha256;
    let cache = MAPS.get_or_init(|| Mutex::new(Vec::new()));
    if let Some(hit) = cache
        .lock()
        .ok()?
        .iter()
        .find(|(k, _)| *k == sha)
        .map(|(_, m)| m.clone())
    {
        return Some(hit);
    }
    if !db::observability::has_sourcemap(state.db(), &e.org_id, &sha)
        .await
        .ok()?
    {
        return None;
    }
    let bytes = state
        .storage()
        .get(&Storage::sourcemap_key(&e.org_id, &sha))
        .await
        .ok()?;
    let map = tokio::task::spawn_blocking(move || sourcemap::decode_slice(&bytes))
        .await
        .ok()?
        .ok()?;
    let map = Arc::new(map);
    if let Ok(mut c) = cache.lock() {
        c.retain(|(k, _)| *k != sha);
        if c.len() >= MAX_MAPS {
            c.remove(0);
        }
        c.push((sha, map.clone()));
    }
    Some(map)
}

/// Hourly: drop error events, logs and metric points past retention.
async fn retention_loop(state: AppState) {
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(3600));
    loop {
        tick.tick().await;
        let days = state.config().observability.retention_days.max(1);
        let cutoff = crate::util::rfc3339_in(-days * 86_400);
        match db::observability::prune(state.db(), &cutoff).await {
            Ok(n) if n > 0 => tracing::info!(removed = n, "telemetry retention sweep"),
            Ok(_) => {}
            Err(e) => tracing::warn!(error = %e, "telemetry retention sweep failed"),
        }
    }
}
