//! bsdiff incremental patches for launch bundles (expo-updates SDK 55+).
//!
//! Contract (from the client source, not the protocol spec): the device sends
//! `A-IM: bsdiff` on the launch-asset request together with
//! `Expo-Current-Update-ID` (the update it runs — the patch base) and
//! `Expo-Requested-Update-ID` (the update it's downloading). A patch response
//! is `226 IM Used` + `IM: bsdiff` + `expo-base-update-id: <from-update-id>`
//! with a raw classic **BSDIFF40** (bzip2) body — the vendored bspatch.c
//! refuses anything else. The client applies the patch and verifies the
//! result against the manifest's launchAsset hash, falling back to a full
//! download on any failure, so serving the full bundle is always safe.
//!
//! Generation is lazy: the first request for a (from, to) pair enqueues a job
//! and falls through to the full-bundle redirect; once the background worker
//! has built and stored the patch, subsequent requests get the 226.

use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};

use crate::db;
use crate::error::Result;
use crate::state::AppState;
use crate::storage::Storage;

/// Try to serve (or enqueue) a patch for a launch-asset request. Returns
/// `None` when the request isn't patch-eligible or no patch is ready — the
/// caller then serves the full bundle as usual.
pub async fn maybe_serve_patch(
    state: &AppState,
    app: &db::apps::App,
    requested_sha256: &str,
    headers: &HeaderMap,
) -> Result<Option<Response>> {
    if !state.config().patches.enabled {
        return Ok(None);
    }
    let accepts_bsdiff = headers
        .get("a-im")
        .and_then(|v| v.to_str().ok())
        .map(|v| {
            v.split(',')
                .any(|im| im.trim().eq_ignore_ascii_case("bsdiff"))
        })
        .unwrap_or(false);
    if !accepts_bsdiff {
        return Ok(None);
    }
    let header = |name: &str| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty())
    };
    let (Some(from_id), Some(to_id)) = (
        header("expo-current-update-id"),
        header("expo-requested-update-id"),
    ) else {
        return Ok(None);
    };
    if from_id == to_id {
        return Ok(None);
    }

    // Both updates must belong to this app, and the requested asset must be
    // the TO update's launch bundle.
    let Some((from_update, from_launch)) = update_with_launch(state, app, &from_id).await? else {
        return Ok(None);
    };
    let Some((_to_update, to_launch)) = update_with_launch(state, app, &to_id).await? else {
        return Ok(None);
    };
    if to_launch.sha256 != requested_sha256 {
        return Ok(None);
    }

    match db::patches::find(state.db(), &from_update.id, &to_id).await? {
        Some(p) if p.status == "ready" => {
            let key = Storage::patch_key(&app.org_id, &from_launch.sha256, &to_launch.sha256);
            // Stream the patch straight from storage rather than buffering
            // the whole object per request.
            let (len, body) = match state.storage().get_stream(&key).await {
                Ok(b) => b,
                Err(e) => {
                    // A lost object must not strand devices on 226 errors —
                    // requeue and serve the full bundle.
                    tracing::warn!(error = %e, key, "ready patch object missing; requeueing");
                    db::patches::requeue(state.db(), &p.id).await?;
                    return Ok(None);
                }
            };
            metrics::counter!("airlift_patch_served_total", "app" => app.slug.clone()).increment(1);
            let mut resp = (
                StatusCode::IM_USED,
                [
                    ("IM", "bsdiff".to_string()),
                    ("expo-base-update-id", from_update.id.clone()),
                    ("content-type", "application/octet-stream".to_string()),
                    ("cache-control", "private, max-age=0".to_string()),
                ],
                body,
            )
                .into_response();
            if let Some(len) = len.or(p.size) {
                resp.headers_mut()
                    .insert(axum::http::header::CONTENT_LENGTH, len.into());
            }
            Ok(Some(resp))
        }
        Some(_) => Ok(None), // queued / generating / failed / not_beneficial
        None => {
            db::patches::enqueue(state.db(), &from_update.id, &to_id).await?;
            tracing::info!(from = %from_id, to = %to_id, app = %app.slug, "patch enqueued");
            Ok(None)
        }
    }
}

/// Resolve an update id to (update, launch asset), confined to `app` and to
/// normal (non-rollback) groups.
async fn update_with_launch(
    state: &AppState,
    app: &db::apps::App,
    update_id: &str,
) -> Result<Option<(db::updates::Update, db::updates::Asset)>> {
    let Some(update) = db::updates::find_update_in_app(state.db(), &app.id, update_id).await?
    else {
        return Ok(None);
    };
    let Some(launch) = db::updates::launch_asset(state.db(), &update.id).await? else {
        return Ok(None);
    };
    Ok(Some((update, launch)))
}

// ───────────────────────── background worker ─────────────────────────

/// A `generating` lease older than this is presumed dead and requeued. Far
/// above any real bsdiff run on a JS bundle.
const STALE_LEASE_SECS: i64 = 30 * 60;

/// Generation attempts before a pair is marked `failed` for good.
const MAX_ATTEMPTS: i64 = 3;
/// First retry delay; doubles per attempt (60s, 120s).
const RETRY_BASE_SECS: i64 = 60;

/// Poll for queued patch jobs and generate them, one at a time (bsdiff is
/// CPU- and memory-hungry; concurrency 1 keeps a small box healthy).
pub async fn worker_loop(state: AppState) {
    let cfg = state.config().patches.clone();
    if !cfg.enabled {
        return;
    }
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(cfg.poll_secs.max(1)));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        // Reclaim jobs whose worker died mid-generation. Only leases older
        // than STALE_LEASE_SECS: a job another live process is generating
        // right now must not be handed out twice.
        let cutoff = crate::util::rfc3339_in(-STALE_LEASE_SECS);
        match db::patches::requeue_stale(state.db(), &cutoff).await {
            Ok(n) if n > 0 => tracing::info!(requeued = n, "requeued stale patch jobs"),
            Ok(_) => {}
            Err(e) => tracing::warn!(error = %e, "patch requeue failed"),
        }
        loop {
            match generate_next(&state).await {
                Ok(true) => continue, // drained one job; try for more
                Ok(false) => break,
                Err(e) => {
                    tracing::error!(error = %e, "patch generation pass failed");
                    break;
                }
            }
        }
    }
}

/// Claim and process one queued job. Returns whether a job was processed.
async fn generate_next(state: &AppState) -> Result<bool> {
    let Some(job) = db::patches::claim_next(state.db()).await? else {
        return Ok(false);
    };
    match generate_one(state, &job).await {
        Ok(()) => {}
        // Failures are often transient (storage timeouts, a busy DB): retry
        // with exponential backoff, and only give up after MAX_ATTEMPTS.
        Err(e) if job.attempts + 1 < MAX_ATTEMPTS => {
            let backoff = RETRY_BASE_SECS << job.attempts;
            tracing::warn!(error = %e, patch = %job.id, attempt = job.attempts + 1,
                backoff, "patch generation failed; will retry");
            let not_before = crate::util::rfc3339_in(backoff);
            db::patches::retry_later(state.db(), &job, &e.to_string(), &not_before).await?;
        }
        Err(e) => {
            tracing::warn!(error = %e, patch = %job.id, "patch generation failed; giving up");
            db::patches::mark_failed(state.db(), &job, &e.to_string()).await?;
        }
    }
    Ok(true)
}

async fn generate_one(state: &AppState, job: &db::patches::PatchRow) -> Result<()> {
    let db = state.db();
    let from_launch = db::updates::launch_asset(db, &job.from_update_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("from-update lost its bundle"))?;
    let to_launch = db::updates::launch_asset(db, &job.to_update_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("to-update lost its bundle"))?;
    let org_id = from_launch.org_id.clone();

    let storage = state.storage();
    let from_bytes = storage
        .get(&Storage::asset_key(&org_id, &from_launch.sha256))
        .await?;
    let to_bytes = storage
        .get(&Storage::asset_key(&org_id, &to_launch.sha256))
        .await?;

    // Integrity-gate both inputs before diffing: a corrupt base would produce
    // a patch that fails on every device.
    verify_sha(&from_bytes, &from_launch.sha256, "base bundle")?;
    verify_sha(&to_bytes, &to_launch.sha256, "target bundle")?;

    let to_len = to_bytes.len();
    let patch = tokio::task::spawn_blocking(move || -> anyhow::Result<Vec<u8>> {
        let mut out = Vec::new();
        qbsdiff::Bsdiff::new(&from_bytes, &to_bytes).compare(std::io::Cursor::new(&mut out))?;
        Ok(out)
    })
    .await
    .map_err(|e| anyhow::anyhow!("bsdiff task: {e}"))??;

    let max_ratio = state.config().patches.max_size_ratio;
    if (patch.len() as f64) >= (to_len as f64) * max_ratio {
        db::patches::mark_not_beneficial(db, job, patch.len() as i64).await?;
        tracing::info!(patch = %job.id, size = patch.len(), full = to_len,
            "patch not beneficial; devices keep full downloads");
        return Ok(());
    }

    let sha = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(&patch));
    let size = patch.len() as i64;
    let key = Storage::patch_key(&org_id, &from_launch.sha256, &to_launch.sha256);
    storage.put(&key, patch).await?;
    db::patches::mark_ready(db, job, &sha, size).await?;
    tracing::info!(patch = %job.id, size, full = to_len, "patch ready");
    Ok(())
}

fn verify_sha(bytes: &[u8], expect_hex: &str, what: &str) -> Result<()> {
    let got = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(bytes));
    if got != expect_hex {
        return Err(crate::error::Error::Other(anyhow::anyhow!(
            "{what} failed integrity check ({got} != {expect_hex})"
        )));
    }
    Ok(())
}
