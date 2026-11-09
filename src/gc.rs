//! Garbage collection: delete assets no longer referenced by any update.
//!
//! Updates record their files in `update_assets` (plus the launch bundle via
//! `updates.launch_asset_id`), so an asset is collectable once nothing points
//! at it. A grace window protects assets uploaded by an in-flight publish
//! whose update rows aren't committed yet (publish refreshes `created_at` on
//! reuse). Deletion removes the row (re-checking it's still unreferenced) and
//! then the object.

use crate::db;
use crate::state::AppState;
use crate::storage::Storage;

/// Run one GC sweep, returning the number of assets collected.
pub async fn run(state: &AppState) -> anyhow::Result<usize> {
    let cutoff = crate::util::rfc3339_in(-state.config().gc.grace_secs);
    let orphans = db::updates::unreferenced_assets(state.db(), &cutoff).await?;
    let mut collected = 0;
    tracing::debug!(count = orphans.len(), "gc: unreferenced assets found");
    for (id, org_id, sha256) in orphans {
        // Row first, conditionally: a publish may have reused this asset since
        // the listing. Only once the row is gone (so no new reference can
        // attach and dedup won't hand it out) is the object deleted. A failed
        // object delete just leaks bytes; a re-publish re-uploads the key.
        if !db::updates::delete_asset_if_unreferenced(state.db(), &id, &cutoff).await? {
            tracing::debug!(%org_id, %sha256, "gc: asset reused meanwhile; kept");
            continue;
        }
        let key = Storage::asset_key(&org_id, &sha256);
        tracing::debug!(%org_id, %sha256, "gc: collecting asset");
        if let Err(e) = state.storage().delete(&key).await {
            tracing::warn!(error = %e, key, "gc: failed to delete object (row already removed)");
        }
        collected += 1;
    }
    if collected > 0 {
        tracing::info!(collected, "gc sweep complete");
    }
    Ok(collected)
}

/// Background GC loop, runs every `interval_secs` (0 disables it).
pub async fn background(state: AppState, interval_secs: u64) {
    if interval_secs == 0 {
        return;
    }
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
    loop {
        tick.tick().await;
        if let Err(e) = run(&state).await {
            tracing::error!(error = %e, "background gc failed");
        }
    }
}
