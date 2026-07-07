//! The publish endpoint: accepts a zipped `expo export` archive, stores its
//! files content-addressed in object storage, records the update group, and
//! advances auto-release channels.
//!
//! `POST /api/v1/apps/{app_id}/updates` — multipart form:
//!   branch            target branch name (auto-created)
//!   runtime_version   expo runtime version this update targets
//!   message           optional release message
//!   git_branch / git_commit   optional VCS info
//!   expo_config       optional JSON: resolved Expo config (manifest `extra.expoClient`)
//!   archive           the zipped export directory (must contain metadata.json)

use std::collections::BTreeMap;
use std::io::Read;

use axum::{
    extract::{Multipart, Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::auth::{rbac, ApiUser};
use crate::db;
use crate::error::{Error, Result};
use crate::models::Permission;
use crate::state::AppState;

/// `metadata.json` inside an `expo export` output directory.
#[derive(Deserialize)]
struct ExportMetadata {
    #[allow(dead_code)]
    version: Option<i64>,
    #[serde(rename = "fileMetadata")]
    file_metadata: BTreeMap<String, PlatformMetadata>,
}

#[derive(Deserialize, Clone)]
struct PlatformMetadata {
    bundle: String,
    #[serde(default)]
    assets: Vec<AssetEntry>,
}

#[derive(Deserialize, Clone)]
struct AssetEntry {
    path: String,
    ext: String,
}

pub async fn publish(
    State(state): State<AppState>,
    caller: ApiUser,
    Path(app_id): Path<String>,
    mut multipart: Multipart,
) -> Result<Response> {
    let app = db::apps::find_by_id(state.db(), &app_id)
        .await?
        .ok_or(Error::NotFound)?;
    rbac::require(state.db(), &caller, &app, Permission::Publish).await?;

    // ── collect form fields ──
    let mut branch_name = None;
    let mut runtime_version = None;
    let mut message = None;
    let mut git_branch = None;
    let mut git_commit = None;
    let mut expo_config = None;
    let mut archive: Option<Vec<u8>> = None;

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| Error::bad_request(format!("malformed multipart body: {e}")))?
    {
        let name = field.name().unwrap_or_default().to_string();
        match name.as_str() {
            "branch" => branch_name = Some(text(field).await?),
            "runtime_version" => runtime_version = Some(text(field).await?),
            "message" => message = Some(text(field).await?),
            "git_branch" => git_branch = Some(text(field).await?),
            "git_commit" => git_commit = Some(text(field).await?),
            "expo_config" => expo_config = Some(text(field).await?),
            "archive" => {
                archive = Some(
                    field
                        .bytes()
                        .await
                        .map_err(|e| Error::bad_request(format!("archive read: {e}")))?
                        .to_vec(),
                )
            }
            _ => {}
        }
    }

    let branch_name = required(branch_name, "branch")?;
    let runtime_version = required(runtime_version, "runtime_version")?;
    let archive = archive.ok_or_else(|| Error::bad_request("missing archive file field"))?;
    if let Some(cfg) = &expo_config {
        serde_json::from_str::<serde_json::Value>(cfg)
            .map_err(|_| Error::bad_request("expo_config is not valid JSON"))?;
    }

    // ── parse the export archive ──
    let mut zip = zip::ZipArchive::new(std::io::Cursor::new(archive))
        .map_err(|e| Error::bad_request(format!("archive is not a valid zip: {e}")))?;
    let metadata: ExportMetadata = {
        let mut f = zip
            .by_name("metadata.json")
            .map_err(|_| Error::bad_request("archive is missing metadata.json"))?;
        let mut s = String::new();
        f.read_to_string(&mut s)
            .map_err(|e| Error::bad_request(format!("metadata.json: {e}")))?;
        serde_json::from_str(&s).map_err(|e| Error::bad_request(format!("metadata.json: {e}")))?
    };
    if metadata.file_metadata.is_empty() {
        return Err(Error::bad_request("export contains no platforms"));
    }
    for platform in metadata.file_metadata.keys() {
        if !matches!(platform.as_str(), "ios" | "android") {
            return Err(Error::bad_request(format!("unknown platform {platform}")));
        }
    }

    // Stage every file (launch bundles + assets): hash, upload if new, and
    // remember the rows to create. BTreeMap iteration keeps the content hash
    // deterministic.
    struct Staged {
        launch: db::updates::Asset,
        assets: Vec<(db::updates::Asset, String, Option<String>, String)>, // (asset, key, ext, content_type)
        metadata_json: String,
    }
    let mut staged: BTreeMap<String, Staged> = BTreeMap::new();
    let mut content_hasher = Sha256::new();

    for (platform, pm) in &metadata.file_metadata {
        let bundle_bytes = read_zip_file(&mut zip, &pm.bundle)?;
        let launch =
            store_asset(&state, &app.org_id, bundle_bytes, "application/javascript").await?;
        content_hasher.update(platform.as_bytes());
        content_hasher.update(launch.sha256.as_bytes());

        let mut assets = Vec::with_capacity(pm.assets.len());
        for entry in &pm.assets {
            let bytes = read_zip_file(&mut zip, &entry.path)?;
            let content_type = mime_guess::from_ext(&entry.ext)
                .first_or_octet_stream()
                .to_string();
            let asset = store_asset(&state, &app.org_id, bytes, &content_type).await?;
            content_hasher.update(asset.sha256.as_bytes());
            // The manifest asset key is the export filename (an md5 hash).
            let key = entry
                .path
                .rsplit('/')
                .next()
                .unwrap_or(&entry.path)
                .to_string();
            assets.push((asset, key, Some(entry.ext.clone()), content_type));
        }
        staged.insert(
            platform.clone(),
            Staged {
                launch,
                assets,
                metadata_json: serde_json::to_string(&json!({
                    "bundle": pm.bundle,
                    "assetCount": pm.assets.len(),
                }))
                .unwrap_or_default(),
            },
        );
    }
    let content_hash = hex::encode(content_hasher.finalize());

    // ── create the group (refusing a byte-identical republish of the head) ──
    let branch = db::updates::ensure_branch(state.db(), &app.id, &branch_name).await?;
    if let Some(head) = db::updates::head_group(state.db(), &branch.id, &runtime_version).await? {
        if head.content_hash == content_hash {
            return Err(Error::conflict(
                "this exact update is already the head of the branch",
            ));
        }
    }

    let group = db::updates::create_group(
        state.db(),
        &branch.id,
        &runtime_version,
        message.as_deref(),
        git_branch.as_deref(),
        git_commit.as_deref(),
        "normal",
        expo_config.as_deref(),
        &content_hash,
    )
    .await?;

    let mut platforms = Vec::new();
    for (platform, s) in &staged {
        let update = db::updates::create_update(
            state.db(),
            &group.id,
            platform,
            &s.launch.id,
            &s.metadata_json,
        )
        .await?;
        for (asset, key, ext, content_type) in &s.assets {
            db::updates::add_update_asset(
                state.db(),
                &update.id,
                &asset.id,
                key,
                ext.as_deref(),
                content_type,
            )
            .await?;
        }
        platforms.push(platform.clone());
    }

    let released = advance_channels(&state, &app, &branch, &group).await?;

    db::audit::record(
        state.db(),
        Some(&caller.user.id),
        Some(&app.org_id),
        "update.publish",
        Some(&format!("{}/{}", app.slug, branch.name)),
        Some(&group.id),
    )
    .await
    .ok();

    Ok((
        StatusCode::CREATED,
        Json(json!({
            "group_id": group.id,
            "branch": branch.name,
            "runtime_version": runtime_version,
            "platforms": platforms,
            "channels": released,
        })),
    )
        .into_response())
}

/// Advance the release pointer of every auto-release channel pointing at
/// `branch`; gated channels are reported as pending. If no channel points at
/// the branch yet, create a same-named auto-release channel (EAS-like default
/// so a fresh `publish --branch production` is immediately servable on the
/// `production` channel).
pub(crate) async fn advance_channels(
    state: &AppState,
    app: &db::apps::App,
    branch: &db::updates::Branch,
    group: &db::updates::UpdateGroup,
) -> Result<Vec<serde_json::Value>> {
    let mut channels = db::updates::channels_for_branch(state.db(), &branch.id).await?;
    if channels.is_empty()
        && db::updates::find_channel(state.db(), &app.id, &branch.name)
            .await?
            .is_none()
    {
        let ch =
            db::updates::create_channel(state.db(), &app.id, &branch.name, Some(&branch.id), true)
                .await?;
        channels.push(ch);
    }

    let mut released = Vec::new();
    for ch in channels {
        if ch.auto_release {
            db::updates::set_channel_release(state.db(), &ch.id, &group.runtime_version, &group.id)
                .await?;
            released.push(json!({ "channel": ch.name, "status": "released" }));
        } else {
            released.push(json!({ "channel": ch.name, "status": "pending" }));
        }
    }
    Ok(released)
}

async fn text(field: axum::extract::multipart::Field<'_>) -> Result<String> {
    field
        .text()
        .await
        .map_err(|e| Error::bad_request(format!("malformed field: {e}")))
}

fn required(v: Option<String>, name: &str) -> Result<String> {
    v.map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| Error::bad_request(format!("missing required field {name}")))
}

fn read_zip_file(
    zip: &mut zip::ZipArchive<std::io::Cursor<Vec<u8>>>,
    path: &str,
) -> Result<Vec<u8>> {
    let mut f = zip.by_name(path).map_err(|_| {
        Error::bad_request(format!(
            "archive is missing {path} (listed in metadata.json)"
        ))
    })?;
    let mut buf = Vec::with_capacity(f.size() as usize);
    f.read_to_end(&mut buf)
        .map_err(|e| Error::bad_request(format!("reading {path}: {e}")))?;
    Ok(buf)
}

/// Hash a file, upload it to object storage if the org doesn't have it yet,
/// and return its asset row.
async fn store_asset(
    state: &AppState,
    org_id: &str,
    bytes: Vec<u8>,
    content_type: &str,
) -> Result<db::updates::Asset> {
    let sha256 = hex::encode(Sha256::digest(&bytes));
    if let Some(existing) = db::updates::find_asset(state.db(), org_id, &sha256).await? {
        return Ok(existing);
    }
    let key = crate::storage::Storage::asset_key(org_id, &sha256);
    let size = bytes.len() as i64;
    state.storage().put(&key, bytes).await?;
    db::updates::ensure_asset(state.db(), org_id, &sha256, size, content_type).await
}
