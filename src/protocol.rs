//! The Expo Updates protocol surface (spec v0 + v1), served unauthenticated:
//!
//!   GET /u/{app_id}/manifest        — the update check
//!   GET /u/{app_id}/assets/{sha256} — 307 redirect to a presigned storage URL
//!
//! Responses are `multipart/mixed` with a `manifest` part (or, under protocol
//! 1, a `directive` part: `noUpdateAvailable` / `rollBackToEmbedded`) and an
//! `extensions` part. When the client sends `expo-expect-signature`, the
//! manifest/directive part carries an `expo-signature` header: RSA-SHA256
//! (pkcs1v15) over the exact part body, verified against the app's
//! certificate embedded in the binary.

use axum::{
    extract::{Path, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Redirect, Response},
    routing::get,
    Json, Router,
};
use base64::Engine;
use rsa::pkcs1v15::SigningKey;
use rsa::sha2::Sha256 as RsaSha256;
use rsa::signature::{SignatureEncoding, Signer};
use serde_json::json;

use crate::db;
use crate::error::{Error, Result};
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/u/{app_id}/manifest", get(manifest))
        .route("/u/{app_id}/assets/{sha256}", get(asset))
}

/// A protocol request header, also accepted as a query parameter (parity with
/// expo-open-ota; useful for debugging in a browser).
fn param(
    headers: &HeaderMap,
    query: &std::collections::HashMap<String, String>,
    name: &str,
) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .or_else(|| query.get(name).cloned())
        .filter(|s| !s.is_empty())
}

// ───────────────────────── manifest ─────────────────────────

/// Server-defined header carrying the updates this device must never be
/// served again. expo-updates stores `expo-server-defined-headers` and sends
/// them back on every request, so the block outlives the client's own
/// (short, self-pruning) `Expo-Recent-Failed-Update-IDs` list.
const BLOCKED_HEADER: &str = "airlift-blocked-updates";
/// Cap on remembered blocked update ids (newest failures kept).
const MAX_BLOCKED: usize = 20;

/// Parse a list of update ids from a header value: an SFV list of strings
/// (`"id1", "id2"`) or a plain comma/space separated list. Anything that isn't
/// a UUID is dropped; ids are lowercased.
fn parse_update_ids(value: &str) -> Vec<String> {
    value
        .split(|c: char| c == ',' || c.is_whitespace())
        .map(|s| s.trim().trim_matches('"'))
        .filter_map(|s| uuid::Uuid::parse_str(s).ok())
        .map(|u| u.hyphenated().to_string())
        .collect()
}

/// Updates to refuse for this device: what it just reported as failed
/// (first, so they survive the cap) plus what we told it to remember.
fn blocked_updates(
    headers: &HeaderMap,
    query: &std::collections::HashMap<String, String>,
) -> (Vec<String>, Vec<String>) {
    let failed = param(headers, query, "expo-recent-failed-update-ids")
        .map(|v| parse_update_ids(&v))
        .unwrap_or_default();
    let remembered = param(headers, query, BLOCKED_HEADER)
        .map(|v| parse_update_ids(&v))
        .unwrap_or_default();
    let mut blocked: Vec<String> = Vec::new();
    for id in failed.iter().chain(remembered.iter()) {
        if !blocked.contains(id) && blocked.len() < MAX_BLOCKED {
            blocked.push(id.clone());
        }
    }
    (failed, blocked)
}

async fn manifest(
    State(state): State<AppState>,
    Path(app_id): Path<String>,
    headers: HeaderMap,
    Query(query): Query<std::collections::HashMap<String, String>>,
) -> Result<Response> {
    let (failed, blocked) = blocked_updates(&headers, &query);
    let mut resp = manifest_inner(&state, &app_id, &headers, &query, &failed, &blocked).await?;
    // Always (re)state the full blocked set: the client replaces its stored
    // server-defined headers with whatever the latest response carries.
    let value = if blocked.is_empty() {
        String::new()
    } else {
        format!("{BLOCKED_HEADER}=\"{}\"", blocked.join(","))
    };
    if let Ok(v) = axum::http::HeaderValue::from_str(&value) {
        resp.headers_mut().insert(
            header::HeaderName::from_static("expo-server-defined-headers"),
            v,
        );
    }
    Ok(resp)
}

async fn manifest_inner(
    state: &AppState,
    app_id: &str,
    headers: &HeaderMap,
    query: &std::collections::HashMap<String, String>,
    failed: &[String],
    blocked: &[String],
) -> Result<Response> {
    let app = db::apps::find_by_id(state.db(), app_id)
        .await?
        .ok_or(Error::NotFound)?;

    let platform = param(headers, query, "expo-platform")
        .ok_or_else(|| Error::bad_request("missing expo-platform"))?;
    if !matches!(platform.as_str(), "ios" | "android") {
        return Err(Error::bad_request("expo-platform must be ios or android"));
    }
    let runtime_version = param(headers, query, "expo-runtime-version")
        .ok_or_else(|| Error::bad_request("missing expo-runtime-version"))?;
    let channel_name = param(headers, query, "expo-channel-name")
        .ok_or_else(|| Error::bad_request("missing expo-channel-name"))?;
    let protocol: u8 = param(headers, query, "expo-protocol-version")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    if protocol > 1 {
        return Err(Error::bad_request("unsupported expo-protocol-version"));
    }
    let current_update_id =
        param(headers, query, "expo-current-update-id").map(|s| s.to_ascii_lowercase());
    let expect_signature = param(headers, query, "expo-expect-signature").is_some();
    let client_id = param(headers, query, "eas-client-id");
    let embedded_update_id = param(headers, query, "expo-embedded-update-id");

    // Off-hot-path accounting: bump the Prometheus counter and record the
    // device check-in (flushed to SQLite by the background loop).
    let track = |result: &'static str, served_update_id: &str| {
        metrics::counter!(
            "airlift_manifest_requests_total",
            "app" => app.slug.clone(),
            "platform" => platform.clone(),
            "result" => result,
        )
        .increment(1);
        state.usage().record_checkin(
            &app.id,
            client_id.as_deref(),
            &platform,
            &runtime_version,
            &channel_name,
            embedded_update_id.as_deref(),
            current_update_id.as_deref(),
            served_update_id,
            failed,
        );
    };

    let channel = db::updates::find_channel(state.db(), &app.id, &channel_name)
        .await?
        .ok_or_else(|| Error::bad_request("unknown channel"))?;
    // A/B split: a stable share of devices is served from another channel
    // (the experiment branch). One hop only — the target's own split is not
    // followed.
    let channel = match (
        &channel.split_channel_id,
        channel.split_percent,
        &channel.split_salt,
    ) {
        (Some(target), Some(pct), Some(salt))
            if crate::rollout::included(client_id.as_deref(), salt, pct) =>
        {
            db::updates::find_channel_by_id(state.db(), target)
                .await?
                .unwrap_or(channel)
        }
        _ => channel,
    };

    // The release pointer is the source of truth, whether or not the channel
    // tracks a branch (a branchless channel is served purely by promote).
    // During a progressive rollout only devices bucketed inside get the new
    // group; everyone else (incl. devices without a client id) keeps the last
    // full release.
    let (group, in_rollout) =
        resolve_release(state, &channel.id, &runtime_version, client_id.as_deref()).await?;

    let Some(group) = group else {
        track("no_update", "");
        return no_update_response(state, &app, protocol, expect_signature).await;
    };

    // A rollback group emits the protocol-1 directive; protocol-0 clients
    // can't process directives, so they get "no update" semantics.
    if group.group_type == "rollback_to_embedded" {
        track("rollback", "");
        if protocol == 1 {
            let directive = json!({
                "type": "rollBackToEmbedded",
                "parameters": { "commitTime": crate::util::normalize_rfc3339(&group.created_at) },
            });
            return multipart_response(
                state,
                &app,
                protocol,
                "directive",
                &directive,
                expect_signature,
            )
            .await;
        }
        return Ok(no_update_v0());
    }

    let updates = db::updates::updates_in_group(state.db(), &group.id).await?;
    let Some(update) = updates.into_iter().find(|u| u.platform == platform) else {
        track("no_update", "");
        return no_update_response(state, &app, protocol, expect_signature).await;
    };

    // Never re-serve an update this device crashed on (or was told to
    // remember as crashed): it stays on whatever it runs now.
    if blocked.contains(&update.id.to_ascii_lowercase()) {
        track("blocked", "");
        return no_update_response(state, &app, protocol, expect_signature).await;
    }

    // The client is already running exactly this update. Attribute the
    // check-in to that update so adoption stats count settled devices.
    if current_update_id.as_deref() == Some(&update.id.to_ascii_lowercase()) {
        track("up_to_date", &update.id);
        return no_update_response(state, &app, protocol, expect_signature).await;
    }
    track("manifest", &update.id);

    // ── build the manifest ──
    let base = crate::auth::base_url(state, headers);
    let launch = db::updates::launch_asset(state.db(), &update.id)
        .await?
        .ok_or_else(|| Error::Other(anyhow::anyhow!("update {} lost its bundle", update.id)))?;
    let assets = db::updates::assets_for_update(state.db(), &update.id).await?;

    let asset_url = |sha256: &str| format!("{base}/u/{}/assets/{}", app.id, sha256);
    let assets_json: Vec<_> = assets
        .iter()
        .map(|a| {
            json!({
                "hash": hex_to_b64url(&a.sha256),
                "key": a.key,
                "fileExtension": a.file_extension.as_deref().map(|e| format!(".{}", e.trim_start_matches('.'))),
                "contentType": a.content_type,
                "url": asset_url(&a.sha256),
            })
        })
        .collect();

    let extra_expo_client: serde_json::Value = group
        .expo_config_json
        .as_deref()
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or(serde_json::Value::Null);

    let manifest = json!({
        "id": update.id,
        "createdAt": crate::util::normalize_rfc3339(&group.created_at),
        "runtimeVersion": group.runtime_version,
        "launchAsset": {
            "hash": hex_to_b64url(&launch.sha256),
            // expo-updates uses the key as the asset's unique id and skips the
            // download when it already holds that key, so it must change with
            // the content (the reference server uses the bundle's md5).
            "key": format!("bundle-{}", launch.sha256),
            "fileExtension": ".bundle",
            "contentType": launch.content_type,
            "url": asset_url(&launch.sha256),
        },
        "assets": assets_json,
        "metadata": {},
        "extra": { "expoClient": extra_expo_client },
    });

    // Rollout manifests pin EAS-Client-ID on every asset download, so the
    // asset endpoint can re-check rollout membership even if the client
    // wouldn't otherwise send the header there.
    let mut asset_headers = serde_json::Map::new();
    if let (true, Some(cid)) = (in_rollout, client_id.as_deref()) {
        let pin = json!({ "EAS-Client-ID": cid });
        asset_headers.insert(format!("bundle-{}", launch.sha256), pin.clone());
        for a in &assets {
            asset_headers.insert(a.key.clone(), pin.clone());
        }
    }

    multipart_response_with(
        state,
        &app,
        protocol,
        "manifest",
        &manifest,
        expect_signature,
        asset_headers,
    )
    .await
}

/// The group this device should get on a channel/runtime, and whether it got
/// it as part of a running rollout.
async fn resolve_release(
    state: &AppState,
    channel_id: &str,
    runtime_version: &str,
    client_id: Option<&str>,
) -> Result<(Option<db::updates::UpdateGroup>, bool)> {
    let Some(r) = db::updates::release(state.db(), channel_id, runtime_version).await? else {
        return Ok((None, false));
    };
    let (group_id, in_rollout) = match (r.rollout_percent, r.rollout_salt.as_deref()) {
        (Some(p), Some(salt)) if crate::rollout::included(client_id, salt, p) => {
            (Some(r.group_id), true)
        }
        (Some(_), _) => (r.previous_group_id, false),
        (None, _) => (Some(r.group_id), false),
    };
    let group = match group_id {
        Some(id) => db::updates::find_group(state.db(), &id).await?,
        None => None,
    };
    Ok((group, in_rollout))
}

/// Protocol 1 answers "you're current" with a directive; protocol 0 has no
/// directives, so it gets a 404-style JSON (matching the original expo
/// updates server's behavior).
async fn no_update_response(
    state: &AppState,
    app: &db::apps::App,
    protocol: u8,
    expect_signature: bool,
) -> Result<Response> {
    if protocol == 1 {
        let directive = json!({ "type": "noUpdateAvailable" });
        return multipart_response(
            state,
            app,
            protocol,
            "directive",
            &directive,
            expect_signature,
        )
        .await;
    }
    Ok(no_update_v0())
}

fn no_update_v0() -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(json!({ "error": { "code": "no_update", "message": "no update available" } })),
    )
        .into_response()
}

/// Assemble the `multipart/mixed` protocol response with one JSON part
/// (`manifest` or `directive`) plus the `extensions` part.
async fn multipart_response(
    state: &AppState,
    app: &db::apps::App,
    protocol: u8,
    part_name: &str,
    part_json: &serde_json::Value,
    expect_signature: bool,
) -> Result<Response> {
    multipart_response_with(
        state,
        app,
        protocol,
        part_name,
        part_json,
        expect_signature,
        serde_json::Map::new(),
    )
    .await
}

/// [`multipart_response`] with per-asset request headers in the extensions
/// part (`assetRequestHeaders`: asset key → headers the client must send
/// when downloading that asset).
async fn multipart_response_with(
    state: &AppState,
    app: &db::apps::App,
    protocol: u8,
    part_name: &str,
    part_json: &serde_json::Value,
    expect_signature: bool,
    asset_request_headers: serde_json::Map<String, serde_json::Value>,
) -> Result<Response> {
    let _ = state;
    let body_json = serde_json::to_string(part_json)
        .map_err(|e| Error::Other(anyhow::anyhow!("manifest serialize: {e}")))?;

    let signature = if expect_signature {
        Some(sign_for_app(app, body_json.as_bytes().to_vec()).await?)
    } else {
        None
    };

    let boundary = format!("airlift-{}", uuid::Uuid::new_v4());
    let mut body = String::new();
    body.push_str(&format!("--{boundary}\r\n"));
    body.push_str(&format!(
        "Content-Disposition: form-data; name=\"{part_name}\"\r\n"
    ));
    body.push_str("Content-Type: application/json\r\n");
    if let Some(sig) = &signature {
        body.push_str(&format!(
            "expo-signature: sig=\"{sig}\", keyid=\"main\"\r\n"
        ));
    }
    body.push_str("\r\n");
    body.push_str(&body_json);
    body.push_str("\r\n");

    // Extensions part: asset request headers. Normally empty (assets are
    // public presigned redirects); a rollout manifest pins EAS-Client-ID on
    // every asset so the asset endpoint can apply the same rollout check.
    let extensions = json!({ "assetRequestHeaders": asset_request_headers }).to_string();
    body.push_str(&format!("--{boundary}\r\n"));
    body.push_str("Content-Disposition: form-data; name=\"extensions\"\r\n");
    body.push_str("Content-Type: application/json\r\n\r\n");
    body.push_str(&extensions);
    body.push_str("\r\n");
    body.push_str(&format!("--{boundary}--\r\n"));

    Ok((
        StatusCode::OK,
        [
            (
                header::CONTENT_TYPE,
                format!("multipart/mixed; boundary={boundary}"),
            ),
            (header::CACHE_CONTROL, "private, max-age=0".to_string()),
            (
                header::HeaderName::from_static("expo-protocol-version"),
                protocol.to_string(),
            ),
            (
                header::HeaderName::from_static("expo-sfv-version"),
                "0".to_string(),
            ),
            (
                header::HeaderName::from_static("expo-manifest-filters"),
                String::new(),
            ),
            (
                header::HeaderName::from_static("expo-server-defined-headers"),
                String::new(),
            ),
        ],
        body,
    )
        .into_response())
}

/// RSA-SHA256 (pkcs1v15) signature over `bytes`, base64 (standard) encoded —
/// the `alg: "rsa-v1_5-sha256"` scheme expo-updates expects.
#[cfg(test)]
fn sign_rsa_sha256(private_key_pem: &str, bytes: &[u8]) -> Result<String> {
    let key = crate::keys::private_key_from_pem(private_key_pem)?;
    Ok(sign_with(&SigningKey::<RsaSha256>::new(key), bytes))
}

fn sign_with(key: &SigningKey<RsaSha256>, bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(key.sign(bytes).to_bytes())
}

/// Parsed signing keys per app, keyed by app id and checked against the PEM
/// (so a rotated key is picked up). Parsing a PKCS#8 RSA key on every
/// manifest request was pure waste on the hot path.
#[allow(clippy::type_complexity)]
static SIGNERS: std::sync::LazyLock<
    dashmap::DashMap<String, (String, std::sync::Arc<SigningKey<RsaSha256>>)>,
> = std::sync::LazyLock::new(dashmap::DashMap::new);

/// Sign `bytes` with the app's key. RSA signing is CPU work, so it (and any
/// key parse) runs on the blocking pool, not an async worker.
async fn sign_for_app(app: &db::apps::App, bytes: Vec<u8>) -> Result<String> {
    let cached = SIGNERS
        .get(&app.id)
        .filter(|e| e.0 == app.private_key_pem)
        .map(|e| e.1.clone());
    let pem = app.private_key_pem.clone();
    let (key, sig) = tokio::task::spawn_blocking(move || -> Result<_> {
        let key = match cached {
            Some(k) => k,
            None => std::sync::Arc::new(SigningKey::<RsaSha256>::new(
                crate::keys::private_key_from_pem(&pem)?,
            )),
        };
        let sig = sign_with(&key, &bytes);
        Ok((key, sig))
    })
    .await
    .map_err(|e| Error::Other(anyhow::anyhow!("signing task: {e}")))??;
    SIGNERS.insert(app.id.clone(), (app.private_key_pem.clone(), key));
    Ok(sig)
}

/// Convert a stored hex sha256 into the base64url (no padding) form the
/// protocol uses for asset hashes.
fn hex_to_b64url(hex_digest: &str) -> String {
    let bytes = hex::decode(hex_digest).unwrap_or_default();
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

// ───────────────────────── assets ─────────────────────────

async fn asset(
    State(state): State<AppState>,
    Path((app_id, sha256)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response> {
    let sha256 = sha256.to_ascii_lowercase();
    if sha256.len() != 64 || !sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(Error::bad_request("invalid asset digest"));
    }
    let app = db::apps::find_by_id(state.db(), &app_id)
        .await?
        .ok_or(Error::NotFound)?;
    // Strict per-app confinement: this endpoint is public, so an asset is only
    // served if one of THIS app's updates references it — org-level dedup must
    // not become a cross-app oracle.
    // Same rollout check as the manifest: an asset only reachable through a
    // running rollout is served only to devices bucketed inside it.
    let access = db::updates::asset_access(state.db(), &app.id, &sha256).await?;
    if !access.in_app {
        return Err(Error::NotFound);
    }
    if !access.open {
        let client_id = headers.get("eas-client-id").and_then(|v| v.to_str().ok());
        if !access
            .rollouts
            .iter()
            .any(|(salt, pct)| crate::rollout::included(client_id, salt, *pct))
        {
            return Err(Error::NotFound);
        }
    }
    // SDK 55+ clients may ask for a bsdiff patch of the launch bundle
    // (A-IM: bsdiff). When one is ready this answers 226 with the patch;
    // otherwise (or on any mismatch) we fall through to the full bundle —
    // the client verifies hashes and falls back on its own, so the full
    // download is always the safe default.
    if let Some(resp) = crate::patches::maybe_serve_patch(&state, &app, &sha256, &headers).await? {
        return Ok(resp);
    }
    let key = crate::storage::Storage::asset_key(&app.org_id, &sha256);
    let url = state.storage().presign_get(&key).await?;
    metrics::counter!("airlift_asset_redirects_total", "app" => app.slug.clone()).increment(1);
    Ok(Redirect::temporary(&url).into_response())
}

#[cfg(test)]
mod tests {
    use base64::Engine;
    use rsa::pkcs1v15::VerifyingKey;
    use rsa::sha2::Sha256;
    use rsa::signature::Verifier;
    use rsa::RsaPublicKey;

    /// The signature produced by `sign_rsa_sha256` must verify against the
    /// public key extracted from the app's certificate — exactly what
    /// expo-updates does on device.
    #[test]
    fn signature_roundtrip() {
        let id = crate::keys::generate("sig test").expect("generate");
        let sig_b64 = super::sign_rsa_sha256(&id.private_key_pem, b"hello manifest").unwrap();
        let sig_bytes = base64::engine::general_purpose::STANDARD
            .decode(sig_b64)
            .unwrap();

        let key = crate::keys::private_key_from_pem(&id.private_key_pem).unwrap();
        let public = RsaPublicKey::from(&key);
        let verifying: VerifyingKey<Sha256> = VerifyingKey::new(public);
        let signature = rsa::pkcs1v15::Signature::try_from(sig_bytes.as_slice()).unwrap();
        verifying.verify(b"hello manifest", &signature).unwrap();
    }
}
