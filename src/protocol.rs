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

async fn manifest(
    State(state): State<AppState>,
    Path(app_id): Path<String>,
    headers: HeaderMap,
    Query(query): Query<std::collections::HashMap<String, String>>,
) -> Result<Response> {
    let app = db::apps::find_by_id(state.db(), &app_id)
        .await?
        .ok_or(Error::NotFound)?;

    let platform = param(&headers, &query, "expo-platform")
        .ok_or_else(|| Error::bad_request("missing expo-platform"))?;
    if !matches!(platform.as_str(), "ios" | "android") {
        return Err(Error::bad_request("expo-platform must be ios or android"));
    }
    let runtime_version = param(&headers, &query, "expo-runtime-version")
        .ok_or_else(|| Error::bad_request("missing expo-runtime-version"))?;
    let channel_name = param(&headers, &query, "expo-channel-name")
        .ok_or_else(|| Error::bad_request("missing expo-channel-name"))?;
    let protocol: u8 = param(&headers, &query, "expo-protocol-version")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    if protocol > 1 {
        return Err(Error::bad_request("unsupported expo-protocol-version"));
    }
    let current_update_id =
        param(&headers, &query, "expo-current-update-id").map(|s| s.to_ascii_lowercase());
    let expect_signature = param(&headers, &query, "expo-expect-signature").is_some();
    let client_id = param(&headers, &query, "eas-client-id");
    let embedded_update_id = param(&headers, &query, "expo-embedded-update-id");

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
        );
    };

    let channel = db::updates::find_channel(state.db(), &app.id, &channel_name)
        .await?
        .ok_or_else(|| Error::bad_request("unknown channel"))?;

    let group = match &channel.branch_id {
        Some(_) => db::updates::channel_release(state.db(), &channel.id, &runtime_version).await?,
        None => None,
    };

    let Some(group) = group else {
        track("no_update", "");
        return no_update_response(&state, &app, protocol, expect_signature);
    };

    // A rollback group emits the protocol-1 directive; protocol-0 clients
    // can't process directives, so they get "no update" semantics.
    if group.group_type == "rollback_to_embedded" {
        track("rollback", "");
        if protocol == 1 {
            let directive = json!({
                "type": "rollBackToEmbedded",
                "parameters": { "commitTime": group.created_at },
            });
            return multipart_response(
                &state,
                &app,
                protocol,
                "directive",
                &directive,
                expect_signature,
            );
        }
        return Ok(no_update_v0());
    }

    let updates = db::updates::updates_in_group(state.db(), &group.id).await?;
    let Some(update) = updates.into_iter().find(|u| u.platform == platform) else {
        track("no_update", "");
        return no_update_response(&state, &app, protocol, expect_signature);
    };

    // The client is already running exactly this update. Attribute the
    // check-in to that update so adoption stats count settled devices.
    if current_update_id.as_deref() == Some(&update.id.to_ascii_lowercase()) {
        track("up_to_date", &update.id);
        return no_update_response(&state, &app, protocol, expect_signature);
    }
    track("manifest", &update.id);

    // ── build the manifest ──
    let base = crate::auth::base_url(&state, &headers);
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
        "createdAt": group.created_at,
        "runtimeVersion": group.runtime_version,
        "launchAsset": {
            "hash": hex_to_b64url(&launch.sha256),
            "key": "bundle",
            "contentType": launch.content_type,
            "url": asset_url(&launch.sha256),
        },
        "assets": assets_json,
        "metadata": {},
        "extra": { "expoClient": extra_expo_client },
    });

    multipart_response(
        &state,
        &app,
        protocol,
        "manifest",
        &manifest,
        expect_signature,
    )
}

/// Protocol 1 answers "you're current" with a directive; protocol 0 has no
/// directives, so it gets a 404-style JSON (matching the original expo
/// updates server's behavior).
fn no_update_response(
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
        );
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
fn multipart_response(
    state: &AppState,
    app: &db::apps::App,
    protocol: u8,
    part_name: &str,
    part_json: &serde_json::Value,
    expect_signature: bool,
) -> Result<Response> {
    let _ = state;
    let body_json = serde_json::to_string(part_json)
        .map_err(|e| Error::Other(anyhow::anyhow!("manifest serialize: {e}")))?;

    let signature = if expect_signature {
        Some(sign_rsa_sha256(&app.private_key_pem, body_json.as_bytes())?)
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

    // Extensions part: reserved for asset request headers (e.g. auth for a
    // private CDN). Ours are public presigned redirects, so it's empty.
    let extensions = json!({ "assetRequestHeaders": {} }).to_string();
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
fn sign_rsa_sha256(private_key_pem: &str, bytes: &[u8]) -> Result<String> {
    let key = crate::keys::private_key_from_pem(private_key_pem)?;
    let signing_key = SigningKey::<RsaSha256>::new(key);
    let signature = signing_key.sign(bytes);
    Ok(base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()))
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
    if !db::updates::asset_in_app(state.db(), &app.id, &sha256).await? {
        return Err(Error::NotFound);
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
