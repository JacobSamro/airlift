//! End-to-end tests: boot the real binary against an in-process S3 stub and
//! drive it over HTTP exactly like the publish CLI + an expo-updates client.

mod common;

use base64::Engine;
use common::{export_zip, parse_multipart, sha256_hex, spawn_s3_stub, Airlift};
use rsa::pkcs1v15::{Signature, VerifyingKey};
use rsa::sha2::Sha256 as RsaSha256;
use rsa::signature::Verifier;
use rsa::RsaPublicKey;
use serde_json::{json, Value};

/// A logged-in dashboard client plus a publish PAT and one created app.
struct Ctx {
    http: reqwest::Client,
    base: String,
    pat: String,
    app_id: String,
}

async fn setup_instance(server: &Airlift) -> Ctx {
    let http = reqwest::Client::builder()
        .cookie_store(true)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let base = server.base.clone();

    // First-run setup: super-admin + org.
    let resp = http
        .post(format!("{base}/api/v1/setup"))
        .json(&json!({
            "email": "admin@example.com", "username": "admin",
            "password": "password123", "org_slug": "acme", "org_name": "Acme",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "setup failed: {}",
        resp.text().await.unwrap()
    );

    // Create an app (generates the RSA signing identity).
    let resp = http
        .post(format!("{base}/api/v1/orgs/acme/apps"))
        .json(&json!({ "slug": "mobile", "name": "Acme Mobile" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201, "{}", resp.text().await.unwrap());
    let app: Value = resp.json().await.unwrap();
    let app_id = app["app"]["id"].as_str().unwrap().to_string();

    // A publish-capped PAT, as the CLI would use.
    let resp = http
        .post(format!("{base}/api/v1/tokens"))
        .json(&json!({ "name": "ci", "org": "acme", "permission": "publish" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let tok: Value = resp.json().await.unwrap();
    let pat = tok["token"].as_str().unwrap().to_string();

    Ctx {
        http,
        base,
        pat,
        app_id,
    }
}

/// Publish an export zip to a branch with the PAT; returns the response JSON.
async fn publish(ctx: &Ctx, branch: &str, runtime: &str, zip: Vec<u8>) -> (u16, Value) {
    let config = json!({ "name": "Acme Mobile", "slug": "mobile" });
    publish_with_config(ctx, branch, runtime, zip, config).await
}

async fn publish_with_config(
    ctx: &Ctx,
    branch: &str,
    runtime: &str,
    zip: Vec<u8>,
    config: Value,
) -> (u16, Value) {
    let form = reqwest::multipart::Form::new()
        .text("branch", branch.to_string())
        .text("runtime_version", runtime.to_string())
        .text("message", "test release")
        .text("git_branch", "main")
        .text("git_commit", "abc1234")
        .text("expo_config", config.to_string())
        .part(
            "archive",
            reqwest::multipart::Part::bytes(zip).file_name("dist.zip"),
        );
    let resp = ctx
        .http
        .post(format!("{}/api/v1/apps/{}/updates", ctx.base, ctx.app_id))
        .bearer_auth(&ctx.pat)
        .multipart(form)
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    let body: Value = resp.json().await.unwrap_or(Value::Null);
    (status, body)
}

/// Request the manifest like an expo-updates client.
async fn manifest_request(
    ctx: &Ctx,
    channel: &str,
    runtime: &str,
    platform: &str,
    protocol: &str,
    current_update_id: Option<&str>,
) -> reqwest::Response {
    let mut extra = vec![("EAS-Client-ID", "test-device-1")];
    if let Some(id) = current_update_id {
        extra.push(("expo-current-update-id", id));
    }
    manifest_request_with(ctx, channel, runtime, platform, protocol, &extra).await
}

/// A protocol request with arbitrary extra headers (client id, failed ids…).
async fn manifest_request_with(
    ctx: &Ctx,
    channel: &str,
    runtime: &str,
    platform: &str,
    protocol: &str,
    extra: &[(&str, &str)],
) -> reqwest::Response {
    let mut req = ctx
        .http
        .get(format!("{}/u/{}/manifest", ctx.base, ctx.app_id))
        .header("expo-platform", platform)
        .header("expo-runtime-version", runtime)
        .header("expo-channel-name", channel)
        .header("expo-protocol-version", protocol)
        .header(
            "expo-expect-signature",
            "sig, keyid=\"main\", alg=\"rsa-v1_5-sha256\"",
        );
    for (k, v) in extra {
        req = req.header(*k, *v);
    }
    req.send().await.unwrap()
}

/// Extract and parse the named part; verify its expo-signature against the
/// app's certificate (exactly what expo-updates does on device).
async fn verified_part(ctx: &Ctx, resp: reqwest::Response, part: &str) -> Value {
    assert_eq!(resp.status(), 200);
    let ct = resp
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(ct.starts_with("multipart/mixed"), "content-type: {ct}");
    assert_eq!(resp.headers().get("expo-sfv-version").unwrap(), "0");
    let body = resp.text().await.unwrap();
    let parts = parse_multipart(&ct, &body);
    let (headers, content) = parts.get(part).unwrap_or_else(|| {
        panic!(
            "no {part} part; parts: {:?}",
            parts.keys().collect::<Vec<_>>()
        )
    });

    // Signature verification against the served certificate.
    let sig_b64 = headers
        .lines()
        .find(|l| l.to_ascii_lowercase().starts_with("expo-signature:"))
        .and_then(|l| l.split("sig=\"").nth(1))
        .and_then(|s| s.split('"').next())
        .expect("expo-signature header on the signed part");
    let cert_pem = ctx
        .http
        .get(format!(
            "{}/api/v1/orgs/acme/apps/mobile/certificate",
            ctx.base
        ))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let (_, cert) = x509_parser::pem::parse_x509_pem(cert_pem.as_bytes()).unwrap();
    let cert = cert.parse_x509().unwrap();
    let spki = cert.public_key().raw;
    use rsa::pkcs8::DecodePublicKey;
    let public = RsaPublicKey::from_public_key_der(spki).expect("cert public key");
    let verifying: VerifyingKey<RsaSha256> = VerifyingKey::new(public);
    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(sig_b64)
        .unwrap();
    let signature = Signature::try_from(sig_bytes.as_slice()).unwrap();
    verifying
        .verify(content.as_bytes(), &signature)
        .expect("manifest signature must verify against the app certificate");

    serde_json::from_str(content).unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn publish_and_serve_lifecycle() {
    let stub = spawn_s3_stub().await;
    let server = Airlift::spawn(&stub).await;
    let ctx = setup_instance(&server).await;

    // ── publish v1 to the production branch ──
    let (status, body) = publish(
        &ctx,
        "production",
        "1.0.0",
        export_zip(&["ios", "android"], "v1"),
    )
    .await;
    assert_eq!(status, 201, "{body}");
    let group1 = body["group_id"].as_str().unwrap().to_string();
    // A same-named auto-release channel was created and released.
    assert_eq!(body["channels"][0]["channel"], "production");
    assert_eq!(body["channels"][0]["status"], "released");

    // ── byte-identical republish is refused ──
    let (status, _) = publish(
        &ctx,
        "production",
        "1.0.0",
        export_zip(&["ios", "android"], "v1"),
    )
    .await;
    assert_eq!(status, 409);

    // ── …but a config-only change (served as Constants.expoConfig) ships ──
    let (status, body) = publish_with_config(
        &ctx,
        "staging",
        "1.0.0",
        export_zip(&["ios"], "cfg"),
        json!({ "slug": "mobile", "extra": { "apiUrl": "a" } }),
    )
    .await;
    assert_eq!(status, 201, "{body}");
    let (status, body) = publish_with_config(
        &ctx,
        "staging",
        "1.0.0",
        export_zip(&["ios"], "cfg"),
        json!({ "slug": "mobile", "extra": { "apiUrl": "b" } }),
    )
    .await;
    assert_eq!(status, 201, "{body}");

    // ── the client gets a signed manifest ──
    let resp = manifest_request(&ctx, "production", "1.0.0", "ios", "1", None).await;
    assert_eq!(resp.headers().get("expo-protocol-version").unwrap(), "1");
    let manifest = verified_part(&ctx, resp, "manifest").await;
    assert_eq!(manifest["runtimeVersion"], "1.0.0");
    assert_eq!(manifest["extra"]["expoClient"]["slug"], "mobile");
    let update_id = manifest["id"].as_str().unwrap().to_string();
    let launch_url = manifest["launchAsset"]["url"].as_str().unwrap().to_string();
    let launch_hash = manifest["launchAsset"]["hash"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(manifest["assets"].as_array().unwrap().len(), 1);

    // ── launch asset: 307 redirect to the (stub) presigned URL, bytes verify ──
    let resp = ctx.http.get(&launch_url).send().await.unwrap();
    assert_eq!(resp.status(), 307);
    let presigned = resp
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(
        presigned.contains(&server.stub),
        "redirects to storage: {presigned}"
    );
    let bytes = reqwest::get(&presigned)
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    let expect_hash = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&launch_hash)
        .unwrap();
    assert_eq!(hex::encode(expect_hash), sha256_hex(&bytes));

    // ── a current client gets noUpdateAvailable (protocol 1) ──
    let resp = manifest_request(&ctx, "production", "1.0.0", "ios", "1", Some(&update_id)).await;
    let directive = verified_part(&ctx, resp, "directive").await;
    assert_eq!(directive["type"], "noUpdateAvailable");

    // ── protocol 0 has no directives: unknown runtime is a 404 ──
    let resp = manifest_request(&ctx, "production", "9.9.9", "ios", "0", None).await;
    assert_eq!(resp.status(), 404);

    // ── publish v2; auto channel advances ──
    let (status, body) = publish(
        &ctx,
        "production",
        "1.0.0",
        export_zip(&["ios", "android"], "v2"),
    )
    .await;
    assert_eq!(status, 201, "{body}");
    let group2 = body["group_id"].as_str().unwrap().to_string();
    let resp = manifest_request(&ctx, "production", "1.0.0", "ios", "1", None).await;
    let manifest2 = verified_part(&ctx, resp, "manifest").await;
    assert_ne!(manifest2["id"].as_str().unwrap(), update_id);

    // ── rollback: channel serves v1 again ──
    let resp = ctx
        .http
        .post(format!(
            "{}/api/v1/orgs/acme/apps/mobile/channels/production/rollback",
            ctx.base
        ))
        .json(&json!({ "runtime_version": "1.0.0" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "{}", resp.text().await.unwrap());
    let resp = manifest_request(&ctx, "production", "1.0.0", "ios", "1", None).await;
    let manifest3 = verified_part(&ctx, resp, "manifest").await;
    // Same content as v1, but a fresh identity and a NEWER createdAt than v2:
    // devices only load updates newer than the one they run.
    assert_eq!(
        manifest3["launchAsset"]["hash"],
        manifest["launchAsset"]["hash"]
    );
    assert_ne!(manifest3["id"].as_str().unwrap(), update_id);
    assert!(
        manifest3["createdAt"].as_str().unwrap() > manifest2["createdAt"].as_str().unwrap(),
        "rollback must be newer than what devices run"
    );

    // ── a second rollback has nothing left: v2 was rolled back, v1 is first ──
    let resp = ctx
        .http
        .post(format!(
            "{}/api/v1/orgs/acme/apps/mobile/channels/production/rollback",
            ctx.base
        ))
        .json(&json!({ "runtime_version": "1.0.0" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);

    // ── promote back to v2 explicitly ──
    let resp = ctx
        .http
        .post(format!(
            "{}/api/v1/orgs/acme/apps/mobile/channels/production/promote",
            ctx.base
        ))
        .json(&json!({ "group_id": group2 }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let resp = manifest_request(&ctx, "production", "1.0.0", "ios", "1", None).await;
    let manifest4 = verified_part(&ctx, resp, "manifest").await;
    assert_eq!(
        manifest4["launchAsset"]["hash"],
        manifest2["launchAsset"]["hash"]
    );
    assert!(manifest4["createdAt"].as_str().unwrap() > manifest3["createdAt"].as_str().unwrap());
    let _ = group1;

    // ── rollback-to-embedded emits the protocol-1 directive ──
    let resp = ctx
        .http
        .post(format!(
            "{}/api/v1/orgs/acme/apps/mobile/branches/production/rollback-to-embedded",
            ctx.base
        ))
        .json(&json!({ "runtime_version": "1.0.0" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "{}", resp.text().await.unwrap());
    let resp = manifest_request(&ctx, "production", "1.0.0", "ios", "1", None).await;
    let directive = verified_part(&ctx, resp, "directive").await;
    assert_eq!(directive["type"], "rollBackToEmbedded");
    assert!(directive["parameters"]["commitTime"].is_string());
    // A protocol-0 client can't take directives → no-update 404.
    let resp = manifest_request(&ctx, "production", "1.0.0", "ios", "0", None).await;
    assert_eq!(resp.status(), 404);
}

#[tokio::test(flavor = "multi_thread")]
async fn gated_channels_and_promotion_flow() {
    let stub = spawn_s3_stub().await;
    let server = Airlift::spawn(&stub).await;
    let ctx = setup_instance(&server).await;

    // staging: auto; production: gated, pointing at the same branch.
    let (status, _) = publish(&ctx, "main", "1.0.0", export_zip(&["ios"], "r1")).await;
    assert_eq!(status, 201);
    let resp = ctx
        .http
        .post(format!(
            "{}/api/v1/orgs/acme/apps/mobile/channels",
            ctx.base
        ))
        .json(&json!({ "name": "production", "branch": "main", "auto_release": false }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201, "{}", resp.text().await.unwrap());

    // Gated channel has no release yet → noUpdateAvailable.
    let resp = manifest_request(&ctx, "production", "1.0.0", "ios", "1", None).await;
    let directive = verified_part(&ctx, resp, "directive").await;
    assert_eq!(directive["type"], "noUpdateAvailable");

    // New publish: auto channel (main) advances, gated stays pending.
    let (status, body) = publish(&ctx, "main", "1.0.0", export_zip(&["ios"], "r2")).await;
    assert_eq!(status, 201);
    let statuses: Vec<(String, String)> = body["channels"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| {
            (
                c["channel"].as_str().unwrap().to_string(),
                c["status"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    assert!(statuses.contains(&("main".into(), "released".into())));
    assert!(statuses.contains(&("production".into(), "pending".into())));
    let group2 = body["group_id"].as_str().unwrap().to_string();

    // main serves r2 immediately.
    let resp = manifest_request(&ctx, "main", "1.0.0", "ios", "1", None).await;
    let m = verified_part(&ctx, resp, "manifest").await;
    let main_update = m["id"].as_str().unwrap().to_string();

    // Promote r2 to production; both channels now serve the same update.
    let resp = ctx
        .http
        .post(format!(
            "{}/api/v1/orgs/acme/apps/mobile/channels/production/promote",
            ctx.base
        ))
        .json(&json!({ "group_id": group2 }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let resp = manifest_request(&ctx, "production", "1.0.0", "ios", "1", None).await;
    let m = verified_part(&ctx, resp, "manifest").await;
    assert_eq!(m["id"].as_str().unwrap(), main_update);

    // A channel with no branch is served purely by promote.
    let resp = ctx
        .http
        .post(format!(
            "{}/api/v1/orgs/acme/apps/mobile/channels",
            ctx.base
        ))
        .json(&json!({ "name": "beta" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let resp = ctx
        .http
        .post(format!(
            "{}/api/v1/orgs/acme/apps/mobile/channels/beta/promote",
            ctx.base
        ))
        .json(&json!({ "group_id": group2 }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let resp = manifest_request(&ctx, "beta", "1.0.0", "ios", "1", None).await;
    let beta = verified_part(&ctx, resp, "manifest").await;
    assert_eq!(beta["launchAsset"]["hash"], m["launchAsset"]["hash"]);

    // Repointing production at another branch serves that branch's head at
    // once, without waiting for the next publish there.
    let (status, _) = publish(&ctx, "hotfix", "1.0.0", export_zip(&["ios"], "h1")).await;
    assert_eq!(status, 201);
    let resp = manifest_request(&ctx, "hotfix", "1.0.0", "ios", "1", None).await;
    let hotfix = verified_part(&ctx, resp, "manifest").await;
    let resp = ctx
        .http
        .patch(format!(
            "{}/api/v1/orgs/acme/apps/mobile/channels/production",
            ctx.base
        ))
        .json(&json!({ "branch": "hotfix" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "{}", resp.text().await.unwrap());
    let resp = manifest_request(&ctx, "production", "1.0.0", "ios", "1", None).await;
    let m = verified_part(&ctx, resp, "manifest").await;
    assert_eq!(m["launchAsset"]["hash"], hotfix["launchAsset"]["hash"]);
}

#[tokio::test(flavor = "multi_thread")]
async fn asset_endpoint_is_app_confined() {
    let stub = spawn_s3_stub().await;
    let server = Airlift::spawn(&stub).await;
    let ctx = setup_instance(&server).await;

    let (status, _) = publish(&ctx, "production", "1.0.0", export_zip(&["ios"], "iso")).await;
    assert_eq!(status, 201);
    let resp = manifest_request(&ctx, "production", "1.0.0", "ios", "1", None).await;
    let manifest = verified_part(&ctx, resp, "manifest").await;
    let launch_url = manifest["launchAsset"]["url"].as_str().unwrap().to_string();
    let sha = launch_url.rsplit('/').next().unwrap().to_string();

    // A second app in the same org must NOT serve the first app's asset, even
    // though assets are deduplicated per org under the hood.
    let resp = ctx
        .http
        .post(format!("{}/api/v1/orgs/acme/apps", ctx.base))
        .json(&json!({ "slug": "other", "name": "Other" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let other: serde_json::Value = resp.json().await.unwrap();
    let other_id = other["app"]["id"].as_str().unwrap();

    let resp = ctx
        .http
        .get(format!("{}/u/{}/assets/{}", ctx.base, other_id, sha))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);

    // Garbage digests are rejected outright.
    let resp = ctx
        .http
        .get(format!("{}/u/{}/assets/{}", ctx.base, ctx.app_id, "zz"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}

#[tokio::test(flavor = "multi_thread")]
async fn bsdiff_patch_lifecycle() {
    let stub = spawn_s3_stub().await;
    let server = Airlift::spawn(&stub).await;
    let ctx = setup_instance(&server).await;

    // v1: the update the device currently runs. Download its bundle like the
    // device did (it's the patch base on disk).
    let (status, _) = publish(&ctx, "production", "1.0.0", export_zip(&["ios"], "p1")).await;
    assert_eq!(status, 201);
    let resp = manifest_request(&ctx, "production", "1.0.0", "ios", "1", None).await;
    let m1 = verified_part(&ctx, resp, "manifest").await;
    let v1_id = m1["id"].as_str().unwrap().to_string();
    let v1_url = m1["launchAsset"]["url"].as_str().unwrap().to_string();
    let v1_redirect = ctx.http.get(&v1_url).send().await.unwrap();
    assert_eq!(v1_redirect.status(), 307);
    let loc = v1_redirect.headers()["location"]
        .to_str()
        .unwrap()
        .to_string();
    let v1_bundle = reqwest::get(&loc)
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap()
        .to_vec();

    // v2: what the device is updating to.
    let (status, _) = publish(&ctx, "production", "1.0.0", export_zip(&["ios"], "p2")).await;
    assert_eq!(status, 201);
    let resp = manifest_request(&ctx, "production", "1.0.0", "ios", "1", Some(&v1_id)).await;
    let m2 = verified_part(&ctx, resp, "manifest").await;
    let v2_id = m2["id"].as_str().unwrap().to_string();
    let v2_url = m2["launchAsset"]["url"].as_str().unwrap().to_string();
    let v2_hash = m2["launchAsset"]["hash"].as_str().unwrap().to_string();
    // The launch asset key is the client's asset identity: a new bundle must
    // get a new key or the device reuses the old file.
    assert_ne!(m1["launchAsset"]["key"], m2["launchAsset"]["key"]);

    let patch_request = || {
        ctx.http
            .get(&v2_url)
            .header("A-IM", "bsdiff")
            .header("Expo-Current-Update-ID", &v1_id)
            .header("Expo-Requested-Update-ID", &v2_id)
            .send()
    };

    // First patch-capable request: nothing is ready yet → full bundle (307)
    // and the pair is enqueued for generation.
    let first = patch_request().await.unwrap();
    assert_eq!(
        first.status(),
        307,
        "first request falls back to full bundle"
    );

    // The 1s worker builds the patch; poll until the 226 arrives.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    let resp = loop {
        let resp = patch_request().await.unwrap();
        if resp.status() == 226 {
            break resp;
        }
        assert_eq!(resp.status(), 307, "only full-bundle fallback while queued");
        assert!(
            std::time::Instant::now() < deadline,
            "patch never became ready"
        );
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    };
    assert_eq!(resp.headers()["im"].to_str().unwrap(), "bsdiff");
    assert_eq!(
        resp.headers()["expo-base-update-id"]
            .to_str()
            .unwrap()
            .to_lowercase(),
        v1_id.to_lowercase()
    );
    let patch = resp.bytes().await.unwrap().to_vec();
    // Classic bsdiff container — the only thing the client's bspatch accepts.
    assert_eq!(&patch[..8], b"BSDIFF40");

    // Apply the patch exactly like the device and verify the manifest hash.
    let mut patched = Vec::new();
    qbsdiff::Bspatch::new(&patch)
        .unwrap()
        .apply(&v1_bundle, std::io::Cursor::new(&mut patched))
        .unwrap();
    let expect = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&v2_hash)
        .unwrap();
    assert_eq!(
        hex::encode(expect),
        sha256_hex(&patched),
        "patched bundle matches manifest hash"
    );

    // A plain request (no A-IM) still gets the full-bundle redirect.
    let resp = ctx.http.get(&v2_url).send().await.unwrap();
    assert_eq!(resp.status(), 307);

    // An unknown base update id can't get a patch.
    let resp = ctx
        .http
        .get(&v2_url)
        .header("A-IM", "bsdiff")
        .header(
            "Expo-Current-Update-ID",
            "00000000-0000-0000-0000-000000000000",
        )
        .header("Expo-Requested-Update-ID", &v2_id)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 307);
}

#[tokio::test(flavor = "multi_thread")]
async fn client_monitoring_and_metrics() {
    let stub = spawn_s3_stub().await;
    let server = Airlift::spawn(&stub).await;
    let ctx = setup_instance(&server).await;

    let (status, _) = publish(&ctx, "production", "1.0.0", export_zip(&["ios"], "m1")).await;
    assert_eq!(status, 201);

    // Two devices check in; one is already current.
    let resp = manifest_request(&ctx, "production", "1.0.0", "ios", "1", None).await;
    let manifest = verified_part(&ctx, resp, "manifest").await;
    let update_id = manifest["id"].as_str().unwrap().to_string();
    let _ = ctx
        .http
        .get(format!("{}/u/{}/manifest", ctx.base, ctx.app_id))
        .header("expo-platform", "ios")
        .header("expo-runtime-version", "1.0.0")
        .header("expo-channel-name", "production")
        .header("expo-protocol-version", "1")
        .header("EAS-Client-ID", "device-2")
        .header("expo-current-update-id", &update_id)
        .send()
        .await
        .unwrap();

    // Wait for the 1s flush loop to persist the check-ins.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let stats = loop {
        let stats: Value = ctx
            .http
            .get(format!("{}/api/v1/orgs/acme/apps/mobile/stats", ctx.base))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        if stats["total_devices"].as_i64().unwrap_or(0) >= 2 {
            break stats;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "check-ins never flushed: {stats}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    };
    // device-2 is attributed to the update it runs.
    let adoption = stats["adoption"].as_array().unwrap();
    assert!(adoption.iter().any(
        |a| a["current_update_id"].as_str() == Some(update_id.as_str())
            && a["devices"].as_i64() == Some(1)
    ));
    assert!(!stats["series"].as_array().unwrap().is_empty());

    let clients: Value = ctx
        .http
        .get(format!("{}/api/v1/orgs/acme/apps/mobile/clients", ctx.base))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let ids: Vec<&str> = clients["clients"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["client_id"].as_str().unwrap())
        .collect();
    assert!(ids.contains(&"test-device-1") && ids.contains(&"device-2"));

    // Prometheus endpoint exposes the counters.
    let metrics = ctx
        .http
        .get(format!("{}/metrics", ctx.base))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        metrics.contains("airlift_manifest_requests_total"),
        "{metrics}"
    );
    assert!(metrics.contains("airlift_publish_total"));

    // …but it lists every org's app slugs, so it isn't public.
    let resp = reqwest::get(format!("{}/metrics", ctx.base)).await.unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test(flavor = "multi_thread")]
async fn publish_requires_a_capable_token() {
    let stub = spawn_s3_stub().await;
    let server = Airlift::spawn(&stub).await;
    let ctx = setup_instance(&server).await;

    // A read-capped token must not publish.
    let read_pat = {
        let resp = ctx
            .http
            .post(format!("{}/api/v1/tokens", ctx.base))
            .json(&json!({ "name": "ro", "org": "acme", "permission": "read" }))
            .send()
            .await
            .unwrap();
        let v: serde_json::Value = resp.json().await.unwrap();
        v["token"].as_str().unwrap().to_string()
    };

    let form = reqwest::multipart::Form::new()
        .text("branch", "production")
        .text("runtime_version", "1.0.0")
        .part(
            "archive",
            reqwest::multipart::Part::bytes(export_zip(&["ios"], "denied")),
        );
    let resp = ctx
        .http
        .post(format!("{}/api/v1/apps/{}/updates", ctx.base, ctx.app_id))
        .bearer_auth(&read_pat)
        .multipart(form)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    // An admin token scoped to one app can't create apps (scope ∩ cap).
    let resp = ctx
        .http
        .post(format!("{}/api/v1/tokens", ctx.base))
        .json(&json!({ "name": "one-app", "org": "acme", "app": "mobile", "permission": "admin" }))
        .send()
        .await
        .unwrap();
    let v: serde_json::Value = resp.json().await.unwrap();
    let app_pat = v["token"].as_str().unwrap().to_string();
    let resp = reqwest::Client::new()
        .post(format!("{}/api/v1/orgs/acme/apps", ctx.base))
        .bearer_auth(&app_pat)
        .json(&json!({ "slug": "sneaky", "name": "Sneaky" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    // A narrow scope request missing its org must be refused, not widened.
    for body in [
        json!({ "name": "x", "app": "mobile" }),
        json!({ "name": "x", "scope": "org" }),
        json!({ "name": "x", "scope": "app", "org": "acme" }),
    ] {
        let resp = ctx
            .http
            .post(format!("{}/api/v1/tokens", ctx.base))
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 400, "{body}");
    }

    // No token at all → 401.
    let form = reqwest::multipart::Form::new()
        .text("branch", "production")
        .text("runtime_version", "1.0.0")
        .part(
            "archive",
            reqwest::multipart::Part::bytes(export_zip(&["ios"], "anon")),
        );
    let anon = reqwest::Client::new();
    let resp = anon
        .post(format!("{}/api/v1/apps/{}/updates", ctx.base, ctx.app_id))
        .multipart(form)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test(flavor = "multi_thread")]
async fn org_admins_cannot_take_over_ownership() {
    let stub = spawn_s3_stub().await;
    let server = Airlift::spawn(&stub).await;
    let ctx = setup_instance(&server).await;

    let resp = ctx
        .http
        .post(format!("{}/api/v1/users", ctx.base))
        .json(&json!({ "email": "eve@example.com", "username": "eve", "password": "password123" }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "{}", resp.text().await.unwrap());
    let resp = ctx
        .http
        .post(format!("{}/api/v1/orgs/acme/members", ctx.base))
        .json(&json!({ "login": "eve", "role": "admin" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let members: Value = ctx
        .http
        .get(format!("{}/api/v1/orgs/acme/members", ctx.base))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let id_of = |name: &str| {
        members["members"]
            .as_array()
            .unwrap()
            .iter()
            .find(|m| m["username"] == name)
            .unwrap()["user_id"]
            .as_str()
            .unwrap()
            .to_string()
    };
    let (eve_id, owner_id) = (id_of("eve"), id_of("admin"));

    let eve = reqwest::Client::builder()
        .cookie_store(true)
        .build()
        .unwrap();
    let resp = eve
        .post(format!("{}/api/v1/auth/login", ctx.base))
        .json(&json!({ "login": "eve", "password": "password123" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Self-promotion to owner, and removing/demoting the owner: forbidden.
    let resp = eve
        .post(format!("{}/api/v1/orgs/acme/members/{eve_id}", ctx.base))
        .json(&json!({ "role": "owner" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
    let resp = eve
        .delete(format!("{}/api/v1/orgs/acme/members/{owner_id}", ctx.base))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
    let resp = eve
        .post(format!("{}/api/v1/orgs/acme/members", ctx.base))
        .json(&json!({ "login": "admin", "role": "member" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    // The last owner can't demote themselves either.
    let resp = ctx
        .http
        .post(format!("{}/api/v1/orgs/acme/members/{owner_id}", ctx.base))
        .json(&json!({ "role": "admin" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}

#[tokio::test(flavor = "multi_thread")]
async fn members_only_list_apps_they_can_read() {
    let stub = spawn_s3_stub().await;
    let server = Airlift::spawn(&stub).await;
    let ctx = setup_instance(&server).await;

    let resp = ctx
        .http
        .post(format!("{}/api/v1/users", ctx.base))
        .json(&json!({ "email": "mo@example.com", "username": "mo", "password": "password123" }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let resp = ctx
        .http
        .post(format!("{}/api/v1/orgs/acme/members", ctx.base))
        .json(&json!({ "login": "mo", "role": "member" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let mo = reqwest::Client::builder()
        .cookie_store(true)
        .build()
        .unwrap();
    let resp = mo
        .post(format!("{}/api/v1/auth/login", ctx.base))
        .json(&json!({ "login": "mo", "password": "password123" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // A plain member with no team grant sees no apps (app ids are the public
    // protocol URL segment), while the owner still sees "mobile".
    let v: Value = mo
        .get(format!("{}/api/v1/orgs/acme/apps", ctx.base))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(v["apps"].as_array().unwrap().len(), 0, "{v}");
    let v: Value = ctx
        .http
        .get(format!("{}/api/v1/orgs/acme/apps", ctx.base))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(v["apps"].as_array().unwrap().len(), 1, "{v}");
}

#[tokio::test(flavor = "multi_thread")]
async fn single_platform_publish_keeps_the_other_platform_live() {
    let stub = spawn_s3_stub().await;
    let server = Airlift::spawn(&stub).await;
    let ctx = setup_instance(&server).await;

    let (status, _) = publish(
        &ctx,
        "production",
        "1.0.0",
        export_zip(&["ios", "android"], "both"),
    )
    .await;
    assert_eq!(status, 201);
    let resp = manifest_request(&ctx, "production", "1.0.0", "android", "1", None).await;
    let android_before = verified_part(&ctx, resp, "manifest").await;

    // An iOS-only hotfix must not take Android's release away.
    let (status, body) =
        publish(&ctx, "production", "1.0.0", export_zip(&["ios"], "ios-fix")).await;
    assert_eq!(status, 201, "{body}");
    assert_eq!(body["carried_platforms"], json!(["android"]));
    let resp = manifest_request(&ctx, "production", "1.0.0", "android", "1", None).await;
    let android_after = verified_part(&ctx, resp, "manifest").await;
    assert_eq!(
        android_after["launchAsset"]["hash"],
        android_before["launchAsset"]["hash"]
    );

    // The timeline lists both groups newest-first, with their platforms.
    let v: Value = ctx
        .http
        .get(format!("{}/api/v1/orgs/acme/apps/mobile/updates", ctx.base))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let updates = v["updates"].as_array().unwrap();
    assert_eq!(updates.len(), 2, "{v}");
    assert_eq!(updates[0]["id"], body["group_id"]);
    assert_eq!(updates[0]["branch"], "production");
    assert_eq!(updates[0]["platforms"], json!(["android", "ios"]));
}

#[tokio::test(flavor = "multi_thread")]
async fn crashed_updates_are_never_reserved() {
    let stub = spawn_s3_stub().await;
    let server = Airlift::spawn(&stub).await;
    let ctx = setup_instance(&server).await;

    let (status, _) = publish(&ctx, "production", "1.0.0", export_zip(&["ios"], "ok")).await;
    assert_eq!(status, 201);
    let resp = manifest_request(&ctx, "production", "1.0.0", "ios", "1", None).await;
    let v1 = verified_part(&ctx, resp, "manifest").await;
    let v1_id = v1["id"].as_str().unwrap().to_string();
    let (status, _) = publish(&ctx, "production", "1.0.0", export_zip(&["ios"], "bad")).await;
    assert_eq!(status, 201);
    let resp = manifest_request(&ctx, "production", "1.0.0", "ios", "1", Some(&v1_id)).await;
    let v2 = verified_part(&ctx, resp, "manifest").await;
    let v2_id = v2["id"].as_str().unwrap().to_string();

    // The device crashed on v2 and fell back to v1: it reports v2 as failed.
    let failed = format!("\"{v2_id}\"");
    let resp = manifest_request_with(
        &ctx,
        "production",
        "1.0.0",
        "ios",
        "1",
        &[
            ("EAS-Client-ID", "crashy"),
            ("expo-current-update-id", &v1_id),
            ("expo-recent-failed-update-ids", &failed),
        ],
    )
    .await;
    let remembered = resp.headers()["expo-server-defined-headers"]
        .to_str()
        .unwrap()
        .to_string();
    assert_eq!(remembered, format!("airlift-blocked-updates=\"{v2_id}\""));
    let directive = verified_part(&ctx, resp, "directive").await;
    assert_eq!(directive["type"], "noUpdateAvailable");

    // Later the client's own failed list is gone, but it echoes the
    // server-defined header back: v2 is still refused.
    let resp = manifest_request_with(
        &ctx,
        "production",
        "1.0.0",
        "ios",
        "1",
        &[
            ("EAS-Client-ID", "crashy"),
            ("expo-current-update-id", &v1_id),
            ("airlift-blocked-updates", &v2_id),
        ],
    )
    .await;
    let directive = verified_part(&ctx, resp, "directive").await;
    assert_eq!(directive["type"], "noUpdateAvailable");

    // Other devices still get v2.
    let resp = manifest_request(&ctx, "production", "1.0.0", "ios", "1", Some(&v1_id)).await;
    let m = verified_part(&ctx, resp, "manifest").await;
    assert_eq!(m["id"].as_str().unwrap(), v2_id);
}

/// Parse a protocol response without signature checks: (part → json).
async fn parts_of(resp: reqwest::Response) -> std::collections::HashMap<String, Value> {
    assert_eq!(resp.status(), 200);
    let ct = resp.headers()["content-type"].to_str().unwrap().to_string();
    let body = resp.text().await.unwrap();
    parse_multipart(&ct, &body)
        .into_iter()
        .map(|(k, (_, v))| (k, serde_json::from_str(&v).unwrap()))
        .collect()
}

/// The update id a device is offered, or None for a directive.
async fn offered(ctx: &Ctx, client_id: Option<&str>) -> Option<String> {
    let mut extra = vec![];
    if let Some(c) = client_id {
        extra.push(("EAS-Client-ID", c));
    }
    let resp = manifest_request_with(ctx, "production", "1.0.0", "ios", "1", &extra).await;
    parts_of(resp)
        .await
        .get("manifest")
        .map(|m| m["id"].as_str().unwrap().to_string())
}

#[tokio::test(flavor = "multi_thread")]
async fn progressive_rollout_buckets_devices_stably() {
    let stub = spawn_s3_stub().await;
    let server = Airlift::spawn(&stub).await;
    let ctx = setup_instance(&server).await;

    let (status, _) = publish(&ctx, "production", "1.0.0", export_zip(&["ios"], "base")).await;
    assert_eq!(status, 201);
    let v1 = offered(&ctx, Some("probe")).await.unwrap();

    // v2 published as a 30% rollout.
    let form = reqwest::multipart::Form::new()
        .text("branch", "production")
        .text("runtime_version", "1.0.0")
        .text("rollout_percent", "30")
        .part(
            "archive",
            reqwest::multipart::Part::bytes(export_zip(&["ios"], "canary")).file_name("d.zip"),
        );
    let resp = ctx
        .http
        .post(format!("{}/api/v1/apps/{}/updates", ctx.base, ctx.app_id))
        .bearer_auth(&ctx.pat)
        .multipart(form)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["channels"][0]["status"], "rolling_out");

    let devices: Vec<String> = (0..200).map(|i| format!("dev-{i}")).collect();
    let mut inside = Vec::new();
    let mut v2 = None;
    for d in &devices {
        let got = offered(&ctx, Some(d)).await.unwrap();
        if got != v1 {
            v2 = Some(got);
            inside.push(d.clone());
        }
    }
    let v2 = v2.expect("some devices are in the rollout");
    assert!(
        (30..90).contains(&inside.len()),
        "~30% of 200: {}",
        inside.len()
    );
    // No client id → never inside.
    assert_eq!(offered(&ctx, None).await.unwrap(), v1);

    // Asset path applies the same check; rollout manifests pin the client id.
    let resp = manifest_request_with(
        &ctx,
        "production",
        "1.0.0",
        "ios",
        "1",
        &[("EAS-Client-ID", &inside[0])],
    )
    .await;
    let parts = parts_of(resp).await;
    let url = parts["manifest"]["launchAsset"]["url"]
        .as_str()
        .unwrap()
        .to_string();
    let key = parts["manifest"]["launchAsset"]["key"].as_str().unwrap();
    assert_eq!(
        parts["extensions"]["assetRequestHeaders"][key]["EAS-Client-ID"],
        inside[0].as_str()
    );
    let outside = devices.iter().find(|d| !inside.contains(d)).unwrap();
    let fetch = |cid: Option<String>| {
        let mut r = ctx.http.get(&url);
        if let Some(c) = cid {
            r = r.header("EAS-Client-ID", c);
        }
        r.send()
    };
    assert_eq!(fetch(Some(inside[0].clone())).await.unwrap().status(), 307);
    assert_eq!(fetch(Some(outside.clone())).await.unwrap().status(), 404);
    assert_eq!(fetch(None).await.unwrap().status(), 404);

    // Growing to 60%: everyone inside at 30% stays inside.
    let set = |pct: f64| {
        ctx.http
            .patch(format!(
                "{}/api/v1/orgs/acme/apps/mobile/channels/production/rollout",
                ctx.base
            ))
            .json(&json!({ "runtime_version": "1.0.0", "percent": pct }))
            .send()
    };
    assert_eq!(set(60.0).await.unwrap().status(), 200);
    for d in &inside {
        assert_eq!(offered(&ctx, Some(d)).await.unwrap(), v2);
    }

    // 100% completes it: everyone (even without a client id) gets v2, and
    // the asset is open again.
    assert_eq!(set(100.0).await.unwrap().status(), 200);
    assert_eq!(offered(&ctx, None).await.unwrap(), v2);
    assert_eq!(fetch(None).await.unwrap().status(), 307);
    // Nothing left to adjust.
    assert_eq!(set(50.0).await.unwrap().status(), 400);
}

#[tokio::test(flavor = "multi_thread")]
async fn ab_split_serves_two_branches_on_one_channel() {
    let stub = spawn_s3_stub().await;
    let server = Airlift::spawn(&stub).await;
    let ctx = setup_instance(&server).await;

    let (status, _) = publish(&ctx, "production", "1.0.0", export_zip(&["ios"], "ctrl")).await;
    assert_eq!(status, 201);
    let control = offered(&ctx, Some("probe")).await.unwrap();
    let (status, _) = publish(&ctx, "experiment", "1.0.0", export_zip(&["ios"], "exp")).await;
    assert_eq!(status, 201);

    let split = |body: Value| {
        ctx.http
            .put(format!(
                "{}/api/v1/orgs/acme/apps/mobile/channels/production/split",
                ctx.base
            ))
            .json(&body)
            .send()
    };
    let resp = split(json!({ "branch": "experiment", "percent": 50 }))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "{}", resp.text().await.unwrap());

    let devices: Vec<String> = (0..100).map(|i| format!("ab-{i}")).collect();
    let mut b_side = Vec::new();
    for d in &devices {
        if offered(&ctx, Some(d)).await.unwrap() != control {
            b_side.push(d.clone());
        }
    }
    assert!(
        (25..75).contains(&b_side.len()),
        "~50/100: {}",
        b_side.len()
    );
    // No client id → always the channel's own branch.
    assert_eq!(offered(&ctx, None).await.unwrap(), control);

    // A new publish on the experiment branch reaches the B side only.
    let (status, _) = publish(&ctx, "experiment", "1.0.0", export_zip(&["ios"], "exp2")).await;
    assert_eq!(status, 201);
    let b_now = offered(&ctx, Some(&b_side[0])).await.unwrap();
    assert_ne!(b_now, control);
    let a = devices.iter().find(|d| !b_side.contains(d)).unwrap();
    assert_eq!(offered(&ctx, Some(a)).await.unwrap(), control);

    // Growing the split keeps the B side stable.
    let resp = split(json!({ "branch": "experiment", "percent": 80 }))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    for d in &b_side {
        assert_ne!(offered(&ctx, Some(d)).await.unwrap(), control);
    }

    // Clearing it sends everyone back to the channel's branch.
    let resp = ctx
        .http
        .delete(format!(
            "{}/api/v1/orgs/acme/apps/mobile/channels/production/split",
            ctx.base
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(offered(&ctx, Some(&b_side[0])).await.unwrap(), control);
}
