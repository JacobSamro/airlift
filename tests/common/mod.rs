//! Shared test harness: an in-process S3 stub and a launcher for the real
//! `airlift` binary. No Docker, no external network — everything runs locally
//! and deterministically, so `cargo test` exercises the whole stack over the
//! wire (setup, PAT auth, publish uploads to "S3", the Expo Updates protocol
//! with presigned-redirect assets, and the dashboard API).

#![allow(dead_code)]

use std::collections::{BTreeMap, HashMap};
use std::process::{Child, Command};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, State},
    http::{HeaderMap, Method, StatusCode, Uri},
    response::{IntoResponse, Response},
    Router,
};
use sha2::{Digest, Sha256};

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Pick a currently-free TCP port on loopback.
pub fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

// ───────────────────────── in-process S3 stub ─────────────────────────

#[derive(Default)]
struct Store {
    /// Final objects, keyed by S3 object key.
    objects: HashMap<String, Vec<u8>>,
    /// In-progress multipart uploads: upload-id -> (part-number -> bytes).
    uploads: HashMap<String, BTreeMap<i32, Vec<u8>>>,
    counter: u64,
}

type Shared = Arc<Mutex<Store>>;

/// Spawn the S3 stub on a random loopback port; returns its `host:port`.
pub async fn spawn_s3_stub() -> String {
    let store: Shared = Arc::new(Mutex::new(Store::default()));
    let app = Router::new()
        .fallback(handle)
        .layer(DefaultBodyLimit::disable())
        .with_state(store);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    format!("{}:{}", addr.ip(), addr.port())
}

fn query_map(uri: &Uri) -> HashMap<String, String> {
    let mut m = HashMap::new();
    if let Some(q) = uri.query() {
        for pair in q.split('&') {
            let mut it = pair.splitn(2, '=');
            let k = it.next().unwrap_or("").to_string();
            let v = it.next().unwrap_or("").to_string();
            m.insert(k, v);
        }
    }
    m
}

/// `/{bucket}/{key...}` -> key (single-bucket stub; bucket segment ignored).
fn object_key(path: &str) -> String {
    let p = path.trim_start_matches('/');
    match p.split_once('/') {
        Some((_bucket, key)) => key.to_string(),
        None => String::new(),
    }
}

async fn handle(
    State(store): State<Shared>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let key = object_key(uri.path());
    let q = query_map(&uri);
    let mut s = store.lock().unwrap();

    match method {
        // CreateMultipartUpload: POST ...?uploads
        Method::POST if q.contains_key("uploads") => {
            s.counter += 1;
            let upload_id = format!("upload-{}", s.counter);
            s.uploads.insert(upload_id.clone(), BTreeMap::new());
            xml(format!(
                "<?xml version=\"1.0\"?><InitiateMultipartUploadResult>\
                 <Bucket>test</Bucket><Key>{key}</Key><UploadId>{upload_id}</UploadId>\
                 </InitiateMultipartUploadResult>"
            ))
        }
        // CompleteMultipartUpload: POST ...?uploadId=
        Method::POST if q.contains_key("uploadId") => {
            let id = &q["uploadId"];
            let assembled: Vec<u8> = s
                .uploads
                .remove(id)
                .map(|parts| parts.into_values().flatten().collect())
                .unwrap_or_default();
            s.objects.insert(key.clone(), assembled);
            xml(format!(
                "<?xml version=\"1.0\"?><CompleteMultipartUploadResult>\
                 <Location>http://stub/test/{key}</Location><Bucket>test</Bucket>\
                 <Key>{key}</Key><ETag>\"complete\"</ETag></CompleteMultipartUploadResult>"
            ))
        }
        // UploadPart: PUT ...?partNumber=&uploadId=
        Method::PUT if q.contains_key("partNumber") && q.contains_key("uploadId") => {
            let id = q["uploadId"].clone();
            let pn: i32 = q["partNumber"].parse().unwrap_or(0);
            s.uploads.entry(id).or_default().insert(pn, body.to_vec());
            etag(format!("\"part-{pn}\""))
        }
        // PutObject
        Method::PUT => {
            let _ = headers;
            s.objects.insert(key, body.to_vec());
            etag("\"put\"".to_string())
        }
        // GetObject (also serves presigned URLs — signature ignored)
        Method::GET => match s.objects.get(&key) {
            Some(data) => (StatusCode::OK, data.clone()).into_response(),
            None => StatusCode::NOT_FOUND.into_response(),
        },
        // HeadObject
        Method::HEAD => match s.objects.get(&key) {
            Some(data) => (
                StatusCode::OK,
                [(axum::http::header::CONTENT_LENGTH, data.len().to_string())],
            )
                .into_response(),
            None => StatusCode::NOT_FOUND.into_response(),
        },
        // AbortMultipartUpload
        Method::DELETE if q.contains_key("uploadId") => {
            s.uploads.remove(&q["uploadId"]);
            StatusCode::NO_CONTENT.into_response()
        }
        // DeleteObject
        Method::DELETE => {
            s.objects.remove(&key);
            StatusCode::NO_CONTENT.into_response()
        }
        _ => StatusCode::METHOD_NOT_ALLOWED.into_response(),
    }
}

fn xml(body: String) -> Response {
    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "application/xml")],
        body,
    )
        .into_response()
}

fn etag(tag: String) -> Response {
    (StatusCode::OK, [(axum::http::header::ETAG, tag)]).into_response()
}

// ───────────────────────── airlift binary launcher ─────────────────────────

/// A running `airlift serve` child process; killed on drop.
pub struct Airlift {
    child: Child,
    pub base: String,
    pub db_path: String,
    pub stub: String,
    _tmp: tempfile::TempDir,
}

impl Airlift {
    /// Boot the real binary against the given S3 stub and wait until healthy.
    pub async fn spawn(stub: &str) -> Airlift {
        Self::spawn_with(stub, &[]).await
    }

    /// Like [`Airlift::spawn`] but with extra `AIRLIFT_*` environment overrides.
    pub async fn spawn_with(stub: &str, extra_env: &[(&str, &str)]) -> Airlift {
        let tmp = tempfile::tempdir().unwrap();
        let db_path = tmp.path().join("airlift.db").to_string_lossy().to_string();
        let cfg = tmp.path().join("none.toml").to_string_lossy().to_string();
        let port = free_port();
        let base = format!("http://127.0.0.1:{port}");

        let mut cmd = Command::new(env!("CARGO_BIN_EXE_airlift"));
        cmd.args(["--config", &cfg, "serve"])
            .env("RUST_LOG", "error")
            .env("AIRLIFT_DATABASE__PATH", &db_path)
            .env("AIRLIFT_SERVER__HTTP_ADDR", format!("127.0.0.1:{port}"))
            // TLS defaults on; the e2e drives plain HTTP on a loopback port.
            .env("AIRLIFT_TLS__ENABLED", "false")
            .env("AIRLIFT_STORAGE__ENDPOINT", format!("http://{stub}"))
            .env("AIRLIFT_STORAGE__BUCKET", "test")
            .env("AIRLIFT_STORAGE__REGION", "us-east-1")
            .env("AIRLIFT_STORAGE__ACCESS_KEY_ID", "test")
            .env("AIRLIFT_STORAGE__SECRET_ACCESS_KEY", "test")
            .env("AIRLIFT_STORAGE__FORCE_PATH_STYLE", "true")
            .env("AIRLIFT_GC__GRACE_SECS", "0");
        for (k, v) in extra_env {
            cmd.env(k, v);
        }
        let child = cmd.spawn().expect("failed to spawn airlift binary");

        let r = Airlift {
            child,
            base,
            db_path,
            stub: stub.to_string(),
            _tmp: tmp,
        };

        // Wait for readiness.
        let client = reqwest::Client::new();
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if let Ok(resp) = client.get(format!("{}/healthz", r.base)).send().await {
                if resp.status().is_success() {
                    break;
                }
            }
            assert!(Instant::now() < deadline, "airlift did not become ready");
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        r
    }

    /// Run a one-off `airlift admin …` subcommand against the same db; returns
    /// stdout. Admin commands touch only SQLite (no storage needed).
    pub fn run_admin(&self, args: &[&str]) -> String {
        let mut full: Vec<&str> = vec!["--config", "/nonexistent", "admin"];
        full.extend_from_slice(args);
        let out = Command::new(env!("CARGO_BIN_EXE_airlift"))
            .args(&full)
            .env("RUST_LOG", "error")
            .env("AIRLIFT_DATABASE__PATH", &self.db_path)
            .output()
            .expect("failed to run admin");
        assert!(
            out.status.success(),
            "admin {:?} failed: {}",
            args,
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).into_owned()
    }
}

impl Drop for Airlift {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

// ───────────────────────── expo export fixtures ─────────────────────────

/// Build a minimal `expo export`-shaped zip archive in memory. Each platform
/// gets a distinct launch bundle (`seed` varies the bytes) plus one shared png
/// asset, mirroring metro's `metadata.json` layout.
pub fn export_zip(platforms: &[&str], seed: &str) -> Vec<u8> {
    use std::io::Write;
    use zip::write::SimpleFileOptions;

    let mut file_metadata = serde_json::Map::new();
    let mut files: Vec<(String, Vec<u8>)> = Vec::new();

    let asset_bytes = format!("png-asset-{seed}").into_bytes();
    let asset_name = sha256_hex(&asset_bytes)[..32].to_string(); // md5-ish name
    files.push((format!("assets/{asset_name}"), asset_bytes));

    for platform in platforms {
        let bundle = format!("// bundle for {platform} — {seed}\nconsole.log('hi');").into_bytes();
        let bundle_path = format!("_expo/static/js/{platform}/entry-{seed}.hbc");
        files.push((bundle_path.clone(), bundle));
        file_metadata.insert(
            platform.to_string(),
            serde_json::json!({
                "bundle": bundle_path,
                "assets": [{ "path": format!("assets/{asset_name}"), "ext": "png" }],
            }),
        );
    }

    let metadata = serde_json::json!({
        "version": 0,
        "bundler": "metro",
        "fileMetadata": file_metadata,
    });

    let mut buf = Vec::new();
    {
        let mut zw = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));
        let opts = SimpleFileOptions::default();
        zw.start_file("metadata.json", opts).unwrap();
        zw.write_all(metadata.to_string().as_bytes()).unwrap();
        for (path, bytes) in &files {
            zw.start_file(path, opts).unwrap();
            zw.write_all(bytes).unwrap();
        }
        zw.finish().unwrap();
    }
    buf
}

/// Split a `multipart/mixed` protocol response into (part-name → (headers, body)).
pub fn parse_multipart(content_type: &str, body: &str) -> HashMap<String, (String, String)> {
    let boundary = content_type
        .split("boundary=")
        .nth(1)
        .expect("boundary in content-type")
        .trim();
    let mut parts = HashMap::new();
    for raw in body.split(&format!("--{boundary}")) {
        let raw = raw.trim_start_matches("\r\n");
        if raw.is_empty() || raw.starts_with("--") {
            continue;
        }
        let Some((headers, content)) = raw.split_once("\r\n\r\n") else {
            continue;
        };
        let name = headers
            .lines()
            .find_map(|l| l.split("name=\"").nth(1))
            .and_then(|s| s.split('"').next())
            .unwrap_or("")
            .to_string();
        parts.insert(
            name,
            (
                headers.to_string(),
                content.trim_end_matches("\r\n").to_string(),
            ),
        );
    }
    parts
}
