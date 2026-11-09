//! In-process S3 stub: just enough of the S3 API (path-style Put/Get/Head/
//! Delete + multipart) for airlift. Presigned GETs are served with the
//! signature ignored. Shared by the cargo e2e harness and the standalone
//! `examples/s3_stub.rs` used by the on-device e2e (`e2e-device/`).

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, State},
    http::{HeaderMap, Method, StatusCode, Uri},
    response::{IntoResponse, Response},
    Router,
};

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
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(serve_s3_stub(listener));
    format!("{}:{}", addr.ip(), addr.port())
}

/// Serve the stub on an already-bound listener until the task is dropped.
pub async fn serve_s3_stub(listener: tokio::net::TcpListener) {
    let store: Shared = Arc::new(Mutex::new(Store::default()));
    let app = Router::new()
        .fallback(handle)
        .layer(DefaultBodyLimit::disable())
        .with_state(store);
    let _ = axum::serve(listener, app).await;
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
