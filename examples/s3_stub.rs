//! Standalone S3 stub for the on-device e2e (`e2e-device/run.sh`): the same
//! in-memory stub `cargo test` uses, bound to a fixed address so a simulator
//! or emulator can follow airlift's presigned asset redirects to it.
//!
//! `cargo run --example s3_stub -- 127.0.0.1:47301`

#[allow(dead_code)]
#[path = "../tests/common/s3_stub.rs"]
mod s3_stub;

#[tokio::main]
async fn main() {
    let addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:47301".to_string());
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .unwrap_or_else(|e| panic!("bind {addr}: {e}"));
    eprintln!("s3 stub listening on {addr}");
    s3_stub::serve_s3_stub(listener).await;
}
