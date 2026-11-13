//! Graceful shutdown with automatic TLS on.
//!
//! Reproduces the production sequence that hung `systemctl restart` until
//! systemd's SIGKILL: the server starts with no domain (plain HTTP, which
//! installs a SIGTERM handler), a domain is added from the dashboard (the
//! server switches to the ACME/TLS listeners), then SIGTERM arrives.
//!
//! Once a domain exists the server starts rustls-acme against Let's Encrypt
//! *staging* for a `.test` domain. That order is refused (or fails offline);
//! the test never depends on it, it only needs the TLS listeners running.

mod common;

use std::time::Duration;

use common::{free_port, spawn_s3_stub, Airlift};
use serde_json::json;

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn sigterm_stops_the_server_after_a_domain_is_added() {
    let stub = spawn_s3_stub().await;
    let https_port = free_port();
    let https_addr = format!("127.0.0.1:{https_port}");
    let acme_dir = tempfile::tempdir().unwrap();
    let mut server = Airlift::spawn_with(
        &stub,
        &[
            ("AIRLIFT_TLS__ENABLED", "true"),
            ("AIRLIFT_TLS__STAGING", "true"),
            ("AIRLIFT_TLS__CONTACT_EMAIL", "ops@example.test"),
            ("AIRLIFT_TLS__CACHE_DIR", acme_dir.path().to_str().unwrap()),
            ("AIRLIFT_SERVER__HTTPS_ADDR", &https_addr),
        ],
    )
    .await;

    // First-run setup gives us an instance admin session.
    let client = reqwest::Client::builder()
        .cookie_store(true)
        .build()
        .unwrap();
    let resp = client
        .post(format!("{}/api/v1/setup", server.base))
        .json(&json!({
            "email": "admin@example.test", "username": "admin",
            "password": "password123", "org_slug": "acme", "org_name": "Acme",
        }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "setup: {}", resp.status());

    let resp = client
        .post(format!("{}/api/v1/domains", server.base))
        .json(&json!({ "domain": "ota.example.test" }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "add domain: {}", resp.status());

    // Wait until the server has switched to the TLS listeners (:443 accepts).
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    while tokio::net::TcpStream::connect(&https_addr).await.is_err() {
        assert!(
            std::time::Instant::now() < deadline,
            "HTTPS listener never came up after adding a domain"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Before the fix this hung forever: the plain-HTTP branch's SIGTERM
    // handler outlived it, so the OS no longer killed the process, and the
    // TLS loop never watched for the signal.
    let status = server
        .terminate(Duration::from_secs(10))
        .await
        .expect("airlift did not exit within 10 s of SIGTERM");
    assert!(status.success(), "expected a clean exit, got {status}");
}
