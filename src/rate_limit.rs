//! Per-IP rate limiting for sensitive endpoints (login, setup), to blunt
//! credential-stuffing and brute-force attempts.

use std::num::NonZeroU32;
use std::sync::LazyLock;

use axum::extract::{ConnectInfo, Request};
use axum::http::{header, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use governor::{clock::DefaultClock, state::keyed::DefaultKeyedStateStore, Quota, RateLimiter};
use serde_json::json;

type Limiter = RateLimiter<String, DefaultKeyedStateStore<String>, DefaultClock>;

/// Strict limit for the human-facing credential endpoints (dashboard login and
/// first-run setup): 10 requests/second per IP with a burst of 20. Generous for
/// a person, hostile to a brute-force script.
static LOGIN_LIMITER: LazyLock<Limiter> = LazyLock::new(|| {
    let quota =
        Quota::per_second(NonZeroU32::new(10).unwrap()).allow_burst(NonZeroU32::new(20).unwrap());
    RateLimiter::keyed(quota)
});

fn is_guarded(path: &str) -> bool {
    matches!(path, "/api/v1/auth/login" | "/api/v1/setup")
}

/// Client IP for rate-limit keying. Forwarded headers are honored ONLY when
/// `trust_proxy` is set (i.e. a trusted proxy populates them); otherwise the
/// real peer socket address is used so a client can't spoof a fresh key.
fn client_ip(req: &Request, trust_proxy: bool) -> String {
    if trust_proxy {
        let h = req.headers();
        if let Some(xff) = h.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
            // Take the first non-empty hop; an empty/whitespace header must not
            // collapse every client onto one degenerate rate-limit key.
            if let Some(first) = xff.split(',').map(str::trim).find(|s| !s.is_empty()) {
                return first.to_string();
            }
        }
        if let Some(rip) = h.get("x-real-ip").and_then(|v| v.to_str().ok()) {
            let rip = rip.trim();
            if !rip.is_empty() {
                return rip.to_string();
            }
        }
    }
    req.extensions()
        .get::<ConnectInfo<std::net::SocketAddr>>()
        .map(|c| c.0.ip().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

/// `429` carrying the dashboard JSON error schema.
fn too_many() -> Response {
    let body = json!({ "error": { "code": "rate_limited", "message": "rate limit exceeded" } });
    (
        StatusCode::TOO_MANY_REQUESTS,
        [(header::RETRY_AFTER, "1")],
        Json(body),
    )
        .into_response()
}

pub async fn middleware(trust_proxy: bool, req: Request, next: Next) -> Response {
    if is_guarded(req.uri().path()) {
        let ip = client_ip(&req, trust_proxy);
        if LOGIN_LIMITER.check_key(&ip).is_err() {
            return too_many();
        }
    }
    next.run(req).await
}
