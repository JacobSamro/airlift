//! HTTP server assembly: router, middleware stack, and listener.

use std::time::Duration;

use axum::{
    extract::State,
    http::{header, HeaderValue, StatusCode},
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use tower_http::{
    compression::CompressionLayer, set_header::SetResponseHeaderLayer, trace::TraceLayer,
};

use crate::state::AppState;

/// The global Prometheus recorder, installed once on first router build.
static PROMETHEUS: std::sync::OnceLock<metrics_exporter_prometheus::PrometheusHandle> =
    std::sync::OnceLock::new();

fn prometheus_handle() -> &'static metrics_exporter_prometheus::PrometheusHandle {
    PROMETHEUS.get_or_init(|| {
        metrics_exporter_prometheus::PrometheusBuilder::new()
            .install_recorder()
            .expect("install prometheus recorder")
    })
}

/// Build the full application router with the shared middleware stack.
pub fn router(state: AppState) -> Router {
    let hsts = state.config().tls.enabled;
    let security_headers = tower::ServiceBuilder::new()
        .layer(SetResponseHeaderLayer::overriding(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::HeaderName::from_static("x-frame-options"),
            HeaderValue::from_static("DENY"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::HeaderName::from_static("referrer-policy"),
            HeaderValue::from_static("no-referrer"),
        ))
        // Strict default for every response. HTML responses override this in
        // `crate::web` with a CSP that whitelists the dashboard's inline
        // bootstrap script by hash (hence `if_not_present`, not `overriding`).
        .layer(SetResponseHeaderLayer::if_not_present(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_str(&crate::web::csp_policy(&[]))
                .expect("default CSP is valid header value"),
        ));

    // Install the recorder before any request can emit a metric.
    let _ = prometheus_handle();

    let mut router = Router::new()
        .route("/healthz", get(healthz))
        .route("/metrics", get(metrics))
        .merge(crate::api::routes())
        .merge(crate::protocol::routes())
        .merge(crate::observability::ingest::routes())
        .fallback(crate::web::handler)
        // Bounds uploaded `expo export` archives (axum's default is 2 MB).
        .layer(axum::extract::DefaultBodyLimit::max(
            state.config().server.max_body_bytes,
        ));

    if hsts {
        router = router.layer(SetResponseHeaderLayer::overriding(
            header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static("max-age=63072000; includeSubDomains"),
        ));
    }

    let trust_proxy = state.config().server.trust_proxy;
    router
        .layer(security_headers)
        .layer(axum::middleware::from_fn(move |req, next| {
            crate::rate_limit::middleware(trust_proxy, req, next)
        }))
        .layer(CompressionLayer::new())
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

/// Liveness/readiness probe. Verifies the database is reachable.
/// Prometheus exposition. Labels carry every org's app slugs, so it is not
/// public: scrape with `Authorization: Bearer <server.metrics_token>`, or be
/// signed in as an instance admin (unscoped, admin-capped).
async fn metrics(
    State(state): State<AppState>,
    mut parts: axum::http::request::Parts,
) -> axum::response::Response {
    use axum::extract::FromRequestParts;
    let token = &state.config().server.metrics_token;
    let bearer = parts
        .headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::trim);
    if !token.is_empty() && bearer.is_some_and(|b| constant_time_eq(b.as_bytes(), token.as_bytes()))
    {
        return prometheus_handle().render().into_response();
    }
    match crate::auth::ApiUser::from_request_parts(&mut parts, &state).await {
        Ok(u)
            if u.user.is_admin
                && u.cap == crate::models::Permission::Admin
                && matches!(u.scope, crate::models::TokenScope::All) =>
        {
            prometheus_handle().render().into_response()
        }
        Ok(_) => crate::error::Error::Forbidden.into_response(),
        Err(e) => e.into_response(),
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

async fn healthz(State(state): State<AppState>) -> impl IntoResponse {
    match sqlx::query("SELECT 1").execute(state.db()).await {
        Ok(_) => (StatusCode::OK, Json(serde_json::json!({ "status": "ok" }))),
        Err(e) => {
            tracing::error!(error = %e, "healthz db check failed");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({ "status": "degraded" })),
            )
        }
    }
}

/// Bind the plain-HTTP listener and serve until shutdown. `ConnectInfo` is
/// enabled so per-IP rate limiting works without a proxy.
pub async fn serve_http(addr: &str, app: Router) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "airlift listening (http)");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;
    Ok(())
}

/// Resolve when the process receives Ctrl-C or SIGTERM.
pub async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl-C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    tracing::info!("shutdown signal received");
    let _ = Duration::from_secs(0);
}
