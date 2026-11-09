//! OAuth 2.1 authorization server for MCP clients (agents), per the MCP
//! authorization spec:
//!
//!   GET  /.well-known/oauth-protected-resource[/mcp]  RFC 9728
//!   GET  /.well-known/oauth-authorization-server      RFC 8414
//!   POST /oauth/register                              RFC 7591 (public clients)
//!   GET  /oauth/authorize                             → dashboard consent page
//!   POST /oauth/token                                 code (+PKCE S256) / refresh
//!   GET  /api/v1/oauth/client                         consent page: who's asking
//!   POST /api/v1/oauth/consent                        consent page: approve/deny
//!
//! Access tokens are expiring PATs carrying the cap and resource scope the
//! user chose on the consent page, so they act with that user's permissions
//! (RBAC ∩ scope ∩ cap) and are listed/revocable under Access Tokens.

use axum::extract::{Form, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::Json;
use base64::Engine;
use serde::Deserialize;
use serde_json::json;
use sha2::Digest;

use super::json_ok;
use crate::auth::SessionUser;
use crate::db;
use crate::error::{Error, Result};
use crate::state::AppState;

fn base(state: &AppState, headers: &HeaderMap) -> String {
    crate::auth::base_url(state, headers)
}

pub async fn protected_resource(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let b = base(&state, &headers);
    json_ok(json!({
        "resource": format!("{b}/mcp"),
        "authorization_servers": [b],
        "bearer_methods_supported": ["header"],
        "scopes_supported": ["airlift"],
        "resource_name": "airlift",
    }))
}

pub async fn authorization_server(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let b = base(&state, &headers);
    json_ok(json!({
        "issuer": b,
        "authorization_endpoint": format!("{b}/oauth/authorize"),
        "token_endpoint": format!("{b}/oauth/token"),
        "registration_endpoint": format!("{b}/oauth/register"),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
        "scopes_supported": ["airlift"],
    }))
}

/// Allowed redirect URIs: https, http on loopback (RFC 8252), or a
/// private-use scheme for native apps — never javascript:/data:/file:.
fn valid_redirect(uri: &str) -> bool {
    let Ok(u) = reqwest::Url::parse(uri) else {
        return false;
    };
    if u.fragment().is_some() {
        return false;
    }
    match u.scheme() {
        "https" => u.host_str().is_some(),
        "http" => is_loopback(&u),
        "javascript" | "data" | "file" | "vbscript" | "blob" | "about" | "ftp" | "ws" | "wss" => {
            false
        }
        _ => true,
    }
}

fn is_loopback(u: &reqwest::Url) -> bool {
    matches!(u.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"))
}

/// Exact match, except loopback http URIs may differ in port (RFC 8252 §7.3).
fn redirect_matches(registered: &str, requested: &str) -> bool {
    if registered == requested {
        return true;
    }
    match (
        reqwest::Url::parse(registered),
        reqwest::Url::parse(requested),
    ) {
        (Ok(a), Ok(b)) if a.scheme() == "http" && is_loopback(&a) && is_loopback(&b) => {
            a.scheme() == b.scheme()
                && a.host_str() == b.host_str()
                && a.path() == b.path()
                && a.query() == b.query()
        }
        _ => false,
    }
}

fn oauth_error(status: StatusCode, error: &str, desc: &str) -> Response {
    (
        status,
        [(header::CACHE_CONTROL, "no-store")],
        Json(json!({ "error": error, "error_description": desc })),
    )
        .into_response()
}

#[derive(Deserialize)]
pub struct RegisterReq {
    #[serde(default)]
    client_name: Option<String>,
    #[serde(default)]
    redirect_uris: Vec<String>,
}

pub async fn register(State(state): State<AppState>, Json(req): Json<RegisterReq>) -> Response {
    if req.redirect_uris.is_empty() || req.redirect_uris.len() > 10 {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_redirect_uri",
            "1 to 10 redirect_uris required",
        );
    }
    if let Some(bad) = req.redirect_uris.iter().find(|u| !valid_redirect(u)) {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_redirect_uri",
            &format!("not allowed: {bad}"),
        );
    }
    let name: String = req
        .client_name
        .unwrap_or_else(|| "MCP client".into())
        .chars()
        .filter(|c| !c.is_control())
        .take(100)
        .collect();
    match db::oauth::register_client(state.db(), &name, &req.redirect_uris).await {
        Ok(id) => (
            StatusCode::CREATED,
            Json(json!({
                "client_id": id,
                "client_name": name,
                "redirect_uris": req.redirect_uris,
                "token_endpoint_auth_method": "none",
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
            })),
        )
            .into_response(),
        Err(e) => oauth_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            &e.to_string(),
        ),
    }
}

#[derive(Deserialize)]
pub struct AuthorizeQuery {
    response_type: Option<String>,
    client_id: Option<String>,
    redirect_uri: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    state: Option<String>,
    resource: Option<String>,
}

/// Validate the request, then hand the browser to the dashboard consent
/// page (which handles sign-in if needed).
pub async fn authorize(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<AuthorizeQuery>,
) -> Result<Response> {
    let client = check_client(&state, q.client_id.as_deref(), q.redirect_uri.as_deref()).await?;
    let redirect_uri = q.redirect_uri.clone().unwrap_or_default();
    // From here errors go back to the client's redirect URI.
    let back = |error: &str| {
        let mut u = reqwest::Url::parse(&redirect_uri).expect("validated");
        u.query_pairs_mut().append_pair("error", error);
        if let Some(s) = &q.state {
            u.query_pairs_mut().append_pair("state", s);
        }
        Redirect::to(u.as_str()).into_response()
    };
    if q.response_type.as_deref() != Some("code") {
        return Ok(back("unsupported_response_type"));
    }
    if q.code_challenge.as_deref().unwrap_or("").len() < 43
        || q.code_challenge_method.as_deref() != Some("S256")
    {
        return Ok(back("invalid_request"));
    }
    if let Some(r) = &q.resource {
        let b = base(&state, &headers);
        if r.trim_end_matches('/') != b && *r != format!("{b}/mcp") {
            return Ok(back("invalid_target"));
        }
    }
    let mut consent = reqwest::Url::parse("http://x/oauth/consent").expect("static");
    consent
        .query_pairs_mut()
        .append_pair("client_id", &client.id)
        .append_pair("redirect_uri", &redirect_uri)
        .append_pair("code_challenge", q.code_challenge.as_deref().unwrap_or(""))
        .append_pair("state", q.state.as_deref().unwrap_or(""));
    Ok(Redirect::to(&format!("/oauth/consent?{}", consent.query().unwrap_or(""))).into_response())
}

async fn check_client(
    state: &AppState,
    client_id: Option<&str>,
    redirect_uri: Option<&str>,
) -> Result<db::oauth::Client> {
    let client = db::oauth::find_client(state.db(), client_id.unwrap_or(""))
        .await?
        .ok_or_else(|| Error::bad_request("unknown client_id"))?;
    let ru = redirect_uri.unwrap_or("");
    if !client.uris().iter().any(|r| redirect_matches(r, ru)) {
        return Err(Error::bad_request(
            "redirect_uri is not registered for this client",
        ));
    }
    Ok(client)
}

#[derive(Deserialize)]
pub struct ClientQuery {
    client_id: String,
    redirect_uri: String,
}

/// For the consent page: who is asking, and where the code will go.
pub async fn client_info(
    State(state): State<AppState>,
    SessionUser(_user): SessionUser,
    Query(q): Query<ClientQuery>,
) -> Result<Response> {
    let c = check_client(&state, Some(&q.client_id), Some(&q.redirect_uri)).await?;
    let host = reqwest::Url::parse(&q.redirect_uri)
        .ok()
        .and_then(|u| {
            u.host_str()
                .map(String::from)
                .or(Some(u.scheme().to_string()))
        })
        .unwrap_or_default();
    Ok(json_ok(json!({ "name": c.name, "redirect_host": host })))
}

#[derive(Deserialize)]
pub struct ConsentReq {
    client_id: String,
    redirect_uri: String,
    code_challenge: String,
    #[serde(default)]
    state: String,
    approve: bool,
    /// read | publish | admin (caps the user's own access).
    #[serde(default)]
    permission: Option<String>,
    /// Optional org slug / app slug to confine the grant.
    #[serde(default)]
    org: Option<String>,
    #[serde(default)]
    app: Option<String>,
}

/// Approve or deny; returns where to send the browser.
pub async fn consent(
    State(state): State<AppState>,
    SessionUser(user): SessionUser,
    Json(req): Json<ConsentReq>,
) -> Result<Response> {
    check_client(&state, Some(&req.client_id), Some(&req.redirect_uri)).await?;
    let mut back = reqwest::Url::parse(&req.redirect_uri)
        .map_err(|_| Error::bad_request("bad redirect_uri"))?;
    if !req.approve {
        back.query_pairs_mut().append_pair("error", "access_denied");
    } else {
        let max_perm = match req.permission.as_deref() {
            None | Some("admin") => "admin",
            Some("publish") => "publish",
            Some("read") => "read",
            _ => return Err(Error::bad_request("permission: read | publish | admin")),
        };
        // Resource scope, checked like PAT creation (must be a member).
        let (kind, org_id, app_id) = match (
            req.org.as_deref().filter(|s| !s.is_empty()),
            req.app.as_deref().filter(|s| !s.is_empty()),
        ) {
            (None, None) => ("all", None, None),
            (Some(slug), app) => {
                let (org, _) = super::member_of(&state, &user.id, slug).await?;
                match app {
                    None => ("org", Some(org.id), None),
                    Some(a) => {
                        let app = db::apps::find_by_slug(state.db(), &org.id, a)
                            .await?
                            .ok_or_else(|| Error::bad_request("no such app"))?;
                        ("app", None, Some(app.id))
                    }
                }
            }
            (None, Some(_)) => return Err(Error::bad_request("app scope requires org")),
        };
        let code = db::oauth::create_code(
            state.db(),
            &db::oauth::Grant {
                client_id: req.client_id.clone(),
                user_id: user.id.clone(),
                redirect_uri: req.redirect_uri.clone(),
                code_challenge: req.code_challenge.clone(),
                max_perm: max_perm.into(),
                scope_kind: kind.into(),
                scope_org_id: org_id,
                scope_app_id: app_id,
            },
        )
        .await?;
        back.query_pairs_mut().append_pair("code", &code);
        db::audit::record(
            state.db(),
            Some(&user.id),
            None,
            "oauth.grant",
            Some(&req.client_id),
            Some(max_perm),
        )
        .await
        .ok();
    }
    if !req.state.is_empty() {
        back.query_pairs_mut().append_pair("state", &req.state);
    }
    Ok(json_ok(json!({ "redirect": back.to_string() })))
}

#[derive(Deserialize)]
pub struct TokenForm {
    grant_type: String,
    code: Option<String>,
    redirect_uri: Option<String>,
    client_id: Option<String>,
    code_verifier: Option<String>,
    refresh_token: Option<String>,
}

fn token_response(access: String, refresh: String, grant_scope: &str) -> Response {
    (
        StatusCode::OK,
        [(header::CACHE_CONTROL, "no-store")],
        Json(json!({
            "access_token": access,
            "token_type": "Bearer",
            "expires_in": db::oauth::ACCESS_TTL_SECS,
            "refresh_token": refresh,
            "scope": grant_scope,
        })),
    )
        .into_response()
}

pub async fn token(State(state): State<AppState>, Form(f): Form<TokenForm>) -> Response {
    let client_id = f.client_id.clone().unwrap_or_default();
    let client = match db::oauth::find_client(state.db(), &client_id).await {
        Ok(Some(c)) => c,
        _ => {
            return oauth_error(
                StatusCode::UNAUTHORIZED,
                "invalid_client",
                "unknown client_id",
            )
        }
    };
    match f.grant_type.as_str() {
        "authorization_code" => {
            let grant =
                match db::oauth::take_code(state.db(), f.code.as_deref().unwrap_or("")).await {
                    Ok(Some(g)) => g,
                    _ => {
                        return oauth_error(
                            StatusCode::BAD_REQUEST,
                            "invalid_grant",
                            "code invalid, expired or used",
                        )
                    }
                };
            if grant.client_id != client.id
                || grant.redirect_uri != f.redirect_uri.clone().unwrap_or_default()
            {
                return oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "client or redirect_uri mismatch",
                );
            }
            let verifier = f.code_verifier.clone().unwrap_or_default();
            let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(sha2::Sha256::digest(verifier.as_bytes()));
            if verifier.len() < 43 || challenge != grant.code_challenge {
                return oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "PKCE verification failed",
                );
            }
            match db::oauth::issue_tokens(state.db(), &grant, &client.name).await {
                Ok((a, r)) => token_response(a, r, "airlift"),
                Err(e) => oauth_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "server_error",
                    &e.to_string(),
                ),
            }
        }
        "refresh_token" => {
            match db::oauth::refresh(
                state.db(),
                f.refresh_token.as_deref().unwrap_or(""),
                &client.id,
            )
            .await
            {
                Ok(Some((a, r))) => token_response(a, r, "airlift"),
                Ok(None) => oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "refresh token invalid, expired or revoked",
                ),
                Err(e) => oauth_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "server_error",
                    &e.to_string(),
                ),
            }
        }
        _ => oauth_error(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            "authorization_code or refresh_token",
        ),
    }
}

/// Used by the MCP endpoint's 401.
pub fn resource_metadata_url(state: &AppState, headers: &HeaderMap) -> String {
    format!(
        "{}/.well-known/oauth-protected-resource",
        base(state, headers)
    )
}
