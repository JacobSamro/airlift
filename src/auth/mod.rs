//! Authentication: password hashing, PATs, RBAC, sessions, and the request
//! extractors that enforce them.

pub mod oauth;
pub mod password;
pub mod pat;
pub mod rbac;
pub mod session;

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::{header, HeaderMap};
use axum_extra::extract::CookieJar;

use crate::db;
use crate::error::Error;
use crate::models::{Permission, TokenScope, User};
use crate::state::AppState;

/// Effective public base URL for building absolute URLs (asset URLs, OAuth
/// redirect URIs). The configured/derived public URL wins; during the IP-only
/// bootstrap phase fall back to the request's `Host` header.
pub fn base_url(state: &AppState, headers: &HeaderMap) -> String {
    let configured = state.public_url();
    if !configured.is_empty() {
        return configured.trim_end_matches('/').to_string();
    }
    let host = headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("localhost");
    let scheme = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("http");
    format!("{scheme}://{host}")
}

/// Extract the `Bearer <token>` value from an Authorization header.
#[allow(dead_code)]
pub fn parse_bearer(header: &str) -> Option<&str> {
    header
        .strip_prefix("Bearer ")
        .or_else(|| header.strip_prefix("bearer "))
        .map(|s| s.trim())
}

/// An authenticated dashboard user, resolved from the session cookie.
pub struct SessionUser(pub User);

impl FromRequestParts<AppState> for SessionUser {
    type Rejection = Error;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let jar = CookieJar::from_headers(&parts.headers);
        let sid = jar
            .get(session::COOKIE_NAME)
            .map(|c| c.value().to_string())
            .ok_or(Error::Unauthorized)?;
        let user = db::users::user_for_session(state.db(), &sid)
            .await?
            .ok_or(Error::Unauthorized)?;
        Ok(SessionUser(user))
    }
}

/// An authenticated API caller: either a personal access token (`Bearer
/// alt_…`, used by the publish CLI/CI) or a dashboard session cookie. Carries
/// the token's resource scope and permission cap; a session user is unscoped.
/// (Used by the publish API in a later phase.)
#[allow(dead_code)]
pub struct ApiUser {
    pub user: User,
    pub scope: TokenScope,
    pub cap: Permission,
}

impl FromRequestParts<AppState> for ApiUser {
    type Rejection = Error;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        if let Some(bearer) = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(parse_bearer)
        {
            let (user, scope, cap) = db::users::user_for_pat(state.db(), bearer)
                .await?
                .ok_or(Error::Unauthorized)?;
            return Ok(ApiUser { user, scope, cap });
        }
        let SessionUser(user) = SessionUser::from_request_parts(parts, state).await?;
        Ok(ApiUser {
            user,
            scope: TokenScope::All,
            cap: Permission::Admin,
        })
    }
}
