//! Dashboard REST API (`/api/v1`), authenticated by the session cookie (or a
//! PAT for the automation-facing endpoints).

pub mod apps;
pub mod publish;

use axum::{
    extract::{Path, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
    Json, Router,
};
use axum_extra::extract::cookie::{Cookie, SameSite};
use axum_extra::extract::CookieJar;
use serde::Deserialize;
use serde_json::json;

use crate::auth::{oauth, password, session, SessionUser};
use crate::db;
use crate::error::{Error, Result};
use crate::models::OrgRole;
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/v1/setup/status", get(setup_status))
        .route("/api/v1/setup", post(setup))
        .route("/api/v1/auth/login", post(login))
        .route("/api/v1/auth/logout", post(logout))
        .route("/api/v1/auth/me", get(me))
        .route("/api/v1/auth/providers", get(providers))
        .route("/api/v1/auth/google/login", get(google_login))
        .route("/api/v1/auth/google/callback", get(google_callback))
        .route("/api/v1/users", get(list_users).post(create_user))
        .route("/api/v1/orgs", get(list_orgs).post(create_org))
        .route("/api/v1/admin/orgs", get(list_all_orgs))
        .route("/api/v1/orgs/{slug}", get(get_org))
        .route(
            "/api/v1/orgs/{slug}/apps",
            get(apps::list_apps).post(apps::create_app),
        )
        .route(
            "/api/v1/orgs/{slug}/apps/{app}",
            get(apps::get_app).delete(apps::delete_app),
        )
        .route(
            "/api/v1/orgs/{slug}/apps/{app}/certificate",
            get(apps::get_certificate),
        )
        .route(
            "/api/v1/orgs/{slug}/apps/{app}/signing-keys",
            get(apps::list_signing_keys).post(apps::create_signing_key),
        )
        .route(
            "/api/v1/orgs/{slug}/apps/{app}/updates",
            get(apps::list_updates),
        )
        .route(
            "/api/v1/orgs/{slug}/apps/{app}/updates/{group}/republish",
            post(apps::republish),
        )
        .route("/api/v1/orgs/{slug}/apps/{app}/stats", get(apps::app_stats))
        .route(
            "/api/v1/orgs/{slug}/apps/{app}/clients",
            get(apps::app_clients),
        )
        .route(
            "/api/v1/orgs/{slug}/apps/{app}/channels",
            post(apps::create_channel),
        )
        .route(
            "/api/v1/orgs/{slug}/apps/{app}/channels/{channel}",
            axum::routing::patch(apps::update_channel).delete(apps::delete_channel),
        )
        .route(
            "/api/v1/orgs/{slug}/apps/{app}/channels/{channel}/promote",
            post(apps::promote),
        )
        .route(
            "/api/v1/orgs/{slug}/apps/{app}/channels/{channel}/rollback",
            post(apps::rollback),
        )
        .route(
            "/api/v1/orgs/{slug}/apps/{app}/channels/{channel}/rollout",
            post(apps::start_rollout).patch(apps::set_rollout),
        )
        .route(
            "/api/v1/orgs/{slug}/apps/{app}/channels/{channel}/split",
            axum::routing::put(apps::set_split).delete(apps::clear_split),
        )
        .route(
            "/api/v1/orgs/{slug}/apps/{app}/branches/{branch}/rollback-to-embedded",
            post(apps::rollback_to_embedded),
        )
        .route("/api/v1/apps/{app_id}/updates", post(publish::publish))
        .route(
            "/api/v1/orgs/{slug}/members",
            get(list_members).post(add_member),
        )
        .route(
            "/api/v1/orgs/{slug}/members/{user_id}",
            post(set_role).delete(remove_member),
        )
        .route(
            "/api/v1/orgs/{slug}/teams",
            get(list_teams).post(create_team),
        )
        .route(
            "/api/v1/orgs/{slug}/teams/{team}/members",
            get(team_members).post(add_team_member),
        )
        .route(
            "/api/v1/orgs/{slug}/teams/{team}/members/{user_id}",
            axum::routing::delete(remove_team_member),
        )
        .route(
            "/api/v1/orgs/{slug}/teams/{team}/perms",
            get(team_perms).post(set_team_perm),
        )
        .route("/api/v1/orgs/{slug}/roles", get(list_roles))
        .route(
            "/api/v1/orgs/{slug}/roles/{name}",
            axum::routing::put(put_role).delete(delete_role),
        )
        .route(
            "/api/v1/orgs/{slug}/apps/{app}/branches/{branch}/protection",
            axum::routing::put(apps::set_branch_protection),
        )
        .route("/api/v1/tokens", get(list_tokens).post(create_token))
        .route("/api/v1/tokens/{id}", axum::routing::delete(delete_token))
        .route("/api/v1/domains", get(list_domains).post(add_domain))
        .route(
            "/api/v1/domains/{domain}",
            axum::routing::delete(delete_domain),
        )
        .route("/api/v1/domains/{domain}/primary", post(set_primary_domain))
        .route("/api/v1/orgs/{slug}/audit", get(list_audit))
        .route(
            "/api/v1/settings/storage",
            get(get_storage_settings).put(update_storage_settings),
        )
        .route(
            "/api/v1/settings/oauth",
            get(get_oauth_settings).put(update_oauth_settings),
        )
        .route(
            "/api/v1/settings/tls",
            get(get_tls_settings).put(update_tls_settings),
        )
}

// ───────────────────────── helpers ─────────────────────────

pub(crate) fn json_ok<T: serde::Serialize>(v: T) -> Response {
    (StatusCode::OK, Json(v)).into_response()
}

pub(crate) fn valid_slug(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 40
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        && !s.starts_with('-')
        && !s.ends_with('-')
}

/// Resolve an org the user belongs to, returning it with their role.
pub(crate) async fn member_of(
    state: &AppState,
    user_id: &str,
    slug: &str,
) -> Result<(db::orgs::Org, OrgRole)> {
    let org = db::orgs::find_org_by_slug(state.db(), slug)
        .await?
        .ok_or(Error::NotFound)?;
    let role = db::orgs::org_role(state.db(), &org.id, user_id)
        .await?
        .ok_or(Error::Forbidden)?;
    Ok((org, role))
}

/// Guard for membership changes by an org admin/owner (`actor_role`):
/// only owners (or instance admins) may grant the owner role or touch an
/// existing owner's membership, and the last owner can't be demoted/removed.
/// `new_role` is `None` for a removal.
async fn guard_member_change(
    state: &AppState,
    org: &db::orgs::Org,
    actor: &crate::models::User,
    actor_role: OrgRole,
    target_user_id: &str,
    new_role: Option<OrgRole>,
) -> Result<()> {
    let actor_is_owner = actor_role == OrgRole::Owner || actor.is_admin;
    let target_role = db::orgs::org_role(state.db(), &org.id, target_user_id).await?;
    let touches_owner = new_role == Some(OrgRole::Owner) || target_role == Some(OrgRole::Owner);
    if touches_owner && !actor_is_owner {
        return Err(Error::Forbidden);
    }
    if target_role == Some(OrgRole::Owner) && new_role != Some(OrgRole::Owner) {
        let owners = db::orgs::list_members(state.db(), &org.id)
            .await?
            .into_iter()
            .filter(|m| m.role == OrgRole::Owner.as_str())
            .count();
        if owners <= 1 {
            return Err(Error::bad_request("an org must keep at least one owner"));
        }
    }
    Ok(())
}

/// Like [`member_of`] but requires an admin/owner role.
pub(crate) async fn admin_of(
    state: &AppState,
    user_id: &str,
    slug: &str,
) -> Result<(db::orgs::Org, OrgRole)> {
    let (org, role) = member_of(state, user_id, slug).await?;
    if role < OrgRole::Admin {
        return Err(Error::Forbidden);
    }
    Ok((org, role))
}

// ───────────────────────── setup / auth ─────────────────────────

async fn setup_status(State(state): State<AppState>) -> Result<Response> {
    let needs = db::users::count(state.db()).await? == 0;
    Ok(json_ok(json!({ "needs_setup": needs })))
}

#[derive(Deserialize)]
struct SetupReq {
    email: String,
    username: String,
    password: String,
    org_slug: String,
    org_name: String,
}

async fn setup(State(state): State<AppState>, Json(req): Json<SetupReq>) -> Result<Response> {
    if db::users::count(state.db()).await? != 0 {
        return Err(Error::conflict("setup already completed"));
    }
    if !valid_slug(&req.org_slug) {
        return Err(Error::bad_request("invalid org slug"));
    }
    if req.password.len() < 8 {
        return Err(Error::bad_request("password must be at least 8 characters"));
    }
    let hash = password::hash_password_blocking(req.password.clone()).await?;
    // Atomic guarded insert: only the first of any racing first-run requests
    // creates the super-admin; the rest see `None` and get a conflict, so
    // concurrent setup can't mint multiple instance admins.
    let Some(user) =
        db::users::create_first_admin(state.db(), &req.email, &req.username, &hash).await?
    else {
        return Err(Error::conflict("setup already completed"));
    };
    let org = db::orgs::create_org(state.db(), &req.org_slug, &req.org_name).await?;
    db::orgs::add_org_member(state.db(), &org.id, &user.id, OrgRole::Owner).await?;
    db::settings::set(state.db(), "setup_complete", "1")
        .await
        .ok();

    let sid = db::users::create_session(
        state.db(),
        &user.id,
        state.config().auth.session_ttl_secs as i64,
    )
    .await?;
    let cookie = session::build_cookie(
        sid,
        state.config().auth.session_ttl_secs as i64,
        state.cookie_secure(),
    );
    Ok((
        StatusCode::OK,
        [(header::SET_COOKIE, session::set_cookie_header(&cookie))],
        Json(json!({ "user": user, "org": org })),
    )
        .into_response())
}

#[derive(Deserialize)]
struct LoginReq {
    login: String,
    password: String,
}

async fn login(State(state): State<AppState>, Json(req): Json<LoginReq>) -> Result<Response> {
    let user = db::users::find_by_login(state.db(), &req.login)
        .await?
        .ok_or(Error::Unauthorized)?;
    if !password::verify_password_blocking(req.password.clone(), user.password_hash.clone()).await {
        return Err(Error::Unauthorized);
    }

    let sid = db::users::create_session(
        state.db(),
        &user.id,
        state.config().auth.session_ttl_secs as i64,
    )
    .await?;
    let cookie = session::build_cookie(
        sid,
        state.config().auth.session_ttl_secs as i64,
        state.cookie_secure(),
    );
    Ok((
        StatusCode::OK,
        [(header::SET_COOKIE, session::set_cookie_header(&cookie))],
        Json(json!({ "user": user })),
    )
        .into_response())
}

async fn logout(
    State(state): State<AppState>,
    jar: axum_extra::extract::CookieJar,
) -> Result<Response> {
    if let Some(c) = jar.get(session::COOKIE_NAME) {
        db::users::delete_session(state.db(), c.value()).await.ok();
    }
    let cookie = session::clear_cookie(state.cookie_secure());
    Ok((
        StatusCode::OK,
        [(header::SET_COOKIE, session::set_cookie_header(&cookie))],
        Json(json!({ "ok": true })),
    )
        .into_response())
}

async fn me(State(state): State<AppState>, SessionUser(user): SessionUser) -> Result<Response> {
    let orgs = db::orgs::orgs_for_user(state.db(), &user.id).await?;
    let orgs: Vec<_> = orgs
        .into_iter()
        .map(|(o, role)| json!({ "id": o.id, "slug": o.slug, "name": o.name, "role": role }))
        .collect();
    Ok(json_ok(json!({ "user": user, "orgs": orgs })))
}

// ───────────────────────── google sign-in ─────────────────────────

const OAUTH_STATE_COOKIE: &str = "airlift_oauth_state";

/// Which external sign-in providers are configured (shown on the login page).
async fn providers(State(state): State<AppState>) -> Result<Response> {
    let g = oauth::load(state.db()).await?;
    Ok(json_ok(json!({ "google": g.is_active() })))
}

/// The OAuth redirect URI (must be registered in the Google Cloud console).
fn google_redirect_uri(state: &AppState, headers: &HeaderMap) -> String {
    format!(
        "{}{}",
        crate::auth::base_url(state, headers),
        oauth::CALLBACK_PATH
    )
}

/// `GET /api/v1/auth/google/login` — kick off the OAuth dance.
async fn google_login(
    State(state): State<AppState>,
    headers: HeaderMap,
    jar: CookieJar,
) -> Response {
    let cfg = match oauth::load(state.db()).await {
        Ok(c) if c.is_active() => c,
        _ => return Redirect::to("/login?error=oauth_disabled").into_response(),
    };
    let csrf = crate::util::random_id();
    let redirect_uri = google_redirect_uri(&state, &headers);
    let url = oauth::authorize_url(&cfg, &redirect_uri, &csrf);

    // Short-lived CSRF state cookie. SameSite=Lax so it survives the top-level
    // redirect back from Google.
    let mut cookie = Cookie::new(OAUTH_STATE_COOKIE, csrf);
    cookie.set_http_only(true);
    cookie.set_secure(state.cookie_secure());
    cookie.set_same_site(SameSite::Lax);
    cookie.set_path("/");
    cookie.set_max_age(time::Duration::seconds(600));

    (jar.add(cookie), Redirect::to(&url)).into_response()
}

#[derive(Deserialize)]
struct OAuthCallback {
    #[serde(default)]
    code: String,
    #[serde(default)]
    state: String,
}

/// `GET /api/v1/auth/google/callback` — verify state, exchange the code, then
/// link/provision the user and start a session.
async fn google_callback(
    State(state): State<AppState>,
    headers: HeaderMap,
    jar: CookieJar,
    Query(q): Query<OAuthCallback>,
) -> Response {
    match google_callback_inner(&state, &headers, &jar, &q).await {
        Ok(resp) => resp,
        Err(e) => {
            tracing::warn!(error = %e, "google sign-in failed");
            let jar = jar.remove(Cookie::from(OAUTH_STATE_COOKIE));
            (jar, Redirect::to("/login?error=oauth")).into_response()
        }
    }
}

async fn google_callback_inner(
    state: &AppState,
    headers: &HeaderMap,
    jar: &CookieJar,
    q: &OAuthCallback,
) -> Result<Response> {
    let cfg = oauth::load(state.db()).await?;
    if !cfg.is_active() {
        return Err(Error::Forbidden);
    }
    // CSRF: the state in the query must match the cookie we set.
    let cookie_state = jar.get(OAUTH_STATE_COOKIE).map(|c| c.value().to_string());
    if q.state.is_empty() || cookie_state.as_deref() != Some(q.state.as_str()) {
        return Err(Error::Unauthorized);
    }

    let redirect_uri = google_redirect_uri(state, headers);
    let info = oauth::exchange_code(&cfg, &redirect_uri, &q.code).await?;
    if !info.email_verified {
        return Err(Error::bad_request("email not verified by Google"));
    }
    let email = info.email.to_ascii_lowercase();
    if !cfg.allowed_domain.is_empty() {
        let email_domain = email.rsplit('@').next().unwrap_or("");
        let hosted_domain = info.hd.to_ascii_lowercase();
        // Accept on the email domain or the Google Workspace hosted domain.
        if email_domain != cfg.allowed_domain && hosted_domain != cfg.allowed_domain {
            return Err(Error::Forbidden);
        }
    }

    // Link to an existing account by email, or auto-provision when an allowed
    // domain is configured (otherwise unknown emails are rejected). Match the
    // email column ONLY: a user whose *username* equals this address must not
    // be handed to whoever controls the Google account.
    let user = match db::users::find_by_email(state.db(), &email).await? {
        Some(u) => u,
        None if cfg.allowed_domain.is_empty() => return Err(Error::Forbidden),
        None => provision_oauth_user(state.db(), &email, &info.name).await?,
    };

    let ttl = state.config().auth.session_ttl_secs as i64;
    let sid = db::users::create_session(state.db(), &user.id, ttl).await?;
    let session_cookie = session::build_cookie(sid, ttl, state.cookie_secure());

    let jar = jar
        .clone()
        .add(session_cookie)
        .remove(Cookie::from(OAUTH_STATE_COOKIE));
    Ok((jar, Redirect::to("/")).into_response())
}

/// Create a new local account for an OAuth user (unusable random password).
async fn provision_oauth_user(db: &db::Db, email: &str, name: &str) -> Result<crate::models::User> {
    let base = sanitize_username(if name.trim().is_empty() { email } else { name });
    let username = unique_username(db, &base).await?;
    let random = format!("{}{}", crate::util::random_id(), crate::util::random_id());
    let hash = password::hash_password_blocking(random).await?;
    db::users::create(db, email, &username, &hash, false).await
}

fn sanitize_username(s: &str) -> String {
    let local = s.split('@').next().unwrap_or(s);
    let cleaned: String = local
        .to_ascii_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    let trimmed = cleaned.trim_matches('-').to_string();
    if trimmed.is_empty() {
        "user".to_string()
    } else {
        trimmed
    }
}

async fn unique_username(db: &db::Db, base: &str) -> Result<String> {
    let mut candidate = base.to_string();
    let mut n = 1;
    while db::users::find_by_login(db, &candidate).await?.is_some() {
        candidate = format!("{base}-{n}");
        n += 1;
    }
    Ok(candidate)
}

// ───────────────────────── users (instance admin) ─────────────────────────

async fn list_users(
    State(state): State<AppState>,
    SessionUser(user): SessionUser,
) -> Result<Response> {
    if !user.is_admin {
        return Err(Error::Forbidden);
    }
    let users = db::users::list_all(state.db()).await?;
    Ok(json_ok(json!({ "users": users })))
}

#[derive(Deserialize)]
struct CreateUserReq {
    email: String,
    username: String,
    password: String,
    #[serde(default)]
    is_admin: bool,
}

async fn create_user(
    State(state): State<AppState>,
    SessionUser(user): SessionUser,
    Json(req): Json<CreateUserReq>,
) -> Result<Response> {
    if !user.is_admin {
        return Err(Error::Forbidden);
    }
    if req.password.len() < 8 {
        return Err(Error::bad_request("password must be at least 8 characters"));
    }
    let hash = password::hash_password_blocking(req.password.clone()).await?;
    let created =
        db::users::create(state.db(), &req.email, &req.username, &hash, req.is_admin).await?;
    Ok(json_ok(json!({ "user": created })))
}

// ───────────────────────── orgs ─────────────────────────

async fn list_orgs(
    State(state): State<AppState>,
    SessionUser(user): SessionUser,
) -> Result<Response> {
    let orgs = db::orgs::orgs_for_user(state.db(), &user.id).await?;
    let orgs: Vec<_> = orgs
        .into_iter()
        .map(|(o, role)| json!({ "id": o.id, "slug": o.slug, "name": o.name, "role": role }))
        .collect();
    Ok(json_ok(json!({ "orgs": orgs })))
}

/// Super-admin view of every organization on the instance (with counts).
async fn list_all_orgs(
    State(state): State<AppState>,
    SessionUser(user): SessionUser,
) -> Result<Response> {
    if !user.is_admin {
        return Err(Error::Forbidden);
    }
    let orgs = db::orgs::list_all_with_counts(state.db()).await?;
    Ok(json_ok(json!({ "orgs": orgs })))
}

#[derive(Deserialize)]
struct CreateOrgReq {
    slug: String,
    name: String,
}

async fn create_org(
    State(state): State<AppState>,
    SessionUser(user): SessionUser,
    Json(req): Json<CreateOrgReq>,
) -> Result<Response> {
    if !valid_slug(&req.slug) {
        return Err(Error::bad_request(
            "invalid slug (lowercase letters, digits, hyphens)",
        ));
    }
    if db::orgs::find_org_by_slug(state.db(), &req.slug)
        .await?
        .is_some()
    {
        return Err(Error::conflict("org slug already taken"));
    }
    let org = db::orgs::create_org(state.db(), &req.slug, &req.name).await?;
    db::orgs::add_org_member(state.db(), &org.id, &user.id, OrgRole::Owner).await?;
    Ok(json_ok(json!({ "org": org })))
}

async fn get_org(
    State(state): State<AppState>,
    SessionUser(user): SessionUser,
    Path(slug): Path<String>,
) -> Result<Response> {
    let (org, role) = member_of(&state, &user.id, &slug).await?;
    let stats = db::orgs::org_stats(state.db(), &org.id).await?;
    Ok(json_ok(json!({ "org": org, "role": role, "stats": stats })))
}

// ───────────────────────── members ─────────────────────────

async fn list_members(
    State(state): State<AppState>,
    SessionUser(user): SessionUser,
    Path(slug): Path<String>,
) -> Result<Response> {
    let (org, _) = member_of(&state, &user.id, &slug).await?;
    let members = db::orgs::list_members(state.db(), &org.id).await?;
    Ok(json_ok(json!({ "members": members })))
}

#[derive(Deserialize)]
struct AddMemberReq {
    login: String,
    #[serde(default = "default_role")]
    role: String,
}
fn default_role() -> String {
    "member".to_string()
}

async fn add_member(
    State(state): State<AppState>,
    SessionUser(user): SessionUser,
    Path(slug): Path<String>,
    Json(req): Json<AddMemberReq>,
) -> Result<Response> {
    let (org, actor_role) = admin_of(&state, &user.id, &slug).await?;
    let role = OrgRole::parse(&req.role).ok_or_else(|| Error::bad_request("invalid role"))?;
    let target = db::users::find_by_login(state.db(), &req.login)
        .await?
        .ok_or_else(|| Error::bad_request("no such user"))?;
    guard_member_change(&state, &org, &user, actor_role, &target.id, Some(role)).await?;
    db::orgs::add_org_member(state.db(), &org.id, &target.id, role).await?;
    db::audit::record(
        state.db(),
        Some(&user.id),
        Some(&org.id),
        "member.add",
        Some(&target.username),
        Some(req.role.as_str()),
    )
    .await
    .ok();
    Ok(json_ok(json!({ "ok": true })))
}

#[derive(Deserialize)]
struct SetRoleReq {
    role: String,
}

async fn set_role(
    State(state): State<AppState>,
    SessionUser(user): SessionUser,
    Path((slug, user_id)): Path<(String, String)>,
    Json(req): Json<SetRoleReq>,
) -> Result<Response> {
    let (org, actor_role) = admin_of(&state, &user.id, &slug).await?;
    let role = OrgRole::parse(&req.role).ok_or_else(|| Error::bad_request("invalid role"))?;
    guard_member_change(&state, &org, &user, actor_role, &user_id, Some(role)).await?;
    db::orgs::set_member_role(state.db(), &org.id, &user_id, role).await?;
    Ok(json_ok(json!({ "ok": true })))
}

async fn remove_member(
    State(state): State<AppState>,
    SessionUser(user): SessionUser,
    Path((slug, user_id)): Path<(String, String)>,
) -> Result<Response> {
    let (org, actor_role) = admin_of(&state, &user.id, &slug).await?;
    guard_member_change(&state, &org, &user, actor_role, &user_id, None).await?;
    db::orgs::remove_member(state.db(), &org.id, &user_id).await?;
    db::audit::record(
        state.db(),
        Some(&user.id),
        Some(&org.id),
        "member.remove",
        Some(&user_id),
        None,
    )
    .await
    .ok();
    Ok(json_ok(json!({ "ok": true })))
}

// ───────────────────────── teams ─────────────────────────

async fn list_teams(
    State(state): State<AppState>,
    SessionUser(user): SessionUser,
    Path(slug): Path<String>,
) -> Result<Response> {
    let (org, _) = member_of(&state, &user.id, &slug).await?;
    let teams = db::orgs::list_teams(state.db(), &org.id).await?;
    Ok(json_ok(json!({ "teams": teams })))
}

#[derive(Deserialize)]
struct CreateTeamReq {
    slug: String,
    name: String,
}

async fn create_team(
    State(state): State<AppState>,
    SessionUser(user): SessionUser,
    Path(slug): Path<String>,
    Json(req): Json<CreateTeamReq>,
) -> Result<Response> {
    let (org, _) = admin_of(&state, &user.id, &slug).await?;
    if !valid_slug(&req.slug) {
        return Err(Error::bad_request("invalid team slug"));
    }
    let team = db::orgs::create_team(state.db(), &org.id, &req.slug, &req.name).await?;
    Ok(json_ok(json!({ "team": team })))
}

async fn team_members(
    State(state): State<AppState>,
    SessionUser(user): SessionUser,
    Path((slug, team)): Path<(String, String)>,
) -> Result<Response> {
    let (org, _) = member_of(&state, &user.id, &slug).await?;
    let team = db::orgs::find_team(state.db(), &org.id, &team)
        .await?
        .ok_or(Error::NotFound)?;
    let members = db::orgs::list_team_members(state.db(), &team.id).await?;
    Ok(json_ok(json!({ "members": members })))
}

#[derive(Deserialize)]
struct AddTeamMemberReq {
    login: String,
    #[serde(default = "default_role")]
    role: String,
}

async fn add_team_member(
    State(state): State<AppState>,
    SessionUser(user): SessionUser,
    Path((slug, team)): Path<(String, String)>,
    Json(req): Json<AddTeamMemberReq>,
) -> Result<Response> {
    let (org, _) = admin_of(&state, &user.id, &slug).await?;
    let team = db::orgs::find_team(state.db(), &org.id, &team)
        .await?
        .ok_or(Error::NotFound)?;
    let target = db::users::find_by_login(state.db(), &req.login)
        .await?
        .ok_or_else(|| Error::bad_request("no such user"))?;
    db::orgs::add_team_member(state.db(), &team.id, &target.id, &req.role).await?;
    Ok(json_ok(json!({ "ok": true })))
}

async fn remove_team_member(
    State(state): State<AppState>,
    SessionUser(user): SessionUser,
    Path((slug, team, user_id)): Path<(String, String, String)>,
) -> Result<Response> {
    let (org, _) = admin_of(&state, &user.id, &slug).await?;
    let team = db::orgs::find_team(state.db(), &org.id, &team)
        .await?
        .ok_or(Error::NotFound)?;
    db::orgs::remove_team_member(state.db(), &team.id, &user_id).await?;
    Ok(json_ok(json!({ "ok": true })))
}

async fn team_perms(
    State(state): State<AppState>,
    SessionUser(user): SessionUser,
    Path((slug, team)): Path<(String, String)>,
) -> Result<Response> {
    let (org, _) = member_of(&state, &user.id, &slug).await?;
    let team = db::orgs::find_team(state.db(), &org.id, &team)
        .await?
        .ok_or(Error::NotFound)?;
    let perms = db::orgs::list_team_perms(state.db(), &team.id).await?;
    Ok(json_ok(json!({ "permissions": perms })))
}

#[derive(Deserialize)]
struct SetTeamPermReq {
    app: String,
    permission: String,
}

async fn set_team_perm(
    State(state): State<AppState>,
    SessionUser(user): SessionUser,
    Path((slug, team)): Path<(String, String)>,
    Json(req): Json<SetTeamPermReq>,
) -> Result<Response> {
    let (org, _) = admin_of(&state, &user.id, &slug).await?;
    let team = db::orgs::find_team(state.db(), &org.id, &team)
        .await?
        .ok_or(Error::NotFound)?;
    // A built-in level, or `role:<name>` for one of the org's custom roles.
    let valid = match req.permission.strip_prefix("role:") {
        Some(name) => db::orgs::list_roles(state.db(), &org.id)
            .await?
            .iter()
            .any(|r| r.name == name),
        None => crate::models::Permission::parse(&req.permission).is_some(),
    };
    if !valid {
        return Err(Error::bad_request(
            "invalid permission (read|publish|admin|role:<custom role>)",
        ));
    }
    let app = db::apps::find_by_slug(state.db(), &org.id, &req.app)
        .await?
        .ok_or_else(|| Error::bad_request("no such app"))?;
    db::orgs::set_team_app_perm(state.db(), &team.id, &app.id, &req.permission).await?;
    Ok(json_ok(json!({ "ok": true })))
}

// ───────────────────────── custom roles ─────────────────────────

async fn list_roles(
    State(state): State<AppState>,
    SessionUser(user): SessionUser,
    Path(slug): Path<String>,
) -> Result<Response> {
    let (org, _) = member_of(&state, &user.id, &slug).await?;
    let roles = db::orgs::list_roles(state.db(), &org.id).await?;
    let capabilities: Vec<_> = crate::models::Capability::ALL
        .iter()
        .map(|c| c.as_str())
        .collect();
    Ok(json_ok(
        json!({ "roles": roles, "capabilities": capabilities }),
    ))
}

#[derive(Deserialize)]
struct PutRoleReq {
    capabilities: Vec<String>,
}

/// Create or replace a custom role: a named set of app capabilities that
/// team grants can use (`role:<name>`).
async fn put_role(
    State(state): State<AppState>,
    SessionUser(user): SessionUser,
    Path((slug, name)): Path<(String, String)>,
    Json(req): Json<PutRoleReq>,
) -> Result<Response> {
    let (org, _) = admin_of(&state, &user.id, &slug).await?;
    if !valid_slug(&name) {
        return Err(Error::bad_request(
            "invalid role name (lowercase letters, digits, hyphens)",
        ));
    }
    if matches!(name.as_str(), "read" | "publish" | "admin" | "none") {
        return Err(Error::bad_request("that name is a built-in level"));
    }
    let caps = crate::models::Caps::from_names(&req.capabilities)
        .filter(|c| !c.is_empty())
        .ok_or_else(|| {
            Error::bad_request(
                "capabilities: non-empty list of read|publish|release|channels|keys|protected",
            )
        })?;
    db::orgs::upsert_role(state.db(), &org.id, &name, caps).await?;
    db::audit::record(
        state.db(),
        Some(&user.id),
        Some(&org.id),
        "role.put",
        Some(&name),
        Some(&caps.names().join(",")),
    )
    .await
    .ok();
    Ok(json_ok(
        json!({ "ok": true, "name": name, "capabilities": caps.names() }),
    ))
}

async fn delete_role(
    State(state): State<AppState>,
    SessionUser(user): SessionUser,
    Path((slug, name)): Path<(String, String)>,
) -> Result<Response> {
    let (org, _) = admin_of(&state, &user.id, &slug).await?;
    if !db::orgs::delete_role(state.db(), &org.id, &name).await? {
        return Err(Error::NotFound);
    }
    db::audit::record(
        state.db(),
        Some(&user.id),
        Some(&org.id),
        "role.delete",
        Some(&name),
        None,
    )
    .await
    .ok();
    Ok(json_ok(json!({ "ok": true })))
}

// ───────────────────────── personal access tokens ─────────────────────────

async fn list_tokens(
    State(state): State<AppState>,
    SessionUser(user): SessionUser,
) -> Result<Response> {
    let tokens = db::users::list_pats(state.db(), &user.id).await?;
    Ok(json_ok(json!({ "tokens": tokens })))
}

#[derive(Deserialize)]
struct CreateTokenReq {
    name: String,
    /// Optional org slug to scope the token to.
    #[serde(default)]
    org: Option<String>,
    /// Optional app slug (within `org`) to scope the token to a single app.
    #[serde(default)]
    app: Option<String>,
    /// Optional permission cap: "read", "publish", or "admin" (default).
    #[serde(default)]
    permission: Option<String>,
    /// Optional explicit scope kind ("all" | "org" | "app"). When given, the
    /// matching `org`/`app` fields are required — a narrow scope request
    /// must never silently become an all-scope token.
    #[serde(default)]
    scope: Option<String>,
    /// Optional IP allowlist: addresses or CIDR ranges the token may be used
    /// from. Empty / absent = anywhere.
    #[serde(default)]
    allowed_ips: Option<Vec<String>>,
}

async fn create_token(
    State(state): State<AppState>,
    SessionUser(user): SessionUser,
    Json(req): Json<CreateTokenReq>,
) -> Result<Response> {
    // Resolve the requested scope. The user must belong to any org they scope
    // to; the resulting token is still bounded by their RBAC at use time.
    // Anything ambiguous is a 400, never a silent widening to "all".
    let has_org = req.org.as_deref().is_some_and(|s| !s.is_empty());
    let has_app = req.app.as_deref().is_some_and(|s| !s.is_empty());
    match (req.scope.as_deref(), has_org, has_app) {
        (_, false, true) => return Err(Error::bad_request("app scope requires org")),
        (Some("org"), false, _) => return Err(Error::bad_request("org scope requires org")),
        (Some("app"), _, false) => {
            return Err(Error::bad_request("app scope requires org and app"))
        }
        (Some("all"), true, _) => {
            return Err(Error::bad_request("all scope can't name an org or app"))
        }
        (Some("org"), _, true) => return Err(Error::bad_request("org scope can't name an app")),
        (None | Some("all" | "org" | "app"), _, _) => {}
        (Some(_), _, _) => return Err(Error::bad_request("invalid scope (all|org|app)")),
    }
    let (kind, org_id, app_id) = match (req.org.as_deref(), req.app.as_deref()) {
        (Some(slug), Some(app_slug)) => {
            let (org, _) = member_of(&state, &user.id, slug).await?;
            let app = db::apps::find_by_slug(state.db(), &org.id, app_slug)
                .await?
                .ok_or_else(|| Error::bad_request("no such app"))?;
            ("app".to_string(), None, Some(app.id))
        }
        (Some(slug), None) => {
            let (org, _) = member_of(&state, &user.id, slug).await?;
            ("org".to_string(), Some(org.id), None)
        }
        _ => ("all".to_string(), None, None),
    };

    let max_perm = match req.permission.as_deref() {
        None | Some("admin") => "admin",
        Some("publish") => "publish",
        Some("read") => "read",
        Some(_) => {
            return Err(Error::bad_request(
                "invalid permission (read|publish|admin)",
            ))
        }
    };

    // Optional IP allowlist (IPs / CIDRs), stored normalized.
    let allowed_ips = match req.allowed_ips.as_deref() {
        None | Some([]) => None,
        Some(list) => Some(
            crate::auth::ipallow::parse_list(list)
                .ok_or_else(|| Error::bad_request("allowed_ips: invalid IP or CIDR"))?
                .iter()
                .map(|n| n.to_string())
                .collect::<Vec<_>>()
                .join(","),
        ),
    };

    let plaintext = db::users::create_pat(
        state.db(),
        &user.id,
        &req.name,
        &kind,
        org_id.as_deref(),
        app_id.as_deref(),
        max_perm,
        allowed_ips.as_deref(),
    )
    .await?;
    Ok(json_ok(
        json!({ "token": plaintext, "username": user.username }),
    ))
}

async fn delete_token(
    State(state): State<AppState>,
    SessionUser(user): SessionUser,
    Path(id): Path<String>,
) -> Result<Response> {
    db::users::delete_pat(state.db(), &user.id, &id).await?;
    Ok(json_ok(json!({ "ok": true })))
}

// ───────────────────── storage settings (instance admin) ─────────────────────

async fn get_storage_settings(
    State(state): State<AppState>,
    SessionUser(user): SessionUser,
) -> Result<Response> {
    if !user.is_admin {
        return Err(Error::Forbidden);
    }
    let cfg = db::settings::effective_storage(state.db(), &state.config().storage).await?;
    // The secret is never returned — only whether one is set.
    Ok(json_ok(json!({
        "endpoint": cfg.endpoint,
        "bucket": cfg.bucket,
        "region": cfg.region,
        "access_key_id": cfg.access_key_id,
        "secret_set": !cfg.secret_access_key.is_empty(),
        "cdn_url": cfg.cdn_url,
        "force_path_style": cfg.force_path_style,
        "presign_ttl_secs": cfg.presign_ttl_secs,
    })))
}

#[derive(Deserialize)]
struct StorageUpdate {
    #[serde(default)]
    endpoint: Option<String>,
    #[serde(default)]
    bucket: Option<String>,
    #[serde(default)]
    region: Option<String>,
    #[serde(default)]
    access_key_id: Option<String>,
    /// Empty/absent keeps the existing secret.
    #[serde(default)]
    secret_access_key: Option<String>,
    #[serde(default)]
    cdn_url: Option<String>,
    #[serde(default)]
    force_path_style: Option<bool>,
    #[serde(default)]
    presign_ttl_secs: Option<u64>,
}

async fn update_storage_settings(
    State(state): State<AppState>,
    SessionUser(user): SessionUser,
    Json(req): Json<StorageUpdate>,
) -> Result<Response> {
    if !user.is_admin {
        return Err(Error::Forbidden);
    }
    let db = state.db();
    if let Some(v) = req.endpoint {
        db::settings::set(db, "storage_endpoint", v.trim()).await?;
    }
    if let Some(v) = req.bucket {
        db::settings::set(db, "storage_bucket", v.trim()).await?;
    }
    if let Some(v) = req.region {
        db::settings::set(db, "storage_region", v.trim()).await?;
    }
    if let Some(v) = req.access_key_id {
        db::settings::set(db, "storage_access_key_id", v.trim()).await?;
    }
    if let Some(v) = req.secret_access_key {
        // Only overwrite the secret when a non-empty value is provided.
        if !v.is_empty() {
            db::settings::set(db, "storage_secret_access_key", &v).await?;
        }
    }
    if let Some(v) = req.cdn_url {
        db::settings::set(db, "storage_cdn_url", v.trim()).await?;
    }
    if let Some(v) = req.force_path_style {
        db::settings::set(
            db,
            "storage_force_path_style",
            if v { "true" } else { "false" },
        )
        .await?;
    }
    if let Some(v) = req.presign_ttl_secs {
        db::settings::set(db, "storage_presign_ttl_secs", &v.to_string()).await?;
    }

    // Rebuild + hot-swap the storage client so changes take effect immediately.
    let cfg = db::settings::effective_storage(db, &state.config().storage).await?;
    let storage = crate::storage::Storage::new(&cfg)
        .await
        .map_err(|e| Error::bad_request(format!("invalid storage settings: {e}")))?;
    state.set_storage(storage);

    db::audit::record(db, Some(&user.id), None, "storage.update", None, None)
        .await
        .ok();
    Ok(json_ok(json!({ "ok": true })))
}

// ───────────────────── sign-in settings (instance admin) ─────────────────────

async fn get_oauth_settings(
    State(state): State<AppState>,
    SessionUser(user): SessionUser,
    headers: HeaderMap,
) -> Result<Response> {
    if !user.is_admin {
        return Err(Error::Forbidden);
    }
    let cfg = oauth::load(state.db()).await?;
    Ok(json_ok(json!({
        "enabled": cfg.enabled,
        "client_id": cfg.client_id,
        "secret_set": !cfg.client_secret.is_empty(),
        "allowed_domain": cfg.allowed_domain,
        // The exact URI to register under "Authorized redirect URIs" in GCP.
        "redirect_uri": google_redirect_uri(&state, &headers),
    })))
}

#[derive(Deserialize)]
struct OAuthUpdate {
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default)]
    client_id: Option<String>,
    /// Empty/absent keeps the existing secret.
    #[serde(default)]
    client_secret: Option<String>,
    #[serde(default)]
    allowed_domain: Option<String>,
}

async fn update_oauth_settings(
    State(state): State<AppState>,
    SessionUser(user): SessionUser,
    Json(req): Json<OAuthUpdate>,
) -> Result<Response> {
    if !user.is_admin {
        return Err(Error::Forbidden);
    }
    let db = state.db();
    if let Some(v) = req.enabled {
        db::settings::set(db, "oauth_google_enabled", if v { "true" } else { "false" }).await?;
    }
    if let Some(v) = req.client_id {
        db::settings::set(db, "oauth_google_client_id", v.trim()).await?;
    }
    if let Some(v) = req.client_secret {
        if !v.is_empty() {
            db::settings::set(db, "oauth_google_client_secret", v.trim()).await?;
        }
    }
    if let Some(v) = req.allowed_domain {
        db::settings::set(
            db,
            "oauth_google_allowed_domain",
            &v.trim().to_ascii_lowercase(),
        )
        .await?;
    }
    db::audit::record(db, Some(&user.id), None, "oauth.update", None, None)
        .await
        .ok();
    Ok(json_ok(json!({ "ok": true })))
}

// ───────────────────────── audit ─────────────────────────

async fn list_audit(
    State(state): State<AppState>,
    SessionUser(user): SessionUser,
    Path(slug): Path<String>,
) -> Result<Response> {
    let (org, _) = admin_of(&state, &user.id, &slug).await?;
    let entries = db::audit::list(state.db(), &org.id, 200).await?;
    Ok(json_ok(json!({ "entries": entries })))
}

// ───────────────────── domains / TLS (instance admin) ─────────────────────

fn valid_domain(d: &str) -> bool {
    !d.is_empty()
        && d.len() <= 253
        && !d.starts_with('.')
        && !d.ends_with('.')
        && d.contains('.')
        && d.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
}

async fn list_domains(
    State(state): State<AppState>,
    SessionUser(user): SessionUser,
) -> Result<Response> {
    if !user.is_admin {
        return Err(Error::Forbidden);
    }
    let domains = db::domains::list(state.db()).await?;
    let tls = &state.config().tls;
    let contact_email =
        db::settings::effective_contact_email(state.db(), &tls.contact_email).await?;
    Ok(json_ok(json!({
        "domains": domains,
        "tls_enabled": tls.enabled,
        "contact_email": contact_email,
    })))
}

#[derive(Deserialize)]
struct TlsUpdate {
    /// ACME (Let's Encrypt) contact email used for expiry notices.
    contact_email: String,
}

async fn get_tls_settings(
    State(state): State<AppState>,
    SessionUser(user): SessionUser,
) -> Result<Response> {
    if !user.is_admin {
        return Err(Error::Forbidden);
    }
    let tls = &state.config().tls;
    let contact_email =
        db::settings::effective_contact_email(state.db(), &tls.contact_email).await?;
    Ok(json_ok(json!({
        "enabled": tls.enabled,
        "staging": tls.staging,
        "contact_email": contact_email,
    })))
}

async fn update_tls_settings(
    State(state): State<AppState>,
    SessionUser(user): SessionUser,
    Json(req): Json<TlsUpdate>,
) -> Result<Response> {
    if !user.is_admin {
        return Err(Error::Forbidden);
    }
    let email = req.contact_email.trim();
    // Light validation: empty clears it; otherwise require a plausible address.
    if !email.is_empty() && (!email.contains('@') || email.contains(char::is_whitespace)) {
        return Err(Error::bad_request("invalid contact email"));
    }
    db::settings::set(state.db(), "tls_contact_email", email).await?;
    db::audit::record(state.db(), Some(&user.id), None, "tls.update", None, None)
        .await
        .ok();
    // Pick up the new email on the next ACME (re)load (used when registering a
    // fresh Let's Encrypt account, e.g. before the first certificate).
    state.notify_domains_changed();
    Ok(json_ok(json!({ "ok": true })))
}

#[derive(Deserialize)]
struct AddDomainReq {
    domain: String,
}

async fn add_domain(
    State(state): State<AppState>,
    SessionUser(user): SessionUser,
    Json(req): Json<AddDomainReq>,
) -> Result<Response> {
    if !user.is_admin {
        return Err(Error::Forbidden);
    }
    let domain = req.domain.trim().to_ascii_lowercase();
    if !valid_domain(&domain) {
        return Err(Error::bad_request("invalid domain name"));
    }
    // A contact email is required so Let's Encrypt can reach the operator about
    // expiry/issues before a certificate is ever requested for this domain.
    let contact =
        db::settings::effective_contact_email(state.db(), &state.config().tls.contact_email)
            .await?;
    if contact.is_empty() {
        return Err(Error::bad_request(
            "set a Let's Encrypt contact email before adding a domain",
        ));
    }
    db::domains::add(state.db(), &domain).await?;
    // Refresh immediately after the commit so the effective public URL reflects
    // the new primary domain before any subsequent request observes it.
    state.refresh_public_url().await;
    db::audit::record(
        state.db(),
        Some(&user.id),
        None,
        "domain.add",
        Some(&domain),
        None,
    )
    .await
    .ok();
    state.notify_domains_changed();
    Ok(json_ok(json!({ "ok": true })))
}

async fn delete_domain(
    State(state): State<AppState>,
    SessionUser(user): SessionUser,
    Path(domain): Path<String>,
) -> Result<Response> {
    if !user.is_admin {
        return Err(Error::Forbidden);
    }
    db::domains::delete(state.db(), &domain).await?;
    state.refresh_public_url().await;
    db::audit::record(
        state.db(),
        Some(&user.id),
        None,
        "domain.remove",
        Some(&domain),
        None,
    )
    .await
    .ok();
    state.notify_domains_changed();
    Ok(json_ok(json!({ "ok": true })))
}

async fn set_primary_domain(
    State(state): State<AppState>,
    SessionUser(user): SessionUser,
    Path(domain): Path<String>,
) -> Result<Response> {
    if !user.is_admin {
        return Err(Error::Forbidden);
    }
    db::domains::set_primary(state.db(), &domain).await?;
    state.refresh_public_url().await;
    Ok(json_ok(json!({ "ok": true })))
}
