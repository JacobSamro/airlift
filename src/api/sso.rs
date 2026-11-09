//! SSO: provider management and the login flows.
//!
//! Management:
//!   GET/POST   /api/v1/sso/providers              instance-wide (instance admin)
//!   GET/POST   /api/v1/orgs/{slug}/sso            org-scoped (org admin)
//!   PATCH/DELETE /api/v1/sso/providers/{id}
//! Login (public):
//!   GET  /api/v1/auth/sso/discover?email=…        which provider handles a domain
//!   GET  /api/v1/auth/sso/{id}/login              → IdP
//!   GET  /api/v1/auth/sso/{id}/callback           OIDC redirect URI
//!   POST /api/v1/auth/sso/{id}/saml/acs           SAML ACS (HTTP-POST)
//!   GET  /api/v1/auth/sso/{id}/saml/metadata      SAML SP metadata (entity id)
//!
//! Trust model: instance-wide providers are configured by instance admins and
//! may sign in any account within their domains. Org providers are configured
//! by org admins, must list their domains, and may only sign in that org's
//! existing members (never instance admins) or provision new users into it —
//! so an org admin's IdP can't be used to take over accounts elsewhere.

use axum::extract::{Form, Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::Json;
use axum_extra::extract::cookie::CookieJar;
use serde::Deserialize;
use serde_json::{json, Value};

use super::json_ok;
use crate::auth::{session, SessionUser};
use crate::db;
use crate::error::{Error, Result};
use crate::models::OrgRole;
use crate::sso::{oidc, saml, xmldsig};
use crate::state::AppState;

// ───────────────────────── management ─────────────────────────

#[derive(Deserialize)]
pub struct ProviderReq {
    /// oidc | saml (create only).
    kind: Option<String>,
    name: String,
    #[serde(default = "yes")]
    enabled: bool,
    #[serde(default)]
    domains: Vec<String>,
    #[serde(default)]
    auto_provision: bool,
    default_role: Option<String>,
    /// oidc: {issuer, client_id, client_secret, scopes?, allow_unverified_email?}
    /// saml: {idp_sso_url, idp_entity_id?, idp_cert_pem}
    #[serde(default)]
    config: Value,
}
fn yes() -> bool {
    true
}

fn valid_domain(d: &str) -> bool {
    !d.is_empty()
        && d.len() <= 253
        && d.contains('.')
        && d.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
}

fn https_or_local(url: &str) -> bool {
    reqwest::Url::parse(url).is_ok_and(|u| {
        u.scheme() == "https"
            || (u.scheme() == "http"
                && matches!(u.host_str(), Some("localhost" | "127.0.0.1" | "[::1]")))
    })
}

/// Validate a request into the stored columns; `existing` keeps a secret the
/// admin didn't re-enter.
fn validate(
    req: &ProviderReq,
    kind: &str,
    org_scoped: bool,
    existing: Option<&db::sso::Provider>,
) -> Result<(String, String, String)> {
    if req.name.trim().is_empty() || req.name.len() > 80 {
        return Err(Error::bad_request("name required"));
    }
    let domains: Vec<String> = req
        .domains
        .iter()
        .map(|d| d.trim().trim_start_matches('@').to_ascii_lowercase())
        .filter(|d| !d.is_empty())
        .collect();
    if let Some(bad) = domains.iter().find(|d| !valid_domain(d)) {
        return Err(Error::bad_request(format!("invalid domain {bad}")));
    }
    if org_scoped && domains.is_empty() {
        return Err(Error::bad_request(
            "an org SSO provider must list the email domains it may sign in",
        ));
    }
    let role = req.default_role.as_deref().unwrap_or("member");
    if !matches!(role, "member" | "admin") {
        return Err(Error::bad_request("default_role: member | admin"));
    }
    let prev = existing.map(|p| p.config_json()).unwrap_or_default();
    let s = |k: &str| {
        req.config[k]
            .as_str()
            .map(|v| v.trim().to_string())
            .unwrap_or_default()
    };
    let config = match kind {
        "oidc" => {
            let issuer = s("issuer");
            if !https_or_local(&issuer) {
                return Err(Error::bad_request("issuer must be an https URL"));
            }
            if s("client_id").is_empty() {
                return Err(Error::bad_request("client_id required"));
            }
            let secret = match s("client_secret") {
                x if x.is_empty() => prev["client_secret"].as_str().unwrap_or("").to_string(),
                x => x,
            };
            if secret.is_empty() {
                return Err(Error::bad_request("client_secret required"));
            }
            let scopes = match s("scopes") {
                x if x.is_empty() => "openid email profile".to_string(),
                x if !x.split_whitespace().any(|s| s == "openid") => format!("openid {x}"),
                x => x,
            };
            json!({
                "issuer": issuer.trim_end_matches('/'),
                "client_id": s("client_id"),
                "client_secret": secret,
                "scopes": scopes,
                "allow_unverified_email": req.config["allow_unverified_email"].as_bool().unwrap_or(false),
            })
        }
        "saml" => {
            let sso_url = s("idp_sso_url");
            if !https_or_local(&sso_url) {
                return Err(Error::bad_request("idp_sso_url must be an https URL"));
            }
            let cert = s("idp_cert_pem");
            xmldsig::rsa_key_from_cert_pem(&cert)?;
            json!({
                "idp_sso_url": sso_url,
                "idp_entity_id": s("idp_entity_id"),
                "idp_cert_pem": cert,
            })
        }
        _ => return Err(Error::bad_request("kind: oidc | saml")),
    };
    Ok((domains.join(","), role.to_string(), config.to_string()))
}

/// Admin-facing view: no secrets; plus the URLs to give the IdP.
fn view(p: &db::sso::Provider, base: &str) -> Value {
    let mut cfg = p.config_json();
    let has_secret = cfg["client_secret"].as_str().is_some_and(|s| !s.is_empty());
    if let Some(o) = cfg.as_object_mut() {
        o.remove("client_secret");
    }
    let root = format!("{base}/api/v1/auth/sso/{}", p.id);
    json!({
        "id": p.id, "org_id": p.org_id, "kind": p.kind, "name": p.name,
        "enabled": p.enabled, "domains": p.domain_list(), "auto_provision": p.auto_provision,
        "default_role": p.default_role, "config": cfg, "has_client_secret": has_secret,
        "login_url": format!("{root}/login"),
        "oidc_redirect_uri": format!("{root}/callback"),
        "saml_acs_url": format!("{root}/saml/acs"),
        "saml_entity_id": format!("{root}/saml/metadata"),
        "created_at": p.created_at,
    })
}

/// Who may manage a provider: instance admins always; org admins for their
/// org's providers.
async fn can_manage(
    state: &AppState,
    user: &crate::models::User,
    org_id: Option<&str>,
) -> Result<bool> {
    if user.is_admin {
        return Ok(true);
    }
    Ok(match org_id {
        Some(o) => db::orgs::org_role(state.db(), o, &user.id)
            .await?
            .is_some_and(|r| r >= OrgRole::Admin),
        None => false,
    })
}

pub async fn list_instance(
    State(state): State<AppState>,
    SessionUser(user): SessionUser,
    headers: HeaderMap,
) -> Result<Response> {
    if !user.is_admin {
        return Err(Error::Forbidden);
    }
    let base = crate::auth::base_url(&state, &headers);
    let ps = db::sso::list(state.db(), None).await?;
    Ok(json_ok(
        json!({ "providers": ps.iter().map(|p| view(p, &base)).collect::<Vec<_>>() }),
    ))
}

pub async fn list_org(
    State(state): State<AppState>,
    SessionUser(user): SessionUser,
    Path(slug): Path<String>,
    headers: HeaderMap,
) -> Result<Response> {
    let (org, _) = super::admin_of(&state, &user.id, &slug).await?;
    let base = crate::auth::base_url(&state, &headers);
    let ps = db::sso::list(state.db(), Some(&org.id)).await?;
    Ok(json_ok(
        json!({ "providers": ps.iter().map(|p| view(p, &base)).collect::<Vec<_>>() }),
    ))
}

async fn create(
    state: &AppState,
    user: &crate::models::User,
    org_id: Option<&str>,
    req: ProviderReq,
    headers: &HeaderMap,
) -> Result<Response> {
    let kind = req.kind.clone().unwrap_or_default();
    let (domains, role, config) = validate(&req, &kind, org_id.is_some(), None)?;
    let id = db::sso::create(
        state.db(),
        &db::sso::NewProvider {
            org_id,
            kind: &kind,
            name: req.name.trim(),
            enabled: req.enabled,
            domains: &domains,
            auto_provision: req.auto_provision,
            default_role: &role,
            config: &config,
        },
    )
    .await?;
    db::audit::record(
        state.db(),
        Some(&user.id),
        org_id,
        "sso.create",
        Some(&id),
        Some(&kind),
    )
    .await
    .ok();
    let p = db::sso::find(state.db(), &id)
        .await?
        .ok_or(Error::NotFound)?;
    let base = crate::auth::base_url(state, headers);
    Ok((
        StatusCode::CREATED,
        Json(json!({ "provider": view(&p, &base) })),
    )
        .into_response())
}

pub async fn create_instance(
    State(state): State<AppState>,
    SessionUser(user): SessionUser,
    headers: HeaderMap,
    Json(req): Json<ProviderReq>,
) -> Result<Response> {
    if !user.is_admin {
        return Err(Error::Forbidden);
    }
    create(&state, &user, None, req, &headers).await
}

pub async fn create_org(
    State(state): State<AppState>,
    SessionUser(user): SessionUser,
    Path(slug): Path<String>,
    headers: HeaderMap,
    Json(req): Json<ProviderReq>,
) -> Result<Response> {
    let (org, _) = super::admin_of(&state, &user.id, &slug).await?;
    create(&state, &user, Some(&org.id), req, &headers).await
}

pub async fn update(
    State(state): State<AppState>,
    SessionUser(user): SessionUser,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(req): Json<ProviderReq>,
) -> Result<Response> {
    let p = db::sso::find(state.db(), &id)
        .await?
        .ok_or(Error::NotFound)?;
    if !can_manage(&state, &user, p.org_id.as_deref()).await? {
        return Err(Error::NotFound);
    }
    let (domains, role, config) = validate(&req, &p.kind, p.org_id.is_some(), Some(&p))?;
    db::sso::update(
        state.db(),
        &id,
        &db::sso::NewProvider {
            org_id: p.org_id.as_deref(),
            kind: &p.kind,
            name: req.name.trim(),
            enabled: req.enabled,
            domains: &domains,
            auto_provision: req.auto_provision,
            default_role: &role,
            config: &config,
        },
    )
    .await?;
    db::audit::record(
        state.db(),
        Some(&user.id),
        p.org_id.as_deref(),
        "sso.update",
        Some(&id),
        None,
    )
    .await
    .ok();
    let p = db::sso::find(state.db(), &id)
        .await?
        .ok_or(Error::NotFound)?;
    Ok(json_ok(
        json!({ "provider": view(&p, &crate::auth::base_url(&state, &headers)) }),
    ))
}

pub async fn delete(
    State(state): State<AppState>,
    SessionUser(user): SessionUser,
    Path(id): Path<String>,
) -> Result<Response> {
    let p = db::sso::find(state.db(), &id)
        .await?
        .ok_or(Error::NotFound)?;
    if !can_manage(&state, &user, p.org_id.as_deref()).await? {
        return Err(Error::NotFound);
    }
    db::sso::delete(state.db(), &id).await?;
    db::audit::record(
        state.db(),
        Some(&user.id),
        p.org_id.as_deref(),
        "sso.delete",
        Some(&id),
        None,
    )
    .await
    .ok();
    Ok(json_ok(json!({ "ok": true })))
}

// ───────────────────────── login flows ─────────────────────────

#[derive(Deserialize)]
pub struct DiscoverQuery {
    email: String,
}

/// Which provider handles an email's domain (for the login page's "Continue
/// with SSO"). Only says whether SSO applies and its name.
pub async fn discover(
    State(state): State<AppState>,
    Query(q): Query<DiscoverQuery>,
) -> Result<Response> {
    let domain = q
        .email
        .rsplit_once('@')
        .map(|(_, d)| d.trim().to_ascii_lowercase())
        .ok_or_else(|| Error::bad_request("enter your work email"))?;
    let p = db::sso::for_domain(state.db(), &domain)
        .await?
        .into_iter()
        .next()
        .ok_or(Error::NotFound)?;
    Ok(json_ok(
        json!({ "provider_id": p.id, "name": p.name, "kind": p.kind }),
    ))
}

/// Send the browser back to the login page with a reason.
fn fail(msg: &str) -> Response {
    let mut url = reqwest::Url::parse("http://x/login").expect("static");
    url.query_pairs_mut()
        .append_pair("error", "sso")
        .append_pair("message", msg);
    Redirect::to(&format!("/login?{}", url.query().unwrap_or(""))).into_response()
}

fn sp_urls(state: &AppState, headers: &HeaderMap, id: &str) -> (String, String, String) {
    let root = format!(
        "{}/api/v1/auth/sso/{id}",
        crate::auth::base_url(state, headers)
    );
    (
        format!("{root}/callback"),
        format!("{root}/saml/acs"),
        format!("{root}/saml/metadata"),
    )
}

pub async fn login(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    match login_inner(&state, &id, &headers).await {
        Ok(url) => Redirect::to(&url).into_response(),
        Err(e) => {
            tracing::warn!(error = %e, provider = %id, "sso login start failed");
            fail(&e.to_string())
        }
    }
}

async fn login_inner(state: &AppState, id: &str, headers: &HeaderMap) -> Result<String> {
    let p = db::sso::find(state.db(), id)
        .await?
        .filter(|p| p.enabled)
        .ok_or_else(|| Error::bad_request("this SSO provider is not available"))?;
    let cfg = p.config_json();
    let (redirect_uri, acs, entity) = sp_urls(state, headers, id);
    match p.kind.as_str() {
        "oidc" => {
            let d = oidc::discover(cfg["issuer"].as_str().unwrap_or("")).await?;
            let (verifier, challenge) = oidc::pkce();
            let nonce = crate::util::random_id();
            let st = db::sso::create_request(state.db(), id, Some(&nonce), Some(&verifier), None)
                .await?;
            oidc::authorize_url(
                &d,
                &oidc::Client {
                    client_id: cfg["client_id"].as_str().unwrap_or(""),
                    client_secret: "",
                    redirect_uri: &redirect_uri,
                    scopes: cfg["scopes"].as_str().unwrap_or("openid email profile"),
                },
                &st,
                &nonce,
                &challenge,
            )
        }
        "saml" => {
            let request_id = format!("_{}", uuid::Uuid::new_v4().simple());
            let st = db::sso::create_request(state.db(), id, None, None, Some(&request_id)).await?;
            saml::authn_redirect(
                &saml::ServiceProvider {
                    entity_id: &entity,
                    acs_url: &acs,
                },
                cfg["idp_sso_url"].as_str().unwrap_or(""),
                &request_id,
                &st,
            )
        }
        _ => Err(Error::bad_request("unknown provider kind")),
    }
}

#[derive(Deserialize)]
pub struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

pub async fn oidc_callback(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    jar: CookieJar,
    Query(q): Query<CallbackQuery>,
) -> Response {
    let res = async {
        if let Some(e) = q.error {
            return Err(Error::bad_request(format!(
                "IdP refused: {}",
                q.error_description.unwrap_or(e)
            )));
        }
        let req = db::sso::take_request(state.db(), q.state.as_deref().unwrap_or(""))
            .await?
            .filter(|r| r.provider_id == id)
            .ok_or_else(|| Error::bad_request("login expired or already used; try again"))?;
        let p = db::sso::find(state.db(), &id)
            .await?
            .filter(|p| p.enabled && p.kind == "oidc")
            .ok_or(Error::NotFound)?;
        let cfg = p.config_json();
        let d = oidc::discover(cfg["issuer"].as_str().unwrap_or("")).await?;
        let (redirect_uri, _, _) = sp_urls(&state, &headers, &id);
        let client = oidc::Client {
            client_id: cfg["client_id"].as_str().unwrap_or(""),
            client_secret: cfg["client_secret"].as_str().unwrap_or(""),
            redirect_uri: &redirect_uri,
            scopes: "",
        };
        let token = oidc::exchange(
            &d,
            &client,
            q.code.as_deref().unwrap_or(""),
            req.pkce_verifier.as_deref().unwrap_or(""),
        )
        .await?;
        let claims = oidc::verify(
            &d,
            &token,
            client.client_id,
            req.nonce.as_deref().unwrap_or(""),
        )
        .await?;
        let email = claims.email.ok_or_else(|| {
            Error::bad_request("the IdP sent no email (add the email scope/claim)")
        })?;
        if !claims.email_verified && !cfg["allow_unverified_email"].as_bool().unwrap_or(false) {
            return Err(Error::bad_request(
                "the IdP did not mark this email as verified",
            ));
        }
        complete_login(&state, &p, &email, claims.name.as_deref(), jar).await
    }
    .await;
    res.unwrap_or_else(|e| {
        tracing::warn!(error = %e, provider = %id, "oidc sign-in failed");
        fail(&e.to_string())
    })
}

#[derive(Deserialize)]
pub struct AcsForm {
    #[serde(rename = "SAMLResponse")]
    saml_response: String,
    #[serde(rename = "RelayState")]
    relay_state: Option<String>,
}

pub async fn saml_acs(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    jar: CookieJar,
    Form(form): Form<AcsForm>,
) -> Response {
    let res = async {
        // RelayState carries our request; IdP-initiated (unsolicited)
        // logins are refused — they can't be bound to a request.
        let req = db::sso::take_request(state.db(), form.relay_state.as_deref().unwrap_or(""))
            .await?
            .filter(|r| r.provider_id == id)
            .ok_or_else(|| {
                Error::bad_request(
                    "login expired, already used, or IdP-initiated; start from airlift",
                )
            })?;
        let p = db::sso::find(state.db(), &id)
            .await?
            .filter(|p| p.enabled && p.kind == "saml")
            .ok_or(Error::NotFound)?;
        let cfg = p.config_json();
        let key = xmldsig::rsa_key_from_cert_pem(cfg["idp_cert_pem"].as_str().unwrap_or(""))?;
        let (_, acs, entity) = sp_urls(&state, &headers, &id);
        let identity = saml::validate_response(
            &form.saml_response,
            &saml::Expect {
                sp: saml::ServiceProvider {
                    entity_id: &entity,
                    acs_url: &acs,
                },
                request_id: req.saml_request_id.as_deref().unwrap_or(""),
                idp_entity_id: cfg["idp_entity_id"].as_str(),
                idp_key: &key,
                now: time::OffsetDateTime::now_utc(),
            },
        )?;
        complete_login(&state, &p, &identity.email, identity.name.as_deref(), jar).await
    }
    .await;
    res.unwrap_or_else(|e| {
        tracing::warn!(error = %e, provider = %id, "saml sign-in failed");
        fail(&e.to_string())
    })
}

pub async fn saml_metadata(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Response> {
    db::sso::find(state.db(), &id)
        .await?
        .filter(|p| p.kind == "saml")
        .ok_or(Error::NotFound)?;
    let (_, acs, entity) = sp_urls(&state, &headers, &id);
    let xml = saml::metadata(&saml::ServiceProvider {
        entity_id: &entity,
        acs_url: &acs,
    });
    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/samlmetadata+xml")],
        xml,
    )
        .into_response())
}

/// Map a verified IdP identity to an airlift account and sign it in.
async fn complete_login(
    state: &AppState,
    p: &db::sso::Provider,
    email: &str,
    name: Option<&str>,
    jar: CookieJar,
) -> Result<Response> {
    let email = email.trim().to_ascii_lowercase();
    let domain = email.rsplit_once('@').map(|(_, d)| d).unwrap_or("");
    let domains = p.domain_list();
    if !domains.is_empty() && !domains.iter().any(|d| d == domain) {
        return Err(Error::bad_request(format!(
            "{domain} is not an allowed domain for this SSO provider"
        )));
    }
    let existing = db::users::find_by_email(state.db(), &email).await?;
    let user = match (existing, &p.org_id) {
        (Some(u), None) => u,
        (Some(u), Some(org_id)) => {
            // Org IdPs can't sign in instance admins or other orgs' users.
            if u.is_admin {
                return Err(Error::bad_request(
                    "instance admins can't use an organization's SSO; use password or instance SSO",
                ));
            }
            match db::orgs::org_role(state.db(), org_id, &u.id).await? {
                Some(_) => u,
                None if p.auto_provision => {
                    let role = OrgRole::parse(&p.default_role).unwrap_or(OrgRole::Member);
                    db::orgs::add_org_member(state.db(), org_id, &u.id, role).await?;
                    u
                }
                None => {
                    return Err(Error::bad_request(
                        "your account isn't a member of this organization",
                    ))
                }
            }
        }
        (None, _) if !p.auto_provision => {
            return Err(Error::bad_request(
                "no airlift account for this email; ask an admin to invite you",
            ))
        }
        (None, org_id) => {
            let u = super::provision_oauth_user(state.db(), &email, name.unwrap_or("")).await?;
            if let Some(org_id) = org_id {
                let role = OrgRole::parse(&p.default_role).unwrap_or(OrgRole::Member);
                db::orgs::add_org_member(state.db(), org_id, &u.id, role).await?;
            }
            u
        }
    };
    let ttl = state.config().auth.session_ttl_secs as i64;
    let sid = db::users::create_session(state.db(), &user.id, ttl).await?;
    db::audit::record(
        state.db(),
        Some(&user.id),
        p.org_id.as_deref(),
        "auth.sso_login",
        Some(&user.username),
        Some(&p.name),
    )
    .await
    .ok();
    let jar = jar.add(session::build_cookie(sid, ttl, state.cookie_secure()));
    Ok((jar, Redirect::to("/")).into_response())
}
