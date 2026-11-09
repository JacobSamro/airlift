//! App, branch, and channel management endpoints (`/api/v1/orgs/{slug}/apps…`).
//! Authenticated by session cookie or PAT (`ApiUser`); every app-scoped call
//! goes through `auth::rbac` so token scope + permission caps hold everywhere.

use axum::{
    extract::{Path, Query, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use serde_json::json;

use crate::auth::{rbac, ApiUser};
use crate::db;
use crate::error::{Error, Result};
use crate::models::{OrgRole, Permission, TokenScope};
use crate::state::AppState;

use super::{json_ok, valid_slug};

/// Resolve `{org}/{app}` and require `needed` permission for the caller.
async fn resolve_app(
    state: &AppState,
    caller: &ApiUser,
    org_slug: &str,
    app_slug: &str,
    needed: Permission,
) -> Result<(db::orgs::Org, db::apps::App)> {
    let org = db::orgs::find_org_by_slug(state.db(), org_slug)
        .await?
        .ok_or(Error::NotFound)?;
    let app = db::apps::find_by_slug(state.db(), &org.id, app_slug)
        .await?
        .ok_or(Error::NotFound)?;
    rbac::require(state.db(), caller, &app, needed).await?;
    Ok((org, app))
}

// ───────────────────────── apps ─────────────────────────

pub async fn list_apps(
    State(state): State<AppState>,
    caller: ApiUser,
    Path(slug): Path<String>,
) -> Result<Response> {
    let org = db::orgs::find_org_by_slug(state.db(), &slug)
        .await?
        .ok_or(Error::NotFound)?;
    // Not a member (or a token scoped elsewhere): no visibility → 404.
    db::orgs::org_role(state.db(), &org.id, &caller.user.id)
        .await?
        .ok_or(Error::NotFound)?;
    if matches!(&caller.scope, TokenScope::Org(oid) if *oid != org.id) {
        return Err(Error::NotFound);
    }
    // Only apps the caller can actually read (org role / team grants ∩ token
    // scope ∩ cap). App ids are the public protocol URL segment, so listing
    // an app the caller has no grant on would leak its manifests.
    let mut apps = Vec::new();
    for app in db::apps::list(state.db(), &org.id).await? {
        if rbac::app_permission(state.db(), &caller, &app).await? >= Permission::Read {
            apps.push(app);
        }
    }
    Ok(json_ok(json!({ "apps": apps })))
}

#[derive(Deserialize)]
pub struct CreateAppReq {
    slug: String,
    name: String,
}

pub async fn create_app(
    State(state): State<AppState>,
    caller: ApiUser,
    Path(slug): Path<String>,
    Json(req): Json<CreateAppReq>,
) -> Result<Response> {
    let (org, _role) = super::admin_of(&state, &caller.user.id, &slug).await?;
    if caller.cap < Permission::Admin {
        return Err(Error::Forbidden);
    }
    // Token resource scope: only unscoped or this-org tokens may create apps
    // (an app-scoped token can't mint new apps, even in its own org).
    match &caller.scope {
        TokenScope::All => {}
        TokenScope::Org(oid) if *oid == org.id => {}
        _ => return Err(Error::Forbidden),
    }
    if !valid_slug(&req.slug) {
        return Err(Error::bad_request(
            "invalid app slug (lowercase letters, digits, hyphens)",
        ));
    }
    if db::apps::find_by_slug(state.db(), &org.id, &req.slug)
        .await?
        .is_some()
    {
        return Err(Error::conflict("app slug already taken"));
    }

    // RSA keygen is CPU-bound; keep it off the async worker.
    let cn = format!("airlift: {}/{}", org.slug, req.slug);
    let identity = tokio::task::spawn_blocking(move || crate::keys::generate(&cn))
        .await
        .map_err(|e| Error::Other(anyhow::anyhow!("keygen task: {e}")))??;

    let app = db::apps::create(
        state.db(),
        &org.id,
        &req.slug,
        &req.name,
        &identity.private_key_pem,
        &identity.certificate_pem,
    )
    .await?;
    db::audit::record(
        state.db(),
        Some(&caller.user.id),
        Some(&org.id),
        "app.create",
        Some(&req.slug),
        None,
    )
    .await
    .ok();
    Ok((StatusCode::CREATED, Json(json!({ "app": app }))).into_response())
}

pub async fn get_app(
    State(state): State<AppState>,
    caller: ApiUser,
    Path((slug, app_slug)): Path<(String, String)>,
) -> Result<Response> {
    let (_org, app) = resolve_app(&state, &caller, &slug, &app_slug, Permission::Read).await?;
    let branches = db::updates::list_branches(state.db(), &app.id).await?;
    let channels = db::updates::list_channels(state.db(), &app.id).await?;
    let mut channel_views = Vec::with_capacity(channels.len());
    for ch in channels {
        let releases = db::updates::releases_for_channel(state.db(), &ch.id).await?;
        let releases: Vec<_> = releases
            .into_iter()
            .map(|r| {
                json!({
                    "runtime_version": r.runtime_version,
                    "group_id": r.group_id,
                    "released_at": r.released_at,
                    "rollout_percent": r.rollout_percent,
                    "previous_group_id": r.previous_group_id,
                })
            })
            .collect();
        let branch_name = match &ch.branch_id {
            Some(bid) => branches
                .iter()
                .find(|b| &b.id == bid)
                .map(|b| b.name.clone()),
            None => None,
        };
        channel_views.push(json!({
            "id": ch.id,
            "name": ch.name,
            "branch_id": ch.branch_id,
            "branch": branch_name,
            "auto_release": ch.auto_release,
            "releases": releases,
        }));
    }
    Ok(json_ok(json!({
        "app": app,
        "branches": branches,
        "channels": channel_views,
    })))
}

pub async fn delete_app(
    State(state): State<AppState>,
    caller: ApiUser,
    Path((slug, app_slug)): Path<(String, String)>,
) -> Result<Response> {
    let (org, app) = resolve_app(&state, &caller, &slug, &app_slug, Permission::Admin).await?;
    // Only org owners may delete an app outright.
    let role = db::orgs::org_role(state.db(), &org.id, &caller.user.id).await?;
    if role != Some(OrgRole::Owner) && !caller.user.is_admin {
        return Err(Error::Forbidden);
    }
    db::apps::delete(state.db(), &org.id, &app.id).await?;
    db::audit::record(
        state.db(),
        Some(&caller.user.id),
        Some(&org.id),
        "app.delete",
        Some(&app.slug),
        None,
    )
    .await
    .ok();
    Ok(json_ok(json!({ "ok": true })))
}

/// The app's code-signing certificate (PEM). Embedded in the app binary via
/// `updates.codeSigningCertificate` by the CLI's `init`.
pub async fn get_certificate(
    State(state): State<AppState>,
    caller: ApiUser,
    Path((slug, app_slug)): Path<(String, String)>,
) -> Result<Response> {
    let (_org, app) = resolve_app(&state, &caller, &slug, &app_slug, Permission::Read).await?;
    Ok((
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/x-pem-file".to_string()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{}-certificate.pem\"", app.slug),
            ),
        ],
        app.certificate_pem,
    )
        .into_response())
}

// ───────────────────────── updates listing ─────────────────────────

#[derive(Deserialize)]
pub struct ListUpdatesQuery {
    branch: Option<String>,
    runtime: Option<String>,
    #[serde(default)]
    limit: Option<i64>,
}

pub async fn list_updates(
    State(state): State<AppState>,
    caller: ApiUser,
    Path((slug, app_slug)): Path<(String, String)>,
    Query(q): Query<ListUpdatesQuery>,
) -> Result<Response> {
    let (_org, app) = resolve_app(&state, &caller, &slug, &app_slug, Permission::Read).await?;
    let limit = q.limit.unwrap_or(30).clamp(1, 200);

    let branch_id = match &q.branch {
        Some(name) => Some(
            db::updates::find_branch(state.db(), &app.id, name)
                .await?
                .ok_or(Error::NotFound)?
                .id,
        ),
        None => None,
    };

    let rows = db::updates::list_groups(
        state.db(),
        &app.id,
        branch_id.as_deref(),
        q.runtime.as_deref(),
        limit,
    )
    .await?;
    let groups_json: Vec<_> = rows.iter().map(group_json).collect();
    Ok(json_ok(json!({ "updates": groups_json })))
}

/// Dashboard/CLI-facing JSON for one update group.
fn group_json(row: &db::updates::GroupListing) -> serde_json::Value {
    let g = &row.group;
    let platforms: Vec<&str> = row
        .platforms
        .as_deref()
        .map(|p| p.split(',').collect())
        .unwrap_or_default();
    json!({
        "id": g.id,
        "branch": row.branch_name,
        "runtime_version": g.runtime_version,
        "message": g.message,
        "git_branch": g.git_branch,
        "git_commit": g.git_commit,
        "group_type": g.group_type,
        "platforms": platforms,
        "created_at": g.created_at,
    })
}

// ───────────────────────── monitoring ─────────────────────────

/// Adoption + activity stats for an app: devices per update (14-day window)
/// and the daily manifest-request series (30 days).
pub async fn app_stats(
    State(state): State<AppState>,
    caller: ApiUser,
    Path((slug, app_slug)): Path<(String, String)>,
) -> Result<Response> {
    let (_org, app) = resolve_app(&state, &caller, &slug, &app_slug, Permission::Read).await?;
    let adoption = db::clients::adoption(state.db(), &app.id).await?;
    let series = db::clients::checkin_series(state.db(), &app.id, 30).await?;
    let total_devices: i64 = adoption.iter().map(|a| a.devices).sum();
    Ok(json_ok(json!({
        "adoption": adoption,
        "series": series,
        "total_devices": total_devices,
    })))
}

/// Recently-seen devices for an app.
pub async fn app_clients(
    State(state): State<AppState>,
    caller: ApiUser,
    Path((slug, app_slug)): Path<(String, String)>,
) -> Result<Response> {
    let (_org, app) = resolve_app(&state, &caller, &slug, &app_slug, Permission::Read).await?;
    let clients = db::clients::list_clients(state.db(), &app.id, 200).await?;
    Ok(json_ok(json!({ "clients": clients })))
}

// ───────────────────────── channels ─────────────────────────

#[derive(Deserialize)]
pub struct CreateChannelReq {
    name: String,
    /// Branch name to point the channel at (created if missing).
    branch: Option<String>,
    #[serde(default = "default_true")]
    auto_release: bool,
}
fn default_true() -> bool {
    true
}

pub async fn create_channel(
    State(state): State<AppState>,
    caller: ApiUser,
    Path((slug, app_slug)): Path<(String, String)>,
    Json(req): Json<CreateChannelReq>,
) -> Result<Response> {
    let (_org, app) = resolve_app(&state, &caller, &slug, &app_slug, Permission::Admin).await?;
    let name = req.name.trim();
    if name.is_empty() || name.len() > 64 {
        return Err(Error::bad_request("invalid channel name"));
    }
    if db::updates::find_channel(state.db(), &app.id, name)
        .await?
        .is_some()
    {
        return Err(Error::conflict("channel already exists"));
    }
    let branch_id = match &req.branch {
        Some(b) => Some(db::updates::ensure_branch(state.db(), &app.id, b).await?.id),
        None => None,
    };
    let ch = db::updates::create_channel(
        state.db(),
        &app.id,
        name,
        branch_id.as_deref(),
        req.auto_release,
    )
    .await?;
    Ok((StatusCode::CREATED, Json(json!({ "channel": ch }))).into_response())
}

#[derive(Deserialize)]
pub struct UpdateChannelReq {
    /// Repoint the channel at another branch (by name).
    branch: Option<String>,
    auto_release: Option<bool>,
}

pub async fn update_channel(
    State(state): State<AppState>,
    caller: ApiUser,
    Path((slug, app_slug, channel)): Path<(String, String, String)>,
    Json(req): Json<UpdateChannelReq>,
) -> Result<Response> {
    let (_org, app) = resolve_app(&state, &caller, &slug, &app_slug, Permission::Admin).await?;
    let ch = db::updates::find_channel(state.db(), &app.id, &channel)
        .await?
        .ok_or(Error::NotFound)?;
    let branch_id = match &req.branch {
        Some(b) => {
            let branch = db::updates::find_branch(state.db(), &app.id, b)
                .await?
                .ok_or_else(|| Error::bad_request("no such branch"))?;
            Some(branch.id)
        }
        None => None,
    };
    db::updates::update_channel(state.db(), &ch.id, branch_id.as_deref(), req.auto_release).await?;
    // Repointing serves the new branch's heads right away (the manifest reads
    // `channel_releases`, not `branch_id`). Runtimes the new branch has never
    // published lose their pointer rather than keep serving the old branch.
    if let Some(new_branch) = branch_id
        .as_deref()
        .filter(|b| ch.branch_id.as_deref() != Some(*b))
    {
        let runtimes = db::updates::branch_runtime_versions(state.db(), new_branch).await?;
        for rv in db::updates::releases_for_channel(state.db(), &ch.id)
            .await?
            .into_iter()
            .map(|r| r.runtime_version)
        {
            if !runtimes.contains(&rv) {
                db::updates::delete_channel_release(state.db(), &ch.id, &rv).await?;
            }
        }
        for rv in runtimes {
            if let Some(head) = db::updates::head_group(state.db(), new_branch, &rv).await? {
                let head = db::updates::fresh_for_channel(state.db(), &ch.id, &head).await?;
                db::updates::set_channel_release(state.db(), &ch.id, &rv, &head.id).await?;
            }
        }
    }
    db::audit::record(
        state.db(),
        Some(&caller.user.id),
        Some(&app.org_id),
        "channel.update",
        Some(&format!("{}/{}", app.slug, ch.name)),
        req.branch.as_deref(),
    )
    .await
    .ok();
    Ok(json_ok(json!({ "ok": true })))
}

pub async fn delete_channel(
    State(state): State<AppState>,
    caller: ApiUser,
    Path((slug, app_slug, channel)): Path<(String, String, String)>,
) -> Result<Response> {
    let (_org, app) = resolve_app(&state, &caller, &slug, &app_slug, Permission::Admin).await?;
    let ch = db::updates::find_channel(state.db(), &app.id, &channel)
        .await?
        .ok_or(Error::NotFound)?;
    db::updates::delete_channel(state.db(), &app.id, &ch.id).await?;
    Ok(json_ok(json!({ "ok": true })))
}

// ───────────────────── promote / rollback ─────────────────────

#[derive(Deserialize)]
pub struct PromoteReq {
    group_id: String,
}

/// Point the channel's release pointer at a specific update group (gated
/// releases, or re-releasing any historical group).
pub async fn promote(
    State(state): State<AppState>,
    caller: ApiUser,
    Path((slug, app_slug, channel)): Path<(String, String, String)>,
    Json(req): Json<PromoteReq>,
) -> Result<Response> {
    let (_org, app) = resolve_app(&state, &caller, &slug, &app_slug, Permission::Publish).await?;
    let ch = db::updates::find_channel(state.db(), &app.id, &channel)
        .await?
        .ok_or(Error::NotFound)?;
    let group = db::updates::find_group(state.db(), &req.group_id)
        .await?
        .ok_or_else(|| Error::bad_request("no such update group"))?;
    // The group must belong to this app (any branch — promoting across
    // branches is exactly the staging→production flow).
    let branches = db::updates::list_branches(state.db(), &app.id).await?;
    if !branches.iter().any(|b| b.id == group.branch_id) {
        return Err(Error::bad_request("update group belongs to another app"));
    }
    // Re-releasing a group older than what the channel serves needs a fresh
    // identity, or devices that already have the newer one ignore it.
    let group = db::updates::fresh_for_channel(state.db(), &ch.id, &group).await?;
    db::updates::set_channel_release(state.db(), &ch.id, &group.runtime_version, &group.id).await?;
    db::audit::record(
        state.db(),
        Some(&caller.user.id),
        Some(&app.org_id),
        "channel.promote",
        Some(&format!("{}/{}", app.slug, ch.name)),
        Some(&group.id),
    )
    .await
    .ok();
    Ok(json_ok(
        json!({ "ok": true, "runtime_version": group.runtime_version, "group_id": group.id }),
    ))
}

// ───────────────────── progressive rollouts ─────────────────────

#[derive(Deserialize)]
pub struct StartRolloutReq {
    group_id: String,
    /// Share of the fleet (0 < p < 100) that gets the group; 100 = promote.
    percent: f64,
}

/// Release a group to only part of the fleet. Devices outside keep the last
/// full release; grow it with PATCH, revert it with rollback.
pub async fn start_rollout(
    State(state): State<AppState>,
    caller: ApiUser,
    Path((slug, app_slug, channel)): Path<(String, String, String)>,
    Json(req): Json<StartRolloutReq>,
) -> Result<Response> {
    let (_org, app) = resolve_app(&state, &caller, &slug, &app_slug, Permission::Publish).await?;
    let pct = valid_percent(req.percent)?;
    let ch = db::updates::find_channel(state.db(), &app.id, &channel)
        .await?
        .ok_or(Error::NotFound)?;
    let group = db::updates::find_group(state.db(), &req.group_id)
        .await?
        .ok_or_else(|| Error::bad_request("no such update group"))?;
    let branches = db::updates::list_branches(state.db(), &app.id).await?;
    if !branches.iter().any(|b| b.id == group.branch_id) {
        return Err(Error::bad_request("update group belongs to another app"));
    }
    let group = db::updates::fresh_for_channel(state.db(), &ch.id, &group).await?;
    let mut tx = state.db().begin_with("BEGIN IMMEDIATE").await?;
    if pct >= 100.0 {
        db::updates::set_channel_release_tx(&mut tx, &ch.id, &group.runtime_version, &group.id)
            .await?;
    } else {
        db::updates::start_rollout_tx(&mut tx, &ch.id, &group.runtime_version, &group.id, pct)
            .await?;
    }
    tx.commit().await?;
    db::audit::record(
        state.db(),
        Some(&caller.user.id),
        Some(&app.org_id),
        "channel.rollout",
        Some(&format!("{}/{}", app.slug, ch.name)),
        Some(&format!("{} {pct}%", group.id)),
    )
    .await
    .ok();
    Ok(json_ok(json!({
        "ok": true,
        "group_id": group.id,
        "runtime_version": group.runtime_version,
        "percent": pct,
    })))
}

#[derive(Deserialize)]
pub struct SetRolloutReq {
    runtime_version: String,
    /// New share; 100 completes the rollout (full release).
    percent: f64,
}

/// Grow (or shrink) a running rollout. Devices already inside stay inside
/// when it grows; shrinking only stops offering it to devices that haven't
/// taken it yet (to pull it from devices, roll back).
pub async fn set_rollout(
    State(state): State<AppState>,
    caller: ApiUser,
    Path((slug, app_slug, channel)): Path<(String, String, String)>,
    Json(req): Json<SetRolloutReq>,
) -> Result<Response> {
    let (_org, app) = resolve_app(&state, &caller, &slug, &app_slug, Permission::Publish).await?;
    let pct = valid_percent(req.percent)?;
    let ch = db::updates::find_channel(state.db(), &app.id, &channel)
        .await?
        .ok_or(Error::NotFound)?;
    if !db::updates::set_rollout_percent(state.db(), &ch.id, &req.runtime_version, pct).await? {
        return Err(Error::bad_request(
            "no rollout is running on this channel for that runtime version",
        ));
    }
    db::audit::record(
        state.db(),
        Some(&caller.user.id),
        Some(&app.org_id),
        "channel.rollout",
        Some(&format!("{}/{}", app.slug, ch.name)),
        Some(&format!("{} {pct}%", req.runtime_version)),
    )
    .await
    .ok();
    Ok(json_ok(
        json!({ "ok": true, "percent": pct, "complete": pct >= 100.0 }),
    ))
}

fn valid_percent(p: f64) -> Result<f64> {
    if p.is_finite() && p > 0.0 && p <= 100.0 {
        Ok(p)
    } else {
        Err(Error::bad_request("percent must be in (0, 100]"))
    }
}

#[derive(Deserialize)]
pub struct RollbackReq {
    runtime_version: String,
}

/// Step the channel's pointer back to the group published before the one it
/// currently serves (for one runtime version).
pub async fn rollback(
    State(state): State<AppState>,
    caller: ApiUser,
    Path((slug, app_slug, channel)): Path<(String, String, String)>,
    Json(req): Json<RollbackReq>,
) -> Result<Response> {
    let (_org, app) = resolve_app(&state, &caller, &slug, &app_slug, Permission::Publish).await?;
    let ch = db::updates::find_channel(state.db(), &app.id, &channel)
        .await?
        .ok_or(Error::NotFound)?;
    db::updates::channel_release(state.db(), &ch.id, &req.runtime_version)
        .await?
        .ok_or_else(|| Error::bad_request("channel has no release for this runtime version"))?;
    // Step back through what THIS channel shipped (not the branch's publish
    // order), and serve it under a fresh identity so devices already running
    // the newer update actually switch back.
    let (current_hist, target_hist, target) =
        db::updates::previous_release(state.db(), &ch.id, &req.runtime_version)
            .await?
            .ok_or_else(|| Error::bad_request("no earlier release to roll back to"))?;
    let previous = db::updates::republish_group(state.db(), &target).await?;
    db::updates::apply_rollback(
        state.db(),
        &ch.id,
        &req.runtime_version,
        current_hist,
        target_hist,
        &previous,
    )
    .await?;
    db::audit::record(
        state.db(),
        Some(&caller.user.id),
        Some(&app.org_id),
        "channel.rollback",
        Some(&format!("{}/{}", app.slug, ch.name)),
        Some(&previous.id),
    )
    .await
    .ok();
    Ok(json_ok(json!({ "ok": true, "group_id": previous.id })))
}

#[derive(Deserialize)]
pub struct RollbackToEmbeddedReq {
    runtime_version: String,
}

/// Publish a `rollback_to_embedded` group on a branch: protocol-1 clients on
/// affected channels revert to the update embedded in their binary.
pub async fn rollback_to_embedded(
    State(state): State<AppState>,
    caller: ApiUser,
    Path((slug, app_slug, branch)): Path<(String, String, String)>,
    Json(req): Json<RollbackToEmbeddedReq>,
) -> Result<Response> {
    let (_org, app) = resolve_app(&state, &caller, &slug, &app_slug, Permission::Publish).await?;
    let branch = db::updates::find_branch(state.db(), &app.id, &branch)
        .await?
        .ok_or(Error::NotFound)?;
    let mut tx = state.db().begin_with("BEGIN IMMEDIATE").await?;
    let group = db::updates::create_group(
        &mut *tx,
        &branch.id,
        &req.runtime_version,
        Some("rollback to embedded"),
        None,
        None,
        "rollback_to_embedded",
        None,
        "",
    )
    .await?;
    let released = super::publish::advance_channels(&mut tx, &app, &branch, &group, None).await?;
    tx.commit().await?;
    db::audit::record(
        state.db(),
        Some(&caller.user.id),
        Some(&app.org_id),
        "branch.rollback_to_embedded",
        Some(&format!("{}/{}", app.slug, branch.name)),
        Some(&req.runtime_version),
    )
    .await
    .ok();
    Ok(json_ok(
        json!({ "ok": true, "group_id": group.id, "channels": released }),
    ))
}
