//! Queries for branches, channels, update groups, updates, assets, and the
//! channel release pointers.

use serde::Serialize;

use crate::error::Result;
use crate::util::now_rfc3339;

use super::Db;

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct Branch {
    pub id: String,
    pub app_id: String,
    pub name: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct Channel {
    pub id: String,
    pub app_id: String,
    pub name: String,
    pub branch_id: Option<String>,
    pub auto_release: bool,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct UpdateGroup {
    pub id: String,
    pub branch_id: String,
    pub runtime_version: String,
    pub message: Option<String>,
    pub git_branch: Option<String>,
    pub git_commit: Option<String>,
    pub group_type: String,
    #[serde(skip_serializing)]
    pub expo_config_json: Option<String>,
    #[serde(skip_serializing)]
    pub content_hash: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct Update {
    pub id: String,
    pub group_id: String,
    pub platform: String,
    pub launch_asset_id: String,
    /// Original export details, kept for debugging/re-derivation.
    #[serde(skip_serializing)]
    #[allow(dead_code)]
    pub metadata_json: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct Asset {
    pub id: String,
    pub org_id: String,
    pub sha256: String,
    pub size: i64,
    pub content_type: String,
    pub created_at: String,
}

/// An asset row joined with its manifest-facing key/type for one update.
#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct UpdateAsset {
    pub key: String,
    pub file_extension: Option<String>,
    pub content_type: String,
    pub sha256: String,
    pub size: i64,
}

// ───────────────────────── branches ─────────────────────────

/// Create the branch if it doesn't exist yet (publish auto-creates branches).
pub async fn ensure_branch(db: &Db, app_id: &str, name: &str) -> Result<Branch> {
    let id = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO branches (id, app_id, name, created_at) VALUES (?, ?, ?, ?)
         ON CONFLICT(app_id, name) DO NOTHING",
    )
    .bind(&id)
    .bind(app_id)
    .bind(name)
    .bind(now_rfc3339())
    .execute(db)
    .await?;
    find_branch(db, app_id, name)
        .await?
        .ok_or(crate::error::Error::NotFound)
}

pub async fn find_branch(db: &Db, app_id: &str, name: &str) -> Result<Option<Branch>> {
    let b = sqlx::query_as::<_, Branch>("SELECT * FROM branches WHERE app_id = ? AND name = ?")
        .bind(app_id)
        .bind(name)
        .fetch_optional(db)
        .await?;
    Ok(b)
}

pub async fn list_branches(db: &Db, app_id: &str) -> Result<Vec<Branch>> {
    let b = sqlx::query_as::<_, Branch>(
        "SELECT * FROM branches WHERE app_id = ? ORDER BY created_at DESC",
    )
    .bind(app_id)
    .fetch_all(db)
    .await?;
    Ok(b)
}

// ───────────────────────── channels ─────────────────────────

pub async fn find_channel(db: &Db, app_id: &str, name: &str) -> Result<Option<Channel>> {
    let c = sqlx::query_as::<_, Channel>(
        "SELECT * FROM channels WHERE app_id = ? AND lower(name) = lower(?)",
    )
    .bind(app_id)
    .bind(name)
    .fetch_optional(db)
    .await?;
    Ok(c)
}

pub async fn list_channels(db: &Db, app_id: &str) -> Result<Vec<Channel>> {
    let c = sqlx::query_as::<_, Channel>("SELECT * FROM channels WHERE app_id = ? ORDER BY name")
        .bind(app_id)
        .fetch_all(db)
        .await?;
    Ok(c)
}

pub async fn create_channel(
    db: &Db,
    app_id: &str,
    name: &str,
    branch_id: Option<&str>,
    auto_release: bool,
) -> Result<Channel> {
    let id = uuid::Uuid::new_v4().to_string();
    let now = now_rfc3339();
    sqlx::query(
        "INSERT INTO channels (id, app_id, name, branch_id, auto_release, created_at)
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(app_id)
    .bind(name)
    .bind(branch_id)
    .bind(auto_release)
    .bind(&now)
    .execute(db)
    .await?;
    Ok(Channel {
        id,
        app_id: app_id.into(),
        name: name.into(),
        branch_id: branch_id.map(|s| s.to_string()),
        auto_release,
        created_at: now,
    })
}

/// Point a channel at a (possibly different) branch and/or toggle gating.
pub async fn update_channel(
    db: &Db,
    channel_id: &str,
    branch_id: Option<&str>,
    auto_release: Option<bool>,
) -> Result<()> {
    if let Some(b) = branch_id {
        sqlx::query("UPDATE channels SET branch_id = ? WHERE id = ?")
            .bind(b)
            .bind(channel_id)
            .execute(db)
            .await?;
    }
    if let Some(a) = auto_release {
        sqlx::query("UPDATE channels SET auto_release = ? WHERE id = ?")
            .bind(a)
            .bind(channel_id)
            .execute(db)
            .await?;
    }
    Ok(())
}

pub async fn delete_channel(db: &Db, app_id: &str, channel_id: &str) -> Result<()> {
    sqlx::query("DELETE FROM channels WHERE app_id = ? AND id = ?")
        .bind(app_id)
        .bind(channel_id)
        .execute(db)
        .await?;
    Ok(())
}

/// Channels currently pointing at a branch.
pub async fn channels_for_branch(db: &Db, branch_id: &str) -> Result<Vec<Channel>> {
    let c = sqlx::query_as::<_, Channel>("SELECT * FROM channels WHERE branch_id = ?")
        .bind(branch_id)
        .fetch_all(db)
        .await?;
    Ok(c)
}

// ───────────────────────── assets ─────────────────────────

pub async fn find_asset(db: &Db, org_id: &str, sha256: &str) -> Result<Option<Asset>> {
    let a = sqlx::query_as::<_, Asset>("SELECT * FROM assets WHERE org_id = ? AND sha256 = ?")
        .bind(org_id)
        .bind(sha256)
        .fetch_optional(db)
        .await?;
    Ok(a)
}

/// Record an asset, or return the existing row (content-addressed dedup).
pub async fn ensure_asset(
    db: &Db,
    org_id: &str,
    sha256: &str,
    size: i64,
    content_type: &str,
) -> Result<Asset> {
    let id = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO assets (id, org_id, sha256, size, content_type, created_at)
         VALUES (?, ?, ?, ?, ?, ?)
         ON CONFLICT(org_id, sha256) DO NOTHING",
    )
    .bind(&id)
    .bind(org_id)
    .bind(sha256)
    .bind(size)
    .bind(content_type)
    .bind(now_rfc3339())
    .execute(db)
    .await?;
    find_asset(db, org_id, sha256)
        .await?
        .ok_or(crate::error::Error::NotFound)
}

/// Assets older than `cutoff` referenced by no update (neither as a file nor
/// as a launch bundle). Returns (id, org_id, sha256) for the GC sweep.
pub async fn unreferenced_assets(db: &Db, cutoff: &str) -> Result<Vec<(String, String, String)>> {
    let rows: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT a.id, a.org_id, a.sha256 FROM assets a
         WHERE a.created_at < ?
           AND NOT EXISTS (SELECT 1 FROM update_assets ua WHERE ua.asset_id = a.id)
           AND NOT EXISTS (SELECT 1 FROM updates u WHERE u.launch_asset_id = a.id)",
    )
    .bind(cutoff)
    .fetch_all(db)
    .await?;
    Ok(rows)
}

pub async fn delete_asset(db: &Db, asset_id: &str) -> Result<()> {
    sqlx::query("DELETE FROM assets WHERE id = ?")
        .bind(asset_id)
        .execute(db)
        .await?;
    Ok(())
}

// ───────────────────────── update groups / updates ─────────────────────────

#[allow(clippy::too_many_arguments)]
pub async fn create_group(
    db: &Db,
    branch_id: &str,
    runtime_version: &str,
    message: Option<&str>,
    git_branch: Option<&str>,
    git_commit: Option<&str>,
    group_type: &str,
    expo_config_json: Option<&str>,
    content_hash: &str,
) -> Result<UpdateGroup> {
    let id = uuid::Uuid::new_v4().to_string();
    let now = now_rfc3339();
    sqlx::query(
        "INSERT INTO update_groups
            (id, branch_id, runtime_version, message, git_branch, git_commit,
             group_type, expo_config_json, content_hash, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(branch_id)
    .bind(runtime_version)
    .bind(message)
    .bind(git_branch)
    .bind(git_commit)
    .bind(group_type)
    .bind(expo_config_json)
    .bind(content_hash)
    .bind(&now)
    .execute(db)
    .await?;
    Ok(UpdateGroup {
        id,
        branch_id: branch_id.into(),
        runtime_version: runtime_version.into(),
        message: message.map(String::from),
        git_branch: git_branch.map(String::from),
        git_commit: git_commit.map(String::from),
        group_type: group_type.into(),
        expo_config_json: expo_config_json.map(String::from),
        content_hash: content_hash.into(),
        created_at: now,
    })
}

pub async fn create_update(
    db: &Db,
    group_id: &str,
    platform: &str,
    launch_asset_id: &str,
    metadata_json: &str,
) -> Result<Update> {
    let id = uuid::Uuid::new_v4().to_string();
    let now = now_rfc3339();
    sqlx::query(
        "INSERT INTO updates (id, group_id, platform, launch_asset_id, metadata_json, created_at)
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(group_id)
    .bind(platform)
    .bind(launch_asset_id)
    .bind(metadata_json)
    .bind(&now)
    .execute(db)
    .await?;
    Ok(Update {
        id,
        group_id: group_id.into(),
        platform: platform.into(),
        launch_asset_id: launch_asset_id.into(),
        metadata_json: metadata_json.into(),
        created_at: now,
    })
}

pub async fn add_update_asset(
    db: &Db,
    update_id: &str,
    asset_id: &str,
    key: &str,
    file_extension: Option<&str>,
    content_type: &str,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO update_assets (update_id, asset_id, key, file_extension, content_type)
         VALUES (?, ?, ?, ?, ?)
         ON CONFLICT(update_id, key) DO NOTHING",
    )
    .bind(update_id)
    .bind(asset_id)
    .bind(key)
    .bind(file_extension)
    .bind(content_type)
    .execute(db)
    .await?;
    Ok(())
}

/// The newest group on a branch for a runtime version (the "head").
pub async fn head_group(
    db: &Db,
    branch_id: &str,
    runtime_version: &str,
) -> Result<Option<UpdateGroup>> {
    let g = sqlx::query_as::<_, UpdateGroup>(
        "SELECT * FROM update_groups
         WHERE branch_id = ? AND runtime_version = ?
         ORDER BY created_at DESC, id DESC LIMIT 1",
    )
    .bind(branch_id)
    .bind(runtime_version)
    .fetch_optional(db)
    .await?;
    Ok(g)
}

pub async fn find_group(db: &Db, group_id: &str) -> Result<Option<UpdateGroup>> {
    let g = sqlx::query_as::<_, UpdateGroup>("SELECT * FROM update_groups WHERE id = ?")
        .bind(group_id)
        .fetch_optional(db)
        .await?;
    Ok(g)
}

/// Recent groups on a branch (newest first), optionally filtered by runtime.
pub async fn groups_for_branch(
    db: &Db,
    branch_id: &str,
    runtime_version: Option<&str>,
    limit: i64,
) -> Result<Vec<UpdateGroup>> {
    let g = match runtime_version {
        Some(rv) => {
            sqlx::query_as::<_, UpdateGroup>(
                "SELECT * FROM update_groups WHERE branch_id = ? AND runtime_version = ?
                 ORDER BY created_at DESC, id DESC LIMIT ?",
            )
            .bind(branch_id)
            .bind(rv)
            .bind(limit)
            .fetch_all(db)
            .await?
        }
        None => {
            sqlx::query_as::<_, UpdateGroup>(
                "SELECT * FROM update_groups WHERE branch_id = ?
                 ORDER BY created_at DESC, id DESC LIMIT ?",
            )
            .bind(branch_id)
            .bind(limit)
            .fetch_all(db)
            .await?
        }
    };
    Ok(g)
}

/// Look up an update by id, confined to one app.
pub async fn find_update_in_app(db: &Db, app_id: &str, update_id: &str) -> Result<Option<Update>> {
    let u = sqlx::query_as::<_, Update>(
        "SELECT u.* FROM updates u
         JOIN update_groups g ON g.id = u.group_id
         JOIN branches b ON b.id = g.branch_id
         WHERE b.app_id = ? AND lower(u.id) = lower(?)",
    )
    .bind(app_id)
    .bind(update_id)
    .fetch_optional(db)
    .await?;
    Ok(u)
}

/// Per-platform updates of a group.
pub async fn updates_in_group(db: &Db, group_id: &str) -> Result<Vec<Update>> {
    let u =
        sqlx::query_as::<_, Update>("SELECT * FROM updates WHERE group_id = ? ORDER BY platform")
            .bind(group_id)
            .fetch_all(db)
            .await?;
    Ok(u)
}

/// Manifest-facing asset list for one update (excludes the launch asset).
pub async fn assets_for_update(db: &Db, update_id: &str) -> Result<Vec<UpdateAsset>> {
    let rows = sqlx::query_as::<_, UpdateAsset>(
        "SELECT ua.key, ua.file_extension, ua.content_type, a.sha256, a.size
         FROM update_assets ua JOIN assets a ON a.id = ua.asset_id
         WHERE ua.update_id = ? ORDER BY ua.key",
    )
    .bind(update_id)
    .fetch_all(db)
    .await?;
    Ok(rows)
}

/// The launch asset of an update.
pub async fn launch_asset(db: &Db, update_id: &str) -> Result<Option<Asset>> {
    let a = sqlx::query_as::<_, Asset>(
        "SELECT a.* FROM updates u JOIN assets a ON a.id = u.launch_asset_id WHERE u.id = ?",
    )
    .bind(update_id)
    .fetch_optional(db)
    .await?;
    Ok(a)
}

/// Whether an asset (by hex sha256) is referenced by any update of this app —
/// as a regular asset or a launch bundle. Guards the public asset endpoint so
/// org-level dedup can't leak another app's files.
pub async fn asset_in_app(db: &Db, app_id: &str, sha256: &str) -> Result<bool> {
    let (found,): (i64,) = sqlx::query_as(
        "SELECT EXISTS(
            SELECT 1 FROM assets a
            JOIN update_assets ua ON ua.asset_id = a.id
            JOIN updates u ON u.id = ua.update_id
            JOIN update_groups g ON g.id = u.group_id
            JOIN branches b ON b.id = g.branch_id
            WHERE b.app_id = ?1 AND a.sha256 = ?2
        ) OR EXISTS(
            SELECT 1 FROM assets a
            JOIN updates u ON u.launch_asset_id = a.id
            JOIN update_groups g ON g.id = u.group_id
            JOIN branches b ON b.id = g.branch_id
            WHERE b.app_id = ?1 AND a.sha256 = ?2
        )",
    )
    .bind(app_id)
    .bind(sha256)
    .fetch_one(db)
    .await?;
    Ok(found != 0)
}

// ───────────────────────── channel releases ─────────────────────────

/// Point a channel's release pointer for one runtime version at a group, and
/// append it to the channel's release history.
pub async fn set_channel_release(
    db: &Db,
    channel_id: &str,
    runtime_version: &str,
    group_id: &str,
) -> Result<()> {
    let mut tx = db.begin().await?;
    set_channel_release_tx(&mut tx, channel_id, runtime_version, group_id).await?;
    tx.commit().await?;
    Ok(())
}

pub async fn set_channel_release_tx(
    tx: &mut sqlx::SqliteConnection,
    channel_id: &str,
    runtime_version: &str,
    group_id: &str,
) -> Result<()> {
    let now = now_rfc3339();
    sqlx::query(
        "INSERT INTO channel_releases (channel_id, runtime_version, group_id, released_at)
         VALUES (?, ?, ?, ?)
         ON CONFLICT(channel_id, runtime_version) DO UPDATE
           SET group_id = excluded.group_id, released_at = excluded.released_at",
    )
    .bind(channel_id)
    .bind(runtime_version)
    .bind(group_id)
    .bind(&now)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO channel_release_history (channel_id, runtime_version, group_id, released_at)
         VALUES (?, ?, ?, ?)",
    )
    .bind(channel_id)
    .bind(runtime_version)
    .bind(group_id)
    .bind(&now)
    .execute(&mut *tx)
    .await?;
    Ok(())
}

/// Copy a group (its per-platform updates and asset links) into a brand-new
/// group with fresh ids and a fresh `created_at`.
///
/// expo-updates only loads an update whose commit time is NEWER than the one
/// it is running, so re-serving an older group (rollback, promoting an old
/// group, repointing to a branch with an older head) needs a new identity, or
/// devices that already moved past it ignore it.
pub async fn republish_group(db: &Db, group: &UpdateGroup) -> Result<UpdateGroup> {
    let mut tx = db.begin().await?;
    let id = uuid::Uuid::new_v4().to_string();
    let now = now_rfc3339();
    let message = Some(match &group.message {
        Some(m) => format!("{m} (republish of {})", group.id),
        None => format!("republish of {}", group.id),
    });
    sqlx::query(
        "INSERT INTO update_groups
            (id, branch_id, runtime_version, message, git_branch, git_commit,
             group_type, expo_config_json, content_hash, created_at)
         SELECT ?, branch_id, runtime_version, ?, git_branch, git_commit,
                group_type, expo_config_json, content_hash, ?
         FROM update_groups WHERE id = ?",
    )
    .bind(&id)
    .bind(&message)
    .bind(&now)
    .bind(&group.id)
    .execute(&mut *tx)
    .await?;

    let updates: Vec<(String,)> = sqlx::query_as("SELECT id FROM updates WHERE group_id = ?")
        .bind(&group.id)
        .fetch_all(&mut *tx)
        .await?;
    for (old_update_id,) in updates {
        let new_update_id = uuid::Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO updates (id, group_id, platform, launch_asset_id, metadata_json, created_at)
             SELECT ?, ?, platform, launch_asset_id, metadata_json, ?
             FROM updates WHERE id = ?",
        )
        .bind(&new_update_id)
        .bind(&id)
        .bind(&now)
        .bind(&old_update_id)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "INSERT INTO update_assets (update_id, asset_id, key, file_extension, content_type)
             SELECT ?, asset_id, key, file_extension, content_type
             FROM update_assets WHERE update_id = ?",
        )
        .bind(&new_update_id)
        .bind(&old_update_id)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(UpdateGroup {
        id,
        message,
        created_at: now,
        ..group.clone()
    })
}

/// `group` if it is newer than what the channel currently serves for its
/// runtime version, otherwise a fresh republish of it (see `republish_group`).
pub async fn fresh_for_channel(
    db: &Db,
    channel_id: &str,
    group: &UpdateGroup,
) -> Result<UpdateGroup> {
    match channel_release(db, channel_id, &group.runtime_version).await? {
        Some(current)
            if crate::util::normalize_rfc3339(&group.created_at)
                <= crate::util::normalize_rfc3339(&current.created_at) =>
        {
            republish_group(db, group).await
        }
        _ => Ok(group.clone()),
    }
}

/// The channel's previous (not rolled back) release for a runtime version:
/// returns `(history_id_of_current, history_id_of_target, target_group)`.
pub async fn previous_release(
    db: &Db,
    channel_id: &str,
    runtime_version: &str,
) -> Result<Option<(i64, i64, UpdateGroup)>> {
    let rows: Vec<(i64, String)> = sqlx::query_as(
        "SELECT id, group_id FROM channel_release_history
         WHERE channel_id = ? AND runtime_version = ? AND rolled_back = 0
         ORDER BY id DESC LIMIT 2",
    )
    .bind(channel_id)
    .bind(runtime_version)
    .fetch_all(db)
    .await?;
    let [(current_id, _), (target_id, target_group)] = rows.as_slice() else {
        return Ok(None);
    };
    Ok(find_group(db, target_group)
        .await?
        .map(|g| (*current_id, *target_id, g)))
}

/// Roll the channel back: flag the current history entry as rolled back,
/// re-materialize the target history entry as `fresh` (a republished group),
/// and point the channel at it.
pub async fn apply_rollback(
    db: &Db,
    channel_id: &str,
    runtime_version: &str,
    current_history_id: i64,
    target_history_id: i64,
    fresh: &UpdateGroup,
) -> Result<()> {
    let mut tx = db.begin().await?;
    sqlx::query("UPDATE channel_release_history SET rolled_back = 1 WHERE id = ?")
        .bind(current_history_id)
        .execute(&mut *tx)
        .await?;
    let now = now_rfc3339();
    sqlx::query("UPDATE channel_release_history SET group_id = ?, released_at = ? WHERE id = ?")
        .bind(&fresh.id)
        .bind(&now)
        .bind(target_history_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "INSERT INTO channel_releases (channel_id, runtime_version, group_id, released_at)
         VALUES (?, ?, ?, ?)
         ON CONFLICT(channel_id, runtime_version) DO UPDATE
           SET group_id = excluded.group_id, released_at = excluded.released_at",
    )
    .bind(channel_id)
    .bind(runtime_version)
    .bind(&fresh.id)
    .bind(&now)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

/// The group a channel currently serves for a runtime version.
pub async fn channel_release(
    db: &Db,
    channel_id: &str,
    runtime_version: &str,
) -> Result<Option<UpdateGroup>> {
    let g = sqlx::query_as::<_, UpdateGroup>(
        "SELECT g.* FROM channel_releases cr
         JOIN update_groups g ON g.id = cr.group_id
         WHERE cr.channel_id = ? AND cr.runtime_version = ?",
    )
    .bind(channel_id)
    .bind(runtime_version)
    .fetch_optional(db)
    .await?;
    Ok(g)
}

/// Runtime versions that have at least one group on a branch.
pub async fn branch_runtime_versions(db: &Db, branch_id: &str) -> Result<Vec<String>> {
    let rows: Vec<(String,)> =
        sqlx::query_as("SELECT DISTINCT runtime_version FROM update_groups WHERE branch_id = ?")
            .bind(branch_id)
            .fetch_all(db)
            .await?;
    Ok(rows.into_iter().map(|(rv,)| rv).collect())
}

pub async fn delete_channel_release(
    db: &Db,
    channel_id: &str,
    runtime_version: &str,
) -> Result<()> {
    sqlx::query("DELETE FROM channel_releases WHERE channel_id = ? AND runtime_version = ?")
        .bind(channel_id)
        .bind(runtime_version)
        .execute(db)
        .await?;
    Ok(())
}

/// All release pointers for a channel (dashboard view).
pub async fn releases_for_channel(
    db: &Db,
    channel_id: &str,
) -> Result<Vec<(String, String, String)>> {
    let rows: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT runtime_version, group_id, released_at FROM channel_releases
         WHERE channel_id = ? ORDER BY runtime_version DESC",
    )
    .bind(channel_id)
    .fetch_all(db)
    .await?;
    Ok(rows)
}
