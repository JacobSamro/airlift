//! Manifest hot-path cache.
//!
//! A [`Plan`] is everything needed to answer a manifest request for one
//! (app, channel, runtime, platform, base URL): the app, the channel's release
//! (and its rollout / A/B split sides), and for every group that could be
//! served the fully rendered manifest or directive body. Bodies are signed
//! lazily, once, so a cache hit does no SQL and no RSA work; per-device logic
//! (rollout/split bucketing, crash blocking, "already current") runs on the
//! cached plan.
//!
//! Invalidation: every pooled SQLite connection carries an update hook that
//! flags writes to the tables a plan is built from, and a commit hook that
//! then bumps a global generation; a plan built under an older generation is
//! rebuilt. Because SQLite's commit hook fires just before the commit becomes
//! visible, a plan could in principle be rebuilt from the pre-commit state in
//! that instant — a short TTL bounds any such staleness.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use serde_json::json;

use crate::db;
use crate::error::{Error, Result};
use crate::state::AppState;

/// Bumped whenever a serving table changes (see module docs).
static GENERATION: AtomicU64 = AtomicU64::new(0);
/// Upper bound on how long a plan is trusted regardless of generation.
const TTL: Duration = Duration::from_secs(5);
/// Entry cap; the cache is simply cleared when it grows past this.
const MAX_ENTRIES: usize = 10_000;

/// Tables whose rows feed a [`Plan`].
const SERVING_TABLES: &[&str] = &[
    "apps",
    "channels",
    "channel_releases",
    "update_groups",
    "updates",
    "update_assets",
    "assets",
];

pub fn generation() -> u64 {
    GENERATION.load(Ordering::Acquire)
}

/// Explicit invalidation (tests, admin actions outside SQLite).
#[allow(dead_code)]
pub fn invalidate() {
    GENERATION.fetch_add(1, Ordering::AcqRel);
}

/// Install the invalidation hooks on a freshly opened connection.
pub async fn install_hooks(
    conn: &mut sqlx::SqliteConnection,
) -> std::result::Result<(), sqlx::Error> {
    let dirty = Arc::new(AtomicBool::new(false));
    let mut handle = conn.lock_handle().await?;
    let flag = dirty.clone();
    handle.set_update_hook(move |change| {
        if SERVING_TABLES.contains(&change.table) {
            flag.store(true, Ordering::Release);
        }
    });
    let flag = dirty.clone();
    handle.set_commit_hook(move || {
        if flag.swap(false, Ordering::AcqRel) {
            GENERATION.fetch_add(1, Ordering::AcqRel);
        }
        true // never veto the commit
    });
    let flag = dirty;
    handle.set_rollback_hook(move || flag.store(false, Ordering::Release));
    Ok(())
}

// ───────────────────────── plan types ─────────────────────────

/// A part body with its RSA signature computed at most once.
pub struct SignedBody {
    pub body: String,
    sig: tokio::sync::OnceCell<String>,
}

impl SignedBody {
    fn new(body: String) -> Arc<Self> {
        Arc::new(Self {
            body,
            sig: tokio::sync::OnceCell::new(),
        })
    }

    pub async fn signature(&self, app: &db::apps::App) -> Result<&str> {
        self.sig
            .get_or_try_init(|| crate::protocol::sign_for_app(app, self.body.as_bytes().to_vec()))
            .await
            .map(String::as_str)
    }
}

/// What one group means for one platform.
pub enum Serve {
    /// `rollBackToEmbedded` directive body.
    Rollback(Arc<SignedBody>),
    Manifest {
        /// Lowercased manifest id (for crash-block / up-to-date checks).
        update_id: String,
        body: Arc<SignedBody>,
        /// Every asset key in the manifest (launch asset first).
        asset_keys: Vec<String>,
    },
    /// The group has no update for this platform.
    Nothing,
}

/// A channel's release for one runtime.
#[derive(Default)]
pub struct Release {
    primary: Option<Arc<Serve>>,
    /// Running rollout of `primary`: (salt, percent).
    rollout: Option<(String, f64)>,
    /// What devices outside the rollout get.
    previous: Option<Arc<Serve>>,
}

pub struct Plan {
    pub app: Arc<db::apps::App>,
    pub no_update: Arc<SignedBody>,
    main: Release,
    /// A/B split: (salt, percent, the split channel's release).
    split: Option<(String, f64, Release)>,
}

/// The pick for one device.
pub struct Pick<'a> {
    pub serve: Option<&'a Serve>,
    /// Served as part of a running rollout (asset requests must re-check).
    pub in_rollout: bool,
}

impl Plan {
    pub fn pick(&self, client_id: Option<&str>) -> Pick<'_> {
        let release = match &self.split {
            Some((salt, pct, r)) if crate::rollout::included(client_id, salt, *pct) => r,
            _ => &self.main,
        };
        let (serve, in_rollout) = match &release.rollout {
            Some((salt, pct)) if crate::rollout::included(client_id, salt, *pct) => {
                (release.primary.as_deref(), true)
            }
            Some(_) => (release.previous.as_deref(), false),
            None => (release.primary.as_deref(), false),
        };
        Pick { serve, in_rollout }
    }
}

// ───────────────────────── cache ─────────────────────────

#[derive(Hash, PartialEq, Eq, Clone)]
struct Key {
    app_id: String,
    channel: String,
    runtime: String,
    platform: String,
    base: String,
}

struct Entry {
    generation: u64,
    built: Instant,
    plan: Arc<Plan>,
}

static CACHE: LazyLock<DashMap<Key, Entry>> = LazyLock::new(DashMap::new);

/// The plan for a request: cached, or built from SQLite. `Ok(None)` = the
/// app doesn't exist; an unknown channel is a 400.
pub async fn plan(
    state: &AppState,
    app_id: &str,
    channel: &str,
    runtime: &str,
    platform: &str,
    base: &str,
) -> Result<Option<Arc<Plan>>> {
    let key = Key {
        app_id: app_id.to_string(),
        channel: channel.to_ascii_lowercase(),
        runtime: runtime.to_string(),
        platform: platform.to_string(),
        base: base.to_string(),
    };
    let generation = generation();
    if let Some(e) = CACHE.get(&key) {
        if e.generation == generation && e.built.elapsed() < TTL {
            metrics::counter!("airlift_manifest_cache_total", "result" => "hit").increment(1);
            return Ok(Some(e.plan.clone()));
        }
    }
    metrics::counter!("airlift_manifest_cache_total", "result" => "miss").increment(1);
    let Some(plan) = build(state, &key).await? else {
        return Ok(None);
    };
    let plan = Arc::new(plan);
    // Only cache what was built entirely under one generation.
    if crate::manifest_cache::generation() == generation {
        if CACHE.len() >= MAX_ENTRIES {
            CACHE.clear();
        }
        CACHE.insert(
            key,
            Entry {
                generation,
                built: Instant::now(),
                plan: plan.clone(),
            },
        );
    }
    Ok(Some(plan))
}

async fn build(state: &AppState, key: &Key) -> Result<Option<Plan>> {
    let Some(app) = db::apps::find_by_id(state.db(), &key.app_id).await? else {
        return Ok(None);
    };
    let channel = db::updates::find_channel(state.db(), &app.id, &key.channel)
        .await?
        .ok_or_else(|| Error::bad_request("unknown channel"))?;
    let main = build_release(state, &app, &channel.id, key).await?;
    // One hop only: the split target's own split isn't followed.
    let split = match (
        &channel.split_channel_id,
        channel.split_percent,
        &channel.split_salt,
    ) {
        (Some(target), Some(pct), Some(salt)) => {
            match db::updates::find_channel_by_id(state.db(), target).await? {
                Some(t) => Some((
                    salt.clone(),
                    pct,
                    build_release(state, &app, &t.id, key).await?,
                )),
                None => None,
            }
        }
        _ => None,
    };
    let no_update = SignedBody::new(json!({ "type": "noUpdateAvailable" }).to_string());
    Ok(Some(Plan {
        app: Arc::new(app),
        no_update,
        main,
        split,
    }))
}

async fn build_release(
    state: &AppState,
    app: &db::apps::App,
    channel_id: &str,
    key: &Key,
) -> Result<Release> {
    let Some(r) = db::updates::release(state.db(), channel_id, &key.runtime).await? else {
        return Ok(Release::default());
    };
    let primary = build_serve(state, app, &r.group_id, key).await?;
    let (rollout, previous) = match (r.rollout_percent, r.rollout_salt) {
        (Some(p), Some(salt)) => {
            let previous = match &r.previous_group_id {
                Some(g) => build_serve(state, app, g, key).await?,
                None => None,
            };
            (Some((salt, p)), previous)
        }
        _ => (None, None),
    };
    Ok(Release {
        primary,
        rollout,
        previous,
    })
}

async fn build_serve(
    state: &AppState,
    app: &db::apps::App,
    group_id: &str,
    key: &Key,
) -> Result<Option<Arc<Serve>>> {
    let Some(group) = db::updates::find_group(state.db(), group_id).await? else {
        return Ok(None);
    };
    // A rollback group emits the protocol-1 directive.
    if group.group_type == "rollback_to_embedded" {
        let directive = json!({
            "type": "rollBackToEmbedded",
            "parameters": { "commitTime": crate::util::normalize_rfc3339(&group.created_at) },
        });
        return Ok(Some(Arc::new(Serve::Rollback(SignedBody::new(
            directive.to_string(),
        )))));
    }
    let updates = db::updates::updates_in_group(state.db(), &group.id).await?;
    let Some(update) = updates.into_iter().find(|u| u.platform == key.platform) else {
        return Ok(Some(Arc::new(Serve::Nothing)));
    };
    let launch = db::updates::launch_asset(state.db(), &update.id)
        .await?
        .ok_or_else(|| Error::Other(anyhow::anyhow!("update {} lost its bundle", update.id)))?;
    let assets = db::updates::assets_for_update(state.db(), &update.id).await?;

    let base = &key.base;
    let asset_url = |sha256: &str| format!("{base}/u/{}/assets/{}", app.id, sha256);
    let assets_json: Vec<_> = assets
        .iter()
        .map(|a| {
            json!({
                "hash": crate::protocol::hex_to_b64url(&a.sha256),
                "key": a.key,
                "fileExtension": a.file_extension.as_deref().map(|e| format!(".{}", e.trim_start_matches('.'))),
                "contentType": a.content_type,
                "url": asset_url(&a.sha256),
            })
        })
        .collect();
    let extra_expo_client: serde_json::Value = group
        .expo_config_json
        .as_deref()
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or(serde_json::Value::Null);
    // expo-updates uses the asset key as the asset's unique id and skips the
    // download when it already holds that key, so it must change with the
    // content (the reference server uses the bundle's md5).
    let launch_key = format!("bundle-{}", launch.sha256);
    let manifest = json!({
        "id": update.id,
        "createdAt": crate::util::normalize_rfc3339(&group.created_at),
        "runtimeVersion": group.runtime_version,
        "launchAsset": {
            "hash": crate::protocol::hex_to_b64url(&launch.sha256),
            "key": launch_key,
            "fileExtension": ".bundle",
            "contentType": launch.content_type,
            "url": asset_url(&launch.sha256),
        },
        "assets": assets_json,
        "metadata": {},
        "extra": { "expoClient": extra_expo_client },
    });
    let mut asset_keys = vec![launch_key];
    asset_keys.extend(assets.into_iter().map(|a| a.key));
    Ok(Some(Arc::new(Serve::Manifest {
        update_id: update.id.to_ascii_lowercase(),
        body: SignedBody::new(manifest.to_string()),
        asset_keys,
    })))
}
