//! Client check-in monitoring. Every manifest request upserts an in-memory
//! device record and bumps a daily counter; a background loop flushes both to
//! SQLite. Nothing here ever blocks the manifest hot path.

use dashmap::DashMap;

use crate::state::AppState;
use crate::util::now_rfc3339;

/// Latest state reported by one device (identified by `EAS-Client-ID`).
#[derive(Clone, Debug)]
pub struct ClientCheckin {
    pub platform: String,
    pub runtime_version: String,
    pub channel: String,
    pub embedded_update_id: Option<String>,
    pub current_update_id: Option<String>,
    pub last_seen: String,
    /// Country (ISO 3166-1 alpha-2) and city, when known.
    pub country: Option<String>,
    pub city: Option<String>,
}

/// Key for the daily rollup: (app_id, day, platform, served update id or "").
type DailyKey = (String, String, String, String);
/// One drained device check-in: ((app_id, client_id), latest state).
type DrainedClient = ((String, String), ClientCheckin);
/// Key for per-device update outcomes: (app_id, update_id, client_id).
pub type OutcomeKey = (String, String, String);

/// What a device has reported about one update since the last flush.
#[derive(Clone, Copy, Debug, Default)]
pub struct Outcome {
    pub launched: bool,
    pub failed: bool,
}

/// Drained collector contents.
type Drained = (
    Vec<DrainedClient>,
    Vec<(DailyKey, u64)>,
    Vec<(OutcomeKey, Outcome)>,
);

pub struct UsageCollector {
    enabled: bool,
    /// (app_id, client_id) → latest check-in.
    clients: DashMap<(String, String), ClientCheckin>,
    /// Daily manifest-request counters.
    daily: DashMap<DailyKey, u64>,
    /// Per-device launch/failure outcomes (feeds per-update health).
    outcomes: DashMap<OutcomeKey, Outcome>,
}

impl UsageCollector {
    pub fn new(enabled: bool) -> Self {
        Self {
            enabled,
            clients: DashMap::new(),
            daily: DashMap::new(),
            outcomes: DashMap::new(),
        }
    }

    /// Record one manifest request. `served_update_id` is the update the
    /// response pointed the client at (empty for directives/no-update).
    #[allow(clippy::too_many_arguments)]
    pub fn record_checkin(
        &self,
        app_id: &str,
        client_id: Option<&str>,
        platform: &str,
        runtime_version: &str,
        channel: &str,
        embedded_update_id: Option<&str>,
        current_update_id: Option<&str>,
        served_update_id: &str,
        failed_update_ids: &[String],
        location: crate::geo::Location,
    ) {
        if !self.enabled {
            return;
        }
        if let Some(client_id) = client_id {
            let mark = |update_id: &str, f: fn(&mut Outcome)| {
                let key = (
                    app_id.to_string(),
                    update_id.to_ascii_lowercase(),
                    client_id.to_string(),
                );
                f(&mut self.outcomes.entry(key).or_default());
            };
            if let Some(cur) = current_update_id {
                mark(cur, |o| o.launched = true);
            }
            for id in failed_update_ids {
                mark(id, |o| o.failed = true);
            }
        }
        let day = now_rfc3339().chars().take(10).collect::<String>();
        *self
            .daily
            .entry((
                app_id.to_string(),
                day,
                platform.to_string(),
                served_update_id.to_string(),
            ))
            .or_insert(0) += 1;

        if let Some(client_id) = client_id {
            self.clients.insert(
                (app_id.to_string(), client_id.to_string()),
                ClientCheckin {
                    platform: platform.to_string(),
                    runtime_version: runtime_version.to_string(),
                    channel: channel.to_string(),
                    embedded_update_id: embedded_update_id.map(String::from),
                    current_update_id: current_update_id.map(String::from),
                    last_seen: now_rfc3339(),
                    country: location.country,
                    city: location.city,
                },
            );
        }
    }

    /// Drain everything collected so far. Each entry is taken with an atomic
    /// per-key `remove` (copy-then-`clear` dropped check-ins recorded in
    /// between); anything recorded after its key was removed starts a fresh
    /// entry for the next flush.
    fn drain(&self) -> Drained {
        let client_keys: Vec<_> = self.clients.iter().map(|e| e.key().clone()).collect();
        let clients = client_keys
            .into_iter()
            .filter_map(|k| self.clients.remove(&k))
            .collect();
        let daily_keys: Vec<_> = self.daily.iter().map(|e| e.key().clone()).collect();
        let daily = daily_keys
            .into_iter()
            .filter_map(|k| self.daily.remove(&k))
            .collect();
        let outcome_keys: Vec<_> = self.outcomes.iter().map(|e| e.key().clone()).collect();
        let outcomes = outcome_keys
            .into_iter()
            .filter_map(|k| self.outcomes.remove(&k))
            .collect();
        (clients, daily, outcomes)
    }
}

/// Periodically flush the collector to SQLite.
pub async fn flush_loop(state: AppState, secs: u64) {
    let secs = secs.max(1);
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(secs)).await;
        if let Err(e) = flush_once(&state).await {
            tracing::warn!(error = %e, "analytics flush failed");
        }
    }
}

pub async fn flush_once(state: &AppState) -> crate::error::Result<()> {
    let (clients, daily, outcomes) = state.usage().drain();
    for ((app_id, update_id, client_id), o) in outcomes {
        crate::db::clients::record_outcome(state.db(), &app_id, &update_id, &client_id, o).await?;
    }
    for ((app_id, client_id), c) in clients {
        crate::db::clients::upsert_client(state.db(), &app_id, &client_id, &c).await?;
    }
    for ((app_id, day, platform, update_id), n) in daily {
        crate::db::clients::add_checkins(state.db(), &app_id, &day, &platform, &update_id, n)
            .await?;
    }
    Ok(())
}
