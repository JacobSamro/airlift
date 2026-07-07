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
}

/// Key for the daily rollup: (app_id, day, platform, served update id or "").
type DailyKey = (String, String, String, String);
/// One drained device check-in: ((app_id, client_id), latest state).
type DrainedClient = ((String, String), ClientCheckin);

pub struct UsageCollector {
    enabled: bool,
    /// (app_id, client_id) → latest check-in.
    clients: DashMap<(String, String), ClientCheckin>,
    /// Daily manifest-request counters.
    daily: DashMap<DailyKey, u64>,
}

impl UsageCollector {
    pub fn new(enabled: bool) -> Self {
        Self {
            enabled,
            clients: DashMap::new(),
            daily: DashMap::new(),
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
    ) {
        if !self.enabled {
            return;
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
                },
            );
        }
    }

    /// Drain everything collected so far.
    fn drain(&self) -> (Vec<DrainedClient>, Vec<(DailyKey, u64)>) {
        let clients: Vec<_> = self
            .clients
            .iter()
            .map(|e| (e.key().clone(), e.value().clone()))
            .collect();
        self.clients.clear();
        let daily: Vec<_> = self
            .daily
            .iter()
            .map(|e| (e.key().clone(), *e.value()))
            .collect();
        self.daily.clear();
        (clients, daily)
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
    let (clients, daily) = state.usage().drain();
    for ((app_id, client_id), c) in clients {
        crate::db::clients::upsert_client(state.db(), &app_id, &client_id, &c).await?;
    }
    for ((app_id, day, platform, update_id), n) in daily {
        crate::db::clients::add_checkins(state.db(), &app_id, &day, &platform, &update_id, n)
            .await?;
    }
    Ok(())
}
