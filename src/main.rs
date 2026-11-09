//! airlift — a self-hosted Expo OTA update server, S3-backed (Tigris).

mod analytics;
mod api;
mod auth;
mod config;
mod db;
mod error;
mod gc;
mod geo;
mod keys;
mod manifest_cache;
mod mcp;
mod models;
mod observability;
mod patches;
mod protocol;
mod rate_limit;
mod rollout;
mod server;
mod sso;
mod state;
mod storage;
mod tls;
mod util;
mod web;

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use tracing_subscriber::{prelude::*, EnvFilter};

use models::OrgRole;

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[derive(Parser)]
#[command(name = "airlift", version, about, long_about = None)]
struct Cli {
    /// Path to the configuration file.
    #[arg(
        short,
        long,
        env = "AIRLIFT_CONFIG",
        default_value = "/etc/airlift/config.toml"
    )]
    config: PathBuf,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Run database migrations and start the server (default).
    Serve,
    /// Apply pending database migrations and exit.
    Migrate,
    /// Run a one-off garbage-collection sweep (delete unreferenced assets).
    Gc,
    /// Administrative commands for bootstrapping (orgs, users, tokens).
    #[command(subcommand)]
    Admin(AdminCommand),
}

#[derive(Subcommand)]
enum AdminCommand {
    /// Create a user account.
    CreateUser {
        #[arg(long)]
        email: String,
        #[arg(long)]
        username: String,
        #[arg(long)]
        password: String,
        /// Grant instance super-admin.
        #[arg(long, default_value_t = false)]
        admin: bool,
    },
    /// Create an organization.
    CreateOrg {
        #[arg(long)]
        slug: String,
        #[arg(long)]
        name: String,
    },
    /// Add a user to an org with a role (owner|admin|member).
    AddMember {
        #[arg(long)]
        org: String,
        #[arg(long)]
        username: String,
        #[arg(long, default_value = "member")]
        role: String,
    },
    /// Create a personal access token for a user (printed once).
    CreateToken {
        #[arg(long)]
        username: String,
        #[arg(long, default_value = "cli")]
        name: String,
        /// Scope the token to an org slug.
        #[arg(long)]
        org: Option<String>,
        /// Scope the token to an app slug (requires --org).
        #[arg(long)]
        app: Option<String>,
        /// Permission cap: read | publish | admin.
        #[arg(long, default_value = "admin")]
        permission: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();

    let cli = Cli::parse();
    let config = config::Config::load(Some(&cli.config))?;

    match cli.command.unwrap_or(Command::Serve) {
        Command::Migrate => {
            let pool = db::connect(&config.database.path).await?;
            db::migrate(&pool).await?;
            tracing::info!("migrations applied");
        }
        Command::Gc => {
            let pool = db::connect(&config.database.path).await?;
            db::migrate(&pool).await?;
            let secret_key =
                db::settings::ensure_secret_key(&pool, &config.auth.secret_key).await?;
            let storage_cfg = db::settings::effective_storage(&pool, &config.storage).await?;
            let storage = storage::Storage::new(&storage_cfg).await?;
            let state = state::AppState::new(config, pool, storage, secret_key);
            let n = gc::run(&state).await?;
            println!("garbage collected {n} asset(s)");
        }
        Command::Admin(cmd) => {
            let pool = db::connect(&config.database.path).await?;
            db::migrate(&pool).await?;
            run_admin(&pool, cmd).await?;
        }
        Command::Serve => {
            let pool = db::connect(&config.database.path).await?;
            db::migrate(&pool).await?;

            let secret_key =
                db::settings::ensure_secret_key(&pool, &config.auth.secret_key).await?;

            let storage_cfg = db::settings::effective_storage(&pool, &config.storage).await?;
            let storage = storage::Storage::new(&storage_cfg).await?;

            let tls_enabled = config.tls.enabled;
            let http_addr = config.server.http_addr.clone();
            let analytics_enabled = config.analytics.enabled;
            let rollup_secs = config.analytics.rollup_secs;
            let gc_interval = config.gc.interval_secs;
            geo::init(&config.observability.geoip_mmdb);
            let state = state::AppState::new(config, pool, storage, secret_key);
            // Derive the effective public URL from config or the primary domain
            // before serving, so manifest asset URLs are correct on the first
            // request (no restart needed after a domain is later added).
            state.refresh_public_url().await;
            let app = server::router(state.clone());

            tokio::spawn(gc::background(state.clone(), gc_interval));
            tokio::spawn(patches::worker_loop(state.clone()));
            observability::spawn(state.clone());

            if analytics_enabled {
                tokio::spawn(analytics::flush_loop(state.clone(), rollup_secs));
            }

            if tls_enabled {
                tls::serve(state, app).await?;
            } else {
                server::serve_http(&http_addr, app).await?;
            }
        }
    }

    Ok(())
}

async fn run_admin(pool: &db::Db, cmd: AdminCommand) -> anyhow::Result<()> {
    match cmd {
        AdminCommand::CreateUser {
            email,
            username,
            password,
            admin,
        } => {
            let hash = auth::password::hash_password(&password)?;
            let user = db::users::create(pool, &email, &username, &hash, admin).await?;
            println!("created user {} ({})", user.username, user.id);
        }
        AdminCommand::CreateOrg { slug, name } => {
            let org = db::orgs::create_org(pool, &slug, &name).await?;
            println!("created org {} ({})", org.slug, org.id);
        }
        AdminCommand::AddMember {
            org,
            username,
            role,
        } => {
            let org = db::orgs::find_org_by_slug(pool, &org)
                .await?
                .ok_or_else(|| anyhow::anyhow!("org not found"))?;
            let user = db::users::find_by_login(pool, &username)
                .await?
                .ok_or_else(|| anyhow::anyhow!("user not found"))?;
            let role = OrgRole::parse(&role).ok_or_else(|| anyhow::anyhow!("invalid role"))?;
            db::orgs::add_org_member(pool, &org.id, &user.id, role).await?;
            println!(
                "added {} to {} as {}",
                user.username,
                org.slug,
                role.as_str()
            );
        }
        AdminCommand::CreateToken {
            username,
            name,
            org,
            app,
            permission,
        } => {
            if !matches!(permission.as_str(), "read" | "publish" | "admin") {
                return Err(anyhow::anyhow!("permission must be read|publish|admin"));
            }
            let user = db::users::find_by_login(pool, &username)
                .await?
                .ok_or_else(|| anyhow::anyhow!("user not found"))?;
            let (kind, org_id, app_id) = match (org.as_deref(), app.as_deref()) {
                (Some(slug), Some(app_slug)) => {
                    let org = db::orgs::find_org_by_slug(pool, slug)
                        .await?
                        .ok_or_else(|| anyhow::anyhow!("org not found"))?;
                    let a = db::apps::find_by_slug(pool, &org.id, app_slug)
                        .await?
                        .ok_or_else(|| anyhow::anyhow!("app not found"))?;
                    ("app", None, Some(a.id))
                }
                (Some(slug), None) => {
                    let org = db::orgs::find_org_by_slug(pool, slug)
                        .await?
                        .ok_or_else(|| anyhow::anyhow!("org not found"))?;
                    ("org", Some(org.id), None)
                }
                _ => ("all", None, None),
            };
            let token = db::users::create_pat(
                pool,
                &user.id,
                &name,
                kind,
                org_id.as_deref(),
                app_id.as_deref(),
                &permission,
                None,
            )
            .await?;
            println!("{token}");
        }
    }
    Ok(())
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,airlift=debug,tower_http=info"));
    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer())
        .init();
}
