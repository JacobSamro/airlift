//! SSO identity providers and in-flight login requests.

use serde::Serialize;

use crate::error::Result;
use crate::util::{now_rfc3339, rfc3339_in};

use super::Db;

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct Provider {
    pub id: String,
    pub org_id: Option<String>,
    pub kind: String,
    pub name: String,
    pub enabled: bool,
    pub domains: String,
    pub auto_provision: bool,
    pub default_role: String,
    #[serde(skip_serializing)]
    pub config: String,
    pub created_at: String,
}

impl Provider {
    pub fn domain_list(&self) -> Vec<String> {
        self.domains
            .split(',')
            .map(|d| d.trim().to_ascii_lowercase())
            .filter(|d| !d.is_empty())
            .collect()
    }

    pub fn config_json(&self) -> serde_json::Value {
        serde_json::from_str(&self.config).unwrap_or_default()
    }
}

pub struct NewProvider<'a> {
    pub org_id: Option<&'a str>,
    pub kind: &'a str,
    pub name: &'a str,
    pub enabled: bool,
    pub domains: &'a str,
    pub auto_provision: bool,
    pub default_role: &'a str,
    pub config: &'a str,
}

pub async fn create(db: &Db, p: &NewProvider<'_>) -> Result<String> {
    let id = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO sso_providers
            (id, org_id, kind, name, enabled, domains, auto_provision, default_role, config, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(p.org_id)
    .bind(p.kind)
    .bind(p.name)
    .bind(p.enabled)
    .bind(p.domains)
    .bind(p.auto_provision)
    .bind(p.default_role)
    .bind(p.config)
    .bind(now_rfc3339())
    .execute(db)
    .await?;
    Ok(id)
}

pub async fn update(db: &Db, id: &str, p: &NewProvider<'_>) -> Result<()> {
    sqlx::query(
        "UPDATE sso_providers SET name = ?, enabled = ?, domains = ?, auto_provision = ?,
                default_role = ?, config = ? WHERE id = ?",
    )
    .bind(p.name)
    .bind(p.enabled)
    .bind(p.domains)
    .bind(p.auto_provision)
    .bind(p.default_role)
    .bind(p.config)
    .bind(id)
    .execute(db)
    .await?;
    Ok(())
}

pub async fn delete(db: &Db, id: &str) -> Result<()> {
    sqlx::query("DELETE FROM sso_providers WHERE id = ?")
        .bind(id)
        .execute(db)
        .await?;
    Ok(())
}

pub async fn find(db: &Db, id: &str) -> Result<Option<Provider>> {
    Ok(
        sqlx::query_as::<_, Provider>("SELECT * FROM sso_providers WHERE id = ?")
            .bind(id)
            .fetch_optional(db)
            .await?,
    )
}

/// Providers of one org (`Some`) or the instance-wide ones (`None`).
pub async fn list(db: &Db, org_id: Option<&str>) -> Result<Vec<Provider>> {
    Ok(sqlx::query_as::<_, Provider>(
        "SELECT * FROM sso_providers WHERE org_id IS ? ORDER BY created_at",
    )
    .bind(org_id)
    .fetch_all(db)
    .await?)
}

/// Enabled providers routing this email domain; instance-wide first.
pub async fn for_domain(db: &Db, domain: &str) -> Result<Vec<Provider>> {
    let all = sqlx::query_as::<_, Provider>(
        "SELECT * FROM sso_providers WHERE enabled = 1 ORDER BY org_id IS NOT NULL, created_at",
    )
    .fetch_all(db)
    .await?;
    let domain = domain.to_ascii_lowercase();
    Ok(all
        .into_iter()
        .filter(|p| p.domain_list().contains(&domain))
        .collect())
}

pub async fn create_request(
    db: &Db,
    provider_id: &str,
    nonce: Option<&str>,
    pkce_verifier: Option<&str>,
    saml_request_id: Option<&str>,
) -> Result<String> {
    // Opportunistic cleanup of abandoned logins.
    sqlx::query("DELETE FROM sso_requests WHERE created_at < ?")
        .bind(rfc3339_in(-600))
        .execute(db)
        .await?;
    let id = format!("{}{}", crate::util::random_id(), crate::util::random_id());
    sqlx::query(
        "INSERT INTO sso_requests (id, provider_id, nonce, pkce_verifier, saml_request_id, created_at)
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(provider_id)
    .bind(nonce)
    .bind(pkce_verifier)
    .bind(saml_request_id)
    .bind(now_rfc3339())
    .execute(db)
    .await?;
    Ok(id)
}

#[derive(Debug, sqlx::FromRow)]
pub struct Request {
    pub provider_id: String,
    pub nonce: Option<String>,
    pub pkce_verifier: Option<String>,
    pub saml_request_id: Option<String>,
}

/// Consume a login request (single use; must be < 10 minutes old).
pub async fn take_request(db: &Db, id: &str) -> Result<Option<Request>> {
    Ok(sqlx::query_as::<_, Request>(
        "DELETE FROM sso_requests WHERE id = ? AND created_at >= ?
         RETURNING provider_id, nonce, pkce_verifier, saml_request_id",
    )
    .bind(id)
    .bind(rfc3339_in(-600))
    .fetch_optional(db)
    .await?)
}
