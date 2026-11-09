//! OAuth 2.1 (for MCP clients): registered clients, authorization codes,
//! refresh tokens. Access tokens are expiring PATs.

use crate::auth::pat;
use crate::error::Result;
use crate::util::{now_rfc3339, rfc3339_in};

use super::Db;

pub async fn register_client(db: &Db, name: &str, redirect_uris: &[String]) -> Result<String> {
    let id = format!("mcp_{}", uuid::Uuid::new_v4().simple());
    sqlx::query(
        "INSERT INTO oauth_clients (id, name, redirect_uris, created_at) VALUES (?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(name)
    .bind(serde_json::to_string(redirect_uris).unwrap_or_else(|_| "[]".into()))
    .bind(now_rfc3339())
    .execute(db)
    .await?;
    Ok(id)
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Client {
    pub id: String,
    pub name: String,
    pub redirect_uris: String,
}

impl Client {
    pub fn uris(&self) -> Vec<String> {
        serde_json::from_str(&self.redirect_uris).unwrap_or_default()
    }
}

pub async fn find_client(db: &Db, id: &str) -> Result<Option<Client>> {
    Ok(sqlx::query_as::<_, Client>(
        "SELECT id, name, redirect_uris FROM oauth_clients WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(db)
    .await?)
}

/// The grant a user consented to.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Grant {
    pub client_id: String,
    pub user_id: String,
    pub redirect_uri: String,
    pub code_challenge: String,
    pub max_perm: String,
    pub scope_kind: String,
    pub scope_org_id: Option<String>,
    pub scope_app_id: Option<String>,
}

/// Issue an authorization code (returns the plaintext).
pub async fn create_code(db: &Db, g: &Grant) -> Result<String> {
    let code = format!("{}{}", crate::util::random_id(), crate::util::random_id());
    sqlx::query(
        "INSERT INTO oauth_codes (code_hash, client_id, user_id, redirect_uri, code_challenge,
                                  max_perm, scope_kind, scope_org_id, scope_app_id, expires_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(pat::hash(&code))
    .bind(&g.client_id)
    .bind(&g.user_id)
    .bind(&g.redirect_uri)
    .bind(&g.code_challenge)
    .bind(&g.max_perm)
    .bind(&g.scope_kind)
    .bind(&g.scope_org_id)
    .bind(&g.scope_app_id)
    .bind(rfc3339_in(300))
    .execute(db)
    .await?;
    Ok(code)
}

/// Redeem a code (single use, unexpired).
pub async fn take_code(db: &Db, code: &str) -> Result<Option<Grant>> {
    Ok(sqlx::query_as::<_, Grant>(
        "DELETE FROM oauth_codes WHERE code_hash = ? AND expires_at > ?
         RETURNING client_id, user_id, redirect_uri, code_challenge, max_perm, scope_kind,
                   scope_org_id, scope_app_id",
    )
    .bind(pat::hash(code))
    .bind(now_rfc3339())
    .fetch_optional(db)
    .await?)
}

/// Access-token lifetime.
pub const ACCESS_TTL_SECS: i64 = 3600;
/// Refresh-token lifetime (each refresh rotates and renews it).
pub const REFRESH_TTL_SECS: i64 = 30 * 86_400;

/// Mint an access token (an expiring PAT named after the client) and a
/// refresh token for a grant. Returns (access, refresh).
pub async fn issue_tokens(db: &Db, g: &Grant, client_name: &str) -> Result<(String, String)> {
    let token = pat::generate();
    let pat_id = uuid::Uuid::new_v4().to_string();
    let refresh = format!(
        "rt_{}{}",
        crate::util::random_id(),
        crate::util::random_id()
    );
    let mut tx = db.begin().await?;
    sqlx::query(
        "INSERT INTO personal_access_tokens
            (id, user_id, name, token_prefix, token_hash, created_at, expires_at,
             scope_kind, scope_org_id, scope_app_id, max_perm)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&pat_id)
    .bind(&g.user_id)
    .bind(format!("MCP: {client_name}"))
    .bind(&token.display_prefix)
    .bind(&token.hash)
    .bind(now_rfc3339())
    .bind(rfc3339_in(ACCESS_TTL_SECS))
    .bind(&g.scope_kind)
    .bind(&g.scope_org_id)
    .bind(&g.scope_app_id)
    .bind(&g.max_perm)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO oauth_refresh_tokens (token_hash, pat_id, client_id, expires_at)
         VALUES (?, ?, ?, ?)",
    )
    .bind(pat::hash(&refresh))
    .bind(&pat_id)
    .bind(&g.client_id)
    .bind(rfc3339_in(REFRESH_TTL_SECS))
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok((token.plaintext, refresh))
}

/// Rotate: consume a refresh token, give the same grant (same PAT row) a new
/// access token and a new refresh token. Returns (access, refresh).
pub async fn refresh(
    db: &Db,
    refresh_token: &str,
    client_id: &str,
) -> Result<Option<(String, String)>> {
    let mut tx = db.begin().await?;
    let row: Option<(String,)> = sqlx::query_as(
        "DELETE FROM oauth_refresh_tokens
         WHERE token_hash = ? AND client_id = ? AND expires_at > ?
         RETURNING pat_id",
    )
    .bind(pat::hash(refresh_token))
    .bind(client_id)
    .bind(now_rfc3339())
    .fetch_optional(&mut *tx)
    .await?;
    let Some((pat_id,)) = row else {
        return Ok(None);
    };
    let token = pat::generate();
    let res = sqlx::query(
        "UPDATE personal_access_tokens SET token_hash = ?, token_prefix = ?, expires_at = ?
         WHERE id = ?",
    )
    .bind(&token.hash)
    .bind(&token.display_prefix)
    .bind(rfc3339_in(ACCESS_TTL_SECS))
    .bind(&pat_id)
    .execute(&mut *tx)
    .await?;
    if res.rows_affected() == 0 {
        return Ok(None); // the grant was revoked
    }
    let next = format!(
        "rt_{}{}",
        crate::util::random_id(),
        crate::util::random_id()
    );
    sqlx::query(
        "INSERT INTO oauth_refresh_tokens (token_hash, pat_id, client_id, expires_at)
         VALUES (?, ?, ?, ?)",
    )
    .bind(pat::hash(&next))
    .bind(&pat_id)
    .bind(client_id)
    .bind(rfc3339_in(REFRESH_TTL_SECS))
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Some((token.plaintext, next)))
}
