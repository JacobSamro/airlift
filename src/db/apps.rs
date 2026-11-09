//! Queries for apps (Expo applications served by this instance).

#![allow(dead_code)] // parts are wired up by later build phases
use serde::Serialize;

use crate::error::Result;
use crate::util::now_rfc3339;

use super::Db;

/// An Expo application. `id` is the UUID that appears in the public update URL
/// (`/u/<id>/manifest`). The signing key material is deliberately not
/// serialized; expose the certificate through a dedicated endpoint instead.
#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct App {
    pub id: String,
    pub org_id: String,
    pub slug: String,
    pub name: String,
    #[serde(skip_serializing)]
    pub private_key_pem: String,
    #[serde(skip_serializing)]
    pub certificate_pem: String,
    pub created_at: String,
    pub updated_at: String,
}

pub async fn find_by_id(db: &Db, id: &str) -> Result<Option<App>> {
    let a = sqlx::query_as::<_, App>("SELECT * FROM apps WHERE id = ?")
        .bind(id)
        .fetch_optional(db)
        .await?;
    Ok(a)
}

pub async fn find_by_slug(db: &Db, org_id: &str, slug: &str) -> Result<Option<App>> {
    let a =
        sqlx::query_as::<_, App>("SELECT * FROM apps WHERE org_id = ? AND lower(slug) = lower(?)")
            .bind(org_id)
            .bind(slug)
            .fetch_optional(db)
            .await?;
    Ok(a)
}

/// Create an app with its (already generated) signing keypair.
pub async fn create(
    db: &Db,
    org_id: &str,
    slug: &str,
    name: &str,
    private_key_pem: &str,
    certificate_pem: &str,
) -> Result<App> {
    let id = uuid::Uuid::new_v4().to_string();
    let now = now_rfc3339();
    sqlx::query(
        "INSERT INTO apps (id, org_id, slug, name, private_key_pem, certificate_pem,
                           created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(org_id)
    .bind(slug)
    .bind(name)
    .bind(private_key_pem)
    .bind(certificate_pem)
    .bind(&now)
    .bind(&now)
    .execute(db)
    .await?;
    Ok(App {
        id,
        org_id: org_id.into(),
        slug: slug.into(),
        name: name.into(),
        private_key_pem: private_key_pem.into(),
        certificate_pem: certificate_pem.into(),
        created_at: now.clone(),
        updated_at: now,
    })
}

pub async fn list(db: &Db, org_id: &str) -> Result<Vec<App>> {
    let apps =
        sqlx::query_as::<_, App>("SELECT * FROM apps WHERE org_id = ? ORDER BY updated_at DESC")
            .bind(org_id)
            .fetch_all(db)
            .await?;
    Ok(apps)
}

pub async fn delete(db: &Db, org_id: &str, app_id: &str) -> Result<()> {
    sqlx::query("DELETE FROM apps WHERE org_id = ? AND id = ?")
        .bind(org_id)
        .bind(app_id)
        .execute(db)
        .await?;
    Ok(())
}

/// One of an app's code-signing keys (`main` is the one stored on `apps`).
#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct SigningKey {
    pub keyid: String,
    #[serde(skip_serializing)]
    pub private_key_pem: String,
    pub certificate_pem: String,
    pub created_at: String,
}

/// All of an app's signing keys, `main` first.
pub async fn signing_keys(db: &Db, app: &App) -> Result<Vec<SigningKey>> {
    let mut keys = vec![SigningKey {
        keyid: "main".into(),
        private_key_pem: app.private_key_pem.clone(),
        certificate_pem: app.certificate_pem.clone(),
        created_at: app.created_at.clone(),
    }];
    keys.extend(
        sqlx::query_as::<_, SigningKey>(
            "SELECT keyid, private_key_pem, certificate_pem, created_at
             FROM app_signing_keys WHERE app_id = ? ORDER BY created_at",
        )
        .bind(&app.id)
        .fetch_all(db)
        .await?,
    );
    Ok(keys)
}

pub async fn add_signing_key(
    db: &Db,
    app_id: &str,
    keyid: &str,
    private_key_pem: &str,
    certificate_pem: &str,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO app_signing_keys (app_id, keyid, private_key_pem, certificate_pem, created_at)
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(app_id)
    .bind(keyid)
    .bind(private_key_pem)
    .bind(certificate_pem)
    .bind(now_rfc3339())
    .execute(db)
    .await?;
    Ok(())
}
