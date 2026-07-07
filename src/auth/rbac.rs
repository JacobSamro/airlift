//! Resolve what an authenticated caller may do to a given app: the owner's
//! RBAC (org role + team grants) intersected with the token's resource scope
//! and permission cap.

#![allow(dead_code)] // parts are wired up by later build phases
use crate::auth::ApiUser;
use crate::db::{apps::App, orgs, Db};
use crate::error::{Error, Result};
use crate::models::{Permission, TokenScope};

/// The caller's effective permission on `app` (owner RBAC ∩ scope ∩ cap).
pub async fn app_permission(db: &Db, caller: &ApiUser, app: &App) -> Result<Permission> {
    // Token resource scope first: a token confined to another org/app grants
    // nothing here, regardless of the owner's role.
    match &caller.scope {
        TokenScope::All => {}
        TokenScope::Org(oid) if *oid == app.org_id => {}
        TokenScope::App(aid) if *aid == app.id => {}
        _ => return Ok(Permission::None),
    }

    let capability = orgs::app_permission(db, &app.id, &app.org_id, &caller.user.id).await?;
    Ok(capability.min(caller.cap))
}

/// Require at least `needed` on `app`, mapping a shortfall to 401/403 the same
/// way the dashboard does: no visibility at all → NotFound (don't leak the
/// app's existence), some visibility but not enough → Forbidden.
pub async fn require(db: &Db, caller: &ApiUser, app: &App, needed: Permission) -> Result<()> {
    let have = app_permission(db, caller, app).await?;
    if have >= needed {
        return Ok(());
    }
    if have == Permission::None {
        return Err(Error::NotFound);
    }
    Err(Error::Forbidden)
}
