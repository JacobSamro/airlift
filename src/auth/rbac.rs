//! Resolve what an authenticated caller may do to a given app: the owner's
//! RBAC (org role + team grants, built-in levels or custom roles) intersected
//! with the token's resource scope and permission cap.

use crate::auth::ApiUser;
use crate::db::{apps::App, orgs, Db};
use crate::error::{Error, Result};
use crate::models::{Capability, Caps, TokenScope};

/// The caller's effective capabilities on `app` (owner RBAC ∩ scope ∩ cap).
pub async fn app_caps(db: &Db, caller: &ApiUser, app: &App) -> Result<Caps> {
    // Token resource scope first: a token confined to another org/app grants
    // nothing here, regardless of the owner's role.
    match &caller.scope {
        TokenScope::All => {}
        TokenScope::Org(oid) if *oid == app.org_id => {}
        TokenScope::App(aid) if *aid == app.id => {}
        _ => return Ok(Caps::NONE),
    }
    let owner = orgs::app_capabilities(db, &app.id, &app.org_id, &caller.user.id).await?;
    Ok(owner.intersect(Caps::of_level(caller.cap)))
}

/// Require `needed` on `app`, mapping a shortfall the same way the dashboard
/// does: no visibility at all → NotFound (don't leak the app's existence),
/// some visibility but not this capability → Forbidden.
pub async fn require(db: &Db, caller: &ApiUser, app: &App, needed: Capability) -> Result<Caps> {
    let have = app_caps(db, caller, app).await?;
    if have.has(needed) {
        return Ok(have);
    }
    if have.is_empty() {
        return Err(Error::NotFound);
    }
    Err(Error::Forbidden)
}
