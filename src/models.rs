//! Core domain types shared across the update server and dashboard.

use serde::{Deserialize, Serialize};

/// A user account.
#[derive(Debug, Clone, sqlx::FromRow, Serialize)]
pub struct User {
    pub id: String,
    pub email: String,
    pub username: String,
    #[serde(skip_serializing)]
    pub password_hash: String,
    pub is_admin: bool,
    pub created_at: String,
}

/// Organization-level role, ordered from least to most privileged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OrgRole {
    Member,
    Admin,
    Owner,
}

impl OrgRole {
    pub fn as_str(self) -> &'static str {
        match self {
            OrgRole::Member => "member",
            OrgRole::Admin => "admin",
            OrgRole::Owner => "owner",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "member" => Some(OrgRole::Member),
            "admin" => Some(OrgRole::Admin),
            "owner" => Some(OrgRole::Owner),
            _ => None,
        }
    }
}

/// What a personal access token is allowed to reach, independent of (and
/// intersected with) its owner's RBAC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenScope {
    /// Everything the owner can reach (default).
    All,
    /// Only apps within this org id.
    Org(String),
    /// Only this single app id.
    App(String),
}

/// Permission level on an app, ordered so comparisons express "at least".
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Permission {
    /// No access.
    None,
    /// View the app, its updates and stats.
    Read,
    /// Read + publish updates, promote/rollback channels.
    Publish,
    /// Full control (manage channels/keys, delete).
    Admin,
}

impl Permission {
    #[allow(dead_code)]
    pub fn as_str(self) -> &'static str {
        match self {
            Permission::None => "none",
            Permission::Read => "read",
            Permission::Publish => "publish",
            Permission::Admin => "admin",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "none" => Some(Permission::None),
            "read" => Some(Permission::Read),
            "publish" => Some(Permission::Publish),
            "admin" => Some(Permission::Admin),
            _ => None,
        }
    }
}

/// One fine-grained thing a caller may do to an app. Built-in permission
/// levels and org-defined custom roles are both sets of these.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum Capability {
    /// View the app, its updates, stats and certificates.
    Read = 1,
    /// Publish updates to a branch (and republish old ones).
    Publish = 1 << 1,
    /// Move channel release pointers: promote, rollout, rollback.
    Release = 1 << 2,
    /// Create/configure/delete channels, A/B splits, repointing.
    Channels = 1 << 3,
    /// Manage code-signing keys.
    Keys = 1 << 4,
    /// Publish to / release on protected branches, and manage protection.
    Protected = 1 << 5,
}

impl Capability {
    pub const ALL: [Capability; 6] = [
        Capability::Read,
        Capability::Publish,
        Capability::Release,
        Capability::Channels,
        Capability::Keys,
        Capability::Protected,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Capability::Read => "read",
            Capability::Publish => "publish",
            Capability::Release => "release",
            Capability::Channels => "channels",
            Capability::Keys => "keys",
            Capability::Protected => "protected",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Capability::ALL.into_iter().find(|c| c.as_str() == s)
    }
}

/// A set of [`Capability`]s.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Caps(u32);

impl Caps {
    pub const NONE: Caps = Caps(0);
    pub const ALL: Caps = Caps((1 << 6) - 1);

    pub fn has(self, c: Capability) -> bool {
        self.0 & c as u32 != 0
    }
    pub fn is_empty(self) -> bool {
        self.0 == 0
    }
    pub fn union(self, o: Caps) -> Caps {
        Caps(self.0 | o.0)
    }
    pub fn intersect(self, o: Caps) -> Caps {
        Caps(self.0 & o.0)
    }

    /// What a built-in permission level grants. `publish` is the classic
    /// "release engineer" level: read + publish + release (no channel config,
    /// keys, or protected branches).
    pub fn of_level(p: Permission) -> Caps {
        let c = |list: &[Capability]| Caps(list.iter().fold(0, |a, c| a | *c as u32));
        match p {
            Permission::None => Caps::NONE,
            Permission::Read => c(&[Capability::Read]),
            Permission::Publish => c(&[Capability::Read, Capability::Publish, Capability::Release]),
            Permission::Admin => Caps::ALL,
        }
    }

    /// Parse capability names; unknown names are an error. Any non-empty set
    /// includes `read` (you can't act on what you can't see).
    pub fn from_names<S: AsRef<str>>(names: &[S]) -> Option<Caps> {
        let mut bits = 0;
        for n in names {
            bits |= Capability::parse(n.as_ref())? as u32;
        }
        if bits != 0 {
            bits |= Capability::Read as u32;
        }
        Some(Caps(bits))
    }

    pub fn names(self) -> Vec<&'static str> {
        Capability::ALL
            .into_iter()
            .filter(|c| self.has(*c))
            .map(Capability::as_str)
            .collect()
    }
}
