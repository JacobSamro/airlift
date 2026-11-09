//! Deterministic device bucketing for progressive rollouts and A/B splits.
//!
//! A device's position is `sha256(EAS-Client-ID ":" salt)` mapped to [0,1)
//! (the first 8 digest bytes as a big-endian u64, divided by 2^64). It is
//! stable for a given salt and needs no per-device state, and a device inside
//! at N% stays inside at any higher percentage. Devices without a client id
//! are never inside.

use sha2::{Digest, Sha256};

/// Position of `client_id` in [0,1) for `salt`.
pub fn bucket(client_id: &str, salt: &str) -> f64 {
    let digest = Sha256::new()
        .chain_update(client_id.as_bytes())
        .chain_update(b":")
        .chain_update(salt.as_bytes())
        .finalize();
    let mut head = [0u8; 8];
    head.copy_from_slice(&digest[..8]);
    // u64 → f64 keeps 53 bits of precision, plenty for percentages.
    u64::from_be_bytes(head) as f64 / 18_446_744_073_709_551_616.0
}

/// Whether a device is inside a rollout/split covering `percent` (0–100).
pub fn included(client_id: Option<&str>, salt: &str, percent: f64) -> bool {
    match client_id {
        Some(id) if !id.is_empty() => bucket(id, salt) < percent / 100.0,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inclusion_is_monotonic_and_roughly_proportional() {
        let ids: Vec<String> = (0..10_000).map(|i| format!("device-{i}")).collect();
        let count = |p: f64| ids.iter().filter(|id| included(Some(id), "s", p)).count();
        let (c10, c50) = (count(10.0), count(50.0));
        assert!((800..1200).contains(&c10), "{c10}");
        assert!((4700..5300).contains(&c50), "{c50}");
        // Everyone inside at 10% is inside at 50%.
        for id in &ids {
            if included(Some(id), "s", 10.0) {
                assert!(included(Some(id), "s", 50.0));
            }
        }
        assert_eq!(count(100.0), ids.len());
        assert_eq!(count(0.0), 0);
    }

    #[test]
    fn no_client_id_is_never_included() {
        assert!(!included(None, "s", 100.0));
        assert!(!included(Some(""), "s", 100.0));
    }

    #[test]
    fn salt_changes_the_bucket() {
        assert_ne!(bucket("device-1", "a"), bucket("device-1", "b"));
        assert_eq!(bucket("device-1", "a"), bucket("device-1", "a"));
    }
}
