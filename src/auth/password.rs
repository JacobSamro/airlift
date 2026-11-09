//! Argon2id password hashing.

use argon2::password_hash::{
    rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString,
};
use argon2::Argon2;

use crate::error::{Error, Result};

/// Hash a plaintext password to an Argon2id PHC string.
pub fn hash_password(password: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| Error::Other(anyhow::anyhow!("password hash failed: {e}")))?;
    Ok(hash.to_string())
}

/// Verify a plaintext password against a stored PHC hash.
pub fn verify_password(password: &str, phc: &str) -> bool {
    match PasswordHash::new(phc) {
        Ok(parsed) => Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok(),
        Err(_) => false,
    }
}

/// [`hash_password`] on the blocking pool: Argon2id is deliberately slow
/// (tens of ms of CPU) and must not stall an async worker.
pub async fn hash_password_blocking(password: String) -> Result<String> {
    tokio::task::spawn_blocking(move || hash_password(&password))
        .await
        .map_err(|e| Error::Other(anyhow::anyhow!("password hash task: {e}")))?
}

/// [`verify_password`] on the blocking pool (see [`hash_password_blocking`]).
pub async fn verify_password_blocking(password: String, phc: String) -> bool {
    tokio::task::spawn_blocking(move || verify_password(&password, &phc))
        .await
        .unwrap_or(false)
}
