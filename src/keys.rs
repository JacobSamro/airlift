//! Per-app Expo code-signing key material: an RSA-2048 private key and a
//! long-lived self-signed X.509 certificate. The certificate is embedded in
//! the app binary (`updates.codeSigningCertificate`); expo-updates requires
//! `keyUsage digitalSignature` and `extendedKeyUsage codeSigning`, and RSA
//! pkcs1v15 + SHA-256 signatures (`alg: "rsa-v1_5-sha256"`).

use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey, LineEnding};
use rsa::RsaPrivateKey;

use crate::error::{Error, Result};

/// A freshly generated signing identity, both parts PEM-encoded.
pub struct SigningIdentity {
    pub private_key_pem: String,
    pub certificate_pem: String,
}

/// Generate an RSA-2048 keypair and a 20-year self-signed code-signing cert.
/// Key generation is CPU-bound (~100ms+); callers on the request path should
/// wrap this in `spawn_blocking`.
pub fn generate(common_name: &str) -> Result<SigningIdentity> {
    let mut rng = rand::rngs::OsRng;
    let key = RsaPrivateKey::new(&mut rng, 2048)
        .map_err(|e| Error::Other(anyhow::anyhow!("rsa keygen: {e}")))?;
    let private_key_pem = key
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(|e| Error::Other(anyhow::anyhow!("rsa pem: {e}")))?
        .to_string();

    let certificate_pem = self_signed_cert(&private_key_pem, common_name)?;
    Ok(SigningIdentity {
        private_key_pem,
        certificate_pem,
    })
}

/// Build the self-signed certificate for an existing PKCS#8 RSA key.
fn self_signed_cert(private_key_pem: &str, common_name: &str) -> Result<String> {
    let key_pair = rcgen::KeyPair::from_pem_and_sign_algo(private_key_pem, &rcgen::PKCS_RSA_SHA256)
        .map_err(|e| Error::Other(anyhow::anyhow!("cert keypair: {e}")))?;

    let mut params = rcgen::CertificateParams::new(Vec::new())
        .map_err(|e| Error::Other(anyhow::anyhow!("cert params: {e}")))?;
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, common_name);
    params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::CodeSigning];
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::days(1);
    params.not_after = now + time::Duration::days(365 * 20);

    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| Error::Other(anyhow::anyhow!("cert sign: {e}")))?;
    Ok(cert.pem())
}

/// Load the RSA private key back from its stored PEM (for manifest signing).
#[allow(dead_code)] // used by the manifest endpoint (later build phase)
pub fn private_key_from_pem(pem: &str) -> Result<RsaPrivateKey> {
    RsaPrivateKey::from_pkcs8_pem(pem)
        .map_err(|e| Error::Other(anyhow::anyhow!("stored key unreadable: {e}")))
}

#[cfg(test)]
mod tests {
    /// RSA + rcgen integration is the risky combination here: rcgen only
    /// signs RSA when the aws_lc_rs backend is enabled, so exercise the whole
    /// generate → parse-back path.
    #[test]
    fn generates_rsa_signing_identity() {
        let id = super::generate("airlift test").expect("generate");
        assert!(id.private_key_pem.contains("BEGIN PRIVATE KEY"));
        assert!(id.certificate_pem.contains("BEGIN CERTIFICATE"));
        super::private_key_from_pem(&id.private_key_pem).expect("key parses back");
    }
}
