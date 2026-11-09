//! Generic OpenID Connect relying party: discovery, authorization code flow
//! with PKCE (S256) + state + nonce, and ID-token verification against the
//! issuer's JWKS (RS256/RS384/RS512, ES256). Works with Okta, Entra ID,
//! Google Workspace, Keycloak, Authentik, Auth0, …

use std::sync::LazyLock;
use std::time::{Duration, Instant};

use base64::Engine;
use dashmap::DashMap;
use serde::Deserialize;
use serde_json::Value;
use sha2::Digest;

use crate::error::{Error, Result};

fn bad(msg: impl Into<String>) -> Error {
    Error::bad_request(format!("OIDC: {}", msg.into()))
}

fn b64url(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn b64url_decode(s: &str) -> Result<Vec<u8>> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s.trim_end_matches('='))
        .map_err(|_| bad("invalid base64url"))
}

#[derive(Debug, Clone, Deserialize)]
pub struct Discovery {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    #[serde(default)]
    pub token_endpoint_auth_methods_supported: Vec<String>,
}

const CACHE_TTL: Duration = Duration::from_secs(3600);
static DISCOVERY: LazyLock<DashMap<String, (Instant, Discovery)>> = LazyLock::new(DashMap::new);
static JWKS: LazyLock<DashMap<String, (Instant, Value)>> = LazyLock::new(DashMap::new);

fn http() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("http client")
}

/// `<issuer>/.well-known/openid-configuration`, cached for an hour.
pub async fn discover(issuer: &str) -> Result<Discovery> {
    let issuer = issuer.trim_end_matches('/');
    if let Some(e) = DISCOVERY.get(issuer) {
        if e.0.elapsed() < CACHE_TTL {
            return Ok(e.1.clone());
        }
    }
    let url = format!("{issuer}/.well-known/openid-configuration");
    let d: Discovery = http()
        .get(&url)
        .send()
        .await
        .and_then(|r| r.error_for_status())
        .map_err(|e| bad(format!("discovery {url}: {e}")))?
        .json()
        .await
        .map_err(|e| bad(format!("discovery {url}: {e}")))?;
    // The document must describe the issuer we were configured with.
    if d.issuer.trim_end_matches('/') != issuer {
        return Err(bad(format!(
            "discovery issuer {} does not match configured {issuer}",
            d.issuer
        )));
    }
    DISCOVERY.insert(issuer.to_string(), (Instant::now(), d.clone()));
    Ok(d)
}

async fn jwks(uri: &str, refresh: bool) -> Result<Value> {
    if !refresh {
        if let Some(e) = JWKS.get(uri) {
            if e.0.elapsed() < CACHE_TTL {
                return Ok(e.1.clone());
            }
        }
    }
    let v: Value = http()
        .get(uri)
        .send()
        .await
        .and_then(|r| r.error_for_status())
        .map_err(|e| bad(format!("jwks: {e}")))?
        .json()
        .await
        .map_err(|e| bad(format!("jwks: {e}")))?;
    JWKS.insert(uri.to_string(), (Instant::now(), v.clone()));
    Ok(v)
}

/// PKCE verifier and its S256 challenge.
pub fn pkce() -> (String, String) {
    let verifier = format!("{}{}", crate::util::random_id(), crate::util::random_id());
    let challenge = b64url(&sha2::Sha256::digest(verifier.as_bytes()));
    (verifier, challenge)
}

pub struct Client<'a> {
    pub client_id: &'a str,
    pub client_secret: &'a str,
    pub redirect_uri: &'a str,
    pub scopes: &'a str,
}

pub fn authorize_url(
    d: &Discovery,
    c: &Client<'_>,
    state: &str,
    nonce: &str,
    challenge: &str,
) -> Result<String> {
    let mut url = reqwest::Url::parse(&d.authorization_endpoint)
        .map_err(|_| bad("bad authorization_endpoint"))?;
    url.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", c.client_id)
        .append_pair("redirect_uri", c.redirect_uri)
        .append_pair("scope", c.scopes)
        .append_pair("state", state)
        .append_pair("nonce", nonce)
        .append_pair("code_challenge", challenge)
        .append_pair("code_challenge_method", "S256");
    Ok(url.to_string())
}

/// Exchange the code for tokens; returns the raw ID token.
pub async fn exchange(d: &Discovery, c: &Client<'_>, code: &str, verifier: &str) -> Result<String> {
    let mut form = vec![
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", c.redirect_uri),
        ("code_verifier", verifier),
    ];
    // client_secret_post unless the IdP only does client_secret_basic.
    let basic = !d.token_endpoint_auth_methods_supported.is_empty()
        && !d
            .token_endpoint_auth_methods_supported
            .iter()
            .any(|m| m == "client_secret_post");
    let mut req = http().post(&d.token_endpoint);
    if basic {
        req = req.basic_auth(c.client_id, Some(c.client_secret));
    } else {
        form.push(("client_id", c.client_id));
        form.push(("client_secret", c.client_secret));
    }
    let resp: Value = req
        .form(&form)
        .send()
        .await
        .map_err(|e| bad(format!("token request: {e}")))?
        .json()
        .await
        .map_err(|e| bad(format!("token response: {e}")))?;
    resp["id_token"].as_str().map(String::from).ok_or_else(|| {
        bad(format!(
            "no id_token in token response ({})",
            resp["error_description"]
                .as_str()
                .or(resp["error"].as_str())
                .unwrap_or("unknown error")
        ))
    })
}

/// Verified claims we use.
#[derive(Debug, Clone, PartialEq)]
pub struct Claims {
    pub sub: String,
    pub email: Option<String>,
    pub email_verified: bool,
    pub name: Option<String>,
}

/// Check a JWS signature with one JWK.
fn verify_with_jwk(alg: &str, jwk: &Value, signing_input: &[u8], sig: &[u8]) -> Result<bool> {
    match alg {
        "RS256" | "RS384" | "RS512" => {
            use rsa::pkcs1v15::{Signature, VerifyingKey};
            use rsa::signature::Verifier;
            let n = rsa::BigUint::from_bytes_be(&b64url_decode(jwk["n"].as_str().unwrap_or(""))?);
            let e = rsa::BigUint::from_bytes_be(&b64url_decode(jwk["e"].as_str().unwrap_or(""))?);
            let key = rsa::RsaPublicKey::new(n, e).map_err(|_| bad("bad RSA JWK"))?;
            let sig = Signature::try_from(sig).map_err(|_| bad("bad signature"))?;
            Ok(match alg {
                "RS256" => VerifyingKey::<sha2::Sha256>::new(key).verify(signing_input, &sig),
                "RS384" => VerifyingKey::<sha2::Sha384>::new(key).verify(signing_input, &sig),
                _ => VerifyingKey::<sha2::Sha512>::new(key).verify(signing_input, &sig),
            }
            .is_ok())
        }
        "ES256" => {
            use p256::ecdsa::signature::Verifier;
            let x = b64url_decode(jwk["x"].as_str().unwrap_or(""))?;
            let y = b64url_decode(jwk["y"].as_str().unwrap_or(""))?;
            if x.len() != 32 || y.len() != 32 {
                return Err(bad("bad EC JWK"));
            }
            let point = p256::EncodedPoint::from_affine_coordinates(
                x.as_slice().into(),
                y.as_slice().into(),
                false,
            );
            let key = p256::ecdsa::VerifyingKey::from_encoded_point(&point)
                .map_err(|_| bad("bad EC JWK"))?;
            let sig = p256::ecdsa::Signature::from_slice(sig).map_err(|_| bad("bad signature"))?;
            Ok(key.verify(signing_input, &sig).is_ok())
        }
        _ => Err(bad(format!("unsupported id_token alg {alg}"))),
    }
}

/// Verify an ID token against a JWKS document and the expected
/// issuer/audience/nonce at `now` (unix seconds).
pub fn verify_id_token(
    token: &str,
    jwks: &Value,
    issuer: &str,
    client_id: &str,
    nonce: &str,
    now: i64,
) -> Result<Claims> {
    let parts: Vec<&str> = token.split('.').collect();
    let [h, p, s] = parts.as_slice() else {
        return Err(bad("id_token is not a JWS"));
    };
    let header: Value =
        serde_json::from_slice(&b64url_decode(h)?).map_err(|_| bad("bad id_token header"))?;
    let alg = header["alg"].as_str().unwrap_or("");
    if alg == "none" || alg.starts_with("HS") {
        return Err(bad(format!("refusing id_token alg {alg}")));
    }
    let kid = header["kid"].as_str();
    let keys = jwks["keys"].as_array().cloned().unwrap_or_default();
    let candidates: Vec<&Value> = keys
        .iter()
        .filter(|k| kid.is_none_or(|kid| k["kid"].as_str() == Some(kid)))
        .filter(|k| k["use"].as_str().is_none_or(|u| u == "sig"))
        .collect();
    if candidates.is_empty() {
        return Err(bad("no matching key in the IdP's JWKS"));
    }
    let signing_input = format!("{h}.{p}");
    let sig = b64url_decode(s)?;
    let mut verified = false;
    for k in candidates {
        if verify_with_jwk(alg, k, signing_input.as_bytes(), &sig).unwrap_or(false) {
            verified = true;
            break;
        }
    }
    if !verified {
        return Err(bad("id_token signature verification failed"));
    }

    let c: Value =
        serde_json::from_slice(&b64url_decode(p)?).map_err(|_| bad("bad id_token payload"))?;
    if c["iss"].as_str().map(|i| i.trim_end_matches('/')) != Some(issuer.trim_end_matches('/')) {
        return Err(bad("id_token issuer mismatch"));
    }
    let aud_ok = match &c["aud"] {
        Value::String(a) => a == client_id,
        Value::Array(a) => {
            a.iter().any(|v| v.as_str() == Some(client_id))
                && (a.len() == 1 || c["azp"].as_str() == Some(client_id))
        }
        _ => false,
    };
    if !aud_ok {
        return Err(bad("id_token audience mismatch"));
    }
    const SKEW: i64 = 120;
    let exp = c["exp"]
        .as_i64()
        .ok_or_else(|| bad("id_token has no exp"))?;
    if now - SKEW >= exp {
        return Err(bad("id_token expired"));
    }
    if c["nonce"].as_str() != Some(nonce) {
        return Err(bad("id_token nonce mismatch"));
    }
    let email_verified = match &c["email_verified"] {
        Value::Bool(b) => *b,
        Value::String(s) => s == "true",
        _ => false,
    };
    Ok(Claims {
        sub: c["sub"].as_str().unwrap_or_default().to_string(),
        email: c["email"]
            .as_str()
            .or_else(|| c["preferred_username"].as_str().filter(|u| u.contains('@')))
            .map(|e| e.to_ascii_lowercase()),
        email_verified,
        name: c["name"].as_str().map(String::from),
    })
}

/// Fetch the JWKS (refreshing once on an unknown kid / failed verify, for
/// key rotation) and verify.
pub async fn verify(d: &Discovery, token: &str, client_id: &str, nonce: &str) -> Result<Claims> {
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let keys = jwks(&d.jwks_uri, false).await?;
    match verify_id_token(token, &keys, &d.issuer, client_id, nonce, now) {
        Ok(c) => Ok(c),
        Err(_) => {
            let keys = jwks(&d.jwks_uri, true).await?;
            verify_id_token(token, &keys, &d.issuer, client_id, nonce, now)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn jwt(header: Value, claims: Value, sign: impl Fn(&[u8]) -> Vec<u8>) -> String {
        let h = b64url(header.to_string().as_bytes());
        let p = b64url(claims.to_string().as_bytes());
        let s = b64url(&sign(format!("{h}.{p}").as_bytes()));
        format!("{h}.{p}.{s}")
    }

    fn claims(nonce: &str, exp: i64) -> Value {
        json!({ "iss": "https://idp.example", "aud": "air", "sub": "u1", "exp": exp,
                "nonce": nonce, "email": "Jane@Corp.Example", "email_verified": true, "name": "Jane" })
    }

    #[test]
    fn rs256_and_es256_tokens_verify() {
        use rsa::signature::{SignatureEncoding, Signer};
        use rsa::traits::PublicKeyParts;
        let rsa_key = rsa::RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048).unwrap();
        let pubk = rsa_key.to_public_key();
        let signer = rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new(rsa_key);
        let ec = p256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
        let point = ec.verifying_key().to_encoded_point(false);
        let jwks = json!({ "keys": [
            { "kty": "RSA", "kid": "r1", "use": "sig", "n": b64url(&pubk.n().to_bytes_be()), "e": b64url(&pubk.e().to_bytes_be()) },
            { "kty": "EC", "kid": "e1", "crv": "P-256", "x": b64url(point.x().unwrap()), "y": b64url(point.y().unwrap()) }
        ]});
        let rs = jwt(
            json!({ "alg": "RS256", "kid": "r1" }),
            claims("n1", 2_000_000_000),
            |m| signer.sign(m).to_vec(),
        );
        let c = verify_id_token(
            &rs,
            &jwks,
            "https://idp.example/",
            "air",
            "n1",
            1_900_000_000,
        )
        .unwrap();
        assert_eq!(c.email.as_deref(), Some("jane@corp.example"));
        assert!(c.email_verified);

        let es = jwt(
            json!({ "alg": "ES256", "kid": "e1" }),
            claims("n2", 2_000_000_000),
            |m| {
                let s: p256::ecdsa::Signature = ec.sign(m);
                s.to_bytes().to_vec()
            },
        );
        verify_id_token(
            &es,
            &jwks,
            "https://idp.example",
            "air",
            "n2",
            1_900_000_000,
        )
        .unwrap();

        // Wrong nonce / audience / issuer / expired / tampered / alg none.
        assert!(verify_id_token(
            &rs,
            &jwks,
            "https://idp.example",
            "air",
            "nX",
            1_900_000_000
        )
        .is_err());
        assert!(verify_id_token(
            &rs,
            &jwks,
            "https://idp.example",
            "other",
            "n1",
            1_900_000_000
        )
        .is_err());
        assert!(verify_id_token(
            &rs,
            &jwks,
            "https://evil.example",
            "air",
            "n1",
            1_900_000_000
        )
        .is_err());
        assert!(verify_id_token(
            &rs,
            &jwks,
            "https://idp.example",
            "air",
            "n1",
            2_100_000_000
        )
        .is_err());
        let mut parts: Vec<String> = rs.split('.').map(String::from).collect();
        let mut evil = claims("n1", 2_000_000_000);
        evil["email"] = json!("admin@corp.example");
        parts[1] = b64url(evil.to_string().as_bytes());
        assert!(verify_id_token(
            &parts.join("."),
            &jwks,
            "https://idp.example",
            "air",
            "n1",
            1_900_000_000
        )
        .is_err());
        let none = format!(
            "{}.{}.",
            b64url(json!({ "alg": "none" }).to_string().as_bytes()),
            b64url(claims("n1", 2_000_000_000).to_string().as_bytes())
        );
        assert!(verify_id_token(
            &none,
            &jwks,
            "https://idp.example",
            "air",
            "n1",
            1_900_000_000
        )
        .is_err());
    }
}
