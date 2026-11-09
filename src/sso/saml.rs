//! SAML 2.0 service provider: SP-initiated login via HTTP-Redirect
//! AuthnRequest, HTTP-POST response to the ACS.
//!
//! A response is accepted only if: it's a Success; exactly one (unencrypted)
//! Assertion, a direct child of the Response; the Assertion — or the whole
//! Response — carries a valid enveloped signature by the configured IdP
//! certificate; no duplicate IDs; Destination/Recipient = our ACS URL;
//! Audience = our entity id; InResponseTo = the request we issued (single
//! use, enforced by the caller); within NotBefore/NotOnOrAfter (2 min skew).
//! Claims are read only from that verified Assertion.

use std::io::Write;

use base64::Engine;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use super::xmldsig::{self, Element};
use crate::error::{Error, Result};

const NS_SAMLP: &str = "urn:oasis:names:tc:SAML:2.0:protocol";
const NS_SAML: &str = "urn:oasis:names:tc:SAML:2.0:assertion";
const STATUS_SUCCESS: &str = "urn:oasis:names:tc:SAML:2.0:status:Success";
const CM_BEARER: &str = "urn:oasis:names:tc:SAML:2.0:cm:bearer";
const SKEW_SECS: i64 = 120;
/// Responses bigger than this are refused before parsing.
const MAX_RESPONSE_BYTES: usize = 512 * 1024;

fn bad(msg: impl Into<String>) -> Error {
    Error::bad_request(format!("SAML: {}", msg.into()))
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Our side of the federation.
pub struct ServiceProvider<'a> {
    /// SP entity id (we use the metadata URL).
    pub entity_id: &'a str,
    /// Assertion Consumer Service URL (HTTP-POST binding).
    pub acs_url: &'a str,
}

/// SP metadata XML for the IdP admin to import.
pub fn metadata(sp: &ServiceProvider<'_>) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{entity}">
  <md:SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="{acs}" index="0" isDefault="true"/>
  </md:SPSSODescriptor>
</md:EntityDescriptor>
"#,
        entity = xml_escape(sp.entity_id),
        acs = xml_escape(sp.acs_url),
    )
}

/// The IdP redirect URL carrying a deflated AuthnRequest (HTTP-Redirect
/// binding) with `request_id`; `relay_state` comes back with the response.
pub fn authn_redirect(
    sp: &ServiceProvider<'_>,
    idp_sso_url: &str,
    request_id: &str,
    relay_state: &str,
) -> Result<String> {
    let now = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .map_err(|e| Error::Other(anyhow::anyhow!("{e}")))?;
    let req = format!(
        r#"<samlp:AuthnRequest xmlns:samlp="{NS_SAMLP}" xmlns:saml="{NS_SAML}" ID="{id}" Version="2.0" IssueInstant="{now}" Destination="{dest}" AssertionConsumerServiceURL="{acs}" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"><saml:Issuer>{entity}</saml:Issuer><samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" AllowCreate="true"/></samlp:AuthnRequest>"#,
        id = xml_escape(request_id),
        dest = xml_escape(idp_sso_url),
        acs = xml_escape(sp.acs_url),
        entity = xml_escape(sp.entity_id),
    );
    let mut enc = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
    enc.write_all(req.as_bytes())
        .map_err(|e| Error::Other(anyhow::anyhow!("deflate: {e}")))?;
    let deflated = enc
        .finish()
        .map_err(|e| Error::Other(anyhow::anyhow!("deflate: {e}")))?;
    let mut url =
        reqwest::Url::parse(idp_sso_url).map_err(|_| bad("IdP SSO URL is not a valid URL"))?;
    url.query_pairs_mut()
        .append_pair(
            "SAMLRequest",
            &base64::engine::general_purpose::STANDARD.encode(deflated),
        )
        .append_pair("RelayState", relay_state);
    Ok(url.to_string())
}

/// What the IdP told us about the user.
#[derive(Debug, Clone, PartialEq)]
pub struct Identity {
    pub email: String,
    pub name: Option<String>,
    pub name_id: String,
}

/// Validate a POSTed `SAMLResponse` and extract the identity.
pub struct Expect<'a> {
    pub sp: ServiceProvider<'a>,
    /// The AuthnRequest ID we issued (looked up from RelayState).
    pub request_id: &'a str,
    /// Configured IdP entity id; checked against the Issuer when set.
    pub idp_entity_id: Option<&'a str>,
    pub idp_key: &'a rsa::RsaPublicKey,
    pub now: OffsetDateTime,
}

fn time_attr(el: &Element, name: &str) -> Result<Option<OffsetDateTime>> {
    match el.attr(name) {
        None => Ok(None),
        Some(v) => OffsetDateTime::parse(v.trim(), &Rfc3339)
            .map(Some)
            .map_err(|_| bad(format!("bad {name} timestamp"))),
    }
}

pub fn validate_response(saml_response_b64: &str, ex: &Expect<'_>) -> Result<Identity> {
    let clean: String = saml_response_b64
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    let raw = base64::engine::general_purpose::STANDARD
        .decode(clean)
        .map_err(|_| bad("SAMLResponse is not base64"))?;
    if raw.len() > MAX_RESPONSE_BYTES {
        return Err(bad("response too large"));
    }
    let xml = String::from_utf8(raw).map_err(|_| bad("response is not UTF-8"))?;
    let resp = xmldsig::parse(&xml)?;
    if !resp.is(NS_SAMLP, "Response") {
        return Err(bad("not a samlp:Response"));
    }

    // Unique IDs across the document (wrapping attacks rely on duplicates).
    let mut ids = std::collections::HashSet::new();
    for e in resp.descendants() {
        if let Some(id) = e.attr("ID") {
            if !ids.insert(id) {
                return Err(bad("duplicate ID attribute"));
            }
        }
    }
    if resp
        .descendants()
        .iter()
        .any(|e| e.is(NS_SAML, "EncryptedAssertion"))
    {
        return Err(bad(
            "encrypted assertions are not supported; disable assertion encryption at the IdP",
        ));
    }
    let all_assertions: Vec<_> = resp
        .descendants()
        .into_iter()
        .filter(|e| e.is(NS_SAML, "Assertion"))
        .collect();
    let direct: Vec<_> = resp
        .elements()
        .filter(|e| e.is(NS_SAML, "Assertion"))
        .collect();
    let ([assertion], 1) = (direct.as_slice(), all_assertions.len()) else {
        return Err(bad(
            "expected exactly one Assertion directly in the Response",
        ));
    };

    // Signature: on the Assertion, or on the whole Response (which covers it).
    if assertion.child(xmldsig::NS_DSIG, "Signature").is_some() {
        xmldsig::verify_enveloped(assertion, ex.idp_key)?;
    } else if resp.child(xmldsig::NS_DSIG, "Signature").is_some() {
        xmldsig::verify_enveloped(&resp, ex.idp_key)?;
    } else {
        return Err(bad("neither the Assertion nor the Response is signed"));
    }

    // Response-level checks.
    let status = resp
        .child(NS_SAMLP, "Status")
        .and_then(|s| s.child(NS_SAMLP, "StatusCode"))
        .and_then(|c| c.attr("Value"));
    if status != Some(STATUS_SUCCESS) {
        return Err(bad(format!(
            "IdP returned status {}",
            status.unwrap_or("(none)")
        )));
    }
    if let Some(dest) = resp.attr("Destination") {
        if dest != ex.sp.acs_url {
            return Err(bad("Destination is not this ACS URL"));
        }
    }
    if let Some(irt) = resp.attr("InResponseTo") {
        if irt != ex.request_id {
            return Err(bad("InResponseTo does not match the login request"));
        }
    }

    // Assertion checks (claims come only from here).
    if let Some(expected) = ex.idp_entity_id.filter(|s| !s.is_empty()) {
        let issuer = assertion
            .child(NS_SAML, "Issuer")
            .map(|i| i.text())
            .unwrap_or_default();
        if issuer.trim() != expected {
            return Err(bad("unexpected Issuer"));
        }
    }
    let skew = time::Duration::seconds(SKEW_SECS);
    let conditions = assertion
        .child(NS_SAML, "Conditions")
        .ok_or_else(|| bad("assertion has no Conditions"))?;
    if let Some(nb) = time_attr(conditions, "NotBefore")? {
        if ex.now + skew < nb {
            return Err(bad("assertion not yet valid"));
        }
    }
    let not_after =
        time_attr(conditions, "NotOnOrAfter")?.ok_or_else(|| bad("assertion has no expiry"))?;
    if ex.now - skew >= not_after {
        return Err(bad("assertion expired"));
    }
    let audience_ok = conditions
        .elements()
        .filter(|e| e.is(NS_SAML, "AudienceRestriction"))
        .flat_map(|r| r.elements().filter(|a| a.is(NS_SAML, "Audience")))
        .any(|a| a.text().trim() == ex.sp.entity_id);
    if !audience_ok {
        return Err(bad("assertion is not for this service provider (Audience)"));
    }

    let subject = assertion
        .child(NS_SAML, "Subject")
        .ok_or_else(|| bad("assertion has no Subject"))?;
    let confirmed = subject
        .elements()
        .filter(|e| e.is(NS_SAML, "SubjectConfirmation") && e.attr("Method") == Some(CM_BEARER))
        .filter_map(|sc| sc.child(NS_SAML, "SubjectConfirmationData"))
        .any(|d| {
            d.attr("Recipient") == Some(ex.sp.acs_url)
                && d.attr("InResponseTo") == Some(ex.request_id)
                && time_attr(d, "NotOnOrAfter")
                    .ok()
                    .flatten()
                    .is_some_and(|t| ex.now - skew < t)
        });
    if !confirmed {
        return Err(bad(
            "no valid bearer SubjectConfirmation (Recipient/InResponseTo/NotOnOrAfter)",
        ));
    }

    let name_id = subject
        .child(NS_SAML, "NameID")
        .map(|n| n.text().trim().to_string())
        .unwrap_or_default();
    let attr = |names: &[&str]| -> Option<String> {
        assertion
            .elements()
            .filter(|e| e.is(NS_SAML, "AttributeStatement"))
            .flat_map(|s| s.elements().filter(|a| a.is(NS_SAML, "Attribute")))
            .find(|a| a.attr("Name").is_some_and(|n| names.contains(&n)))
            .and_then(|a| a.child(NS_SAML, "AttributeValue"))
            .map(|v| v.text().trim().to_string())
            .filter(|v| !v.is_empty())
    };
    let email = attr(&[
        "email",
        "mail",
        "emailaddress",
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
        "urn:oid:0.9.2342.19200300.100.1.3",
    ])
    .or_else(|| name_id.contains('@').then(|| name_id.clone()))
    .ok_or_else(|| bad("no email in the assertion (NameID or email attribute)"))?;
    let name = attr(&[
        "displayName",
        "name",
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
        "urn:oid:2.16.840.1.113730.3.1.241",
    ]);
    Ok(Identity {
        email: email.to_ascii_lowercase(),
        name,
        name_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const ACS: &str = "https://air.example/api/v1/auth/sso/p1/saml/acs";
    const ENTITY: &str = "https://air.example/api/v1/auth/sso/p1/saml/metadata";

    fn expect(key: &rsa::RsaPublicKey) -> Expect<'_> {
        Expect {
            sp: ServiceProvider {
                entity_id: ENTITY,
                acs_url: ACS,
            },
            request_id: "_req42",
            idp_entity_id: Some("https://idp.example/"),
            idp_key: key,
            now: OffsetDateTime::parse("2026-06-01T00:00:00Z", &Rfc3339).unwrap(),
        }
    }

    fn b64(xml: &str) -> String {
        base64::engine::general_purpose::STANDARD.encode(xml)
    }

    fn idp() -> rsa::RsaPublicKey {
        xmldsig::rsa_key_from_cert_pem(include_str!("testdata/idp.crt")).unwrap()
    }

    const SIGNED_ASSERTION: &str = include_str!("testdata/saml_assertion_signed.xml");
    const SIGNED_RESPONSE: &str = include_str!("testdata/saml_response_signed.xml");

    #[test]
    fn accepts_signed_assertion_and_signed_response() {
        let key = idp();
        for xml in [SIGNED_ASSERTION, SIGNED_RESPONSE] {
            let id = validate_response(&b64(xml), &expect(&key)).unwrap();
            assert_eq!(id.email, "jane.doe@corp.example");
            assert_eq!(id.name.as_deref(), Some("Jane Dö & Co"));
        }
    }

    #[test]
    fn rejects_replays_wrong_audience_and_expiry() {
        let key = idp();
        let mut e = expect(&key);
        e.request_id = "_other";
        assert!(validate_response(&b64(SIGNED_ASSERTION), &e).is_err());

        let mut e = expect(&key);
        e.sp.entity_id = "https://elsewhere.example/";
        assert!(validate_response(&b64(SIGNED_ASSERTION), &e).is_err());

        let mut e = expect(&key);
        e.sp.acs_url = "https://air.example/other";
        assert!(validate_response(&b64(SIGNED_ASSERTION), &e).is_err());

        let mut e = expect(&key);
        e.now = OffsetDateTime::parse("2100-01-01T00:00:00Z", &Rfc3339).unwrap();
        assert!(validate_response(&b64(SIGNED_ASSERTION), &e).is_err());

        let mut e = expect(&key);
        e.idp_entity_id = Some("https://not-the-idp/");
        assert!(validate_response(&b64(SIGNED_ASSERTION), &e).is_err());
    }

    #[test]
    fn rejects_signature_wrapping() {
        let key = idp();
        // Attacker wraps the genuine signed assertion and adds their own
        // unsigned one with a different email as the "real" assertion.
        let evil = SIGNED_ASSERTION.replacen(
            "<saml2:Assertion",
            "<saml2:Assertion xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_evil\" Version=\"2.0\" IssueInstant=\"2026-01-01T00:00:00Z\"><saml2:Issuer>https://idp.example/</saml2:Issuer><saml2:Subject><saml2:NameID>attacker@evil.example</saml2:NameID></saml2:Subject></saml2:Assertion><saml2:Assertion",
            1,
        );
        assert!(validate_response(&b64(&evil), &expect(&key)).is_err());

        // Moving the signed assertion under an extension and adding an
        // unsigned one also fails (exactly one Assertion allowed).
        let doc = xmldsig::parse(SIGNED_ASSERTION).unwrap();
        assert!(doc.descendants().iter().any(|e| e.local == "Assertion"));
        let nested = SIGNED_ASSERTION.replacen(
            "<samlp:Status>",
            "<samlp:Extensions><saml2:Assertion xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_x\"/></samlp:Extensions><samlp:Status>",
            1,
        );
        assert!(validate_response(&b64(&nested), &expect(&key)).is_err());
    }

    #[test]
    fn rejects_unsigned_and_wrong_key() {
        let key = idp();
        let other = xmldsig::rsa_key_from_cert_pem(include_str!("testdata/other.crt")).unwrap();
        assert!(validate_response(&b64(SIGNED_ASSERTION), &expect(&other)).is_err());
        // Strip the signature entirely.
        let start = SIGNED_ASSERTION.find("<ds:Signature").unwrap();
        let end = SIGNED_ASSERTION.find("</ds:Signature>").unwrap() + "</ds:Signature>".len();
        let unsigned = format!("{}{}", &SIGNED_ASSERTION[..start], &SIGNED_ASSERTION[end..]);
        let err = validate_response(&b64(&unsigned), &expect(&key)).unwrap_err();
        assert!(err.to_string().contains("signed"), "{err}");
    }

    #[test]
    fn authn_request_round_trips() {
        let sp = ServiceProvider {
            entity_id: ENTITY,
            acs_url: ACS,
        };
        let url = authn_redirect(&sp, "https://idp.example/sso?x=1", "_req42", "st").unwrap();
        let parsed = reqwest::Url::parse(&url).unwrap();
        let q: std::collections::HashMap<_, _> = parsed.query_pairs().into_owned().collect();
        assert_eq!(q["x"], "1");
        assert_eq!(q["RelayState"], "st");
        let raw = base64::engine::general_purpose::STANDARD
            .decode(&q["SAMLRequest"])
            .unwrap();
        let mut xml = String::new();
        std::io::Read::read_to_string(&mut flate2::read::DeflateDecoder::new(&raw[..]), &mut xml)
            .unwrap();
        let req = xmldsig::parse(&xml).unwrap();
        assert_eq!(req.attr("ID"), Some("_req42"));
        assert_eq!(req.attr("AssertionConsumerServiceURL"), Some(ACS));
        assert!(metadata(&sp).contains(ACS));
    }
}
