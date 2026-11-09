//! A small, strict XML tree + Exclusive XML Canonicalization (exc-c14n,
//! without comments) + XML-DSig enveloped-signature verification — just
//! what SAML 2.0 responses need, in pure Rust (no libxmlsec).
//!
//! Hardening:
//! - DOCTYPEs are rejected outright (no entity expansion / XXE).
//! - Only exc-c14n canonicalization, the enveloped-signature transform,
//!   SHA-256/512 digests and RSA-SHA256/512 signatures are accepted.
//! - A signature must contain exactly one Reference, and it must point at
//!   the element it is an enveloped child of (`URI="#<that element's ID>"`);
//!   callers read claims only from that element (signature-wrapping defence).
//! - The verification key is supplied by the caller (the IdP certificate an
//!   admin configured), never taken from the message's KeyInfo.

use std::collections::BTreeMap;

use base64::Engine;
use quick_xml::events::Event;
use quick_xml::Reader;

use crate::error::{Error, Result};

pub const NS_DSIG: &str = "http://www.w3.org/2000/09/xmldsig#";
const ALG_EXC_C14N: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
const ALG_ENVELOPED: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
const ALG_SHA256: &str = "http://www.w3.org/2001/04/xmlenc#sha256";
const ALG_SHA512: &str = "http://www.w3.org/2001/04/xmlenc#sha512";
const ALG_RSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
const ALG_RSA_SHA512: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";
const NS_XML: &str = "http://www.w3.org/XML/1998/namespace";

fn bad(msg: impl Into<String>) -> Error {
    Error::bad_request(format!("SAML: {}", msg.into()))
}

/// In-scope namespace bindings: prefix ("" = default) → URI ("" = none).
type Scope = BTreeMap<String, String>;

#[derive(Debug, Clone)]
pub struct Attr {
    pub prefix: Option<String>,
    pub local: String,
    pub ns: Option<String>,
    pub value: String,
}

#[derive(Debug, Clone)]
pub struct Element {
    pub prefix: Option<String>,
    pub local: String,
    /// Resolved namespace URI (None = no namespace).
    pub ns: Option<String>,
    /// Non-`xmlns` attributes, in document order.
    pub attrs: Vec<Attr>,
    /// All namespace bindings in scope at this element (input document).
    scope: Scope,
    pub children: Vec<Node>,
}

#[derive(Debug, Clone)]
pub enum Node {
    Element(Element),
    Text(String),
    Pi(String, String),
}

impl Element {
    pub fn is(&self, ns: &str, local: &str) -> bool {
        self.local == local && self.ns.as_deref() == Some(ns)
    }

    pub fn attr(&self, local: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|a| a.local == local && a.ns.is_none())
            .map(|a| a.value.as_str())
    }

    pub fn elements(&self) -> impl Iterator<Item = &Element> {
        self.children.iter().filter_map(|c| match c {
            Node::Element(e) => Some(e),
            _ => None,
        })
    }

    pub fn child(&self, ns: &str, local: &str) -> Option<&Element> {
        self.elements().find(|e| e.is(ns, local))
    }

    /// Concatenated descendant text.
    pub fn text(&self) -> String {
        let mut s = String::new();
        for c in &self.children {
            match c {
                Node::Text(t) => s.push_str(t),
                Node::Element(e) => s.push_str(&e.text()),
                Node::Pi(..) => {}
            }
        }
        s
    }

    /// Every element in the subtree (self first).
    pub fn descendants(&self) -> Vec<&Element> {
        let mut out = vec![self];
        for e in self.elements() {
            out.extend(e.descendants());
        }
        out
    }
}

/// XML end-of-line handling: CRLF and lone CR become LF.
fn normalize_eol(s: &str) -> String {
    s.replace("\r\n", "\n").replace('\r', "\n")
}

fn unescape(raw: &str) -> Result<String> {
    quick_xml::escape::unescape(raw)
        .map(|c| c.into_owned())
        .map_err(|e| bad(format!("bad entity: {e}")))
}

fn split_qname(q: &str) -> (Option<String>, String) {
    match q.split_once(':') {
        Some((p, l)) => (Some(p.to_string()), l.to_string()),
        None => (None, q.to_string()),
    }
}

/// Parse a document into its root element. Rejects DOCTYPEs.
pub fn parse(xml: &str) -> Result<Element> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(false);
    reader.config_mut().expand_empty_elements = true;
    let mut base_scope = Scope::new();
    base_scope.insert("xml".into(), NS_XML.into());
    let mut stack: Vec<Element> = Vec::new();
    let mut root: Option<Element> = None;
    loop {
        let ev = reader
            .read_event()
            .map_err(|e| bad(format!("malformed XML: {e}")))?;
        match ev {
            Event::DocType(_) => return Err(bad("DOCTYPE is not allowed")),
            Event::Start(e) => {
                let qname = std::str::from_utf8(e.name().as_ref())
                    .map_err(|_| bad("non-UTF-8 name"))?
                    .to_string();
                let mut scope = stack
                    .last()
                    .map(|p| p.scope.clone())
                    .unwrap_or_else(|| base_scope.clone());
                let mut raw_attrs = Vec::new();
                for a in e.attributes() {
                    let a = a.map_err(|e| bad(format!("bad attribute: {e}")))?;
                    let key = std::str::from_utf8(a.key.as_ref())
                        .map_err(|_| bad("non-UTF-8 attribute"))?
                        .to_string();
                    let raw = std::str::from_utf8(&a.value)
                        .map_err(|_| bad("non-UTF-8 attribute value"))?;
                    // Attribute-value normalization (CDATA type): literal
                    // whitespace → space, before resolving references.
                    let norm = normalize_eol(raw).replace(['\t', '\n'], " ");
                    let value = unescape(&norm)?;
                    if key == "xmlns" {
                        scope.insert(String::new(), value);
                    } else if let Some(p) = key.strip_prefix("xmlns:") {
                        scope.insert(p.to_string(), value);
                    } else {
                        raw_attrs.push((key, value));
                    }
                }
                let (prefix, local) = split_qname(&qname);
                let ns = scope
                    .get(prefix.as_deref().unwrap_or(""))
                    .filter(|u| !u.is_empty())
                    .cloned();
                if prefix.is_some() && ns.is_none() {
                    return Err(bad(format!("undeclared prefix in <{qname}>")));
                }
                let mut attrs = Vec::new();
                for (key, value) in raw_attrs {
                    let (p, l) = split_qname(&key);
                    let ans = match &p {
                        Some(p) => Some(
                            scope
                                .get(p)
                                .cloned()
                                .ok_or_else(|| bad(format!("undeclared prefix {p}")))?,
                        ),
                        None => None,
                    };
                    attrs.push(Attr {
                        prefix: p,
                        local: l,
                        ns: ans,
                        value,
                    });
                }
                stack.push(Element {
                    prefix,
                    local,
                    ns,
                    attrs,
                    scope,
                    children: Vec::new(),
                });
            }
            Event::End(_) => {
                let el = stack.pop().ok_or_else(|| bad("unbalanced end tag"))?;
                match stack.last_mut() {
                    Some(parent) => parent.children.push(Node::Element(el)),
                    None => {
                        if root.is_some() {
                            return Err(bad("multiple root elements"));
                        }
                        root = Some(el);
                    }
                }
            }
            Event::Text(t) => {
                let raw = std::str::from_utf8(t.as_ref()).map_err(|_| bad("non-UTF-8 text"))?;
                let text = unescape(&normalize_eol(raw))?;
                if let Some(parent) = stack.last_mut() {
                    parent.children.push(Node::Text(text));
                } else if !text.trim().is_empty() {
                    return Err(bad("text outside the root element"));
                }
            }
            Event::CData(c) => {
                let raw = std::str::from_utf8(c.as_ref()).map_err(|_| bad("non-UTF-8 CDATA"))?;
                if let Some(parent) = stack.last_mut() {
                    parent.children.push(Node::Text(normalize_eol(raw)));
                }
            }
            Event::PI(p) => {
                let raw = std::str::from_utf8(p.as_ref()).map_err(|_| bad("non-UTF-8 PI"))?;
                let (target, data) = raw.split_once(char::is_whitespace).unwrap_or((raw, ""));
                if let Some(parent) = stack.last_mut() {
                    parent
                        .children
                        .push(Node::Pi(target.to_string(), data.trim_start().to_string()));
                }
            }
            Event::Comment(_) | Event::Decl(_) | Event::Empty(_) => {}
            Event::Eof => break,
        }
    }
    if !stack.is_empty() {
        return Err(bad("unclosed element"));
    }
    root.ok_or_else(|| bad("empty document"))
}

// ───────────────────────── exclusive c14n ─────────────────────────

fn esc_text(s: &str, out: &mut String) {
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\r' => out.push_str("&#xD;"),
            c => out.push(c),
        }
    }
}

fn esc_attr(s: &str, out: &mut String) {
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '"' => out.push_str("&quot;"),
            '\t' => out.push_str("&#x9;"),
            '\n' => out.push_str("&#xA;"),
            '\r' => out.push_str("&#xD;"),
            c => out.push(c),
        }
    }
}

/// Exclusive canonical form (without comments) of `el`'s subtree, omitting
/// the `omit` element (enveloped-signature transform) and treating
/// `inclusive` prefixes ("#default" = default namespace) as inclusive.
pub fn exc_c14n(el: &Element, omit: Option<&Element>, inclusive: &[String]) -> String {
    let mut out = String::new();
    write_c14n(el, omit, inclusive, &Scope::new(), &mut out);
    out
}

fn write_c14n(
    el: &Element,
    omit: Option<&Element>,
    inclusive: &[String],
    rendered: &Scope,
    out: &mut String,
) {
    // Prefixes this element must declare: visibly utilized ones, plus the
    // InclusiveNamespaces list (when in scope).
    let mut wanted: Vec<String> = vec![el.prefix.clone().unwrap_or_default()];
    for a in &el.attrs {
        if let Some(p) = &a.prefix {
            if p != "xml" {
                wanted.push(p.clone());
            }
        }
    }
    for p in inclusive {
        let p = if p == "#default" {
            String::new()
        } else {
            p.clone()
        };
        if el.scope.contains_key(&p) {
            wanted.push(p);
        }
    }
    wanted.sort();
    wanted.dedup();

    let mut now_rendered = rendered.clone();
    let mut decls: Vec<(String, String)> = Vec::new();
    for p in wanted {
        let uri = el.scope.get(&p).cloned().unwrap_or_default();
        let prev = rendered.get(&p);
        let needed = if p.is_empty() && uri.is_empty() {
            // xmlns="" only to undo a rendered non-empty default.
            prev.is_some_and(|u| !u.is_empty())
        } else {
            prev != Some(&uri)
        };
        if needed {
            decls.push((p.clone(), uri.clone()));
            now_rendered.insert(p, uri);
        }
    }

    let qname = |prefix: &Option<String>, local: &str| match prefix {
        Some(p) => format!("{p}:{local}"),
        None => local.to_string(),
    };
    out.push('<');
    out.push_str(&qname(&el.prefix, &el.local));
    for (p, uri) in &decls {
        if p.is_empty() {
            out.push_str(" xmlns=\"");
        } else {
            out.push_str(" xmlns:");
            out.push_str(p);
            out.push_str("=\"");
        }
        esc_attr(uri, out);
        out.push('"');
    }
    let mut attrs: Vec<&Attr> = el.attrs.iter().collect();
    attrs.sort_by(|a, b| {
        (a.ns.as_deref().unwrap_or(""), a.local.as_str())
            .cmp(&(b.ns.as_deref().unwrap_or(""), b.local.as_str()))
    });
    for a in attrs {
        out.push(' ');
        out.push_str(&qname(&a.prefix, &a.local));
        out.push_str("=\"");
        esc_attr(&a.value, out);
        out.push('"');
    }
    out.push('>');
    for c in &el.children {
        match c {
            Node::Text(t) => esc_text(t, out),
            Node::Pi(target, data) => {
                out.push_str("<?");
                out.push_str(target);
                if !data.is_empty() {
                    out.push(' ');
                    out.push_str(data);
                }
                out.push_str("?>");
            }
            Node::Element(child) => {
                if omit.is_some_and(|o| std::ptr::eq(o, child)) {
                    continue;
                }
                write_c14n(child, omit, inclusive, &now_rendered, out);
            }
        }
    }
    out.push_str("</");
    out.push_str(&qname(&el.prefix, &el.local));
    out.push('>');
}

// ───────────────────────── signature verification ─────────────────────────

fn inclusive_prefixes(transform: &Element) -> Vec<String> {
    transform
        .elements()
        .find(|e| e.local == "InclusiveNamespaces")
        .and_then(|e| e.attr("PrefixList"))
        .map(|l| l.split_whitespace().map(String::from).collect())
        .unwrap_or_default()
}

fn b64(s: &str) -> Result<Vec<u8>> {
    let clean: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    base64::engine::general_purpose::STANDARD
        .decode(clean)
        .map_err(|_| bad("invalid base64 in signature"))
}

/// Verify the enveloped XML-DSig signature that is a direct child of
/// `target`, against `key`. On success, `target` (and only `target`) is
/// authenticated.
pub fn verify_enveloped(target: &Element, key: &rsa::RsaPublicKey) -> Result<()> {
    use rsa::pkcs1v15::{Signature, VerifyingKey};
    use rsa::signature::Verifier;
    use sha2::Digest;

    let sig = target
        .child(NS_DSIG, "Signature")
        .ok_or_else(|| bad("element is not signed"))?;
    let si = sig
        .child(NS_DSIG, "SignedInfo")
        .ok_or_else(|| bad("no SignedInfo"))?;

    let c14n = si
        .child(NS_DSIG, "CanonicalizationMethod")
        .ok_or_else(|| bad("no CanonicalizationMethod"))?;
    if c14n.attr("Algorithm") != Some(ALG_EXC_C14N) {
        return Err(bad("unsupported canonicalization (exc-c14n only)"));
    }
    let sig_alg = si
        .child(NS_DSIG, "SignatureMethod")
        .and_then(|m| m.attr("Algorithm"))
        .ok_or_else(|| bad("no SignatureMethod"))?;

    let refs: Vec<_> = si
        .elements()
        .filter(|e| e.is(NS_DSIG, "Reference"))
        .collect();
    let [reference] = refs.as_slice() else {
        return Err(bad("exactly one signature Reference is required"));
    };
    let id = target
        .attr("ID")
        .ok_or_else(|| bad("signed element has no ID"))?;
    if reference.attr("URI") != Some(&format!("#{id}")) {
        return Err(bad("signature does not reference the signed element"));
    }
    let mut prefixes = Vec::new();
    let mut saw_c14n = false;
    if let Some(ts) = reference.child(NS_DSIG, "Transforms") {
        for t in ts.elements().filter(|e| e.is(NS_DSIG, "Transform")) {
            match t.attr("Algorithm") {
                Some(ALG_ENVELOPED) => {}
                Some(ALG_EXC_C14N) => {
                    saw_c14n = true;
                    prefixes = inclusive_prefixes(t);
                }
                _ => return Err(bad("unsupported transform")),
            }
        }
    }
    let _ = saw_c14n; // exc-c14n is applied either way (it's the default output form)
    let digest_alg = reference
        .child(NS_DSIG, "DigestMethod")
        .and_then(|m| m.attr("Algorithm"))
        .ok_or_else(|| bad("no DigestMethod"))?;
    let expected = b64(&reference
        .child(NS_DSIG, "DigestValue")
        .ok_or_else(|| bad("no DigestValue"))?
        .text())?;
    let canon = exc_c14n(target, Some(sig), &prefixes);
    let actual: Vec<u8> = match digest_alg {
        ALG_SHA256 => sha2::Sha256::digest(canon.as_bytes()).to_vec(),
        ALG_SHA512 => sha2::Sha512::digest(canon.as_bytes()).to_vec(),
        _ => return Err(bad("unsupported digest (SHA-256/512 only)")),
    };
    if actual != expected {
        return Err(bad("digest mismatch: the signed content was altered"));
    }

    let si_canon = exc_c14n(si, None, &inclusive_prefixes(c14n));
    let sig_bytes = b64(&sig
        .child(NS_DSIG, "SignatureValue")
        .ok_or_else(|| bad("no SignatureValue"))?
        .text())?;
    let signature =
        Signature::try_from(sig_bytes.as_slice()).map_err(|_| bad("malformed signature"))?;
    let ok = match sig_alg {
        ALG_RSA_SHA256 => VerifyingKey::<sha2::Sha256>::new(key.clone())
            .verify(si_canon.as_bytes(), &signature)
            .is_ok(),
        ALG_RSA_SHA512 => VerifyingKey::<sha2::Sha512>::new(key.clone())
            .verify(si_canon.as_bytes(), &signature)
            .is_ok(),
        _ => return Err(bad("unsupported signature algorithm (RSA-SHA256/512 only)")),
    };
    if !ok {
        return Err(bad("signature verification failed"));
    }
    Ok(())
}

/// The RSA public key of a PEM X.509 certificate.
pub fn rsa_key_from_cert_pem(pem: &str) -> Result<rsa::RsaPublicKey> {
    use rsa::pkcs8::DecodePublicKey;
    let (_, p) = x509_parser::pem::parse_x509_pem(pem.trim().as_bytes())
        .map_err(|_| bad("IdP certificate is not valid PEM"))?;
    let cert = p
        .parse_x509()
        .map_err(|_| bad("IdP certificate is not valid X.509"))?;
    rsa::RsaPublicKey::from_public_key_der(cert.public_key().raw)
        .map_err(|_| bad("IdP certificate must carry an RSA key"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_doctype() {
        assert!(parse("<!DOCTYPE x [<!ENTITY a \"b\">]><x>&a;</x>").is_err());
    }

    #[test]
    fn c14n_basics() {
        let doc = parse(
            "<a:r xmlns:a=\"urn:a\" xmlns:b=\"urn:b\" z=\"1\" b:y=\"2\" a=\"&lt;q&quot;\">\r\n<!-- c --><a:e/><![CDATA[x<y]]></a:r>",
        )
        .unwrap();
        // b is used by an attribute → declared; comment dropped; CDATA
        // escaped; empty element expanded; CRLF → LF; attrs sorted.
        assert_eq!(
            exc_c14n(&doc, None, &[]),
            "<a:r xmlns:a=\"urn:a\" xmlns:b=\"urn:b\" a=\"&lt;q&quot;\" z=\"1\" b:y=\"2\">\n<a:e></a:e>x&lt;y</a:r>"
        );
    }
}

/// Cross-checked against libxml2 (lxml) — an independent exc-c14n
/// implementation — and against SAML responses signed with libxml2's c14n +
/// openssl (regenerate with testdata/gen.py).
#[cfg(test)]
mod libxml2_vectors {
    use super::*;

    fn find<'a>(el: &'a Element, local: &str) -> Option<&'a Element> {
        el.descendants().into_iter().find(|e| e.local == local)
    }

    #[test]
    fn c14n_matches_libxml2() {
        let cases: Vec<serde_json::Value> =
            serde_json::from_str(include_str!("testdata/c14n_cases.json")).unwrap();
        assert!(cases.len() > 10);
        for c in cases {
            let doc = parse(c["xml"].as_str().unwrap()).unwrap();
            let target = find(&doc, c["target"].as_str().unwrap()).unwrap();
            let inclusive: Vec<String> = c["inclusive"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap().to_string())
                .collect();
            assert_eq!(
                exc_c14n(target, None, &inclusive),
                c["expected"].as_str().unwrap(),
                "case {c}"
            );
        }
    }

    fn key(pem: &str) -> rsa::RsaPublicKey {
        rsa_key_from_cert_pem(pem).unwrap()
    }

    #[test]
    fn verifies_libxml2_signed_assertion_and_response() {
        let idp = key(include_str!("testdata/idp.crt"));
        let doc = parse(include_str!("testdata/saml_assertion_signed.xml")).unwrap();
        let assertion = find(&doc, "Assertion").unwrap();
        verify_enveloped(assertion, &idp).unwrap();

        let doc = parse(include_str!("testdata/saml_response_signed.xml")).unwrap();
        verify_enveloped(&doc, &idp).unwrap();
    }

    #[test]
    fn rejects_wrong_key_and_tampering() {
        let other = key(include_str!("testdata/other.crt"));
        let idp = key(include_str!("testdata/idp.crt"));
        let xml = include_str!("testdata/saml_assertion_signed.xml");
        let doc = parse(xml).unwrap();
        assert!(verify_enveloped(find(&doc, "Assertion").unwrap(), &other).is_err());

        // Change the signed email: digest mismatch.
        let tampered = xml.replace(
            ">jane.doe@corp.example</saml2:NameID>",
            ">admin@corp.example</saml2:NameID>",
        );
        assert_ne!(tampered, xml);
        let doc = parse(&tampered).unwrap();
        let err = verify_enveloped(find(&doc, "Assertion").unwrap(), &idp).unwrap_err();
        assert!(err.to_string().contains("digest"), "{err}");

        // An unsigned element is rejected (the Response here isn't signed).
        let doc = parse(xml).unwrap();
        assert!(verify_enveloped(&doc, &idp).is_err());
    }
}
