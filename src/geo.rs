//! Device geo: country + city for a check-in, from a MaxMind .mmdb file
//! (`observability.geoip_mmdb`) when configured, else from CDN geo headers
//! (Cloudflare, CloudFront, Vercel, App Engine, generic) — headers only when
//! `server.trust_proxy` is on, since a direct client could forge them.
//! Only the resulting country/city are ever stored; the IP is not.

use std::net::IpAddr;
use std::sync::OnceLock;

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::HeaderMap;

use crate::state::AppState;

static READER: OnceLock<Option<maxminddb::Reader<Vec<u8>>>> = OnceLock::new();

/// Load the GeoIP database once at startup (missing/invalid → headers only).
pub fn init(path: &str) {
    READER.get_or_init(|| {
        if path.is_empty() {
            return None;
        }
        match maxminddb::Reader::open_readfile(path) {
            Ok(r) => {
                tracing::info!(path, "geoip database loaded");
                Some(r)
            }
            Err(e) => {
                tracing::warn!(path, error = %e, "geoip database unavailable; using CDN headers only");
                None
            }
        }
    });
}

/// Where a device checked in from.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Location {
    /// ISO 3166-1 alpha-2, uppercase.
    pub country: Option<String>,
    /// English city name.
    pub city: Option<String>,
}

pub fn locate(ip: Option<IpAddr>, headers: &HeaderMap, trust_proxy: bool) -> Location {
    if let (Some(ip), Some(Some(reader))) = (ip, READER.get()) {
        if let Ok(city) = reader.lookup::<maxminddb::geoip2::City>(ip) {
            let country = city
                .country
                .as_ref()
                .and_then(|c| c.iso_code)
                .map(str::to_ascii_uppercase);
            let name = city
                .city
                .as_ref()
                .and_then(|c| c.names.as_ref())
                .and_then(|n| n.get("en"))
                .map(|s| s.to_string());
            if country.is_some() {
                return Location {
                    country,
                    city: name,
                };
            }
        }
    }
    if !trust_proxy {
        return Location::default();
    }
    let header = |names: &[&str]| {
        names.iter().find_map(|n| {
            headers
                .get(*n)
                .and_then(|v| v.to_str().ok())
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .map(String::from)
        })
    };
    let country = header(&[
        "cf-ipcountry",
        "cloudfront-viewer-country",
        "x-vercel-ip-country",
        "x-appengine-country",
        "x-country-code",
    ])
    .map(|c| c.to_ascii_uppercase())
    // Cloudflare uses XX (unknown) and T1 (Tor).
    .filter(|c| c.len() == 2 && c != "XX" && c != "T1");
    let city = header(&[
        "cf-ipcity",
        "cloudfront-viewer-city",
        "x-vercel-ip-city",
        "x-appengine-city",
    ])
    .map(|c| percent_decode(&c));
    Location { country, city }
}

/// Vercel/CloudFront percent-encode city names.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(b) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(b);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8(out).unwrap_or_else(|_| s.to_string())
}

/// The client's IP as the rate limiter sees it (peer, or the proxy-appended
/// X-Forwarded-For hop under trust_proxy).
pub struct ClientAddr(pub Option<IpAddr>);

impl FromRequestParts<AppState> for ClientAddr {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let ip = crate::rate_limit::client_ip_from(
            &parts.headers,
            &parts.extensions,
            state.config().server.trust_proxy,
        );
        Ok(ClientAddr(ip.parse().ok()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cdn_headers_only_behind_a_trusted_proxy() {
        let mut h = HeaderMap::new();
        h.insert("cf-ipcountry", "de".parse().unwrap());
        h.insert("x-vercel-ip-city", "S%C3%A3o%20Paulo".parse().unwrap());
        let loc = locate(None, &h, true);
        assert_eq!(loc.country.as_deref(), Some("DE"));
        assert_eq!(loc.city.as_deref(), Some("São Paulo"));
        assert_eq!(locate(None, &h, false), Location::default());
        h.insert("cf-ipcountry", "XX".parse().unwrap());
        assert_eq!(locate(None, &h, true).country, None);
    }
}
