//! IP allowlists (single addresses and CIDR ranges, IPv4 and IPv6) for
//! personal access tokens.

use std::net::IpAddr;

/// One allowlist entry: a network address and prefix length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Net {
    addr: IpAddr,
    prefix: u8,
}

impl Net {
    /// Parse `1.2.3.4`, `1.2.3.0/24`, `::1`, `2001:db8::/32`.
    pub fn parse(s: &str) -> Option<Net> {
        let s = s.trim();
        let (ip, prefix) = match s.split_once('/') {
            Some((ip, p)) => (ip.parse::<IpAddr>().ok()?, Some(p.parse::<u8>().ok()?)),
            None => (s.parse::<IpAddr>().ok()?, None),
        };
        let max = if ip.is_ipv4() { 32 } else { 128 };
        let prefix = prefix.unwrap_or(max);
        (prefix <= max).then_some(Net { addr: ip, prefix })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        // An IPv4-mapped IPv6 peer (::ffff:a.b.c.d) matches IPv4 entries.
        let ip = match ip {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
            v4 => v4,
        };
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let mask = u32::MAX.checked_shl(32 - self.prefix as u32).unwrap_or(0);
                u32::from(net) & mask == u32::from(ip) & mask
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let mask = u128::MAX.checked_shl(128 - self.prefix as u32).unwrap_or(0);
                u128::from(net) & mask == u128::from(ip) & mask
            }
            _ => false,
        }
    }
}

impl std::fmt::Display for Net {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

/// Parse a list of entries, normalized (`a.b.c.d/32` form). `None` if any
/// entry is invalid.
pub fn parse_list<S: AsRef<str>>(entries: &[S]) -> Option<Vec<Net>> {
    entries.iter().map(|e| Net::parse(e.as_ref())).collect()
}

/// Whether `ip` is allowed by a stored comma-separated list.
pub fn allows(stored: &str, ip: Option<IpAddr>) -> bool {
    let Some(ip) = ip else { return false };
    stored
        .split(',')
        .filter_map(Net::parse)
        .any(|n| n.contains(ip))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidr_matching() {
        let ip = |s: &str| Some(s.parse::<IpAddr>().unwrap());
        assert!(allows("10.0.0.0/8", ip("10.1.2.3")));
        assert!(!allows("10.0.0.0/8", ip("11.0.0.1")));
        assert!(allows("192.168.1.7", ip("192.168.1.7")));
        assert!(!allows("192.168.1.7", ip("192.168.1.8")));
        assert!(allows("0.0.0.0/0", ip("8.8.8.8")));
        assert!(allows("2001:db8::/32", ip("2001:db8:1::5")));
        assert!(!allows("2001:db8::/32", ip("2001:db9::5")));
        assert!(allows("127.0.0.1", ip("::ffff:127.0.0.1")));
        assert!(!allows("10.0.0.0/8", None));
        assert!(Net::parse("10.0.0.0/33").is_none());
        assert!(Net::parse("nope").is_none());
    }
}
