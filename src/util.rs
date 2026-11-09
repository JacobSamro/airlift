//! Small shared helpers.

use time::format_description::well_known::Rfc3339;
use time::format_description::FormatItem;
use time::macros::format_description;
use time::OffsetDateTime;

/// Fixed-width UTC RFC3339 with exactly millisecond precision. Fixed width
/// keeps text ordering in SQLite chronological, and expo-updates on Android
/// parses `createdAt` with `SimpleDateFormat("…ss.SSS'Z'")`, which misreads
/// any other fraction width.
const TS_FORMAT: &[FormatItem<'static>] =
    format_description!("[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:3]Z");

fn format_ts(t: OffsetDateTime) -> String {
    t.to_offset(time::UtcOffset::UTC)
        .format(TS_FORMAT)
        .unwrap_or_default()
}

/// Current UTC time as an RFC3339 string (the canonical timestamp format in the DB).
pub fn now_rfc3339() -> String {
    format_ts(OffsetDateTime::now_utc())
}

/// An RFC3339 timestamp `secs` seconds in the future.
pub fn rfc3339_in(secs: i64) -> String {
    format_ts(OffsetDateTime::now_utc() + time::Duration::seconds(secs))
}

/// Re-render any RFC3339 timestamp in the canonical millisecond form (rows
/// written before the format was fixed may carry 0–9 fraction digits).
pub fn normalize_rfc3339(s: &str) -> String {
    OffsetDateTime::parse(s, &Rfc3339)
        .map(format_ts)
        .unwrap_or_else(|_| s.to_string())
}

/// UTC calendar day (`YYYY-MM-DD`) `days` before today — the lower bound for
/// analytics range queries.
pub fn utc_day_offset(days: i64) -> String {
    let d = (OffsetDateTime::now_utc() - time::Duration::days(days)).date();
    format!("{:04}-{:02}-{:02}", d.year(), u8::from(d.month()), d.day())
}

/// Generate a random url-safe id (used for session ids and similar).
pub fn random_id() -> String {
    use base64::Engine;
    use rand::RngCore;
    let mut bytes = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
mod tests {
    #[test]
    fn timestamps_have_millisecond_precision() {
        let now = super::now_rfc3339();
        assert_eq!(now.len(), "2026-01-01T00:00:00.000Z".len(), "{now}");
        assert!(now.ends_with('Z'));
        assert_eq!(
            super::normalize_rfc3339("2026-07-08T12:00:00.483920117Z"),
            "2026-07-08T12:00:00.483Z"
        );
        assert_eq!(
            super::normalize_rfc3339("2026-07-08T12:00:00Z"),
            "2026-07-08T12:00:00.000Z"
        );
    }
}
