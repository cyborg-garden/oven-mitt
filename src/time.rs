//! Timestamps. Internally an integer count of milliseconds since the Unix
//! epoch (integers only, so audit entries stay canonicalisable — see
//! `audit::canon`); on the wire and in the audit log, RFC 3339 UTC with
//! millisecond precision.

use jiff::Timestamp;

/// Milliseconds since the Unix epoch.
pub type Millis = i64;

/// Current time.
pub fn now_ms() -> Millis {
    Timestamp::now().as_millisecond()
}

/// `2026-10-12T08:01:02.123Z`.
pub fn to_rfc3339(ms: Millis) -> String {
    match Timestamp::from_millisecond(ms) {
        Ok(ts) => ts.strftime("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(),
        Err(_) => "0000-00-00T00:00:00.000Z".to_owned(),
    }
}

/// Parse an RFC 3339 timestamp to milliseconds.
pub fn parse_rfc3339(s: &str) -> Result<Millis, jiff::Error> {
    s.parse::<Timestamp>().map(Timestamp::as_millisecond)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_with_millis_and_round_trips() {
        let ms = 1_791_792_062_123;
        let s = to_rfc3339(ms);
        assert_eq!(s, "2026-10-12T08:01:02.123Z");
        assert_eq!(parse_rfc3339(&s).ok(), Some(ms));
        assert_eq!(to_rfc3339(0), "1970-01-01T00:00:00.000Z");
    }

    #[test]
    fn now_is_plausible() {
        assert!(now_ms() > 1_700_000_000_000);
    }
}
