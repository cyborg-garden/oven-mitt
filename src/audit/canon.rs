//! Canonical JSON for audit entries (PRD §6.2, DEVELOPMENT.md D-4).
//!
//! RFC 8785 (JCS) needs two things beyond "compact JSON": keys sorted by
//! UTF-16 code unit, and ES6 number formatting. We sidestep both by rule:
//!
//! 1. **Every key is ASCII**, so byte order equals UTF-16 order and
//!    `serde_json`'s `BTreeMap`-backed objects are already sorted.
//! 2. **No floats, ever.** Every number in an audit entry is an integer
//!    (`seq`, `size`, `uid`, `pid`), which JCS prints exactly as
//!    `serde_json` does.
//!
//! String escaping matches JCS already: only `"`, `\` and control
//! characters are escaped, controls as lowercase `\u00xx` (with the short
//! forms for `\b \f \n \r \t`), everything else emitted as raw UTF-8.
//!
//! `canonical()` enforces both rules and refuses anything else, so a future
//! field that breaks the chain's reproducibility fails a test the day it is
//! added rather than silently changing hashes in production.

use serde_json::Value;

use crate::crypto::sha256_hex;

/// Why a value can't be canonicalised.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CanonError {
    #[error("audit entries must not contain floating-point numbers (key {0:?})")]
    Float(String),
    #[error("audit entry keys must be ASCII (key {0:?})")]
    NonAsciiKey(String),
}

fn check(value: &Value, path: &str) -> Result<(), CanonError> {
    match value {
        Value::Number(n) if n.is_f64() => Err(CanonError::Float(path.to_owned())),
        Value::Object(map) => {
            for (k, v) in map {
                if !k.is_ascii() {
                    return Err(CanonError::NonAsciiKey(k.clone()));
                }
                check(v, k)?;
            }
            Ok(())
        }
        Value::Array(items) => items.iter().try_for_each(|v| check(v, path)),
        _ => Ok(()),
    }
}

/// Canonical bytes of a JSON value: sorted ASCII keys, compact, no floats.
pub fn canonical(value: &Value) -> Result<Vec<u8>, CanonError> {
    check(value, "")?;
    // serde_json::Value::Object is a BTreeMap (the `preserve_order` feature
    // is off), so keys serialise sorted. This is asserted by test, not hoped.
    Ok(serde_json::to_vec(value).unwrap_or_default())
}

/// `SHA-256(canonical(value))` as lowercase hex — the hash the next entry's
/// `prev` field carries, and the head hash `audit head` prints.
pub fn entry_hash(value: &Value) -> Result<String, CanonError> {
    Ok(sha256_hex(&canonical(value)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn keys_come_out_sorted_and_compact() {
        let v = json!({"zeta": 1, "alpha": {"y": [1, 2], "x": "s"}, "mid": null});
        let c = canonical(&v).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            String::from_utf8_lossy(&c),
            r#"{"alpha":{"x":"s","y":[1,2]},"mid":null,"zeta":1}"#
        );
    }

    #[test]
    fn floats_are_refused_anywhere() {
        assert_eq!(
            canonical(&json!({"size": 1.5})),
            Err(CanonError::Float("size".to_owned()))
        );
        assert_eq!(
            canonical(&json!({"caller": {"uid": 1000, "load": 0.5}})),
            Err(CanonError::Float("load".to_owned()))
        );
        assert_eq!(
            canonical(&json!({"xs": [1, 2.0]})),
            Err(CanonError::Float("xs".to_owned()))
        );
        assert!(canonical(&json!({"size": 18_446_744_073_709_551_615u64})).is_ok());
        assert!(canonical(&json!({"n": -1})).is_ok());
    }

    #[test]
    fn non_ascii_keys_are_refused_but_values_pass_through_raw() {
        assert!(matches!(
            canonical(&json!({"nämé": 1})),
            Err(CanonError::NonAsciiKey(_))
        ));
        let c =
            canonical(&json!({"name": "wāhi tapu \u{1F600}"})).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            String::from_utf8_lossy(&c),
            "{\"name\":\"wāhi tapu \u{1F600}\"}"
        );
    }

    #[test]
    fn escaping_matches_jcs() {
        let c =
            canonical(&json!({"s": "a\"b\\c\n\t\u{1}\u{1f}/"})).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            String::from_utf8_lossy(&c),
            r#"{"s":"a\"b\\c\n\t\u0001\u001f/"}"#
        );
    }

    #[test]
    fn hash_is_stable_across_key_order() {
        let a = json!({"seq": 1, "ts": "2026-10-12T08:00:00.000Z", "event": "start"});
        let b = json!({"event": "start", "ts": "2026-10-12T08:00:00.000Z", "seq": 1});
        assert_eq!(
            entry_hash(&a).unwrap_or_else(|e| panic!("{e}")),
            entry_hash(&b).unwrap_or_else(|e| panic!("{e}"))
        );
        // known answer, so a serde_json formatting change would be noticed
        assert_eq!(
            entry_hash(&json!({"a": 1})).unwrap_or_else(|e| panic!("{e}")),
            sha256_hex(br#"{"a":1}"#)
        );
    }
}
