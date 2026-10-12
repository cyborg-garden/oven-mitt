//! Object metadata records (PRD R-OBJ-2, DEVELOPMENT.md §4).
//!
//! Two records per object. `meta.json` is cleartext so `list` works without
//! decrypting; it holds nothing the agent can't already see. `meta.enc` is
//! encrypted under the object's DEK and holds the name, labels, and the
//! plaintext hash (which exists only for the audit log).

use serde::{Deserialize, Serialize};

use crate::handle::Handle;
use crate::time::{Millis, to_rfc3339};

/// `objects/<handle>/meta.json`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ObjectMeta {
    pub handle: Handle,
    pub vault: String,
    pub size: u64,
    pub mime: String,
    pub created: Millis,
    /// Last body commit. TTL counts from here (F-10).
    pub modified: Millis,
    /// Current generation; `gen-<N>/` holds the body.
    pub generation: u32,
}

/// `objects/<handle>/gen-N/meta.enc`, decrypted.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct PrivateMeta {
    pub name: Option<String>,
    pub labels: Vec<String>,
    /// Hex SHA-256 of the plaintext body. Audit-only; never served.
    pub sha256: String,
}

/// What the agent sees (PRD §4.3 `ObjectInfo`). `name` is `null` when the
/// vault hides names, so clients can tell "hidden" from "absent".
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ObjectInfo {
    pub handle: Handle,
    pub vault: String,
    pub size: u64,
    pub mime: String,
    pub created: String,
    pub modified: String,
    pub labels: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    pub name: Option<String>,
}

impl ObjectInfo {
    pub(crate) fn build(
        meta: &ObjectMeta,
        private: &PrivateMeta,
        expose_names: bool,
        expires_at: Option<Millis>,
    ) -> Self {
        Self {
            handle: meta.handle.clone(),
            vault: meta.vault.clone(),
            size: meta.size,
            mime: meta.mime.clone(),
            created: to_rfc3339(meta.created),
            modified: to_rfc3339(meta.modified),
            labels: private.labels.clone(),
            expires_at: expires_at.map(to_rfc3339),
            name: if expose_names {
                private.name.clone()
            } else {
                None
            },
        }
    }
}

/// Label limits (PRD R-OBJ-8).
pub const MAX_LABELS: usize = 16;
pub const MAX_LABEL_BYTES: usize = 256;

/// Validate a label set.
pub fn validate_labels(labels: &[String]) -> Result<(), String> {
    if labels.len() > MAX_LABELS {
        return Err(format!("at most {MAX_LABELS} labels per object"));
    }
    for l in labels {
        if l.is_empty() {
            return Err("labels must not be empty".to_owned());
        }
        if l.len() > MAX_LABEL_BYTES {
            return Err(format!("labels must be at most {MAX_LABEL_BYTES} bytes"));
        }
        if l.chars().any(char::is_control) {
            return Err("labels must not contain control characters".to_owned());
        }
    }
    Ok(())
}

/// Name limit. Names are stored but hidden unless the vault exposes them.
pub const MAX_NAME_BYTES: usize = 512;

/// Validate an original name.
pub fn validate_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("name must not be empty".to_owned());
    }
    if name.len() > MAX_NAME_BYTES {
        return Err(format!("name must be at most {MAX_NAME_BYTES} bytes"));
    }
    if name.chars().any(char::is_control) {
        return Err("name must not contain control characters".to_owned());
    }
    Ok(())
}

/// MIME type: client-declared, lightly checked for shape (R-OBJ-7).
pub const DEFAULT_MIME: &str = "application/octet-stream";

/// Validate a declared MIME type: `type/subtype` with optional parameters,
/// printable ASCII, bounded length.
pub fn validate_mime(mime: &str) -> Result<(), String> {
    if mime.len() > 255 || !mime.is_ascii() || mime.bytes().any(|b| b < 0x21 && b != b' ') {
        return Err("mime type must be printable ASCII, at most 255 bytes".to_owned());
    }
    let main = mime.split(';').next().unwrap_or("");
    let mut parts = main.trim().splitn(2, '/');
    let (Some(t), Some(st)) = (parts.next(), parts.next()) else {
        return Err("mime type must look like type/subtype".to_owned());
    };
    if t.is_empty() || st.is_empty() || t.contains(' ') || st.contains(' ') {
        return Err("mime type must look like type/subtype".to_owned());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn info_hides_name_unless_exposed_and_omits_expiry_when_none() {
        let meta = ObjectMeta {
            handle: Handle::parse("v_0123456789ab").unwrap_or_else(|e| panic!("{e}")),
            vault: "private".into(),
            size: 5,
            mime: "text/plain".into(),
            created: 1_791_792_062_123,
            modified: 1_791_792_062_123,
            generation: 1,
        };
        let private = PrivateMeta {
            name: Some("secret.txt".into()),
            labels: vec!["a".into()],
            sha256: "00".into(),
        };
        let hidden = ObjectInfo::build(&meta, &private, false, None);
        let json = serde_json::to_string(&hidden).unwrap_or_else(|e| panic!("{e}"));
        assert!(json.contains("\"name\":null"), "{json}");
        assert!(!json.contains("expires_at"), "{json}");
        assert!(!json.contains("sha256"), "{json}");
        let shown = ObjectInfo::build(&meta, &private, true, Some(1_791_792_062_123 + 1000));
        let json = serde_json::to_string(&shown).unwrap_or_else(|e| panic!("{e}"));
        assert!(json.contains("\"name\":\"secret.txt\""), "{json}");
        assert!(
            json.contains("\"expires_at\":\"2026-10-12T08:01:03.123Z\""),
            "{json}"
        );
    }

    #[test]
    fn label_limits() {
        assert!(validate_labels(&[]).is_ok());
        assert!(validate_labels(&["ok".into()]).is_ok());
        assert!(validate_labels(&vec!["x".to_owned(); 16]).is_ok());
        assert!(validate_labels(&vec!["x".to_owned(); 17]).is_err());
        assert!(validate_labels(&[String::new()]).is_err());
        assert!(validate_labels(&["a".repeat(256)]).is_ok());
        assert!(validate_labels(&["a".repeat(257)]).is_err());
        assert!(validate_labels(&["new\nline".into()]).is_err());
        assert!(validate_labels(&["wāhi tapu".into()]).is_ok());
    }

    #[test]
    fn mime_shape() {
        assert!(validate_mime("text/plain").is_ok());
        assert!(validate_mime("text/plain; charset=utf-8").is_ok());
        assert!(validate_mime("application/vnd.ms-excel").is_ok());
        assert!(validate_mime("text").is_err());
        assert!(validate_mime("/plain").is_err());
        assert!(validate_mime("text/").is_err());
        assert!(validate_mime("text/pl ain").is_err());
        assert!(validate_mime("tëxt/plain").is_err());
        assert!(validate_mime(&"a/".repeat(200)).is_err());
    }

    #[test]
    fn name_limits() {
        assert!(validate_name("hui-notes.txt").is_ok());
        assert!(validate_name("").is_err());
        assert!(validate_name(&"a".repeat(513)).is_err());
        assert!(validate_name("a\tb").is_err());
    }
}
