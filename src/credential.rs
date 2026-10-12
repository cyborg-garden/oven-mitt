//! Consumer credentials (PRD R-CRD-1..5, §5.2).
//!
//! A credential is the read barrier: whoever holds one can `resolve` objects
//! in its vaults. Tokens look like `ovm_<id>_<secret>`; the daemon stores
//! only `sha256(secret)` and re-reads the file whenever its mtime changes,
//! so a revoke takes effect on the next request with no restart (D-5).

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};
use std::time::SystemTime;

use base64::Engine;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

use crate::config::valid_name;
use crate::crypto::sha256_hex;
use crate::time::{now_ms, to_rfc3339};

const PREFIX: &str = "ovm_";
const ID_LEN: usize = 8;
const SECRET_BYTES: usize = 32;

/// Which vaults a credential may resolve from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Scope {
    /// `vaults = "*"`
    All(String),
    /// `vaults = ["private", "media"]`
    Some(Vec<String>),
}

impl Scope {
    pub fn all() -> Self {
        Self::All("*".to_owned())
    }

    pub fn permits(&self, vault: &str) -> bool {
        match self {
            Self::All(s) => s == "*",
            Self::Some(v) => v.iter().any(|x| x == vault),
        }
    }
}

/// One stored credential. Never the secret (SI-14).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    pub id: String,
    pub name: String,
    /// `sha256:<hex>` of the token's secret part.
    pub hash: String,
    pub vaults: Scope,
    pub created: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked: Option<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct FileShape {
    #[serde(default, rename = "credential")]
    credentials: Vec<Record>,
}

/// Why a token was rejected. One variant on purpose: a caller learns
/// nothing about which part was wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("credential is unknown, malformed or revoked")]
pub struct Invalid;

/// A verified credential, as the handler sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    pub id: String,
    pub name: String,
    pub vaults: Scope,
}

/// Split and shape-check a token: `ovm_<8 hex>_<43 base64url>`.
fn parse_token(token: &str) -> Option<(&str, &str)> {
    let rest = token.strip_prefix(PREFIX)?;
    let (id, secret) = rest.split_once('_')?;
    if id.len() != ID_LEN || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    if secret.is_empty()
        || secret.len() > 128
        || !secret
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return None;
    }
    Some((id, secret))
}

fn hash_secret(secret: &str) -> String {
    format!("sha256:{}", sha256_hex(secret.as_bytes()))
}

/// Mint a token and its record. The token is returned exactly once.
pub fn issue(name: &str, scope: Scope) -> Result<(String, Record), getrandom::Error> {
    let mut id_bytes = [0u8; ID_LEN / 2];
    getrandom::fill(&mut id_bytes)?;
    let id = hex::encode(id_bytes);
    let mut secret_bytes = [0u8; SECRET_BYTES];
    getrandom::fill(&mut secret_bytes)?;
    let secret = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(secret_bytes);
    let token = format!("{PREFIX}{id}_{secret}");
    let record = Record {
        id,
        name: name.to_owned(),
        hash: hash_secret(&secret),
        vaults: scope,
        created: to_rfc3339(now_ms()),
        revoked: None,
    };
    Ok((token, record))
}

/// Read the credentials file. Absent = empty.
pub fn read_file(path: &Path) -> io::Result<Vec<Record>> {
    match fs::read_to_string(path) {
        Ok(text) => {
            let shape: FileShape = toml::from_str(&text).map_err(io::Error::other)?;
            Ok(shape.credentials)
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(e),
    }
}

/// Write the credentials file durably (temp + rename), mode 0600.
pub fn write_file(path: &Path, records: &[Record]) -> io::Result<()> {
    let shape = FileShape {
        credentials: records.to_vec(),
    };
    let text = toml::to_string(&shape).map_err(io::Error::other)?;
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(dir)?;
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| io::Error::other("credentials path has no file name"))?;
    let tmp = dir.join(format!(".{name}.tmp"));
    {
        use std::io::Write;
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))?;
        }
        f.write_all(text.as_bytes())?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    fs::File::open(dir)?.sync_all()
}

/// Validate a scope against the configured vault names.
pub fn validate_scope(scope: &Scope, known: &[String]) -> Result<(), String> {
    match scope {
        Scope::All(s) if s == "*" => Ok(()),
        Scope::All(s) => Err(format!("vaults must be \"*\" or a list, not {s:?}")),
        Scope::Some(v) => {
            if v.is_empty() {
                return Err("vault list must not be empty".to_owned());
            }
            for name in v {
                if !valid_name(name) {
                    return Err(format!("{name:?} is not a valid vault name"));
                }
                if !known.contains(name) {
                    return Err(format!("{name:?} is not a configured vault"));
                }
            }
            Ok(())
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Stamp {
    mtime: Option<SystemTime>,
    len: u64,
}

fn stamp(path: &Path) -> Stamp {
    match fs::metadata(path) {
        Ok(m) => Stamp {
            mtime: m.modified().ok(),
            len: m.len(),
        },
        Err(_) => Stamp {
            mtime: None,
            len: 0,
        },
    }
}

/// The daemon's view of the credentials file, re-read on change.
#[derive(Debug)]
pub struct Credentials {
    path: PathBuf,
    cache: Mutex<(Stamp, Vec<Record>)>,
}

impl Credentials {
    /// Open; a missing file is fine (no credentials yet).
    pub fn open(path: &Path) -> io::Result<Self> {
        let records = read_file(path)?;
        Ok(Self {
            path: path.to_owned(),
            cache: Mutex::new((stamp(path), records)),
        })
    }

    fn records(&self) -> Vec<Record> {
        let mut guard = self.cache.lock().unwrap_or_else(PoisonError::into_inner);
        let now = stamp(&self.path);
        if now != guard.0 {
            match read_file(&self.path) {
                Ok(records) => *guard = (now, records),
                Err(e) => {
                    // Keep the last good set; an unreadable file must not
                    // silently open the vault, nor silently close it.
                    tracing::error!("credentials file unreadable, keeping cached set: {e}");
                }
            }
        }
        guard.1.clone()
    }

    /// Verify a bearer token.
    pub fn check(&self, token: &str) -> Result<Verified, Invalid> {
        let (id, secret) = parse_token(token.trim()).ok_or(Invalid)?;
        let records = self.records();
        let record = records.iter().find(|r| r.id == id).ok_or(Invalid)?;
        if record.revoked.is_some() {
            return Err(Invalid);
        }
        let presented = hash_secret(secret);
        if presented
            .as_bytes()
            .ct_eq(record.hash.as_bytes())
            .unwrap_u8()
            != 1
        {
            return Err(Invalid);
        }
        Ok(Verified {
            id: record.id.clone(),
            name: record.name.clone(),
            vaults: record.vaults.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issue_check_revoke_round_trip() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let path = dir.path().join("credentials.toml");
        let (token, record) = issue("vault_send", Scope::Some(vec!["private".into()]))
            .unwrap_or_else(|e| panic!("{e}"));
        assert!(token.starts_with("ovm_"));
        assert_eq!(token.len(), 4 + 8 + 1 + 43);
        write_file(&path, std::slice::from_ref(&record)).unwrap_or_else(|e| panic!("{e}"));
        let text = fs::read_to_string(&path).unwrap_or_else(|e| panic!("{e}"));
        let secret = token.rsplit('_').next().unwrap_or_default();
        assert!(!text.contains(secret), "secret must not be on disk (SI-14)");
        assert!(text.contains("sha256:"));

        let creds = Credentials::open(&path).unwrap_or_else(|e| panic!("{e}"));
        let v = creds.check(&token).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(v.id, record.id);
        assert!(v.vaults.permits("private"));
        assert!(!v.vaults.permits("media"));
        assert_eq!(creds.check(&format!("{token}x")), Err(Invalid));
        assert_eq!(creds.check(&token.replace("ovm_", "ovn_")), Err(Invalid));
        assert_eq!(creds.check(""), Err(Invalid));
        assert_eq!(creds.check("ovm_deadbeef_"), Err(Invalid));

        // revoke on disk; the daemon picks it up without restart (D-5)
        std::thread::sleep(std::time::Duration::from_millis(20));
        let mut revoked = record.clone();
        revoked.revoked = Some(to_rfc3339(now_ms()));
        write_file(&path, &[revoked]).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(creds.check(&token), Err(Invalid));
    }

    #[test]
    fn scope_serialises_both_shapes_and_validates() {
        let all = Record {
            id: "0".repeat(8),
            name: "n".into(),
            hash: "sha256:x".into(),
            vaults: Scope::all(),
            created: "t".into(),
            revoked: None,
        };
        let text = toml::to_string(&FileShape {
            credentials: vec![all],
        })
        .unwrap_or_else(|e| panic!("{e}"));
        assert!(text.contains("vaults = \"*\""), "{text}");
        let back: FileShape = toml::from_str(&text).unwrap_or_else(|e| panic!("{e}"));
        assert!(back.credentials[0].vaults.permits("anything"));
        let known = vec!["private".to_owned()];
        assert!(validate_scope(&Scope::all(), &known).is_ok());
        assert!(validate_scope(&Scope::Some(vec!["private".into()]), &known).is_ok());
        assert!(validate_scope(&Scope::Some(vec!["media".into()]), &known).is_err());
        assert!(validate_scope(&Scope::Some(vec![]), &known).is_err());
        assert!(validate_scope(&Scope::All("x".into()), &known).is_err());
    }

    #[test]
    fn missing_file_means_no_credentials() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let creds =
            Credentials::open(&dir.path().join("none.toml")).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(creds.check("ovm_0123abcd_AAAA"), Err(Invalid));
    }
}
