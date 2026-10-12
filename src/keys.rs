//! Vault keys on disk (PRD R-VLT-2, R-CRY-4).
//!
//! `keys_dir/<vault>.key` holds 32 raw bytes, mode 0600. The daemon creates a
//! key the first time it sees a vault with no objects, and refuses to start
//! if a vault *has* objects but no key — it never re-keys over data.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use crate::crypto::{CryptoError, Kek};

/// Why a key could not be loaded or created.
#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error(
        "vault {vault:?} has objects but no key file; refusing to start. \
             Losing a vault key means losing the vault — restore {path} from backup, \
             or move the vault's data aside if it is truly gone"
    )]
    MissingWithObjects { vault: String, path: PathBuf },
    #[error("key file {path} is not 32 bytes")]
    BadLength { path: PathBuf },
    #[error("key file {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("{0}")]
    Crypto(#[from] CryptoError),
}

/// The keys directory.
#[derive(Debug, Clone)]
pub struct KeyStore {
    dir: PathBuf,
}

impl KeyStore {
    /// Open (creating if needed) the keys directory with mode 0700.
    pub fn open(dir: &Path) -> Result<Self, KeyError> {
        fs::create_dir_all(dir).map_err(|source| KeyError::Io {
            path: dir.to_owned(),
            source,
        })?;
        set_mode(dir, 0o700).map_err(|source| KeyError::Io {
            path: dir.to_owned(),
            source,
        })?;
        Ok(Self {
            dir: dir.to_owned(),
        })
    }

    fn path_for(&self, vault: &str) -> PathBuf {
        self.dir.join(format!("{vault}.key"))
    }

    /// Load a vault's key if the file exists.
    pub fn load(&self, vault: &str) -> Result<Option<Kek>, KeyError> {
        let path = self.path_for(vault);
        match fs::read(&path) {
            Ok(bytes) => {
                let arr: [u8; 32] = bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| KeyError::BadLength { path: path.clone() })?;
                Ok(Some(Kek::from_bytes(arr)))
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(source) => Err(KeyError::Io { path, source }),
        }
    }

    /// Create a fresh key for a vault. Fails if one already exists.
    pub fn create(&self, vault: &str) -> Result<Kek, KeyError> {
        let path = self.path_for(vault);
        let key = Kek::generate()?;
        let tmp = self.dir.join(format!(".{vault}.key.tmp"));
        let io = |source| KeyError::Io {
            path: path.clone(),
            source,
        };
        {
            let mut f = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&tmp)
                .map_err(io)?;
            set_mode(&tmp, 0o600).map_err(io)?;
            f.write_all(key.as_bytes()).map_err(io)?;
            f.sync_all().map_err(io)?;
        }
        // create_new semantics for the final name: fail rather than clobber.
        if path.exists() {
            let _ = fs::remove_file(&tmp);
            return Err(KeyError::Io {
                path,
                source: io::Error::new(io::ErrorKind::AlreadyExists, "key file already exists"),
            });
        }
        fs::rename(&tmp, &path).map_err(io)?;
        fs::File::open(&self.dir)
            .and_then(|d| d.sync_all())
            .map_err(io)?;
        Ok(key)
    }

    /// Startup rule (R-VLT-2): load the key; if missing, create one only when
    /// the vault has no objects, otherwise refuse.
    pub fn load_or_create(&self, vault: &str, has_objects: bool) -> Result<Kek, KeyError> {
        if let Some(k) = self.load(vault)? {
            return Ok(k);
        }
        if has_objects {
            return Err(KeyError::MissingWithObjects {
                vault: vault.to_owned(),
                path: self.path_for(vault),
            });
        }
        self.create(vault)
    }
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_then_load_round_trips_with_0600() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let ks = KeyStore::open(&dir.path().join("keys")).unwrap_or_else(|e| panic!("{e}"));
        let k = ks.create("private").unwrap_or_else(|e| panic!("{e}"));
        let again = ks
            .load("private")
            .unwrap_or_else(|e| panic!("{e}"))
            .unwrap_or_else(|| panic!("key should exist"));
        assert_eq!(k.as_bytes(), again.as_bytes());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(dir.path().join("keys/private.key"))
                .unwrap_or_else(|e| panic!("{e}"))
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }
        assert!(ks.create("private").is_err(), "must not clobber");
    }

    // SI-16 / AT-19 at unit level.
    #[test]
    fn missing_key_with_objects_refuses_and_does_not_create() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let ks = KeyStore::open(dir.path()).unwrap_or_else(|e| panic!("{e}"));
        let Err(err) = ks.load_or_create("media", true) else {
            panic!("should refuse")
        };
        assert!(matches!(err, KeyError::MissingWithObjects { .. }), "{err}");
        assert!(err.to_string().contains("media"));
        assert!(!dir.path().join("media.key").exists());
    }

    #[test]
    fn missing_key_without_objects_creates() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let ks = KeyStore::open(dir.path()).unwrap_or_else(|e| panic!("{e}"));
        let k = ks
            .load_or_create("media", false)
            .unwrap_or_else(|e| panic!("{e}"));
        let k2 = ks
            .load_or_create("media", true)
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(k.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn wrong_length_key_file_is_an_error() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let ks = KeyStore::open(dir.path()).unwrap_or_else(|e| panic!("{e}"));
        fs::write(dir.path().join("short.key"), b"nope").unwrap_or_else(|e| panic!("{e}"));
        assert!(matches!(ks.load("short"), Err(KeyError::BadLength { .. })));
    }
}
