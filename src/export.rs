//! Export: write an object's plaintext under a declared `fs` root
//! (PRD R-EXP-1..5). The one deliberate plaintext write in the daemon.
//!
//! Confinement is two checks, both cheap: the filename grammar admits no
//! separators or `..`, and the root is re-resolved with `realpath` at export
//! time so a root that has become a symlink elsewhere still can't carry a
//! write outside the configured directory.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use unicode_normalization::UnicodeNormalization;

use crate::handle::Handle;
use crate::store::{Store, StoreError};
use crate::time::Millis;

/// Why an export was refused or failed.
#[derive(Debug, thiserror::Error)]
pub enum ExportError {
    #[error(
        "filename is invalid: use letters, digits, `. _ -` and spaces, starting with a letter or digit, no `..`, at most 255 characters"
    )]
    FilenameInvalid,
    #[error("target path escapes the destination root")]
    PathEscape,
    #[error("a file with that name already exists")]
    Exists,
    #[error("{0}")]
    Store(#[from] StoreError),
    #[error("i/o: {0}")]
    Io(#[from] io::Error),
}

const MAX_FILENAME_CHARS: usize = 255;

/// Validate and NFC-normalise an export filename (R-EXP-2).
pub fn validate_filename(name: &str) -> Result<String, ExportError> {
    let name: String = name.nfc().collect();
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return Err(ExportError::FilenameInvalid);
    };
    if !first.is_ascii_alphanumeric() {
        return Err(ExportError::FilenameInvalid);
    }
    if name.chars().count() > MAX_FILENAME_CHARS {
        return Err(ExportError::FilenameInvalid);
    }
    if !chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | ' ')) {
        return Err(ExportError::FilenameInvalid);
    }
    if name.contains("..") {
        return Err(ExportError::FilenameInvalid);
    }
    Ok(name)
}

/// Resolve the root now and join the (already validated) filename; refuse
/// anything whose parent is not exactly the resolved root (R-EXP-3).
pub fn confined_target(root: &Path, filename: &str) -> Result<(PathBuf, PathBuf), ExportError> {
    let real_root = fs::canonicalize(root).map_err(|_| ExportError::PathEscape)?;
    if !real_root.is_dir() {
        return Err(ExportError::PathEscape);
    }
    let target = real_root.join(filename);
    // Belt and braces: the grammar forbids separators, but check anyway.
    if target.parent() != Some(real_root.as_path()) {
        return Err(ExportError::PathEscape);
    }
    if let Some(name) = target.file_name()
        && name != filename
    {
        return Err(ExportError::PathEscape);
    }
    Ok((real_root, target))
}

/// Outcome of a successful export.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Exported {
    pub filename: String,
    pub size: u64,
    pub sha256: String,
    pub vault: String,
}

/// Decrypt `handle` into `<root>/<filename>` (R-EXP-1, R-EXP-4).
///
/// Written to a temp file in the root, fsynced, then linked into place:
/// `rename` when `overwrite` is set, otherwise `hard_link` — which fails
/// atomically if the name exists, so two concurrent exports can't both
/// think they won.
pub fn export(
    store: &Store,
    handle: &Handle,
    root: &Path,
    filename: &str,
    overwrite: bool,
    now: Millis,
) -> Result<Exported, ExportError> {
    let filename = validate_filename(filename)?;
    let (real_root, target) = confined_target(root, &filename)?;
    if !overwrite && target.symlink_metadata().is_ok() {
        return Err(ExportError::Exists);
    }
    let (mut reader, meta) = store.open_body(handle, now)?;
    let sha256 = store
        .operator_stat(handle)
        .map(|(_, p)| p.sha256)
        .unwrap_or_default();

    let tmp = real_root.join(format!(
        ".ovenmitt-export-{}.tmp",
        crate::store::layout::random_suffix().map_err(|e| io::Error::other(e.to_string()))?
    ));
    let result = (|| -> Result<u64, ExportError> {
        let mut f = OpenOptions::new().write(true).create_new(true).open(&tmp)?;
        set_mode(&tmp, 0o644)?;
        let mut written = 0u64;
        while let Some(chunk) = reader.next_chunk().map_err(StoreError::from)? {
            f.write_all(&chunk)?;
            written += chunk.len() as u64;
        }
        f.sync_all()?;
        drop(f);
        if overwrite {
            fs::rename(&tmp, &target)?;
        } else {
            match fs::hard_link(&tmp, &target) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                    return Err(ExportError::Exists);
                }
                Err(e) => return Err(e.into()),
            }
            fs::remove_file(&tmp)?;
        }
        File::open(&real_root)?.sync_all()?;
        Ok(written)
    })();
    match result {
        Ok(size) => Ok(Exported {
            filename,
            size,
            sha256,
            vault: meta.vault,
        }),
        Err(e) => {
            let _ = fs::remove_file(&tmp);
            Err(e)
        }
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
    fn filename_grammar() {
        for ok in [
            "a",
            "report.txt",
            "Hui notes 2026-10-12.md",
            "x_y-z.tar.gz",
            "9",
        ] {
            assert_eq!(validate_filename(ok).as_deref().ok(), Some(ok), "{ok:?}");
        }
        for bad in [
            "",
            ".hidden",
            "..",
            "a..b",
            "../x",
            "a/b",
            "a\\b",
            "-leading",
            " leading",
            "nul\0byte",
            "tab\tchar",
            "new\nline",
            "ünïcode.txt",
            "emoji\u{1F600}",
            "colon:name",
            "star*",
            "q?",
        ] {
            assert!(validate_filename(bad).is_err(), "{bad:?}");
        }
        assert!(validate_filename(&"a".repeat(255)).is_ok());
        assert!(validate_filename(&"a".repeat(256)).is_err());
    }

    #[test]
    fn nfc_normalisation_is_applied_before_the_grammar() {
        // decomposed "e" + combining acute → composed "é", which is then
        // rejected as non-ASCII; the point is that normalisation happens, so
        // a name can't dodge the grammar by decomposition.
        let decomposed = "caf\u{65}\u{301}.txt";
        assert!(validate_filename(decomposed).is_err());
    }

    #[test]
    fn confinement_resolves_root_symlinks_and_rejects_separators() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let real = dir.path().join("real");
        fs::create_dir(&real).unwrap_or_else(|e| panic!("{e}"));
        let link = dir.path().join("link");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&real, &link).unwrap_or_else(|e| panic!("{e}"));
        #[cfg(not(unix))]
        let link = real.clone();
        let (root, target) = confined_target(&link, "a.txt").unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            root,
            fs::canonicalize(&real).unwrap_or_else(|e| panic!("{e}"))
        );
        assert_eq!(target, root.join("a.txt"));
        assert!(matches!(
            confined_target(&link, "../a.txt"),
            Err(ExportError::PathEscape)
        ));
        assert!(matches!(
            confined_target(&dir.path().join("missing"), "a.txt"),
            Err(ExportError::PathEscape)
        ));
    }
}
