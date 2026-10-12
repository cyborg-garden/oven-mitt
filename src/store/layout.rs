//! Filesystem helpers for the object store: paths, durable writes, and the
//! shred step that makes a deleted generation unrecoverable.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use crate::handle::Handle;

pub const META_JSON: &str = "meta.json";
pub const DEK_WRAP: &str = "dek.wrap";
pub const META_ENC: &str = "meta.enc";
pub const BODY_ENC: &str = "body.enc";

/// `objects/<handle>`
pub fn object_dir(objects: &Path, handle: &Handle) -> PathBuf {
    objects.join(handle.as_str())
}

/// `gen-<N>`
pub fn gen_name(generation: u32) -> String {
    format!("gen-{generation}")
}

/// Parse `gen-<N>` back to N.
pub fn parse_gen(name: &str) -> Option<u32> {
    name.strip_prefix("gen-")?.parse().ok()
}

/// fsync a directory so a rename or create inside it is durable.
pub fn fsync_dir(dir: &Path) -> io::Result<()> {
    File::open(dir)?.sync_all()
}

/// Write `bytes` to `dir/name` durably: temp file, fsync, rename, fsync dir.
pub fn atomic_write(dir: &Path, name: &str, bytes: &[u8]) -> io::Result<()> {
    let tmp = dir.join(format!(".{name}.tmp"));
    let dest = dir.join(name);
    {
        let mut f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, &dest)?;
    fsync_dir(dir)
}

/// Overwrite a file with zeros, fsync, then unlink. Used on `dek.wrap` so
/// that even if the ciphertext blocks survive on the device, the key that
/// could decrypt them does not (crypto-shred, PRD F-8). No claim is made
/// about physical erasure; this is the strongest thing a filesystem lets
/// us do portably.
pub fn shred_file(path: &Path) -> io::Result<()> {
    let len = match fs::metadata(path) {
        Ok(m) => m.len(),
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    {
        let mut f = OpenOptions::new().write(true).open(path)?;
        let zeros = vec![0u8; usize::try_from(len).unwrap_or(usize::MAX)];
        f.write_all(&zeros)?;
        f.sync_all()?;
    }
    fs::remove_file(path)
}

/// Shred a generation directory: key first, then everything else.
pub fn shred_generation(gen_dir: &Path) -> io::Result<()> {
    shred_file(&gen_dir.join(DEK_WRAP))?;
    match fs::remove_dir_all(gen_dir) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// A random suffix for temp directory names.
pub fn random_suffix() -> Result<String, getrandom::Error> {
    let mut b = [0u8; 6];
    getrandom::fill(&mut b)?;
    Ok(hex::encode(b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atomic_write_replaces_and_leaves_no_temp() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        atomic_write(dir.path(), "m.json", b"one").unwrap_or_else(|e| panic!("{e}"));
        atomic_write(dir.path(), "m.json", b"two").unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            fs::read(dir.path().join("m.json")).unwrap_or_else(|e| panic!("{e}")),
            b"two"
        );
        assert!(!dir.path().join(".m.json.tmp").exists());
    }

    #[test]
    fn shred_zeroes_then_removes() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let p = dir.path().join("dek.wrap");
        fs::write(&p, b"secret-key-material").unwrap_or_else(|e| panic!("{e}"));
        shred_file(&p).unwrap_or_else(|e| panic!("{e}"));
        assert!(!p.exists());
        // idempotent
        shred_file(&p).unwrap_or_else(|e| panic!("{e}"));
    }

    #[test]
    fn gen_names_round_trip() {
        assert_eq!(parse_gen(&gen_name(7)), Some(7));
        assert_eq!(parse_gen("gen-x"), None);
        assert_eq!(parse_gen("meta.json"), None);
    }
}
