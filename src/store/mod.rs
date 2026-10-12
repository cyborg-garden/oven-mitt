//! The object store (PRD §3.2, DEVELOPMENT.md §4).
//!
//! Directories and files, no database. The in-memory index is rebuilt at
//! startup from every object's cleartext `meta.json`. Mutations serialise on
//! one lock; streaming — the slow part — happens before the lock is taken.
//!
//! Plaintext never touches disk here (R-CRY-5): a put encrypts each chunk
//! as it arrives, straight into the temp file. A crash mid-put leaves a
//! `tmp/` directory the next startup removes.

pub mod layout;
pub mod meta;

use std::collections::{BTreeMap, HashMap};
use std::fs::{self, File};
use std::io::{self, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError, RwLock};

use crate::config::VaultConfig;
use crate::crypto::{self, BodyDigest, BodyReader, BodyWriter, CryptoError, Dek, Kek};
use crate::handle::Handle;
use crate::keys::{KeyError, KeyStore};
use crate::time::Millis;

pub use meta::{DEFAULT_MIME, ObjectInfo, ObjectMeta, PrivateMeta};

use layout::{BODY_ENC, DEK_WRAP, META_ENC, META_JSON};

/// Store errors. Variants map onto PRD §7 codes in the API layer; the
/// messages here never contain paths, names, or content.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("object not found")]
    NotFound,
    #[error("object expired")]
    Expired(Expired),
    #[error("vault not found")]
    VaultNotFound,
    #[error("object exceeds the vault's size limit")]
    TooLarge,
    #[error("client-supplied sha256 does not match the streamed body")]
    IntegrityMismatch,
    #[error("invalid labels: {0}")]
    LabelInvalid(String),
    #[error("invalid name: {0}")]
    NameInvalid(String),
    #[error("invalid mime type: {0}")]
    MimeInvalid(String),
    #[error("object {handle} is corrupt: {detail}")]
    Corrupt { handle: Handle, detail: String },
    #[error("startup: {0}")]
    Startup(String),
    #[error("{0}")]
    Key(#[from] KeyError),
    #[error("{0}")]
    Crypto(#[from] CryptoError),
    #[error("i/o: {0}")]
    Io(#[from] io::Error),
}

/// An object that was removed because its TTL passed. Carries what the
/// audit `expire` entry needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Expired {
    pub handle: Handle,
    pub vault: String,
    pub size: u64,
    pub sha256: String,
}

/// An object removed by `delete`. Same shape; different audit event.
pub type Deleted = Expired;

/// What `Store::open` did, for the daemon's startup log and audit.
#[derive(Debug, Default, Clone)]
pub struct OpenReport {
    pub objects: usize,
    pub swept_tmp: usize,
    pub expired: Vec<Expired>,
}

/// Parameters for a put or replace.
#[derive(Debug, Clone, Default)]
pub struct PutParams {
    pub name: Option<String>,
    pub mime: Option<String>,
    /// `None` on replace means "carry the existing labels over".
    pub labels: Option<Vec<String>>,
    /// Client-supplied plaintext SHA-256 (hex) to verify (R-OBJ-10).
    pub expected_sha256: Option<String>,
}

#[derive(Debug, Clone)]
struct Entry {
    meta: ObjectMeta,
    private: PrivateMeta,
}

/// The store.
#[derive(Debug)]
pub struct Store {
    objects_dir: PathBuf,
    tmp_dir: PathBuf,
    vaults: BTreeMap<String, VaultConfig>,
    keys: BTreeMap<String, Kek>,
    index: RwLock<HashMap<Handle, Entry>>,
    mutate: Mutex<()>,
}

#[derive(Clone, Copy)]
enum Locked {
    Yes,
    No,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

fn read_index(
    idx: &RwLock<HashMap<Handle, Entry>>,
) -> std::sync::RwLockReadGuard<'_, HashMap<Handle, Entry>> {
    idx.read().unwrap_or_else(PoisonError::into_inner)
}

fn write_index(
    idx: &RwLock<HashMap<Handle, Entry>>,
) -> std::sync::RwLockWriteGuard<'_, HashMap<Handle, Entry>> {
    idx.write().unwrap_or_else(PoisonError::into_inner)
}

impl Store {
    /// Open the store: create directories, sweep temp, rebuild the index,
    /// load (or create) every vault's key, and remove already-expired objects.
    pub fn open(
        data_dir: &Path,
        vaults: BTreeMap<String, VaultConfig>,
        keystore: &KeyStore,
        now: Millis,
    ) -> Result<(Arc<Self>, OpenReport), StoreError> {
        let objects_dir = data_dir.join("objects");
        let tmp_dir = data_dir.join("tmp");
        fs::create_dir_all(&objects_dir)?;
        fs::create_dir_all(&tmp_dir)?;

        let mut report = OpenReport::default();

        // 1. Sweep temp.
        for entry in fs::read_dir(&tmp_dir)? {
            let entry = entry?;
            let p = entry.path();
            if p.is_dir() {
                fs::remove_dir_all(&p)?;
            } else {
                fs::remove_file(&p)?;
            }
            report.swept_tmp += 1;
        }

        // 2. Scan cleartext metadata.
        let mut metas: Vec<ObjectMeta> = Vec::new();
        for entry in fs::read_dir(&objects_dir)? {
            let entry = entry?;
            let p = entry.path();
            if !p.is_dir() {
                continue;
            }
            let meta_path = p.join(META_JSON);
            let bytes = fs::read(&meta_path).map_err(|e| {
                StoreError::Startup(format!("cannot read {}: {e}", meta_path.display()))
            })?;
            let meta: ObjectMeta = serde_json::from_slice(&bytes).map_err(|e| {
                StoreError::Startup(format!("cannot parse {}: {e}", meta_path.display()))
            })?;
            if p.file_name().and_then(|n| n.to_str()) != Some(meta.handle.as_str()) {
                return Err(StoreError::Startup(format!(
                    "{} names a different handle than its directory",
                    meta_path.display()
                )));
            }
            if !vaults.contains_key(&meta.vault) {
                return Err(StoreError::Startup(format!(
                    "object {} belongs to vault {:?}, which is not in the config; \
                     add the vault back or move the object's data aside",
                    meta.handle, meta.vault
                )));
            }
            metas.push(meta);
        }

        // 3. Keys: create only for vaults with no objects; refuse otherwise.
        let mut keys = BTreeMap::new();
        for name in vaults.keys() {
            let has_objects = metas.iter().any(|m| &m.vault == name);
            keys.insert(name.clone(), keystore.load_or_create(name, has_objects)?);
        }

        // 4. Private metadata.
        let mut index = HashMap::with_capacity(metas.len());
        for meta in metas {
            let kek = &keys[&meta.vault];
            let gen_dir = objects_dir
                .join(meta.handle.as_str())
                .join(layout::gen_name(meta.generation));
            let private = load_private(kek, &meta.handle, &gen_dir)?;
            index.insert(meta.handle.clone(), Entry { meta, private });
        }
        report.objects = index.len();

        let store = Arc::new(Self {
            objects_dir,
            tmp_dir,
            vaults,
            keys,
            index: RwLock::new(index),
            mutate: Mutex::new(()),
        });

        // 5. Expire what's already past.
        report.expired = store.sweep_expired(now)?;
        report.objects -= report.expired.len();
        Ok((store, report))
    }

    /// Configured vaults.
    pub fn vaults(&self) -> &BTreeMap<String, VaultConfig> {
        &self.vaults
    }

    /// One vault's config.
    pub fn vault(&self, name: &str) -> Option<&VaultConfig> {
        self.vaults.get(name)
    }

    fn expires_at(&self, meta: &ObjectMeta) -> Option<Millis> {
        let ttl = self.vaults.get(&meta.vault)?.ttl?;
        let ms = i64::try_from(ttl.as_millis()).ok()?;
        meta.modified.checked_add(ms)
    }

    fn info(&self, e: &Entry) -> ObjectInfo {
        let expose = self
            .vaults
            .get(&e.meta.vault)
            .is_some_and(|v| v.expose_names);
        ObjectInfo::build(&e.meta, &e.private, expose, self.expires_at(&e.meta))
    }

    fn removed(e: &Entry) -> Expired {
        Expired {
            handle: e.meta.handle.clone(),
            vault: e.meta.vault.clone(),
            size: e.meta.size,
            sha256: e.private.sha256.clone(),
        }
    }

    /// Fetch a live entry, or delete it and report `Expired` if its TTL has
    /// passed (R-OBJ-6). `Locked::Yes` when the caller already holds
    /// `mutate` (std mutexes don't re-enter).
    fn live(&self, handle: &Handle, now: Millis, locked: Locked) -> Result<Entry, StoreError> {
        let entry = read_index(&self.index)
            .get(handle)
            .cloned()
            .ok_or(StoreError::NotFound)?;
        if self.expires_at(&entry.meta).is_some_and(|t| t <= now) {
            let gone = match locked {
                Locked::Yes => self.remove_locked(handle)?,
                Locked::No => {
                    let _g = lock(&self.mutate);
                    self.remove_locked(handle)?
                }
            };
            return Err(StoreError::Expired(gone));
        }
        Ok(entry)
    }

    /// Agent-visible metadata.
    pub fn stat(&self, handle: &Handle, now: Millis) -> Result<ObjectInfo, StoreError> {
        Ok(self.info(&self.live(handle, now, Locked::No)?))
    }

    /// All live objects, optionally in one vault, ordered by creation.
    /// Expired objects are omitted; the sweep removes them.
    pub fn list(&self, vault: Option<&str>, now: Millis) -> Result<Vec<ObjectInfo>, StoreError> {
        if let Some(v) = vault
            && !self.vaults.contains_key(v)
        {
            return Err(StoreError::VaultNotFound);
        }
        let idx = read_index(&self.index);
        let mut entries: Vec<&Entry> = idx
            .values()
            .filter(|e| vault.is_none_or(|v| e.meta.vault == v))
            .filter(|e| self.expires_at(&e.meta).is_none_or(|t| t > now))
            .collect();
        entries.sort_by(|a, b| {
            a.meta
                .created
                .cmp(&b.meta.created)
                .then_with(|| a.meta.handle.cmp(&b.meta.handle))
        });
        Ok(entries.into_iter().map(|e| self.info(e)).collect())
    }

    /// Replace an object's labels (R-OBJ-8). Does not touch `modified`.
    pub fn label(
        &self,
        handle: &Handle,
        labels: Vec<String>,
        now: Millis,
    ) -> Result<ObjectInfo, StoreError> {
        meta::validate_labels(&labels).map_err(StoreError::LabelInvalid)?;
        let _g = lock(&self.mutate);
        let mut entry = self.live(handle, now, Locked::Yes)?;
        entry.private.labels = labels;
        let kek = &self.keys[&entry.meta.vault];
        let gen_dir = self.gen_dir(&entry.meta);
        let dek = load_dek(kek, handle, &gen_dir)?;
        write_private(&dek, handle, &gen_dir, &entry.private)?;
        write_index(&self.index).insert(handle.clone(), entry.clone());
        Ok(self.info(&entry))
    }

    /// Delete an object: shred its key, remove its files (R-OBJ-5, R-CRY-3).
    pub fn delete(&self, handle: &Handle, now: Millis) -> Result<Deleted, StoreError> {
        let _g = lock(&self.mutate);
        self.live(handle, now, Locked::Yes)?;
        self.remove_locked(handle)
    }

    /// Remove every object whose TTL has passed (R-OBJ-6).
    pub fn sweep_expired(&self, now: Millis) -> Result<Vec<Expired>, StoreError> {
        let _g = lock(&self.mutate);
        let due: Vec<Handle> = read_index(&self.index)
            .values()
            .filter(|e| self.expires_at(&e.meta).is_some_and(|t| t <= now))
            .map(|e| e.meta.handle.clone())
            .collect();
        let mut out = Vec::with_capacity(due.len());
        for h in due {
            out.push(self.remove_locked(&h)?);
        }
        Ok(out)
    }

    /// Open an object's body for streaming decryption (export, resolve).
    pub fn open_body(
        &self,
        handle: &Handle,
        now: Millis,
    ) -> Result<(BodyReader<BufReader<File>>, ObjectMeta), StoreError> {
        let entry = self.live(handle, now, Locked::No)?;
        let kek = &self.keys[&entry.meta.vault];
        let gen_dir = self.gen_dir(&entry.meta);
        let dek = load_dek(kek, handle, &gen_dir)?;
        let file = File::open(gen_dir.join(BODY_ENC))?;
        let reader = BodyReader::new(&dek, handle, BufReader::new(file))?;
        Ok((reader, entry.meta))
    }

    /// Operator view: the stored name regardless of `expose_names`.
    pub fn operator_stat(&self, handle: &Handle) -> Option<(ObjectInfo, PrivateMeta)> {
        let idx = read_index(&self.index);
        let e = idx.get(handle)?;
        Some((self.info(e), e.private.clone()))
    }

    /// Begin streaming a new object into `vault`.
    pub fn begin_put(
        self: &Arc<Self>,
        vault: &str,
        params: PutParams,
    ) -> Result<PutStream, StoreError> {
        let vcfg = self
            .vaults
            .get(vault)
            .ok_or(StoreError::VaultNotFound)?
            .clone();
        validate_params(&params)?;
        let handle = loop {
            let h = Handle::generate().map_err(CryptoError::from)?;
            if !read_index(&self.index).contains_key(&h)
                && !layout::object_dir(&self.objects_dir, &h).exists()
            {
                break h;
            }
        };
        self.start_stream(vcfg, handle, 1, params, None)
    }

    /// Begin streaming a replacement body under an existing handle (R-OBJ-4).
    pub fn begin_replace(
        self: &Arc<Self>,
        handle: &Handle,
        params: PutParams,
        now: Millis,
    ) -> Result<PutStream, StoreError> {
        validate_params(&params)?;
        let entry = self.live(handle, now, Locked::No)?;
        let vcfg = self.vaults[&entry.meta.vault].clone();
        let next_gen = entry
            .meta
            .generation
            .checked_add(1)
            .ok_or_else(|| StoreError::Corrupt {
                handle: handle.clone(),
                detail: "generation counter exhausted".into(),
            })?;
        self.start_stream(vcfg, handle.clone(), next_gen, params, Some(entry))
    }

    fn start_stream(
        self: &Arc<Self>,
        vault: VaultConfig,
        handle: Handle,
        generation: u32,
        params: PutParams,
        replacing: Option<Entry>,
    ) -> Result<PutStream, StoreError> {
        let kek = self.keys[&vault.name].clone();
        let dek = Dek::generate()?;
        let tmp = self.tmp_dir.join(format!(
            "{}.{}",
            handle,
            layout::random_suffix().map_err(CryptoError::from)?
        ));
        let gen_dir = tmp.join(layout::gen_name(generation));
        fs::create_dir_all(&gen_dir)?;
        let wrapped = crypto::wrap_dek(&kek, &handle, &dek)?;
        fs::write(gen_dir.join(DEK_WRAP), wrapped)?;
        let file = File::create(gen_dir.join(BODY_ENC))?;
        let writer = BodyWriter::new(&dek, &handle, BufWriter::new(file))?;
        Ok(PutStream {
            store: Arc::clone(self),
            tmp,
            gen_dir,
            writer: Some(writer),
            dek,
            handle,
            vault,
            generation,
            params,
            replacing,
            written: 0,
            committed: false,
        })
    }

    fn gen_dir(&self, meta: &ObjectMeta) -> PathBuf {
        layout::object_dir(&self.objects_dir, &meta.handle).join(layout::gen_name(meta.generation))
    }

    /// Remove an object: must hold `mutate`.
    fn remove_locked(&self, handle: &Handle) -> Result<Expired, StoreError> {
        let entry = write_index(&self.index)
            .remove(handle)
            .ok_or(StoreError::NotFound)?;
        let dir = layout::object_dir(&self.objects_dir, handle);
        // Shred every generation's key (there should be one), then the dir.
        if let Ok(rd) = fs::read_dir(&dir) {
            for e in rd.flatten() {
                if e.path().is_dir() {
                    layout::shred_generation(&e.path())?;
                }
            }
        }
        match fs::remove_dir_all(&dir) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        layout::fsync_dir(&self.objects_dir)?;
        Ok(Self::removed(&entry))
    }
}

fn validate_params(p: &PutParams) -> Result<(), StoreError> {
    if let Some(n) = &p.name {
        meta::validate_name(n).map_err(StoreError::NameInvalid)?;
    }
    if let Some(m) = &p.mime {
        meta::validate_mime(m).map_err(StoreError::MimeInvalid)?;
    }
    if let Some(l) = &p.labels {
        meta::validate_labels(l).map_err(StoreError::LabelInvalid)?;
    }
    if let Some(h) = &p.expected_sha256
        && (h.len() != 64 || !h.bytes().all(|b| b.is_ascii_hexdigit()))
    {
        return Err(StoreError::IntegrityMismatch);
    }
    Ok(())
}

fn load_dek(kek: &Kek, handle: &Handle, gen_dir: &Path) -> Result<Dek, StoreError> {
    let wrapped = fs::read(gen_dir.join(DEK_WRAP)).map_err(|e| StoreError::Corrupt {
        handle: handle.clone(),
        detail: format!("missing key record: {e}"),
    })?;
    crypto::unwrap_dek(kek, handle, &wrapped).map_err(|_| StoreError::Corrupt {
        handle: handle.clone(),
        detail: "key record does not authenticate".into(),
    })
}

fn load_private(kek: &Kek, handle: &Handle, gen_dir: &Path) -> Result<PrivateMeta, StoreError> {
    let dek = load_dek(kek, handle, gen_dir)?;
    let sealed = fs::read(gen_dir.join(META_ENC)).map_err(|e| StoreError::Corrupt {
        handle: handle.clone(),
        detail: format!("missing metadata record: {e}"),
    })?;
    let plain = crypto::open_meta(&dek, handle, &sealed).map_err(|_| StoreError::Corrupt {
        handle: handle.clone(),
        detail: "metadata record does not authenticate".into(),
    })?;
    serde_json::from_slice(&plain).map_err(|e| StoreError::Corrupt {
        handle: handle.clone(),
        detail: format!("metadata record unparsable: {e}"),
    })
}

fn write_private(
    dek: &Dek,
    handle: &Handle,
    gen_dir: &Path,
    private: &PrivateMeta,
) -> Result<(), StoreError> {
    let plain = serde_json::to_vec(private).map_err(|e| StoreError::Corrupt {
        handle: handle.clone(),
        detail: format!("cannot serialise metadata: {e}"),
    })?;
    let sealed = crypto::seal_meta(dek, handle, &plain)?;
    layout::atomic_write(gen_dir, META_ENC, &sealed)?;
    Ok(())
}

/// An in-flight put or replace. Write bytes, then `commit`; dropping it
/// without committing discards the temp directory (R-OBJ-3).
pub struct PutStream {
    store: Arc<Store>,
    tmp: PathBuf,
    gen_dir: PathBuf,
    writer: Option<BodyWriter<BufWriter<File>>>,
    dek: Dek,
    handle: Handle,
    vault: VaultConfig,
    generation: u32,
    params: PutParams,
    replacing: Option<Entry>,
    written: u64,
    committed: bool,
}

impl std::fmt::Debug for PutStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PutStream")
            .field("handle", &self.handle)
            .field("generation", &self.generation)
            .field("written", &self.written)
            .finish_non_exhaustive()
    }
}

/// Result of a committed put or replace.
#[derive(Debug, Clone)]
pub struct Committed {
    pub info: ObjectInfo,
    pub digest: BodyDigest,
    pub replaced: bool,
}

impl PutStream {
    /// The handle this stream will commit under.
    pub fn handle(&self) -> &Handle {
        &self.handle
    }

    /// Append plaintext. Enforces `max_object_size` as bytes arrive
    /// (R-OBJ-9); on `TooLarge` the stream is dead and must be dropped.
    pub fn write(&mut self, data: &[u8]) -> Result<(), StoreError> {
        let Some(w) = self.writer.as_mut() else {
            return Err(StoreError::Io(io::Error::other("stream already finished")));
        };
        let new_total = self.written.saturating_add(data.len() as u64);
        if self
            .vault
            .max_object_size
            .is_some_and(|max| new_total > max)
        {
            self.writer = None;
            return Err(StoreError::TooLarge);
        }
        w.write_all(data).map_err(|e| {
            // BodyWriter wraps CryptoError into io::Error::other; keep the io
            // flavour — the API maps either to a storage failure.
            StoreError::Io(e)
        })?;
        self.written = new_total;
        Ok(())
    }

    /// Finish the body, verify the optional client hash, and commit
    /// atomically.
    pub fn commit(mut self, now: Millis) -> Result<Committed, StoreError> {
        let writer = self
            .writer
            .take()
            .ok_or_else(|| StoreError::Io(io::Error::other("stream already finished")))?;
        let (buf, digest) = writer.finish()?;
        let file = buf
            .into_inner()
            .map_err(|e| StoreError::Io(e.into_error()))?;
        file.sync_all()?;
        let sha256 = hex::encode(digest.sha256);
        if let Some(expected) = &self.params.expected_sha256
            && !expected.eq_ignore_ascii_case(&sha256)
        {
            return Err(StoreError::IntegrityMismatch);
        }

        let prior = self.replacing.as_ref();
        let private = PrivateMeta {
            name: self
                .params
                .name
                .clone()
                .or_else(|| prior.and_then(|e| e.private.name.clone())),
            labels: self
                .params
                .labels
                .clone()
                .or_else(|| prior.map(|e| e.private.labels.clone()))
                .unwrap_or_default(),
            sha256,
        };
        write_private(&self.dek, &self.handle, &self.gen_dir, &private)?;
        layout::fsync_dir(&self.gen_dir)?;

        let meta = ObjectMeta {
            handle: self.handle.clone(),
            vault: self.vault.name.clone(),
            size: digest.size,
            mime: self
                .params
                .mime
                .clone()
                .or_else(|| prior.map(|e| e.meta.mime.clone()))
                .unwrap_or_else(|| DEFAULT_MIME.to_owned()),
            created: prior.map_or(now, |e| e.meta.created),
            modified: now,
            generation: self.generation,
        };
        let meta_bytes = serde_json::to_vec(&meta).map_err(|e| StoreError::Corrupt {
            handle: self.handle.clone(),
            detail: format!("cannot serialise metadata: {e}"),
        })?;

        let store = Arc::clone(&self.store);
        let _g = lock(&store.mutate);
        let object_dir = layout::object_dir(&store.objects_dir, &self.handle);
        let replaced = if let Some(old) = prior {
            // Object must still exist and be the generation we started from.
            let current = read_index(&store.index)
                .get(&self.handle)
                .map(|e| e.meta.generation)
                .ok_or(StoreError::NotFound)?;
            if current != old.meta.generation {
                return Err(StoreError::NotFound);
            }
            let dest_gen = object_dir.join(layout::gen_name(self.generation));
            fs::rename(&self.gen_dir, &dest_gen)?;
            layout::atomic_write(&object_dir, META_JSON, &meta_bytes)?;
            layout::shred_generation(&object_dir.join(layout::gen_name(old.meta.generation)))?;
            layout::fsync_dir(&object_dir)?;
            true
        } else {
            layout::atomic_write(&self.tmp, META_JSON, &meta_bytes)?;
            fs::rename(&self.tmp, &object_dir)?;
            layout::fsync_dir(&store.objects_dir)?;
            false
        };
        let entry = Entry { meta, private };
        let info = store.info(&entry);
        write_index(&store.index).insert(self.handle.clone(), entry);
        self.committed = true;
        Ok(Committed {
            info,
            digest,
            replaced,
        })
    }
}

impl Drop for PutStream {
    fn drop(&mut self) {
        // Close the file before removing the directory.
        self.writer = None;
        if !self.committed {
            let _ = fs::remove_dir_all(&self.tmp);
        } else if self.replacing.is_some() {
            // The gen dir was moved out; remove the empty temp parent.
            let _ = fs::remove_dir_all(&self.tmp);
        }
    }
}
