#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Store behaviour (M2): atomic commit, replace-and-shred, delete, TTL,
//! index rebuild, and the at-rest sentinel scans (AT-3, AT-14, AT-15,
//! AT-19, AT-21 at the store level).

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::sync::Arc;

use ovenmitt::config::{Config, FsChecks};
use ovenmitt::handle::Handle;
use ovenmitt::keys::{KeyError, KeyStore};
use ovenmitt::store::{PutParams, Store, StoreError};

struct Fixture {
    dir: tempfile::TempDir,
    data: std::path::PathBuf,
    keys: std::path::PathBuf,
    vaults: BTreeMap<String, ovenmitt::config::VaultConfig>,
}

fn fixture(ttl: Option<&str>, max: Option<&str>) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let ttl_line = ttl.map(|t| format!("ttl = \"{t}\"\n")).unwrap_or_default();
    let max_line = max
        .map(|m| format!("max_object_size = \"{m}\"\n"))
        .unwrap_or_default();
    let src = format!(
        "[vault.private]\nexpose_names = true\n{ttl_line}{max_line}\n[vault.hidden]\nexpose_names = false\n"
    );
    let cfg = Config::parse(&src, FsChecks::No).unwrap();
    Fixture {
        data: dir.path().join("data"),
        keys: dir.path().join("keys"),
        dir,
        vaults: cfg.vaults,
    }
}

fn open(f: &Fixture, now: i64) -> (Arc<Store>, ovenmitt::store::OpenReport) {
    let ks = KeyStore::open(&f.keys).unwrap();
    Store::open(&f.data, f.vaults.clone(), &ks, now).unwrap()
}

fn sentinel() -> Vec<u8> {
    let mut b = [0u8; 64];
    getrandom::fill(&mut b).unwrap();
    // printable so a naive grep would find it if it leaked
    b.iter().map(|x| b'a' + (x % 26)).collect()
}

/// Every file under `root` (recursively).
fn all_files(root: &Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    if let Ok(rd) = fs::read_dir(root) {
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                out.extend(all_files(&p));
            } else {
                out.push(p);
            }
        }
    }
    out
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

fn assert_absent(root: &Path, needle: &[u8]) {
    for f in all_files(root) {
        let bytes = fs::read(&f).unwrap();
        assert!(
            !contains(&bytes, needle),
            "sentinel found in {}",
            f.display()
        );
    }
}

fn put(store: &Arc<Store>, vault: &str, data: &[u8], now: i64) -> ovenmitt::store::Committed {
    let mut s = store
        .begin_put(
            vault,
            PutParams {
                name: Some("secret-name.txt".into()),
                mime: Some("text/plain".into()),
                labels: Some(vec!["lbl".into()]),
                expected_sha256: None,
            },
        )
        .unwrap();
    for chunk in data.chunks(1000) {
        s.write(chunk).unwrap();
    }
    s.commit(now).unwrap()
}

#[test]
fn put_commit_stat_list_round_trip() {
    let f = fixture(None, None);
    let (store, report) = open(&f, 1_000);
    assert_eq!(report.objects, 0);
    let body = sentinel();
    let c = put(&store, "private", &body, 1_000);
    assert_eq!(c.info.size, 64);
    assert_eq!(c.info.mime, "text/plain");
    assert_eq!(c.info.labels, vec!["lbl"]);
    assert_eq!(c.info.name.as_deref(), Some("secret-name.txt"));
    assert_eq!(c.info.expires_at, None);
    assert!(!c.replaced);
    assert_eq!(
        hex::encode(c.digest.sha256),
        ovenmitt::crypto::sha256_hex(&body)
    );

    let st = store.stat(&c.info.handle, 1_001).unwrap();
    assert_eq!(st, c.info);
    let listed = store.list(Some("private"), 1_001).unwrap();
    assert_eq!(listed, vec![c.info.clone()]);
    assert!(store.list(Some("hidden"), 1_001).unwrap().is_empty());
    assert!(matches!(
        store.list(Some("nope"), 1_001),
        Err(StoreError::VaultNotFound)
    ));

    // AT-21: nothing under data_dir holds the plaintext, the name, or the hash
    assert_absent(&f.data, &body);
    assert_absent(&f.data, b"secret-name.txt");
    assert_absent(&f.data, ovenmitt::crypto::sha256_hex(&body).as_bytes());
    // but the temp dir is empty and the object dir exists
    assert!(fs::read_dir(f.data.join("tmp")).unwrap().next().is_none());
    assert!(f.data.join("objects").join(c.info.handle.as_str()).is_dir());

    // read it back through the store (what export/resolve use)
    let (reader, meta) = store.open_body(&c.info.handle, 1_002).unwrap();
    assert_eq!(meta.size, 64);
    assert_eq!(reader.read_all().unwrap(), body);
}

#[test]
fn hidden_vault_returns_null_name_but_operator_sees_it() {
    let f = fixture(None, None);
    let (store, _) = open(&f, 1_000);
    let c = put(&store, "hidden", b"x", 1_000);
    assert_eq!(c.info.name, None);
    let (info, private) = store.operator_stat(&c.info.handle).unwrap();
    assert_eq!(info.name, None);
    assert_eq!(private.name.as_deref(), Some("secret-name.txt"));
}

#[test]
fn aborted_put_leaves_nothing_and_startup_sweeps_temp() {
    let f = fixture(None, None);
    let (store, _) = open(&f, 1_000);
    let body = sentinel();
    let handle;
    {
        let mut s = store.begin_put("private", PutParams::default()).unwrap();
        s.write(&body).unwrap();
        handle = s.handle().clone();
        // mid-stream: ciphertext only, even now (SI-9 stalled case)
        assert_absent(&f.data, &body);
        assert!(fs::read_dir(f.data.join("tmp")).unwrap().next().is_some());
        drop(s); // abort
    }
    assert!(matches!(
        store.stat(&handle, 1_001),
        Err(StoreError::NotFound)
    ));
    assert!(store.list(None, 1_001).unwrap().is_empty());
    assert!(fs::read_dir(f.data.join("tmp")).unwrap().next().is_none());

    // simulate a crash: leave junk in tmp, reopen, it's gone
    fs::create_dir_all(f.data.join("tmp/v_000000000000.deadbeef/gen-1")).unwrap();
    fs::write(
        f.data.join("tmp/v_000000000000.deadbeef/gen-1/body.enc"),
        b"junk",
    )
    .unwrap();
    drop(store);
    let (store, report) = open(&f, 2_000);
    assert_eq!(report.swept_tmp, 1);
    assert!(fs::read_dir(f.data.join("tmp")).unwrap().next().is_none());
    assert!(store.list(None, 2_000).unwrap().is_empty());
}

#[test]
fn replace_keeps_handle_resets_modified_and_shreds_old_generation() {
    let f = fixture(None, None);
    let (store, _) = open(&f, 1_000);
    let old_body = sentinel();
    let new_body = sentinel();
    let c1 = put(&store, "private", &old_body, 1_000);
    let h = c1.info.handle.clone();
    let gen1 = f.data.join("objects").join(h.as_str()).join("gen-1");
    assert!(gen1.join("dek.wrap").is_file());

    let mut s = store
        .begin_replace(
            &h,
            PutParams {
                name: None,
                mime: None,
                labels: None,
                expected_sha256: None,
            },
            1_500,
        )
        .unwrap();
    s.write(&new_body[..10]).unwrap();
    // old body still readable while the replacement streams (F-24)
    let (r, _) = store.open_body(&h, 1_600).unwrap();
    assert_eq!(r.read_all().unwrap(), old_body);
    s.write(&new_body[10..]).unwrap();
    let c2 = s.commit(2_000).unwrap();

    assert!(c2.replaced);
    assert_eq!(c2.info.handle, h);
    assert_eq!(c2.info.created, c1.info.created);
    assert_ne!(c2.info.modified, c1.info.modified);
    assert_eq!(c2.info.labels, vec!["lbl"], "labels carry over");
    assert_eq!(
        c2.info.name.as_deref(),
        Some("secret-name.txt"),
        "name carries over"
    );
    assert_eq!(c2.info.mime, "text/plain", "mime carries over");

    // old generation gone, new one present, no temp
    assert!(!gen1.exists());
    assert!(
        f.data
            .join("objects")
            .join(h.as_str())
            .join("gen-2/body.enc")
            .is_file()
    );
    assert!(fs::read_dir(f.data.join("tmp")).unwrap().next().is_none());
    assert_eq!(store.list(None, 2_001).unwrap().len(), 1);
    let (r, _) = store.open_body(&h, 2_001).unwrap();
    assert_eq!(r.read_all().unwrap(), new_body);

    // survives a restart with the new generation
    drop(store);
    let (store, report) = open(&f, 3_000);
    assert_eq!(report.objects, 1);
    let (r, meta) = store.open_body(&h, 3_000).unwrap();
    assert_eq!(meta.generation, 2);
    assert_eq!(r.read_all().unwrap(), new_body);
}

#[test]
fn aborted_replace_keeps_old_body() {
    let f = fixture(None, None);
    let (store, _) = open(&f, 1_000);
    let old_body = sentinel();
    let c1 = put(&store, "private", &old_body, 1_000);
    {
        let mut s = store
            .begin_replace(&c1.info.handle, PutParams::default(), 1_500)
            .unwrap();
        s.write(b"partial").unwrap();
    }
    let (r, meta) = store.open_body(&c1.info.handle, 1_600).unwrap();
    assert_eq!(meta.generation, 1);
    assert_eq!(r.read_all().unwrap(), old_body);
    assert!(fs::read_dir(f.data.join("tmp")).unwrap().next().is_none());
}

#[test]
fn delete_shreds_and_is_gone_after_restart() {
    let f = fixture(None, None);
    let (store, _) = open(&f, 1_000);
    let body = sentinel();
    let c = put(&store, "private", &body, 1_000);
    let h = c.info.handle.clone();
    let obj_dir = f.data.join("objects").join(h.as_str());
    let d = store.delete(&h, 1_001).unwrap();
    assert_eq!(d.handle, h);
    assert_eq!(d.size, 64);
    assert_eq!(d.sha256, ovenmitt::crypto::sha256_hex(&body));
    assert!(!obj_dir.exists());
    assert!(matches!(store.stat(&h, 1_002), Err(StoreError::NotFound)));
    assert!(matches!(store.delete(&h, 1_002), Err(StoreError::NotFound)));
    assert!(matches!(
        store.open_body(&h, 1_002),
        Err(StoreError::NotFound)
    ));
    drop(store);
    let (store, report) = open(&f, 2_000);
    assert_eq!(report.objects, 0);
    assert!(matches!(store.stat(&h, 2_000), Err(StoreError::NotFound)));
}

#[test]
fn ttl_expires_on_access_and_on_sweep_and_replace_resets() {
    let f = fixture(Some("10s"), None);
    let (store, _) = open(&f, 1_000);
    let c = put(&store, "private", b"a", 1_000);
    assert_eq!(
        c.info.expires_at.as_deref(),
        Some(ovenmitt::time::to_rfc3339(11_000).as_str())
    );
    // still there just before expiry
    assert!(store.stat(&c.info.handle, 10_999).is_ok());
    // replace resets the clock (F-10)
    let mut s = store
        .begin_replace(&c.info.handle, PutParams::default(), 5_000)
        .unwrap();
    s.write(b"b").unwrap();
    let c2 = s.commit(8_000).unwrap();
    assert_eq!(
        c2.info.expires_at.as_deref(),
        Some(ovenmitt::time::to_rfc3339(18_000).as_str())
    );
    assert!(store.stat(&c.info.handle, 17_999).is_ok());
    // access after expiry: reported as Expired (API maps to NOT_FOUND) and removed
    let Err(StoreError::Expired(gone)) = store.stat(&c.info.handle, 18_000) else {
        panic!("expected Expired");
    };
    assert_eq!(gone.handle, c.info.handle);
    assert_eq!(gone.sha256, ovenmitt::crypto::sha256_hex(b"b"));
    assert!(matches!(
        store.stat(&c.info.handle, 18_001),
        Err(StoreError::NotFound)
    ));

    // sweep path
    let c3 = put(&store, "private", b"c", 20_000);
    let c4 = put(&store, "private", b"d", 25_000);
    assert_eq!(store.list(None, 29_000).unwrap().len(), 2);
    // list omits expired without removing it; sweep removes it
    assert_eq!(store.list(None, 31_000).unwrap().len(), 1);
    let swept = store.sweep_expired(31_000).unwrap();
    assert_eq!(swept.len(), 1);
    assert_eq!(swept[0].handle, c3.info.handle);
    assert!(store.stat(&c4.info.handle, 31_000).is_ok());

    // startup sweep removes already-expired objects
    drop(store);
    let (store, report) = open(&f, 100_000);
    assert_eq!(report.expired.len(), 1);
    assert_eq!(report.expired[0].handle, c4.info.handle);
    assert_eq!(report.objects, 0);
    assert!(store.list(None, 100_000).unwrap().is_empty());
}

#[test]
fn max_object_size_is_enforced_mid_stream() {
    let f = fixture(None, Some("1KiB"));
    let (store, _) = open(&f, 1_000);
    let mut s = store.begin_put("private", PutParams::default()).unwrap();
    s.write(&[0u8; 1000]).unwrap();
    assert!(matches!(s.write(&[0u8; 25]), Err(StoreError::TooLarge)));
    drop(s);
    assert!(store.list(None, 1_001).unwrap().is_empty());
    assert!(fs::read_dir(f.data.join("tmp")).unwrap().next().is_none());
    // exactly at the limit is fine
    let mut s = store.begin_put("private", PutParams::default()).unwrap();
    s.write(&[0u8; 1024]).unwrap();
    s.commit(1_002).unwrap();
}

#[test]
fn integrity_header_is_checked() {
    let f = fixture(None, None);
    let (store, _) = open(&f, 1_000);
    let good = ovenmitt::crypto::sha256_hex(b"hello");
    let mut s = store
        .begin_put(
            "private",
            PutParams {
                expected_sha256: Some(good.to_uppercase()),
                ..PutParams::default()
            },
        )
        .unwrap();
    s.write(b"hello").unwrap();
    s.commit(1_000).unwrap();

    let mut s = store
        .begin_put(
            "private",
            PutParams {
                expected_sha256: Some(ovenmitt::crypto::sha256_hex(b"other")),
                ..PutParams::default()
            },
        )
        .unwrap();
    s.write(b"hello").unwrap();
    assert!(matches!(
        s.commit(1_001),
        Err(StoreError::IntegrityMismatch)
    ));
    assert_eq!(store.list(None, 1_002).unwrap().len(), 1);
    assert!(fs::read_dir(f.data.join("tmp")).unwrap().next().is_none());

    assert!(matches!(
        store.begin_put(
            "private",
            PutParams {
                expected_sha256: Some("zz".into()),
                ..PutParams::default()
            }
        ),
        Err(StoreError::IntegrityMismatch)
    ));
}

#[test]
fn labels_validated_and_rewritten_without_touching_modified() {
    let f = fixture(None, None);
    let (store, _) = open(&f, 1_000);
    let c = put(&store, "private", b"x", 1_000);
    let info = store
        .label(&c.info.handle, vec!["a".into(), "b".into()], 5_000)
        .unwrap();
    assert_eq!(info.labels, vec!["a", "b"]);
    assert_eq!(info.modified, c.info.modified);
    assert!(matches!(
        store.label(&c.info.handle, vec![String::new()], 5_000),
        Err(StoreError::LabelInvalid(_))
    ));
    assert!(matches!(
        store.label(&c.info.handle, vec!["x".repeat(257)], 5_000),
        Err(StoreError::LabelInvalid(_))
    ));
    // persists across restart
    drop(store);
    let (store, _) = open(&f, 6_000);
    assert_eq!(
        store.stat(&c.info.handle, 6_000).unwrap().labels,
        vec!["a", "b"]
    );
}

#[test]
fn bad_params_rejected_before_streaming() {
    let f = fixture(None, None);
    let (store, _) = open(&f, 1_000);
    assert!(matches!(
        store.begin_put("nope", PutParams::default()),
        Err(StoreError::VaultNotFound)
    ));
    assert!(matches!(
        store.begin_put(
            "private",
            PutParams {
                mime: Some("not-a-mime".into()),
                ..PutParams::default()
            }
        ),
        Err(StoreError::MimeInvalid(_))
    ));
    assert!(matches!(
        store.begin_put(
            "private",
            PutParams {
                name: Some("a\nb".into()),
                ..PutParams::default()
            }
        ),
        Err(StoreError::NameInvalid(_))
    ));
    let h = Handle::parse("v_000000000000").unwrap();
    assert!(matches!(
        store.begin_replace(&h, PutParams::default(), 1_000),
        Err(StoreError::NotFound)
    ));
    assert!(fs::read_dir(f.data.join("tmp")).unwrap().next().is_none());
}

#[test]
fn startup_refuses_when_key_missing_but_objects_exist() {
    let f = fixture(None, None);
    let (store, _) = open(&f, 1_000);
    put(&store, "private", b"x", 1_000);
    drop(store);
    fs::remove_file(f.keys.join("private.key")).unwrap();
    let ks = KeyStore::open(&f.keys).unwrap();
    let err = Store::open(&f.data, f.vaults.clone(), &ks, 2_000)
        .err()
        .unwrap();
    assert!(
        matches!(err, StoreError::Key(KeyError::MissingWithObjects { .. })),
        "{err}"
    );
    assert!(!f.keys.join("private.key").exists(), "must not re-key");
    // the `hidden` vault had no objects, so its key may have been created; that's fine
}

#[test]
fn startup_refuses_objects_from_unconfigured_vault_and_corrupt_records() {
    let f = fixture(None, None);
    let (store, _) = open(&f, 1_000);
    let c = put(&store, "private", b"x", 1_000);
    drop(store);

    // vault removed from config
    let mut fewer = f.vaults.clone();
    fewer.remove("private");
    let ks = KeyStore::open(&f.keys).unwrap();
    let err = Store::open(&f.data, fewer, &ks, 2_000).err().unwrap();
    assert!(matches!(err, StoreError::Startup(_)), "{err}");

    // tampered key record
    let wrap = f
        .data
        .join("objects")
        .join(c.info.handle.as_str())
        .join("gen-1/dek.wrap");
    let mut bytes = fs::read(&wrap).unwrap();
    bytes[20] ^= 0xff;
    fs::write(&wrap, bytes).unwrap();
    let err = Store::open(&f.data, f.vaults.clone(), &ks, 2_000)
        .err()
        .unwrap();
    assert!(matches!(err, StoreError::Corrupt { .. }), "{err}");
}

#[test]
fn index_rebuild_orders_by_created_and_keeps_vault_separation() {
    let f = fixture(None, None);
    let (store, _) = open(&f, 1_000);
    let a = put(&store, "private", b"a", 3_000);
    let b = put(&store, "hidden", b"b", 1_000);
    let c = put(&store, "private", b"c", 2_000);
    drop(store);
    let (store, report) = open(&f, 5_000);
    assert_eq!(report.objects, 3);
    let all: Vec<_> = store
        .list(None, 5_000)
        .unwrap()
        .into_iter()
        .map(|i| i.handle)
        .collect();
    assert_eq!(
        all,
        vec![
            b.info.handle.clone(),
            c.info.handle.clone(),
            a.info.handle.clone()
        ]
    );
    let private: Vec<_> = store
        .list(Some("private"), 5_000)
        .unwrap()
        .into_iter()
        .map(|i| i.handle)
        .collect();
    assert_eq!(private, vec![c.info.handle, a.info.handle]);
}

// --- export (R-EXP, AT-9/AT-10 at the store level) ---------------------

#[test]
fn export_writes_plaintext_under_root_and_refuses_escapes_and_collisions() {
    let f = fixture(None, None);
    let (store, _) = open(&f, 1_000);
    let body = sentinel();
    let c = put(&store, "private", &body, 1_000);
    let root = f.dir.path().join("export-root");
    fs::create_dir(&root).unwrap();

    let out =
        ovenmitt::export::export(&store, &c.info.handle, &root, "out.txt", false, 1_001).unwrap();
    assert_eq!(out.size, 64);
    assert_eq!(out.filename, "out.txt");
    assert_eq!(out.sha256, ovenmitt::crypto::sha256_hex(&body));
    assert_eq!(fs::read(root.join("out.txt")).unwrap(), body);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(root.join("out.txt"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o644
        );
    }
    // no temp file left
    assert_eq!(fs::read_dir(&root).unwrap().count(), 1);

    // collision
    assert!(matches!(
        ovenmitt::export::export(&store, &c.info.handle, &root, "out.txt", false, 1_002),
        Err(ovenmitt::export::ExportError::Exists)
    ));
    assert_eq!(fs::read_dir(&root).unwrap().count(), 1);
    // overwrite allowed by destination config
    let c2 = put(&store, "private", b"second", 1_003);
    ovenmitt::export::export(&store, &c2.info.handle, &root, "out.txt", true, 1_004).unwrap();
    assert_eq!(fs::read(root.join("out.txt")).unwrap(), b"second");

    // escape matrix: nothing lands outside, nothing new lands inside
    let before: Vec<_> = all_files(f.dir.path());
    for bad in [
        "../escape.txt",
        "..",
        "sub/dir.txt",
        "/abs.txt",
        ".dotfile",
        "a\\b",
        "",
        "nul\0",
    ] {
        let r = ovenmitt::export::export(&store, &c.info.handle, &root, bad, false, 1_005);
        assert!(
            matches!(
                r,
                Err(ovenmitt::export::ExportError::FilenameInvalid
                    | ovenmitt::export::ExportError::PathEscape)
            ),
            "{bad:?}: {r:?}"
        );
    }
    assert_eq!(all_files(f.dir.path()), before);

    // root swapped for a symlink to elsewhere after "startup": export still
    // lands under the resolved directory, never beside it
    #[cfg(unix)]
    {
        let elsewhere = f.dir.path().join("elsewhere");
        fs::create_dir(&elsewhere).unwrap();
        let linkroot = f.dir.path().join("linkroot");
        std::os::unix::fs::symlink(&elsewhere, &linkroot).unwrap();
        ovenmitt::export::export(
            &store,
            &c.info.handle,
            &linkroot,
            "via-link.txt",
            false,
            1_006,
        )
        .unwrap();
        assert_eq!(fs::read(elsewhere.join("via-link.txt")).unwrap(), body);
        assert!(!root.join("via-link.txt").exists());
    }

    // missing object / expired
    let h = Handle::parse("v_000000000000").unwrap();
    assert!(matches!(
        ovenmitt::export::export(&store, &h, &root, "x.txt", false, 1_007),
        Err(ovenmitt::export::ExportError::Store(StoreError::NotFound))
    ));
}
