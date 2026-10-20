#![allow(clippy::unwrap_used, clippy::expect_used)]
//! AT-28 / SI-17 / R-DOC-4: no platform, licence, provider or community
//! name in core code, config keys, defaults, shipped examples or tests.
//! The brief's Part C and the docs' motivating-case section are the only
//! places such names may appear, and they are not scanned here.

use std::path::Path;

const DENYLIST: &[&str] = &[
    "discord",
    "signal-cli",
    "signal:",
    "papa reo",
    "papareo",
    "kaitiaki",
    "te hiku",
    "tehiku",
    "mattermost",
    "hermes",
    "swarm map",
    "swarm-map",
    "whatsapp",
    "telegram",
    "slack",
];

const SCAN: &[&str] = &[
    "src",
    "python/src",
    "docker",
    "tests",
    "tests-e2e",
    "python/tests",
];
const SKIP_EXT: &[&str] = &["lock", "pyc"];

fn walk(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    for e in std::fs::read_dir(dir).unwrap().flatten() {
        let p = e.path();
        let name = p.file_name().unwrap().to_string_lossy().into_owned();
        if p.is_dir() {
            if name == ".venv" || name == "__pycache__" || name == "generated" || name == "target" {
                continue;
            }
            walk(&p, out);
        } else if !SKIP_EXT
            .iter()
            .any(|x| p.extension().is_some_and(|e| e == *x))
        {
            out.push(p);
        }
    }
}

/// The harness bridge necessarily names its harness, and nothing else: no
/// platform (it learns the platform from the sender at run time), no
/// provider, licence or community. Its tests are not scanned, because the
/// contract test drives a real platform adapter by name.
const BRIDGE_SCAN: &[&str] = &["hermes-plugin", "hermes-skill"];
const BRIDGE_ALLOWED: &[&str] = &["hermes"];

#[test]
fn bridge_names_no_platform_provider_or_licence() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    for s in BRIDGE_SCAN {
        let p = root.join(s);
        if p.exists() {
            walk(&p, &mut files);
        }
    }
    assert!(
        files.len() >= 4,
        "bridge scan found too few files: {}",
        files.len()
    );
    let mut hits = Vec::new();
    for f in &files {
        let Ok(text) = std::fs::read_to_string(f) else {
            continue;
        };
        let lower = text.to_lowercase();
        for term in DENYLIST.iter().filter(|t| !BRIDGE_ALLOWED.contains(t)) {
            if lower.contains(term) {
                hits.push(format!(
                    "{} contains {term:?}",
                    f.strip_prefix(root).unwrap().display()
                ));
            }
        }
    }
    assert_eq!(
        hits,
        Vec::<String>::new(),
        "domain names found:\n{}",
        hits.join("\n")
    );
}

#[test]
fn no_domain_names_in_code_config_or_tests() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    for s in SCAN {
        let p = root.join(s);
        if p.exists() {
            walk(&p, &mut files);
        }
    }
    assert!(
        files.len() > 20,
        "scan found too few files: {}",
        files.len()
    );
    let mut hits = Vec::new();
    for f in &files {
        let Ok(text) = std::fs::read_to_string(f) else {
            continue;
        };
        // `tokio::signal::` is a Rust path, not a platform.
        let lower = text.to_lowercase().replace("signal::", "");
        for term in DENYLIST {
            if lower.contains(term) {
                hits.push(format!(
                    "{} contains {term:?}",
                    f.strip_prefix(root).unwrap().display()
                ));
            }
        }
    }
    // this file names the terms on purpose
    hits.retain(|h| !h.starts_with("tests/denylist.rs"));
    assert_eq!(
        hits,
        Vec::<String>::new(),
        "domain names found:\n{}",
        hits.join("\n")
    );
}
