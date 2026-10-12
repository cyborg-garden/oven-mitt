//! `ovenmitt object stat <handle>` — operator view including the stored
//! name regardless of `expose_names` (R-OBJ-11, F-15). Reads the object
//! straight from disk; never touches the index or the temp dir, so it is
//! safe beside a running daemon.

use std::path::Path;
use std::process::ExitCode;

use crate::config::{Config, FsChecks};
use crate::handle::Handle;
use crate::keys::KeyStore;
use crate::store::read_object_offline;
use crate::time::to_rfc3339;

pub fn stat(config: &Path, handle: &str) -> anyhow::Result<ExitCode> {
    let cfg = Config::load(config, FsChecks::No)
        .map_err(|e| anyhow::anyhow!("{}:{e}", config.display()))?;
    let handle = Handle::parse(handle).map_err(|e| anyhow::anyhow!("{e}"))?;
    let keystore = KeyStore::open(&cfg.daemon.keys_dir)?;
    let Some((meta, private)) = read_object_offline(&cfg.daemon.data_dir, &keystore, &handle)?
    else {
        eprintln!("no such object: {handle}");
        return Ok(ExitCode::from(1));
    };
    println!("handle:     {}", meta.handle);
    println!("vault:      {}", meta.vault);
    println!("size:       {}", meta.size);
    println!("mime:       {}", meta.mime);
    println!("created:    {}", to_rfc3339(meta.created));
    println!("modified:   {}", to_rfc3339(meta.modified));
    println!("generation: {}", meta.generation);
    println!("name:       {}", private.name.as_deref().unwrap_or("-"));
    println!(
        "labels:     {}",
        if private.labels.is_empty() {
            "-".to_owned()
        } else {
            private.labels.join(", ")
        }
    );
    println!("sha256:     {}", private.sha256);
    Ok(ExitCode::SUCCESS)
}
