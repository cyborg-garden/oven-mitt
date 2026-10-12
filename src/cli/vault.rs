//! `ovenmitt vault list` — the operator's view of the config (R-VLT-4).

use std::path::Path;
use std::process::ExitCode;

use crate::config::{Config, Destination, FsChecks};

pub fn list(config: &Path) -> anyhow::Result<ExitCode> {
    let cfg = Config::load(config, FsChecks::No)
        .map_err(|e| anyhow::anyhow!("{}:{e}", config.display()))?;
    for v in cfg.vaults.values() {
        println!(
            "{}  expose_names={}  ttl={}  max_object_size={}",
            v.name,
            v.expose_names,
            v.ttl
                .map_or("-".to_owned(), |d| format!("{}s", d.as_secs())),
            v.max_object_size.map_or("-".to_owned(), |b| b.to_string())
        );
        for (name, d) in &v.destinations {
            match d {
                Destination::Fs { root, overwrite } => {
                    println!(
                        "    {name}: fs root={} overwrite={overwrite}",
                        root.display()
                    );
                }
                Destination::Send { pattern, max_size } => println!(
                    "    {name}: send match={pattern} max_size={}",
                    max_size.map_or("-".to_owned(), |b| b.to_string())
                ),
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}
