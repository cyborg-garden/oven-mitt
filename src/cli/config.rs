//! `ovenmitt config check` — validate exactly as the daemon would at startup.

use std::path::Path;
use std::process::ExitCode;

use crate::config::{Config, FsChecks};

pub fn check(path: &Path) -> anyhow::Result<ExitCode> {
    match Config::load(path, FsChecks::Yes) {
        Ok(cfg) => {
            println!(
                "ok: {} — {} vault(s), {} destination(s)",
                path.display(),
                cfg.vaults.len(),
                cfg.destination_count()
            );
            Ok(ExitCode::SUCCESS)
        }
        Err(e) => {
            eprintln!("{}:{e}", path.display());
            Ok(ExitCode::from(1))
        }
    }
}
