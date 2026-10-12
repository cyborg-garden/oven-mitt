//! `ovenmitt audit verify|head` (R-AUD-7). `review` arrives in M6.

use std::path::Path;
use std::process::ExitCode;

use crate::audit::verify::{VerifyError, verify_file};
use crate::config::{Config, FsChecks};

fn audit_path(config: &Path) -> anyhow::Result<std::path::PathBuf> {
    let cfg = Config::load(config, FsChecks::No)
        .map_err(|e| anyhow::anyhow!("{}:{e}", config.display()))?;
    Ok(cfg.daemon.audit_log)
}

/// Walk the chain. Exit 0 intact, 1 broken (naming the seq), 2 on I/O error.
pub fn verify(config: &Path) -> anyhow::Result<ExitCode> {
    let path = audit_path(config)?;
    match verify_file(&path) {
        Ok(state) => {
            println!("ok: {} entries, head {}", state.entries, state.head);
            Ok(ExitCode::SUCCESS)
        }
        Err(VerifyError::Chain(c)) => {
            eprintln!("{}: {c}", path.display());
            Ok(ExitCode::from(1))
        }
        Err(VerifyError::Io(e)) => {
            eprintln!("{}: {e}", path.display());
            Ok(ExitCode::from(2))
        }
    }
}

/// Print the head hash for off-host anchoring. Same exit codes as verify.
pub fn head(config: &Path) -> anyhow::Result<ExitCode> {
    let path = audit_path(config)?;
    match verify_file(&path) {
        Ok(state) => {
            println!("{}", state.head);
            Ok(ExitCode::SUCCESS)
        }
        Err(VerifyError::Chain(c)) => {
            eprintln!("{}: {c}", path.display());
            Ok(ExitCode::from(1))
        }
        Err(VerifyError::Io(e)) => {
            eprintln!("{}: {e}", path.display());
            Ok(ExitCode::from(2))
        }
    }
}
