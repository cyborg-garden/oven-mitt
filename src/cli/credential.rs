//! `ovenmitt credential issue|list|revoke` (R-CRD-1..3).

use std::path::Path;
use std::process::ExitCode;

use crate::config::{Config, FsChecks};
use crate::credential::{self, Scope};
use crate::time::{now_ms, to_rfc3339};

fn load(config: &Path) -> anyhow::Result<Config> {
    Config::load(config, FsChecks::No).map_err(|e| anyhow::anyhow!("{}:{e}", config.display()))
}

/// Mint a credential. The token is printed once, to stdout, and nowhere else.
pub fn issue(config: &Path, name: &str, vaults: &[String]) -> anyhow::Result<ExitCode> {
    let cfg = load(config)?;
    if name.is_empty() || name.len() > 64 || name.chars().any(char::is_control) {
        anyhow::bail!("--name must be 1-64 printable characters");
    }
    let scope = if vaults.is_empty() {
        Scope::all()
    } else {
        Scope::Some(vaults.to_vec())
    };
    let known: Vec<String> = cfg.vaults.keys().cloned().collect();
    credential::validate_scope(&scope, &known).map_err(|m| anyhow::anyhow!("--vault: {m}"))?;
    let mut records = credential::read_file(&cfg.daemon.credentials)?;
    let (token, record) = credential::issue(name, scope)?;
    records.push(record.clone());
    credential::write_file(&cfg.daemon.credentials, &records)?;
    eprintln!(
        "issued credential {} ({}) for {}; the token below is shown once and never stored:",
        record.id,
        record.name,
        match &record.vaults {
            Scope::All(_) => "all vaults".to_owned(),
            Scope::Some(v) => v.join(", "),
        }
    );
    println!("{token}");
    Ok(ExitCode::SUCCESS)
}

/// Table of credentials: id, name, scope, created, revoked. Never secrets.
pub fn list(config: &Path) -> anyhow::Result<ExitCode> {
    let cfg = load(config)?;
    let records = credential::read_file(&cfg.daemon.credentials)?;
    println!(
        "{:<10} {:<20} {:<24} {:<26} REVOKED",
        "ID", "NAME", "VAULTS", "CREATED"
    );
    for r in records {
        let scope = match &r.vaults {
            Scope::All(_) => "*".to_owned(),
            Scope::Some(v) => v.join(","),
        };
        println!(
            "{:<10} {:<20} {:<24} {:<26} {}",
            r.id,
            r.name,
            scope,
            r.created,
            r.revoked.as_deref().unwrap_or("-")
        );
    }
    Ok(ExitCode::SUCCESS)
}

/// Revoke by id; takes effect on the daemon's next request.
pub fn revoke(config: &Path, id: &str) -> anyhow::Result<ExitCode> {
    let cfg = load(config)?;
    let mut records = credential::read_file(&cfg.daemon.credentials)?;
    let Some(r) = records.iter_mut().find(|r| r.id == id) else {
        eprintln!("no credential with id {id:?}");
        return Ok(ExitCode::from(1));
    };
    if r.revoked.is_some() {
        eprintln!(
            "credential {id} was already revoked at {}",
            r.revoked.as_deref().unwrap_or("?")
        );
        return Ok(ExitCode::SUCCESS);
    }
    r.revoked = Some(to_rfc3339(now_ms()));
    credential::write_file(&cfg.daemon.credentials, &records)?;
    eprintln!("revoked credential {id}");
    Ok(ExitCode::SUCCESS)
}
