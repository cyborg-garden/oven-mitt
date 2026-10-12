//! `ovenmitt audit verify|head` (R-AUD-7). `review` arrives in M6.

use std::path::Path;
use std::process::ExitCode;

use crate::audit::review::{
    Report, Rules, Severity, describe_since, parse_since, review as run_rules,
};
use crate::audit::verify::{VerifyError, read_entries, verify_file};
use crate::config::{Config, FsChecks};
use crate::time::now_ms;

fn load(config: &Path) -> anyhow::Result<Config> {
    Config::load(config, FsChecks::No).map_err(|e| anyhow::anyhow!("{}:{e}", config.display()))
}

fn audit_path(config: &Path) -> anyhow::Result<std::path::PathBuf> {
    Ok(load(config)?.daemon.audit_log)
}

/// Rule-based review (R-REV-1..4). Findings to stderr; `--json` to stdout.
/// Exit 0 = nothing at/above threshold, 1 = findings, 2 = cannot read.
pub fn review(
    config: &Path,
    since: Option<&str>,
    threshold: Option<&str>,
    json: bool,
) -> anyhow::Result<ExitCode> {
    let cfg = load(config)?;
    let rules = Rules::load(cfg.daemon.review_rules.as_deref())?;
    let threshold = match threshold {
        Some(t) => Severity::parse(t)
            .ok_or_else(|| anyhow::anyhow!("--threshold must be low, medium, high or critical"))?,
        None => rules.threshold,
    };
    let now = now_ms();
    let since = match since {
        Some(s) => Some(parse_since(s, now).map_err(|m| anyhow::anyhow!("--since: {m}"))?),
        None => None,
    };
    let path = cfg.daemon.audit_log;
    let chain_break = match verify_file(&path) {
        Ok(_) => None,
        Err(VerifyError::Chain(c)) => Some(c),
        Err(VerifyError::Io(e)) => {
            eprintln!("{}: {e}", path.display());
            return Ok(ExitCode::from(2));
        }
    };
    let entries = match read_entries(&path) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("{}: {e}", path.display());
            return Ok(ExitCode::from(2));
        }
    };
    let findings = run_rules(&entries, chain_break.as_ref(), &rules, since);
    let report = Report::new(findings, threshold);
    eprintln!(
        "ovenmitt audit review: {} entries, {} finding(s) since {}, threshold {}",
        entries.len(),
        report.findings.len(),
        describe_since(since),
        threshold
    );
    for f in &report.findings {
        eprintln!("{f}");
    }
    if json {
        println!("{}", serde_json::to_string(&report)?);
    }
    Ok(ExitCode::from(report.exit))
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
