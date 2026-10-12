//! `ovenmitt` — one binary. `ovenmitt daemon` serves the socket; everything
//! else is the operator CLI, run inside the daemon container with
//! `docker exec`. The two share every module so they can never disagree
//! about the config, the keys, the audit log or the credentials file.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use ovenmitt::cli;

const DEFAULT_CONFIG: &str = "/etc/ovenmitt/ovenmitt.toml";

#[derive(Debug, Parser)]
#[command(
    name = "ovenmitt",
    version,
    about = "Handle the hot thing without touching it.",
    long_about = "A write-only vault daemon: agents put data in and get an opaque \
                  handle back; nothing on the socket can read it without a credential."
)]
struct Cli {
    /// Path to the operator config file.
    #[arg(long, global = true, default_value = DEFAULT_CONFIG, value_name = "PATH")]
    config: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the daemon (serve the Unix socket).
    Daemon,
    /// Audit log: verify the chain, review for risky activity, print the head hash.
    Audit {
        #[command(subcommand)]
        command: AuditCommand,
    },
    /// Consumer credentials: issue, list, revoke.
    Credential {
        #[command(subcommand)]
        command: CredentialCommand,
    },
    /// Vaults: list.
    Vault {
        #[command(subcommand)]
        command: VaultCommand,
    },
    /// Objects: operator view of one object (shows the stored name).
    Object {
        #[command(subcommand)]
        command: ObjectCommand,
    },
    /// Configuration: validate without starting the daemon.
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
}

#[derive(Debug, Subcommand)]
enum AuditCommand {
    /// Walk the hash chain; exit 0 if intact, 1 naming the first bad entry, 2 on I/O error.
    Verify,
    /// Rule-based review; findings to stderr; exit 1 at or above the threshold.
    Review {
        /// Only report findings after this duration ago (e.g. 24h) or RFC 3339 timestamp.
        #[arg(long, value_name = "DUR|TS")]
        since: Option<String>,
        /// Severity at or above which the exit code is 1.
        #[arg(long, value_name = "low|medium|high|critical")]
        threshold: Option<String>,
        /// Also emit findings as JSON on stdout.
        #[arg(long)]
        json: bool,
    },
    /// Print the current head hash for off-host anchoring.
    Head,
}

#[derive(Debug, Subcommand)]
enum CredentialCommand {
    /// Issue a new consumer credential; the token is printed once.
    Issue {
        #[arg(long)]
        name: String,
        /// Vault(s) this credential may resolve from. Omit for all vaults.
        #[arg(long = "vault", value_name = "NAME")]
        vaults: Vec<String>,
    },
    /// List credentials (ids, names, scopes; never secrets).
    List,
    /// Revoke a credential by id; takes effect on the next request.
    Revoke { id: String },
}

#[derive(Debug, Subcommand)]
enum VaultCommand {
    /// List vaults with their settings and destination names.
    List,
}

#[derive(Debug, Subcommand)]
enum ObjectCommand {
    /// Show one object's metadata, including its stored name.
    Stat { handle: String },
}

#[derive(Debug, Subcommand)]
enum ConfigCommand {
    /// Validate the config file exactly as the daemon would at startup.
    Check {
        /// Config file to check (defaults to --config).
        path: Option<PathBuf>,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Config {
            command: ConfigCommand::Check { path },
        } => cli::config::check(&path.unwrap_or(cli.config)),
        Command::Daemon => not_yet("daemon", "M4"),
        Command::Audit { .. } => not_yet("audit", "M3/M6"),
        Command::Credential { .. } => not_yet("credential", "M5"),
        Command::Vault { .. } => not_yet("vault", "M6"),
        Command::Object { .. } => not_yet("object", "M6"),
    };
    match result {
        Ok(code) => code,
        Err(e) => {
            eprintln!("ovenmitt: {e:#}");
            ExitCode::from(2)
        }
    }
}

fn not_yet(what: &str, milestone: &str) -> anyhow::Result<ExitCode> {
    anyhow::bail!("`{what}` is not implemented yet (arrives in {milestone})")
}
