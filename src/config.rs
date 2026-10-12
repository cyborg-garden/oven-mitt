//! Operator configuration (PRD §5.1, R-DEP-6).
//!
//! The config file is the operator's authority: it lives only in the daemon
//! container and nothing on the socket can read or change it. Validation is
//! fail-closed — the daemon refuses to start on anything it doesn't understand,
//! and `ovenmitt config check` runs exactly the same code.
//!
//! Every error carries a line number where one is known, because an operator
//! fixing a 200-line file at 3am deserves one.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;
use toml::Spanned;

use crate::pattern::Pattern;

/// Name grammar for vaults and destinations: `^[a-z0-9][a-z0-9_-]{0,63}$`.
pub fn valid_name(s: &str) -> bool {
    let mut chars = s.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first.is_ascii_lowercase() || first.is_ascii_digit()) {
        return false;
    }
    if s.len() > 64 {
        return false;
    }
    chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
}

/// Parse `<int><s|m|h|d>` into a duration.
pub fn parse_duration(s: &str) -> Result<Duration, String> {
    let (num, unit) = split_num_unit(s)?;
    let mult: u64 = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86_400,
        other => return Err(format!("unknown duration unit {other:?}; use s, m, h or d")),
    };
    num.checked_mul(mult)
        .map(Duration::from_secs)
        .ok_or_else(|| "duration overflows".to_owned())
}

/// Parse `<int><B|KiB|MiB|GiB>` into a byte count.
pub fn parse_size(s: &str) -> Result<u64, String> {
    let (num, unit) = split_num_unit(s)?;
    let mult: u64 = match unit {
        "B" => 1,
        "KiB" => 1 << 10,
        "MiB" => 1 << 20,
        "GiB" => 1 << 30,
        other => {
            return Err(format!(
                "unknown size unit {other:?}; use B, KiB, MiB or GiB"
            ));
        }
    };
    num.checked_mul(mult)
        .ok_or_else(|| "size overflows".to_owned())
}

fn split_num_unit(s: &str) -> Result<(u64, &str), String> {
    let digits_end = s
        .char_indices()
        .find(|(_, c)| !c.is_ascii_digit())
        .map_or(s.len(), |(i, _)| i);
    if digits_end == 0 {
        return Err(format!("{s:?} must start with a number"));
    }
    let num: u64 = s[..digits_end]
        .parse()
        .map_err(|_| format!("{s:?} has a number too large to parse"))?;
    let unit = &s[digits_end..];
    if unit.is_empty() {
        return Err(format!("{s:?} is missing a unit"));
    }
    Ok((num, unit))
}

// ---------------------------------------------------------------------------
// Raw (deserialised) shapes. Spanned on every field we validate semantically,
// so the error can say which line.
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    #[serde(default)]
    daemon: RawDaemon,
    #[serde(default)]
    vault: BTreeMap<String, Spanned<RawVault>>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDaemon {
    socket: Option<Spanned<String>>,
    socket_mode: Option<Spanned<String>>,
    socket_group: Option<String>,
    data_dir: Option<Spanned<String>>,
    keys_dir: Option<Spanned<String>>,
    audit_log: Option<Spanned<String>>,
    credentials: Option<Spanned<String>>,
    review_rules: Option<Spanned<String>>,
    ttl_sweep_interval: Option<Spanned<String>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawVault {
    #[serde(default)]
    expose_names: bool,
    ttl: Option<Spanned<String>>,
    max_object_size: Option<Spanned<String>>,
    #[serde(default)]
    destinations: BTreeMap<String, Spanned<RawDestination>>,
}

/// A destination table as written. `kind` decides which other keys are
/// allowed; that check is done by hand because serde's internally tagged
/// enums can't carry `Spanned` fields, and we want line numbers.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDestination {
    kind: Spanned<String>,
    root: Option<Spanned<String>>,
    overwrite: Option<Spanned<bool>>,
    #[serde(rename = "match")]
    match_: Option<Spanned<String>>,
    max_size: Option<Spanned<String>>,
}

// ---------------------------------------------------------------------------
// Validated shapes. These are what the rest of the daemon sees.
// ---------------------------------------------------------------------------

/// `[daemon]` section with defaults applied.
#[derive(Debug, Clone)]
pub struct DaemonConfig {
    pub socket: PathBuf,
    pub socket_mode: u32,
    pub socket_group: Option<String>,
    pub data_dir: PathBuf,
    pub keys_dir: PathBuf,
    pub audit_log: PathBuf,
    pub credentials: PathBuf,
    pub review_rules: Option<PathBuf>,
    pub ttl_sweep_interval: Duration,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            socket: PathBuf::from("/run/ovenmitt/ovenmitt.sock"),
            socket_mode: 0o666,
            socket_group: None,
            data_dir: PathBuf::from("/var/lib/ovenmitt/data"),
            keys_dir: PathBuf::from("/var/lib/ovenmitt/keys"),
            audit_log: PathBuf::from("/var/lib/ovenmitt/audit/audit.jsonl"),
            credentials: PathBuf::from("/var/lib/ovenmitt/credentials.toml"),
            review_rules: None,
            ttl_sweep_interval: Duration::from_mins(5),
        }
    }
}

/// A declared destination (PRD R-DST-2, R-DST-3).
#[derive(Debug, Clone)]
pub enum Destination {
    Fs {
        root: PathBuf,
        overwrite: bool,
    },
    Send {
        pattern: Pattern,
        max_size: Option<u64>,
    },
}

impl Destination {
    /// `"fs"` or `"send"`, as shown to the agent by `list_destinations`.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Fs { .. } => "fs",
            Self::Send { .. } => "send",
        }
    }
}

/// A declared vault (PRD R-VLT-3).
#[derive(Debug, Clone)]
pub struct VaultConfig {
    pub name: String,
    pub expose_names: bool,
    pub ttl: Option<Duration>,
    pub max_object_size: Option<u64>,
    pub destinations: BTreeMap<String, Destination>,
}

/// The whole validated configuration.
#[derive(Debug, Clone)]
pub struct Config {
    pub daemon: DaemonConfig,
    pub vaults: BTreeMap<String, VaultConfig>,
}

/// A configuration error, with the line it was found on when known.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError {
    pub line: Option<usize>,
    pub message: String,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.line {
            Some(line) => write!(f, "line {line}: {}", self.message),
            None => f.write_str(&self.message),
        }
    }
}

impl std::error::Error for ConfigError {}

/// Whether to check that paths exist on the filesystem. `config check` and the
/// daemon use `Yes`; unit tests that only exercise the grammar use `No`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsChecks {
    Yes,
    No,
}

struct Lines<'a> {
    src: &'a str,
}

impl Lines<'_> {
    fn of(&self, byte_offset: usize) -> usize {
        self.src[..byte_offset.min(self.src.len())]
            .bytes()
            .filter(|b| *b == b'\n')
            .count()
            + 1
    }
    fn at<T>(&self, s: &Spanned<T>) -> usize {
        self.of(s.span().start)
    }
}

impl Config {
    /// Read and validate a config file.
    pub fn load(path: &Path, fs: FsChecks) -> Result<Self, ConfigError> {
        let src = std::fs::read_to_string(path).map_err(|e| ConfigError {
            line: None,
            message: format!("cannot read {}: {e}", path.display()),
        })?;
        Self::parse(&src, fs)
    }

    /// Validate config text.
    pub fn parse(src: &str, fs: FsChecks) -> Result<Self, ConfigError> {
        let lines = Lines { src };
        let raw: RawConfig = toml::from_str(src).map_err(|e| ConfigError {
            line: e.span().map(|s| lines.of(s.start)),
            message: e.message().to_owned(),
        })?;

        let daemon = validate_daemon(raw.daemon, &lines, fs)?;

        let mut vaults = BTreeMap::new();
        for (name, raw_vault) in raw.vault {
            let vline = Some(lines.at(&raw_vault));
            if !valid_name(&name) {
                return Err(ConfigError {
                    line: vline,
                    message: format!(
                        "vault name {name:?} is invalid; use ^[a-z0-9][a-z0-9_-]{{0,63}}$"
                    ),
                });
            }
            let raw_vault = raw_vault.into_inner();

            let ttl = match &raw_vault.ttl {
                Some(s) => Some(parse_duration(s.get_ref()).map_err(|m| ConfigError {
                    line: Some(lines.at(s)),
                    message: format!("vault {name:?}: ttl: {m}"),
                })?),
                None => None,
            };
            let max_object_size = match &raw_vault.max_object_size {
                Some(s) => Some(parse_size(s.get_ref()).map_err(|m| ConfigError {
                    line: Some(lines.at(s)),
                    message: format!("vault {name:?}: max_object_size: {m}"),
                })?),
                None => None,
            };

            let mut destinations = BTreeMap::new();
            for (dname, raw_dest) in raw_vault.destinations {
                let dline = Some(lines.at(&raw_dest));
                if !valid_name(&dname) {
                    return Err(ConfigError {
                        line: dline,
                        message: format!(
                            "vault {name:?}: destination name {dname:?} is invalid; use ^[a-z0-9][a-z0-9_-]{{0,63}}$"
                        ),
                    });
                }
                let dest = validate_destination(&name, &dname, raw_dest.get_ref(), &lines, fs)?;
                destinations.insert(dname, dest);
            }

            vaults.insert(
                name.clone(),
                VaultConfig {
                    name,
                    expose_names: raw_vault.expose_names,
                    ttl,
                    max_object_size,
                    destinations,
                },
            );
        }

        Ok(Self { daemon, vaults })
    }

    /// Total number of destinations across all vaults (for `config check` output).
    pub fn destination_count(&self) -> usize {
        self.vaults.values().map(|v| v.destinations.len()).sum()
    }
}

fn validate_destination(
    vault: &str,
    dname: &str,
    raw: &RawDestination,
    lines: &Lines<'_>,
    fs: FsChecks,
) -> Result<Destination, ConfigError> {
    let ctx = || format!("vault {vault:?}: destination {dname:?}");
    let not_allowed = |key: &str, line: usize, kind: &str| ConfigError {
        line: Some(line),
        message: format!("{}: `{key}` is not allowed on kind = \"{kind}\"", ctx()),
    };
    let missing = |key: &str, kind: &str| ConfigError {
        line: Some(lines.at(&raw.kind)),
        message: format!("{}: kind = \"{kind}\" requires `{key}`", ctx()),
    };
    match raw.kind.get_ref().as_str() {
        "fs" => {
            if let Some(m) = &raw.match_ {
                return Err(not_allowed("match", lines.at(m), "fs"));
            }
            if let Some(m) = &raw.max_size {
                return Err(not_allowed("max_size", lines.at(m), "fs"));
            }
            let Some(root) = &raw.root else {
                return Err(missing("root", "fs"));
            };
            let root_path = absolute_path(root, lines, || format!("{}: root", ctx()))?;
            if fs == FsChecks::Yes && !root_path.is_dir() {
                return Err(ConfigError {
                    line: Some(lines.at(root)),
                    message: format!("{}: root does not exist or is not a directory", ctx()),
                });
            }
            Ok(Destination::Fs {
                root: root_path,
                overwrite: raw.overwrite.as_ref().is_some_and(|o| *o.get_ref()),
            })
        }
        "send" => {
            if let Some(r) = &raw.root {
                return Err(not_allowed("root", lines.at(r), "send"));
            }
            if let Some(o) = &raw.overwrite {
                return Err(not_allowed("overwrite", lines.at(o), "send"));
            }
            let Some(m) = &raw.match_ else {
                return Err(missing("match", "send"));
            };
            let pattern = Pattern::parse(m.get_ref()).map_err(|e| ConfigError {
                line: Some(lines.at(m)),
                message: format!("{}: match: {e}", ctx()),
            })?;
            let max_size = match &raw.max_size {
                Some(sz) => Some(parse_size(sz.get_ref()).map_err(|msg| ConfigError {
                    line: Some(lines.at(sz)),
                    message: format!("{}: max_size: {msg}", ctx()),
                })?),
                None => None,
            };
            Ok(Destination::Send { pattern, max_size })
        }
        other => Err(ConfigError {
            line: Some(lines.at(&raw.kind)),
            message: format!("{}: unknown kind {other:?}; use \"fs\" or \"send\"", ctx()),
        }),
    }
}

fn absolute_path(
    s: &Spanned<String>,
    lines: &Lines<'_>,
    what: impl FnOnce() -> String,
) -> Result<PathBuf, ConfigError> {
    let p = PathBuf::from(s.get_ref());
    if !p.is_absolute() {
        return Err(ConfigError {
            line: Some(lines.at(s)),
            message: format!("{}: path must be absolute", what()),
        });
    }
    Ok(p)
}

fn validate_daemon(
    raw: RawDaemon,
    lines: &Lines<'_>,
    fs: FsChecks,
) -> Result<DaemonConfig, ConfigError> {
    let mut d = DaemonConfig::default();
    if let Some(s) = &raw.socket {
        d.socket = absolute_path(s, lines, || "daemon.socket".to_owned())?;
    }
    if let Some(s) = &raw.socket_mode {
        d.socket_mode = u32::from_str_radix(s.get_ref(), 8)
            .ok()
            .filter(|m| *m <= 0o777)
            .ok_or_else(|| ConfigError {
                line: Some(lines.at(s)),
                message: format!(
                    "daemon.socket_mode: {:?} is not an octal mode like \"0666\"",
                    s.get_ref()
                ),
            })?;
    }
    d.socket_group = raw.socket_group.filter(|g| !g.is_empty());
    if let Some(s) = &raw.data_dir {
        d.data_dir = absolute_path(s, lines, || "daemon.data_dir".to_owned())?;
    }
    if let Some(s) = &raw.keys_dir {
        d.keys_dir = absolute_path(s, lines, || "daemon.keys_dir".to_owned())?;
    }
    if let Some(s) = &raw.audit_log {
        d.audit_log = absolute_path(s, lines, || "daemon.audit_log".to_owned())?;
    }
    if let Some(s) = &raw.credentials {
        d.credentials = absolute_path(s, lines, || "daemon.credentials".to_owned())?;
    }
    if let Some(s) = &raw.review_rules {
        let p = absolute_path(s, lines, || "daemon.review_rules".to_owned())?;
        if fs == FsChecks::Yes && !p.is_file() {
            return Err(ConfigError {
                line: Some(lines.at(s)),
                message: "daemon.review_rules: file does not exist".to_owned(),
            });
        }
        d.review_rules = Some(p);
    }
    if let Some(s) = &raw.ttl_sweep_interval {
        d.ttl_sweep_interval = parse_duration(s.get_ref()).map_err(|m| ConfigError {
            line: Some(lines.at(s)),
            message: format!("daemon.ttl_sweep_interval: {m}"),
        })?;
        if d.ttl_sweep_interval.is_zero() {
            return Err(ConfigError {
                line: Some(lines.at(s)),
                message: "daemon.ttl_sweep_interval: must be greater than zero".to_owned(),
            });
        }
    }
    Ok(d)
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = r#"
[daemon]
socket = "/run/ovenmitt/ovenmitt.sock"
socket_mode = "0660"
ttl_sweep_interval = "1m"

[vault.private]
expose_names = false
ttl = "30d"
max_object_size = "2GiB"

[vault.private.destinations.nas-archive]
kind = "fs"
root = "/srv/nas/archive"
overwrite = true

[vault.private.destinations.team-chat]
kind = "send"
match = "chat:group/team"

[vault.private.destinations.any-dm]
kind = "send"
match = "chat:dm/*"
max_size = "8MiB"

[vault.media]
"#;

    fn err(src: &str) -> ConfigError {
        match Config::parse(src, FsChecks::No) {
            Ok(_) => panic!("expected an error for:\n{src}"),
            Err(e) => e,
        }
    }

    #[test]
    fn good_config_parses() {
        let c = Config::parse(GOOD, FsChecks::No).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(c.daemon.socket_mode, 0o660);
        assert_eq!(c.daemon.ttl_sweep_interval, Duration::from_mins(1));
        assert_eq!(c.vaults.len(), 2);
        let v = &c.vaults["private"];
        assert_eq!(v.ttl, Some(Duration::from_hours(30 * 24)));
        assert_eq!(v.max_object_size, Some(2 << 30));
        assert_eq!(v.destinations.len(), 3);
        match &v.destinations["nas-archive"] {
            Destination::Fs { root, overwrite } => {
                assert_eq!(root, &PathBuf::from("/srv/nas/archive"));
                assert!(*overwrite);
            }
            other @ Destination::Send { .. } => panic!("wrong kind: {other:?}"),
        }
        match &v.destinations["any-dm"] {
            Destination::Send { pattern, max_size } => {
                assert!(pattern.matches("chat:dm/x"));
                assert_eq!(*max_size, Some(8 << 20));
            }
            other @ Destination::Fs { .. } => panic!("wrong kind: {other:?}"),
        }
        let media = &c.vaults["media"];
        assert!(media.destinations.is_empty());
        assert_eq!(c.destination_count(), 3);
    }

    #[test]
    fn empty_config_is_valid_with_defaults() {
        let c = Config::parse("", FsChecks::No).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            c.daemon.socket,
            PathBuf::from("/run/ovenmitt/ovenmitt.sock")
        );
        assert_eq!(c.daemon.socket_mode, 0o666);
        assert!(c.vaults.is_empty());
    }

    // AT-18: each invalid case refuses with a line number.
    #[test]
    fn unknown_key_in_daemon_has_line() {
        let e = err("[daemon]\nsocket = \"/a\"\nlisten_tcp = \"0.0.0.0:80\"\n");
        assert_eq!(e.line, Some(3), "{e}");
        assert!(e.message.contains("listen_tcp"), "{e}");
    }

    #[test]
    fn unknown_key_in_vault_has_line() {
        let e = err("[vault.v]\nexpose_names = true\nbogus = 1\n");
        assert_eq!(e.line, Some(3), "{e}");
    }

    #[test]
    fn unknown_top_level_table_rejected() {
        let e = err("[review]\nthreshold = \"low\"\n");
        assert_eq!(e.line, Some(1), "{e}");
    }

    #[test]
    fn bad_vault_name() {
        let e = err("[vault.Private]\n");
        assert_eq!(e.line, Some(1), "{e}");
        assert!(e.message.contains("vault name"), "{e}");
        let e = err("[vault._x]\n");
        assert!(e.message.contains("vault name"), "{e}");
    }

    #[test]
    fn bad_destination_name() {
        let e =
            err("[vault.v]\n\n[vault.v.destinations.\"Bad Name\"]\nkind = \"fs\"\nroot = \"/x\"\n");
        assert_eq!(e.line, Some(3), "{e}");
        assert!(e.message.contains("destination name"), "{e}");
    }

    #[test]
    fn bad_ttl_grammar() {
        let e = err("[vault.v]\nttl = \"30 days\"\n");
        assert_eq!(e.line, Some(2), "{e}");
        let e = err("[vault.v]\nttl = \"30\"\n");
        assert_eq!(e.line, Some(2), "{e}");
        let e = err("[vault.v]\nttl = \"d\"\n");
        assert_eq!(e.line, Some(2), "{e}");
    }

    #[test]
    fn bad_size_grammar() {
        let e = err("[vault.v]\nmax_object_size = \"2GB\"\n");
        assert_eq!(e.line, Some(2), "{e}");
        let e = err("[vault.v]\nmax_object_size = \"2 GiB\"\n");
        assert_eq!(e.line, Some(2), "{e}");
    }

    #[test]
    fn kind_specific_keys_only() {
        // `match` on an fs destination
        let e = err(
            "[vault.v]\n[vault.v.destinations.d]\nkind = \"fs\"\nroot = \"/x\"\nmatch = \"a\"\n",
        );
        assert!(e.line.is_some(), "{e}");
        // `root` on a send destination
        let e = err(
            "[vault.v]\n[vault.v.destinations.d]\nkind = \"send\"\nmatch = \"a\"\nroot = \"/x\"\n",
        );
        assert!(e.line.is_some(), "{e}");
        // `overwrite` on a send destination
        let e = err(
            "[vault.v]\n[vault.v.destinations.d]\nkind = \"send\"\nmatch = \"a\"\noverwrite = true\n",
        );
        assert!(e.line.is_some(), "{e}");
        // unknown kind
        let e = err("[vault.v]\n[vault.v.destinations.d]\nkind = \"body\"\n");
        assert!(e.line.is_some(), "{e}");
        // missing kind
        let e = err("[vault.v]\n[vault.v.destinations.d]\nroot = \"/x\"\n");
        assert!(e.line.is_some(), "{e}");
    }

    #[test]
    fn missing_required_destination_key() {
        let e = err("[vault.v]\n[vault.v.destinations.d]\nkind = \"fs\"\n");
        assert!(e.line.is_some(), "{e}");
        let e = err("[vault.v]\n[vault.v.destinations.d]\nkind = \"send\"\n");
        assert!(e.line.is_some(), "{e}");
    }

    #[test]
    fn bad_match_pattern_has_line() {
        let e =
            err("[vault.v]\n\n[vault.v.destinations.d]\nkind = \"send\"\nmatch = \"chat:*/x\"\n");
        assert_eq!(e.line, Some(5), "{e}");
        assert!(e.message.contains("match"), "{e}");
    }

    #[test]
    fn relative_paths_rejected() {
        let e = err("[vault.v]\n[vault.v.destinations.d]\nkind = \"fs\"\nroot = \"srv/x\"\n");
        assert_eq!(e.line, Some(4), "{e}");
        let e = err("[daemon]\ndata_dir = \"data\"\n");
        assert_eq!(e.line, Some(2), "{e}");
    }

    #[test]
    fn duplicate_names_rejected_by_toml() {
        let e = err("[vault.v]\n[vault.v]\n");
        assert_eq!(e.line, Some(2), "{e}");
        let e = err(
            "[vault.v]\n[vault.v.destinations.d]\nkind = \"fs\"\nroot = \"/x\"\n[vault.v.destinations.d]\nkind = \"fs\"\nroot = \"/y\"\n",
        );
        assert_eq!(e.line, Some(5), "{e}");
    }

    #[test]
    fn socket_mode_must_be_octal() {
        let e = err("[daemon]\nsocket_mode = \"rw-rw-rw-\"\n");
        assert_eq!(e.line, Some(2), "{e}");
        let e = err("[daemon]\nsocket_mode = \"0999\"\n");
        assert_eq!(e.line, Some(2), "{e}");
        let e = err("[daemon]\nsocket_mode = 438\n");
        assert_eq!(e.line, Some(2), "{e}");
    }

    #[test]
    fn sweep_interval_must_be_positive() {
        let e = err("[daemon]\nttl_sweep_interval = \"0s\"\n");
        assert_eq!(e.line, Some(2), "{e}");
    }

    #[test]
    fn fs_checks_require_root_dir_to_exist() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let good = format!(
            "[vault.v]\n[vault.v.destinations.d]\nkind = \"fs\"\nroot = \"{}\"\n",
            dir.path().display()
        );
        Config::parse(&good, FsChecks::Yes).unwrap_or_else(|e| panic!("{e}"));
        let missing = format!(
            "[vault.v]\n[vault.v.destinations.d]\nkind = \"fs\"\nroot = \"{}/nope\"\n",
            dir.path().display()
        );
        let Err(e) = Config::parse(&missing, FsChecks::Yes) else {
            panic!("missing root should fail")
        };
        assert_eq!(e.line, Some(4), "{e}");
    }

    #[test]
    fn grammar_helpers() {
        assert_eq!(parse_duration("90s"), Ok(Duration::from_secs(90)));
        assert_eq!(parse_duration("2h"), Ok(Duration::from_hours(2)));
        assert!(parse_duration("1w").is_err());
        assert!(parse_duration("-1s").is_err());
        assert_eq!(parse_size("8KiB"), Ok(8192));
        assert_eq!(parse_size("1B"), Ok(1));
        assert!(parse_size("1kb").is_err());
        assert!(valid_name("a"));
        assert!(valid_name("nas-archive_2"));
        assert!(!valid_name(""));
        assert!(!valid_name("-a"));
        assert!(!valid_name("A"));
        assert!(!valid_name(&"a".repeat(65)));
        assert!(valid_name(&"a".repeat(64)));
    }
}
