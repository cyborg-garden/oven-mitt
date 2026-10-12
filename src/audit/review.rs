//! Rule-based review of the audit log (PRD R-REV-1..4, §5.3, §6.3).
//!
//! Offline, reads the whole log (history is needed for "first time"), and
//! reports findings in the `--since` window ranked by severity. Findings go
//! to stderr so cron mail carries them; `--json` adds a machine shape on
//! stdout. Exit 1 at or above the threshold is what makes it a monitor.

use std::collections::{BTreeSet, HashMap};
use std::fmt;
use std::path::Path;

use serde::{Deserialize, Serialize};

use super::verify::ChainBreak;
use super::{Entry, Event, Outcome};
use crate::config::parse_duration;
use crate::time::{Millis, parse_rfc3339, to_rfc3339};

/// `low < medium < high < critical`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "low" => Some(Self::Low),
            "medium" => Some(Self::Medium),
            "high" => Some(Self::High),
            "critical" => Some(Self::Critical),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SimpleRule {
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub severity: Severity,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BurstRule {
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub severity: Severity,
    pub events: Vec<Event>,
    pub count: usize,
    pub window: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChurnRule {
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub severity: Severity,
    pub count: usize,
    pub window: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRules {
    threshold: Option<Severity>,
    #[serde(default)]
    rules: RawRuleSet,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRuleSet {
    refusal: Option<SimpleRule>,
    first_destination: Option<SimpleRule>,
    burst: Option<BurstRule>,
    churn: Option<ChurnRule>,
    chain: Option<SimpleRule>,
}

/// Validated rules with defaults applied (PRD §5.3).
#[derive(Debug, Clone)]
pub struct Rules {
    pub threshold: Severity,
    pub refusal: SimpleRule,
    pub first_destination: SimpleRule,
    pub burst: BurstRule,
    pub burst_window_ms: Millis,
    pub churn: ChurnRule,
    pub churn_window_ms: Millis,
    pub chain: SimpleRule,
}

impl Default for Rules {
    fn default() -> Self {
        Self {
            threshold: Severity::Medium,
            refusal: SimpleRule {
                enabled: true,
                severity: Severity::High,
            },
            first_destination: SimpleRule {
                enabled: true,
                severity: Severity::Medium,
            },
            burst: BurstRule {
                enabled: true,
                severity: Severity::Medium,
                events: vec![Event::Resolve, Event::Export, Event::Delete],
                count: 20,
                window: "10m".into(),
            },
            burst_window_ms: 10 * 60 * 1000,
            churn: ChurnRule {
                enabled: true,
                severity: Severity::Low,
                count: 10,
                window: "1h".into(),
            },
            churn_window_ms: 60 * 60 * 1000,
            chain: SimpleRule {
                enabled: true,
                severity: Severity::Critical,
            },
        }
    }
}

/// Why a rules file was rejected.
#[derive(Debug, thiserror::Error)]
#[error("review rules: {0}")]
pub struct RulesError(pub String);

impl Rules {
    /// Parse a `review.toml`; missing sections keep their defaults.
    pub fn parse(src: &str) -> Result<Self, RulesError> {
        let raw: RawRules = toml::from_str(src).map_err(|e| RulesError(e.message().to_owned()))?;
        let mut rules = Self::default();
        if let Some(t) = raw.threshold {
            rules.threshold = t;
        }
        if let Some(r) = raw.rules.refusal {
            rules.refusal = r;
        }
        if let Some(r) = raw.rules.first_destination {
            rules.first_destination = r;
        }
        if let Some(r) = raw.rules.burst {
            if r.count == 0 {
                return Err(RulesError("rules.burst.count must be at least 1".into()));
            }
            rules.burst_window_ms = window_ms(&r.window, "rules.burst.window")?;
            rules.burst = r;
        }
        if let Some(r) = raw.rules.churn {
            if r.count == 0 {
                return Err(RulesError("rules.churn.count must be at least 1".into()));
            }
            rules.churn_window_ms = window_ms(&r.window, "rules.churn.window")?;
            rules.churn = r;
        }
        if let Some(r) = raw.rules.chain {
            if r.severity < Severity::High {
                return Err(RulesError(
                    "rules.chain.severity cannot be lowered below \"high\"".into(),
                ));
            }
            rules.chain = r;
        }
        Ok(rules)
    }

    /// Load from a path, or defaults when `None`.
    pub fn load(path: Option<&Path>) -> Result<Self, RulesError> {
        match path {
            None => Ok(Self::default()),
            Some(p) => {
                let src = std::fs::read_to_string(p)
                    .map_err(|e| RulesError(format!("cannot read {}: {e}", p.display())))?;
                Self::parse(&src)
            }
        }
    }
}

fn window_ms(s: &str, what: &str) -> Result<Millis, RulesError> {
    let d = parse_duration(s).map_err(|m| RulesError(format!("{what}: {m}")))?;
    let ms = i64::try_from(d.as_millis()).map_err(|_| RulesError(format!("{what}: too large")))?;
    if ms == 0 {
        return Err(RulesError(format!("{what}: must be greater than zero")));
    }
    Ok(ms)
}

/// One finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    pub severity: Severity,
    pub rule: &'static str,
    pub seq_from: u64,
    pub seq_to: u64,
    pub ts: Option<String>,
    pub summary: String,
}

impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let seq = if self.seq_from == self.seq_to {
            format!("seq={}", self.seq_from)
        } else {
            format!("seq={}..{}", self.seq_from, self.seq_to)
        };
        write!(
            f,
            "{:<8} {:<18} {:<16} {:<24} {}",
            self.severity.as_str().to_ascii_uppercase(),
            self.rule,
            seq,
            self.ts.as_deref().unwrap_or("—"),
            self.summary
        )
    }
}

fn ts_of(e: &Entry) -> Millis {
    parse_rfc3339(&e.ts).unwrap_or(0)
}

/// Parse `--since`: a duration (`24h`) relative to `now`, or an RFC 3339
/// timestamp.
pub fn parse_since(s: &str, now: Millis) -> Result<Millis, String> {
    if let Ok(d) = parse_duration(s) {
        let ms = i64::try_from(d.as_millis()).map_err(|_| "duration too large".to_owned())?;
        return Ok(now.saturating_sub(ms));
    }
    parse_rfc3339(s)
        .map_err(|_| format!("{s:?} is neither a duration like 24h nor an RFC 3339 timestamp"))
}

/// Run every enabled rule. `since` bounds which findings are *reported*;
/// history before it still feeds first-time and window computations.
#[allow(clippy::too_many_lines)]
pub fn review(
    entries: &[Entry],
    chain_break: Option<&ChainBreak>,
    rules: &Rules,
    since: Option<Millis>,
) -> Vec<Finding> {
    let in_window = |e: &Entry| since.is_none_or(|s| ts_of(e) >= s);
    let mut findings = Vec::new();

    if rules.chain.enabled
        && let Some(b) = chain_break
    {
        findings.push(Finding {
            severity: rules.chain.severity,
            rule: "chain",
            seq_from: b.seq,
            seq_to: b.seq,
            ts: None,
            summary: b.kind.to_string(),
        });
    }

    if rules.refusal.enabled {
        for e in entries
            .iter()
            .filter(|e| e.draft.outcome == Outcome::Refused && in_window(e))
        {
            let d = &e.draft;
            let mut parts = vec![d.event.as_str().to_owned()];
            if let Some(h) = &d.handle {
                parts.push(h.to_string());
            }
            if let Some(v) = &d.vault {
                parts.push(format!("vault={v}"));
            }
            if let Some(dest) = &d.dest {
                parts.push(format!("dest={dest}"));
            }
            parts.push(format!("reason={}", d.reason.as_deref().unwrap_or("?")));
            if let Some(c) = &d.caller.cred {
                parts.push(format!("cred={c}"));
            }
            findings.push(Finding {
                severity: rules.refusal.severity,
                rule: "refusal",
                seq_from: e.seq,
                seq_to: e.seq,
                ts: Some(e.ts.clone()),
                summary: parts.join(" "),
            });
        }
    }

    if rules.first_destination.enabled {
        let mut seen: BTreeSet<(String, String)> = BTreeSet::new();
        for e in entries {
            let d = &e.draft;
            if !matches!(d.event, Event::Export | Event::Resolve) || d.outcome != Outcome::Ok {
                continue;
            }
            let (Some(v), Some(dest)) = (&d.vault, &d.dest) else {
                continue;
            };
            if seen.insert((v.clone(), dest.clone())) && in_window(e) {
                findings.push(Finding {
                    severity: rules.first_destination.severity,
                    rule: "first_destination",
                    seq_from: e.seq,
                    seq_to: e.seq,
                    ts: Some(e.ts.clone()),
                    summary: format!("{} {v}/{dest}", d.event.as_str()),
                });
            }
        }
    }

    if rules.burst.enabled {
        for ev in &rules.burst.events {
            let hits: Vec<&Entry> = entries
                .iter()
                .filter(|e| e.draft.event == *ev && e.draft.outcome == Outcome::Ok)
                .collect();
            for (from, to) in bursts(&hits, rules.burst.count, rules.burst_window_ms) {
                let last = hits[to];
                if !in_window(last) {
                    continue;
                }
                findings.push(Finding {
                    severity: rules.burst.severity,
                    rule: "burst",
                    seq_from: hits[from].seq,
                    seq_to: last.seq,
                    ts: Some(hits[from].ts.clone()),
                    summary: format!(
                        "{} {} in {}",
                        to - from + 1,
                        ev.as_str(),
                        rules.burst.window
                    ),
                });
            }
        }
    }

    if rules.churn.enabled {
        let mut per_handle: HashMap<String, Vec<&Entry>> = HashMap::new();
        for e in entries {
            if matches!(e.draft.event, Event::Replace | Event::Label | Event::Delete)
                && e.draft.outcome == Outcome::Ok
                && let Some(h) = &e.draft.handle
            {
                per_handle.entry(h.to_string()).or_default().push(e);
            }
        }
        let mut handles: Vec<_> = per_handle.into_iter().collect();
        handles.sort_by(|a, b| a.0.cmp(&b.0));
        for (handle, hits) in handles {
            for (from, to) in bursts(&hits, rules.churn.count, rules.churn_window_ms) {
                let last = hits[to];
                if !in_window(last) {
                    continue;
                }
                findings.push(Finding {
                    severity: rules.churn.severity,
                    rule: "churn",
                    seq_from: hits[from].seq,
                    seq_to: last.seq,
                    ts: Some(hits[from].ts.clone()),
                    summary: format!(
                        "{} writes to {handle} in {}",
                        to - from + 1,
                        rules.churn.window
                    ),
                });
            }
        }
    }

    findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then(a.seq_from.cmp(&b.seq_from))
    });
    findings
}

/// Maximal runs of at least `count` entries within `window` ms, as index
/// ranges into `hits`. Runs don't overlap: once a burst is found it is
/// extended as far as the window allows, then scanning resumes after it.
fn bursts(hits: &[&Entry], count: usize, window: Millis) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < hits.len() {
        let start = ts_of(hits[i]);
        let mut j = i;
        while j + 1 < hits.len() && ts_of(hits[j + 1]) - start <= window {
            j += 1;
        }
        if j - i + 1 >= count {
            out.push((i, j));
            i = j + 1;
        } else {
            i += 1;
        }
    }
    out
}

/// What `review` returns to the CLI: findings and the exit code.
#[derive(Debug, Serialize)]
pub struct Report {
    pub findings: Vec<Finding>,
    pub threshold: Severity,
    pub exit: u8,
}

impl Report {
    pub fn new(findings: Vec<Finding>, threshold: Severity) -> Self {
        let exit = u8::from(findings.iter().any(|f| f.severity >= threshold));
        Self {
            findings,
            threshold,
            exit,
        }
    }
}

/// A human timestamp for the window start, for the CLI banner.
pub fn describe_since(since: Option<Millis>) -> String {
    since.map_or_else(|| "the beginning".to_owned(), to_rfc3339)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{Caller, Draft};
    use crate::handle::Handle;

    fn entry(seq: u64, ts: Millis, event: Event, outcome: Outcome) -> Entry {
        Entry {
            seq,
            ts: to_rfc3339(ts),
            draft: Draft::new(event, outcome, Caller::daemon()),
            prev: String::new(),
        }
    }

    fn with(mut e: Entry, f: impl FnOnce(&mut Draft)) -> Entry {
        f(&mut e.draft);
        e
    }

    fn h(s: &str) -> Handle {
        Handle::parse(s).unwrap_or_else(|e| panic!("{e}"))
    }

    #[test]
    fn severity_order_and_parse() {
        assert!(Severity::Low < Severity::Medium);
        assert!(Severity::High < Severity::Critical);
        assert_eq!(Severity::parse("HIGH"), Some(Severity::High));
        assert_eq!(Severity::parse("warn"), None);
    }

    #[test]
    fn rules_defaults_and_validation() {
        let r = Rules::parse("").unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(r.threshold, Severity::Medium);
        assert_eq!(r.refusal.severity, Severity::High);
        let r = Rules::parse("threshold = \"low\"\n[rules.burst]\nseverity = \"high\"\nevents = [\"resolve\"]\ncount = 3\nwindow = \"1m\"\n")
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(r.threshold, Severity::Low);
        assert_eq!(r.burst.count, 3);
        assert_eq!(r.burst_window_ms, 60_000);
        assert!(Rules::parse("[rules.chain]\nseverity = \"low\"\n").is_err());
        assert!(
            Rules::parse(
                "[rules.burst]\nseverity = \"low\"\nevents = []\ncount = 0\nwindow = \"1m\"\n"
            )
            .is_err()
        );
        assert!(Rules::parse("[rules.bogus]\nseverity = \"low\"\n").is_err());
        assert!(
            Rules::parse("[rules.churn]\nseverity = \"low\"\ncount = 2\nwindow = \"soon\"\n")
                .is_err()
        );
        let r = Rules::parse("[rules.refusal]\nenabled = false\nseverity = \"high\"\n")
            .unwrap_or_else(|e| panic!("{e}"));
        assert!(!r.refusal.enabled);
    }

    #[test]
    fn refusal_and_chain_findings() {
        let entries = vec![
            entry(1, 0, Event::Start, Outcome::Ok),
            with(entry(2, 1000, Event::Resolve, Outcome::Refused), |d| {
                d.handle = Some(h("v_0123456789ab"));
                d.dest = Some("team-chat".into());
                d.reason = Some("TARGET_NOT_ALLOWED".into());
                d.caller.cred = Some("1a2b3c4d".into());
            }),
        ];
        let b = ChainBreak {
            seq: 2,
            kind: crate::audit::verify::BreakKind::PrevMismatch,
        };
        let f = review(&entries, Some(&b), &Rules::default(), None);
        assert_eq!(f.len(), 2);
        assert_eq!(f[0].rule, "chain");
        assert_eq!(f[0].severity, Severity::Critical);
        assert_eq!(f[1].rule, "refusal");
        assert!(
            f[1].summary.contains(
                "resolve v_0123456789ab dest=team-chat reason=TARGET_NOT_ALLOWED cred=1a2b3c4d"
            ),
            "{}",
            f[1].summary
        );
        let line = f[1].to_string();
        assert!(
            line.starts_with("HIGH     refusal            seq=2"),
            "{line}"
        );
        // since excludes it
        let f = review(&entries, None, &Rules::default(), Some(2000));
        assert!(f.is_empty());
        // chain finding ignores since
        let f = review(&entries, Some(&b), &Rules::default(), Some(2000));
        assert_eq!(f.len(), 1);
        assert_eq!(Report::new(f, Severity::Critical).exit, 1);
    }

    #[test]
    fn first_destination_uses_full_history() {
        let mk = |seq, ts, dest: &str| {
            with(entry(seq, ts, Event::Export, Outcome::Ok), |d| {
                d.vault = Some("private".into());
                d.dest = Some(dest.into());
            })
        };
        let entries = vec![
            mk(1, 0, "a"),
            mk(2, 1000, "a"),
            mk(3, 2000, "b"),
            mk(4, 3000, "a"),
        ];
        let f = review(&entries, None, &Rules::default(), None);
        let fd: Vec<_> = f.iter().filter(|x| x.rule == "first_destination").collect();
        assert_eq!(fd.len(), 2);
        assert_eq!((fd[0].seq_from, fd[1].seq_from), (1, 3));
        // window starting after seq 1: "a" is not new, only "b"
        let f = review(&entries, None, &Rules::default(), Some(500));
        let fd: Vec<_> = f.iter().filter(|x| x.rule == "first_destination").collect();
        assert_eq!(fd.len(), 1);
        assert_eq!(fd[0].seq_from, 3);
    }

    // AT-24: at threshold and one below.
    #[test]
    fn burst_fires_at_count_not_below() {
        let rules = Rules::parse("[rules.burst]\nseverity = \"medium\"\nevents = [\"resolve\"]\ncount = 3\nwindow = \"10s\"\n")
            .unwrap_or_else(|e| panic!("{e}"));
        let two = vec![
            entry(1, 0, Event::Resolve, Outcome::Ok),
            entry(2, 5_000, Event::Resolve, Outcome::Ok),
            entry(3, 30_000, Event::Resolve, Outcome::Ok),
        ];
        assert!(
            review(&two, None, &rules, None)
                .iter()
                .all(|f| f.rule != "burst")
        );
        let three = vec![
            entry(1, 0, Event::Resolve, Outcome::Ok),
            entry(2, 5_000, Event::Resolve, Outcome::Ok),
            entry(3, 10_000, Event::Resolve, Outcome::Ok),
            entry(4, 50_000, Event::Resolve, Outcome::Ok),
            entry(5, 51_000, Event::Export, Outcome::Ok),
            entry(6, 52_000, Event::Export, Outcome::Ok),
            entry(7, 53_000, Event::Export, Outcome::Ok),
        ];
        let f: Vec<_> = review(&three, None, &rules, None)
            .into_iter()
            .filter(|f| f.rule == "burst")
            .collect();
        assert_eq!(f.len(), 1, "exports are not in the configured events");
        assert_eq!((f[0].seq_from, f[0].seq_to), (1, 3));
        assert_eq!(f[0].summary, "3 resolve in 10s");
        // refused entries don't count toward a burst
        let refused: Vec<Entry> = (1..=5)
            .map(|i| entry(i, i.cast_signed() * 100, Event::Resolve, Outcome::Refused))
            .collect();
        assert!(
            review(&refused, None, &rules, None)
                .iter()
                .all(|f| f.rule != "burst")
        );
    }

    #[test]
    fn churn_is_per_handle() {
        let rules = Rules::parse("[rules.churn]\nseverity = \"low\"\ncount = 2\nwindow = \"1m\"\n")
            .unwrap_or_else(|e| panic!("{e}"));
        let a = h("v_aaaaaaaaaaaa");
        let b = h("v_bbbbbbbbbbbb");
        let entries = vec![
            with(entry(1, 0, Event::Label, Outcome::Ok), |d| {
                d.handle = Some(a.clone());
            }),
            with(entry(2, 1000, Event::Replace, Outcome::Ok), |d| {
                d.handle = Some(b.clone());
            }),
            with(entry(3, 2000, Event::Delete, Outcome::Ok), |d| {
                d.handle = Some(a.clone());
            }),
            with(entry(4, 3000, Event::Put, Outcome::Ok), |d| {
                d.handle = Some(b.clone());
            }),
        ];
        let f: Vec<_> = review(&entries, None, &rules, None)
            .into_iter()
            .filter(|f| f.rule == "churn")
            .collect();
        assert_eq!(f.len(), 1);
        assert!(f[0].summary.contains("v_aaaaaaaaaaaa"));
        assert_eq!((f[0].seq_from, f[0].seq_to), (1, 3));
    }

    #[test]
    fn report_exit_and_since_parsing() {
        let f = vec![Finding {
            severity: Severity::Low,
            rule: "churn",
            seq_from: 1,
            seq_to: 1,
            ts: None,
            summary: String::new(),
        }];
        assert_eq!(Report::new(f.clone(), Severity::Medium).exit, 0);
        assert_eq!(Report::new(f, Severity::Low).exit, 1);
        assert_eq!(
            parse_since("24h", 100_000_000),
            Ok(100_000_000 - 86_400_000)
        );
        assert_eq!(
            parse_since("2026-10-12T08:00:00Z", 0),
            Ok(1_791_792_000_000)
        );
        assert!(parse_since("yesterday", 0).is_err());
    }
}
