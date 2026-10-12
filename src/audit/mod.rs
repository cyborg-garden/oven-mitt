//! The audit trail (PRD §6). Append-only, hash-chained JSONL; the single
//! thing that lets an operator be confident about what did and didn't
//! happen to the data.
//!
//! - `canon`: canonical JSON and the entry hash.
//! - `writer`: the one task that appends, with fsync-before-ack.
//! - `verify`: the chain walk used at startup, by `audit verify`, and by
//!   `audit review`.
//! - `review`: rule-based findings (M6).

pub mod canon;
pub mod verify;
pub mod writer;

use serde::{Deserialize, Serialize};

use crate::handle::Handle;

/// What happened (PRD R-AUD-3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Event {
    Start,
    Put,
    Replace,
    Delete,
    Export,
    Resolve,
    Expire,
    Label,
    /// A request that could not be mapped to an operation (unknown route,
    /// bad protocol header, malformed request).
    Request,
}

impl Event {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Start => "start",
            Self::Put => "put",
            Self::Replace => "replace",
            Self::Delete => "delete",
            Self::Export => "export",
            Self::Resolve => "resolve",
            Self::Expire => "expire",
            Self::Label => "label",
            Self::Request => "request",
        }
    }
}

/// How it ended (PRD R-AUD-4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Ok,
    Refused,
    Aborted,
}

/// Who asked. `uid`/`pid` are `SO_PEERCRED`, informational only (F-6);
/// `cred` is the credential id when one was presented and parsed; `daemon`
/// marks entries the daemon originated itself (start, expire).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Caller {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cred: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub daemon: Option<bool>,
}

impl Caller {
    /// The daemon acting on its own (startup, TTL sweep).
    pub fn daemon() -> Self {
        Self {
            daemon: Some(true),
            ..Self::default()
        }
    }

    /// A socket peer without a credential: the agent trust domain.
    pub fn peer(uid: Option<u32>, pid: Option<u32>) -> Self {
        Self {
            uid,
            pid,
            ..Self::default()
        }
    }
}

/// What a handler knows about an operation; the writer adds `seq`, `ts`
/// and `prev` (PRD §6.1 field table).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Draft {
    pub event: Event,
    pub outcome: Outcome,
    pub caller: Caller,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vault: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handle: Option<Handle>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remove_source_requested: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_sha256: Option<String>,
}

impl Draft {
    /// A draft with only the three required fields set.
    pub fn new(event: Event, outcome: Outcome, caller: Caller) -> Self {
        Self {
            event,
            outcome,
            caller,
            vault: None,
            handle: None,
            sha256: None,
            size: None,
            dest: None,
            target: None,
            reason: None,
            name: None,
            remove_source_requested: None,
            config_sha256: None,
        }
    }
}

/// A full entry as it appears on one line of the log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub seq: u64,
    pub ts: String,
    #[serde(flatten)]
    pub draft: Draft,
    pub prev: String,
}

/// `prev` of the first entry.
pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";
