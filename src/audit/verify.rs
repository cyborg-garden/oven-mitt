//! Chain verification (PRD R-AUD-2, R-AUD-7, §6.2).
//!
//! Walks the file: each line parses, `seq` equals its line number, `prev`
//! equals the hash of the previous line's canonical form, `ts` never goes
//! backwards. Stops at the first violation and names it. Tail truncation is
//! not detectable here — that is what off-host anchoring of the head hash
//! is for, and the docs say so.

use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::path::Path;

use serde_json::Value;

use super::canon::{canonical, entry_hash};
use super::{Entry, GENESIS};
use crate::crypto::sha256_hex;
use crate::time::parse_rfc3339;

/// What kind of break was found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BreakKind {
    /// Line is not valid JSON, or not an object.
    Unparsable,
    /// `seq` does not equal the line number.
    SeqMismatch { found: u64 },
    /// `prev` does not equal the hash of the previous entry.
    PrevMismatch,
    /// Entry cannot be canonicalised (a float crept in).
    NotCanonical,
    /// Line bytes differ from the canonical form (someone reformatted it).
    Reformatted,
    /// Timestamp older than the previous entry's.
    TimeWentBackwards,
    /// Entry has the wrong shape (missing required fields).
    BadShape,
}

impl std::fmt::Display for BreakKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unparsable => f.write_str("line is not a JSON object"),
            Self::SeqMismatch { found } => write!(f, "seq {found} does not match line number"),
            Self::PrevMismatch => f.write_str("prev does not match the previous entry's hash"),
            Self::NotCanonical => f.write_str("entry is not canonicalisable"),
            Self::Reformatted => f.write_str("line bytes are not in canonical form"),
            Self::TimeWentBackwards => f.write_str("timestamp is earlier than the previous entry"),
            Self::BadShape => f.write_str("entry is missing required fields"),
        }
    }
}

/// A broken chain: the first bad entry.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("audit chain broken at seq {seq}: {kind}")]
pub struct ChainBreak {
    pub seq: u64,
    pub kind: BreakKind,
}

/// Verification failure: either the chain is broken or the file can't be read.
#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("{0}")]
    Chain(#[from] ChainBreak),
    #[error("cannot read audit log: {0}")]
    Io(#[from] io::Error),
}

/// Result of a successful walk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainState {
    /// Number of entries (= last `seq`; 0 for an empty log).
    pub entries: u64,
    /// Hash of the last entry, or [`GENESIS`] for an empty log.
    pub head: String,
    /// Timestamp of the last entry, if any.
    pub last_ts: Option<i64>,
}

impl ChainState {
    pub fn empty() -> Self {
        Self {
            entries: 0,
            head: GENESIS.to_owned(),
            last_ts: None,
        }
    }
}

/// Walk one line. Returns the entry's hash on success.
fn check_line(
    line: &[u8],
    expected_seq: u64,
    expected_prev: &str,
    last_ts: Option<i64>,
) -> Result<(String, i64), BreakKind> {
    let value: Value = serde_json::from_slice(line).map_err(|_| BreakKind::Unparsable)?;
    if !value.is_object() {
        return Err(BreakKind::Unparsable);
    }
    let canon = canonical(&value).map_err(|_| BreakKind::NotCanonical)?;
    if canon != line {
        return Err(BreakKind::Reformatted);
    }
    let seq = value
        .get("seq")
        .and_then(Value::as_u64)
        .ok_or(BreakKind::BadShape)?;
    if seq != expected_seq {
        return Err(BreakKind::SeqMismatch { found: seq });
    }
    let prev = value
        .get("prev")
        .and_then(Value::as_str)
        .ok_or(BreakKind::BadShape)?;
    if prev != expected_prev {
        return Err(BreakKind::PrevMismatch);
    }
    let ts = value
        .get("ts")
        .and_then(Value::as_str)
        .and_then(|s| parse_rfc3339(s).ok())
        .ok_or(BreakKind::BadShape)?;
    if last_ts.is_some_and(|t| ts < t) {
        return Err(BreakKind::TimeWentBackwards);
    }
    // Shape check: it must deserialise as an Entry.
    serde_json::from_value::<Entry>(value).map_err(|_| BreakKind::BadShape)?;
    Ok((sha256_hex(&canon), ts))
}

/// Walk a log file. An absent file is an empty, valid chain.
pub fn verify_file(path: &Path) -> Result<ChainState, VerifyError> {
    let file = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(ChainState::empty()),
        Err(e) => return Err(e.into()),
    };
    verify_reader(BufReader::new(file))
}

/// Walk a log from any reader.
pub fn verify_reader<R: BufRead>(mut reader: R) -> Result<ChainState, VerifyError> {
    let mut state = ChainState::empty();
    let mut line = Vec::new();
    loop {
        line.clear();
        let n = reader.read_until(b'\n', &mut line)?;
        if n == 0 {
            break;
        }
        let seq = state.entries + 1;
        let body = line.strip_suffix(b"\n").unwrap_or(&line);
        if body.is_empty() {
            // a trailing newline with nothing after it is fine; an empty
            // line in the middle is not
            return Err(ChainBreak {
                seq,
                kind: BreakKind::Unparsable,
            }
            .into());
        }
        let (hash, ts) = check_line(body, seq, &state.head, state.last_ts)
            .map_err(|kind| ChainBreak { seq, kind })?;
        state.entries = seq;
        state.head = hash;
        state.last_ts = Some(ts);
    }
    Ok(state)
}

/// Parse every entry of a verified log (for `review`). Caller runs
/// [`verify_file`] first; this just deserialises.
pub fn read_entries(path: &Path) -> Result<Vec<Entry>, io::Error> {
    let file = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let mut out = Vec::new();
    for line in BufReader::new(file).lines() {
        let line = line?;
        if line.is_empty() {
            continue;
        }
        match serde_json::from_str::<Entry>(&line) {
            Ok(e) => out.push(e),
            Err(_) => break, // review runs over the parseable prefix (R-REV-4)
        }
    }
    Ok(out)
}

/// Hash of an entry value, exposed for the writer.
pub fn hash_of(value: &Value) -> Option<String> {
    entry_hash(value).ok()
}
