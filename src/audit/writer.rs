//! The audit writer (PRD R-AUD-1, R-AUD-2, R-AUD-6; DEVELOPMENT.md §6).
//!
//! One thread owns the file and the chain state. Handlers send a `Draft`
//! and wait for the acknowledgement, which arrives only after the line is
//! appended and fsynced — so a refusal can't be unlogged by killing the
//! connection, and no response ever claims something the log doesn't.
//!
//! Opening the log verifies the whole chain first (D-1): a broken chain
//! refuses startup rather than appending to a log that can no longer be
//! trusted.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread;

use serde_json::Value;
use tokio::sync::{mpsc, oneshot};

use super::canon::canonical;
use super::verify::{ChainBreak, ChainState, verify_file};
use super::{Draft, Entry};
use crate::crypto::sha256_hex;
use crate::time::{now_ms, to_rfc3339};

/// Why an append or open failed.
#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error("{0}")]
    Chain(#[from] ChainBreak),
    #[error("audit log i/o: {0}")]
    Io(#[from] io::Error),
    #[error("audit entry cannot be canonicalised: {0}")]
    Canon(#[from] super::canon::CanonError),
    #[error("audit writer has stopped")]
    Closed,
}

type Ack = oneshot::Sender<Result<u64, AuditError>>;

/// Handle to the writer. Cheap to clone; all clones feed one thread.
#[derive(Debug, Clone)]
pub struct AuditLog {
    tx: mpsc::UnboundedSender<(Draft, Ack)>,
    state: Arc<Mutex<ChainState>>,
    path: PathBuf,
}

impl AuditLog {
    /// Verify the existing chain, open the file for append, start the
    /// writer thread. Returns the chain state found on disk.
    pub fn open(path: &Path) -> Result<(Self, ChainState), AuditError> {
        let initial = verify_file(path).map_err(|e| match e {
            super::verify::VerifyError::Chain(c) => AuditError::Chain(c),
            super::verify::VerifyError::Io(i) => AuditError::Io(i),
        })?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new().append(true).create(true).open(path)?;
        let state = Arc::new(Mutex::new(initial.clone()));
        let (tx, rx) = mpsc::unbounded_channel::<(Draft, Ack)>();
        let thread_state = Arc::clone(&state);
        thread::Builder::new()
            .name("ovenmitt-audit".into())
            .spawn(move || writer_loop(file, rx, &thread_state))?;
        Ok((
            Self {
                tx,
                state,
                path: path.to_owned(),
            },
            initial,
        ))
    }

    /// Append an entry; resolves once it is durable. Returns its `seq`.
    pub async fn append(&self, draft: Draft) -> Result<u64, AuditError> {
        let (ack_tx, ack_rx) = oneshot::channel();
        self.tx
            .send((draft, ack_tx))
            .map_err(|_| AuditError::Closed)?;
        ack_rx.await.map_err(|_| AuditError::Closed)?
    }

    /// Blocking variant for startup and the operator CLI.
    pub fn append_blocking(&self, draft: Draft) -> Result<u64, AuditError> {
        let (ack_tx, ack_rx) = oneshot::channel();
        self.tx
            .send((draft, ack_tx))
            .map_err(|_| AuditError::Closed)?;
        ack_rx.blocking_recv().map_err(|_| AuditError::Closed)?
    }

    /// Current chain state (after the last acknowledged append).
    pub fn state(&self) -> ChainState {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Path of the log file.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Build the line for the next entry. Pure, so it can be tested.
pub fn build_line(
    draft: Draft,
    state: &ChainState,
    now: i64,
) -> Result<(Vec<u8>, String, i64), AuditError> {
    // Timestamps must never go backwards within the log (verify checks it);
    // a clock step backwards is clamped to the previous entry's time.
    let ts = state.last_ts.map_or(now, |last| now.max(last));
    let entry = Entry {
        seq: state.entries + 1,
        ts: to_rfc3339(ts),
        draft,
        prev: state.head.clone(),
    };
    let value: Value = serde_json::to_value(&entry).map_err(io::Error::other)?;
    let canon = canonical(&value)?;
    let hash = sha256_hex(&canon);
    let mut line = canon;
    line.push(b'\n');
    Ok((line, hash, ts))
}

fn writer_loop(
    mut file: File,
    mut rx: mpsc::UnboundedReceiver<(Draft, Ack)>,
    state: &Mutex<ChainState>,
) {
    let mut failed: Option<String> = None;
    while let Some((draft, ack)) = rx.blocking_recv() {
        if let Some(msg) = &failed {
            // Once a write has failed we can't know what's on disk; refuse
            // everything so the daemon stops answering rather than running
            // with an unaccounted-for log.
            let _ = ack.send(Err(AuditError::Io(io::Error::other(msg.clone()))));
            continue;
        }
        let current = state.lock().unwrap_or_else(PoisonError::into_inner).clone();
        let result = build_line(draft, &current, now_ms()).and_then(|(line, hash, ts)| {
            file.write_all(&line)?;
            file.sync_data()?;
            Ok((hash, ts))
        });
        match result {
            Ok((hash, ts)) => {
                let mut s = state.lock().unwrap_or_else(PoisonError::into_inner);
                s.entries += 1;
                s.head = hash;
                s.last_ts = Some(ts);
                let seq = s.entries;
                drop(s);
                let _ = ack.send(Ok(seq));
            }
            Err(e) => {
                failed = Some(e.to_string());
                let _ = ack.send(Err(e));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::{Caller, Event, Outcome, verify::BreakKind};
    use super::*;

    fn draft(event: Event) -> Draft {
        Draft::new(event, Outcome::Ok, Caller::daemon())
    }

    #[test]
    fn appends_chain_and_verify_agrees() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let path = dir.path().join("audit/audit.jsonl");
        let (log, initial) = AuditLog::open(&path).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(initial, ChainState::empty());
        let s1 = log
            .append_blocking(draft(Event::Start))
            .unwrap_or_else(|e| panic!("{e}"));
        let mut d = draft(Event::Put);
        d.vault = Some("private".into());
        d.size = Some(10);
        let s2 = log.append_blocking(d).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!((s1, s2), (1, 2));
        let live = log.state();
        assert_eq!(live.entries, 2);
        let verified = verify_file(&path).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(verified, live);
        assert_ne!(verified.head, super::super::GENESIS);

        // reopening picks up the chain where it left off
        drop(log);
        let (log, reopened) = AuditLog::open(&path).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(reopened, verified);
        log.append_blocking(draft(Event::Delete))
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            verify_file(&path).unwrap_or_else(|e| panic!("{e}")).entries,
            3
        );
    }

    #[test]
    fn lines_are_canonical_and_fields_are_omitted_when_none() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let path = dir.path().join("a.jsonl");
        let (log, _) = AuditLog::open(&path).unwrap_or_else(|e| panic!("{e}"));
        let mut d = Draft::new(
            Event::Resolve,
            Outcome::Refused,
            Caller::peer(Some(1000), Some(42)),
        );
        d.reason = Some("TARGET_NOT_ALLOWED".into());
        d.dest = Some("team-chat".into());
        log.append_blocking(d).unwrap_or_else(|e| panic!("{e}"));
        let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{e}"));
        let line = text.lines().next().unwrap_or_default();
        assert!(line.starts_with("{\"caller\":{\"pid\":42,\"uid\":1000},\"dest\":\"team-chat\",\"event\":\"resolve\",\"outcome\":\"refused\",\"prev\":\"0000"), "{line}");
        assert!(
            line.contains("\"reason\":\"TARGET_NOT_ALLOWED\",\"seq\":1,\"ts\":\""),
            "{line}"
        );
        assert!(!line.contains("handle"), "{line}");
        assert!(!line.contains("null"), "{line}");
    }

    // AT-12: tamper matrix.
    #[test]
    fn tampering_is_detected_at_the_right_seq() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let path = dir.path().join("a.jsonl");
        let (log, _) = AuditLog::open(&path).unwrap_or_else(|e| panic!("{e}"));
        for ev in [Event::Start, Event::Put, Event::Label, Event::Delete] {
            let mut d = draft(ev);
            d.vault = Some("private".into());
            log.append_blocking(d).unwrap_or_else(|e| panic!("{e}"));
        }
        drop(log);
        let original = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{e}"));
        let lines: Vec<&str> = original.lines().collect();
        assert_eq!(lines.len(), 4);

        let check = |content: String| {
            std::fs::write(&path, content).unwrap_or_else(|e| panic!("{e}"));
            match verify_file(&path) {
                Ok(s) => Err(s),
                Err(super::super::verify::VerifyError::Chain(c)) => Ok(c),
                Err(e) => panic!("{e}"),
            }
        };

        // flip a byte inside line 2's vault name (entry stays well-formed)
        let mutated = lines[1].replace("\"vault\":\"private\"", "\"vault\":\"privatf\"");
        assert_ne!(mutated, lines[1]);
        let c = check(format!(
            "{}\n{}\n{}\n{}\n",
            lines[0], mutated, lines[2], lines[3]
        ))
        .unwrap_or_else(|s| panic!("expected break, got {s:?}"));
        // the mutated line itself still parses and its prev is right, so the
        // break shows at the *next* line, whose prev no longer matches
        assert_eq!(c.seq, 3);
        assert_eq!(c.kind, BreakKind::PrevMismatch);

        // drop line 2
        let c = check(format!("{}\n{}\n{}\n", lines[0], lines[2], lines[3]))
            .unwrap_or_else(|s| panic!("expected break, got {s:?}"));
        assert_eq!(c.seq, 2);
        assert!(matches!(c.kind, BreakKind::SeqMismatch { found: 3 }));

        // swap lines 2 and 3
        let c = check(format!(
            "{}\n{}\n{}\n{}\n",
            lines[0], lines[2], lines[1], lines[3]
        ))
        .unwrap_or_else(|s| panic!("expected break, got {s:?}"));
        assert_eq!(c.seq, 2);

        // duplicate line 4
        let c = check(format!(
            "{}\n{}\n{}\n{}\n{}\n",
            lines[0], lines[1], lines[2], lines[3], lines[3]
        ))
        .unwrap_or_else(|s| panic!("expected break, got {s:?}"));
        assert_eq!(c.seq, 5);
        assert!(matches!(c.kind, BreakKind::SeqMismatch { found: 4 }));

        // reformat (pretty-print) line 1: same JSON, different bytes
        let pretty = lines[0].replace(',', ", ");
        let c = check(format!(
            "{}\n{}\n{}\n{}\n",
            pretty, lines[1], lines[2], lines[3]
        ))
        .unwrap_or_else(|s| panic!("expected break, got {s:?}"));
        assert_eq!(c.seq, 1);
        assert_eq!(c.kind, BreakKind::Reformatted);

        // garbage line in the middle
        let c = check(format!(
            "{}\nnot json\n{}\n{}\n",
            lines[0], lines[2], lines[3]
        ))
        .unwrap_or_else(|s| panic!("expected break, got {s:?}"));
        assert_eq!(c.seq, 2);
        assert_eq!(c.kind, BreakKind::Unparsable);

        // truncating the tail is NOT detectable (documented): verify passes
        let s = check(format!("{}\n{}\n", lines[0], lines[1]))
            .err()
            .unwrap_or_else(|| panic!("truncation should verify clean"));
        assert_eq!(s.entries, 2);

        // and a broken chain refuses startup (D-1)
        std::fs::write(&path, format!("{}\n{}\n", lines[0], lines[2]))
            .unwrap_or_else(|e| panic!("{e}"));
        assert!(matches!(AuditLog::open(&path), Err(AuditError::Chain(_))));
    }

    #[test]
    fn clock_going_backwards_is_clamped() {
        let state = ChainState {
            entries: 5,
            head: "ab".into(),
            last_ts: Some(2_000),
        };
        let (line, _, ts) =
            build_line(draft(Event::Put), &state, 1_000).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(ts, 2_000);
        assert!(String::from_utf8_lossy(&line).contains("\"seq\":6"));
    }

    #[tokio::test]
    async fn async_append_works_from_a_runtime() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let path = dir.path().join("a.jsonl");
        let (log, _) = AuditLog::open(&path).unwrap_or_else(|e| panic!("{e}"));
        let seq = log
            .append(draft(Event::Start))
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(seq, 1);
        // concurrent appends serialise and all land
        let mut tasks = Vec::new();
        for _ in 0..20 {
            let l = log.clone();
            tasks.push(tokio::spawn(
                async move { l.append(draft(Event::Label)).await },
            ));
        }
        for t in tasks {
            t.await
                .unwrap_or_else(|e| panic!("{e}"))
                .unwrap_or_else(|e| panic!("{e}"));
        }
        assert_eq!(
            verify_file(&path).unwrap_or_else(|e| panic!("{e}")).entries,
            21
        );
    }
}
