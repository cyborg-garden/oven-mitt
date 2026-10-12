#![allow(clippy::unwrap_used, clippy::expect_used)]
//! `ovenmitt audit verify|head` at the binary level (R-AUD-7, AT-12).

use std::process::Command;

use ovenmitt::audit::writer::AuditLog;
use ovenmitt::audit::{Caller, Draft, Event, Outcome};

fn run(config: &std::path::Path, args: &[&str]) -> (i32, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_ovenmitt"))
        .arg("--config")
        .arg(config)
        .args(args)
        .output()
        .expect("binary runs");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn verify_and_head_follow_the_chain() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("audit.jsonl");
    let cfg = dir.path().join("ovenmitt.toml");
    std::fs::write(
        &cfg,
        format!("[daemon]\naudit_log = \"{}\"\n", log_path.display()),
    )
    .unwrap();

    // absent log: empty chain, genesis head
    let (code, out, _) = run(&cfg, &["audit", "verify"]);
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("0 entries"), "{out}");
    let (code, out, _) = run(&cfg, &["audit", "head"]);
    assert_eq!(code, 0);
    assert_eq!(out.trim(), ovenmitt::audit::GENESIS);

    let (log, _) = AuditLog::open(&log_path).unwrap();
    for ev in [Event::Start, Event::Put, Event::Export] {
        log.append_blocking(Draft::new(ev, Outcome::Ok, Caller::daemon()))
            .unwrap();
    }
    let head = log.state().head;
    drop(log);

    let (code, out, _) = run(&cfg, &["audit", "verify"]);
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("3 entries"), "{out}");
    assert!(out.contains(&head), "{out}");
    let (code, out, _) = run(&cfg, &["audit", "head"]);
    assert_eq!(code, 0);
    assert_eq!(out.trim(), head);

    // tamper: drop the middle line
    let text = std::fs::read_to_string(&log_path).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    std::fs::write(&log_path, format!("{}\n{}\n", lines[0], lines[2])).unwrap();
    let (code, _, err) = run(&cfg, &["audit", "verify"]);
    assert_eq!(code, 1, "{err}");
    assert!(err.contains("seq 2"), "{err}");
    let (code, _, _) = run(&cfg, &["audit", "head"]);
    assert_eq!(code, 1);

    // unreadable: a directory where the file should be
    std::fs::remove_file(&log_path).unwrap();
    std::fs::create_dir(&log_path).unwrap();
    let (code, _, _) = run(&cfg, &["audit", "verify"]);
    assert_eq!(code, 2);
}
