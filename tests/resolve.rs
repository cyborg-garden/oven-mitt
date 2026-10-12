#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::too_many_lines,
    clippy::cast_sign_loss
)]
//! Credentials and `resolve` (M5): AT-4, AT-5 (full truth table), AT-17,
//! SI-1, SI-5, SI-14, and the audit fields for resolve.

mod common;

use std::process::Command;

use common::{TestDaemon, contains, sentinel};
use hyper::StatusCode;
use ovenmitt::audit::{Event, Outcome};
use ovenmitt::credential::{Scope, issue, read_file, write_file};

struct Case {
    label: &'static str,
    token: Option<String>,
    handle: String,
    dest: &'static str,
    target: String,
    expect: Result<(), &'static str>,
}

/// Issue a credential straight into the daemon's credentials file.
fn mint(d: &TestDaemon, name: &str, scope: Scope) -> String {
    let path = &d.config.daemon.credentials;
    let mut records = read_file(path).unwrap();
    let (token, record) = issue(name, scope).unwrap();
    records.push(record);
    write_file(path, &records).unwrap();
    token
}

fn body(dest: &str, target: &str) -> Vec<u8> {
    serde_json::json!({"destination": dest, "target": target})
        .to_string()
        .into_bytes()
}

async fn resolve(d: &TestDaemon, handle: &str, token: Option<&str>, b: Vec<u8>) -> common::Reply {
    let auth = token.map(|t| format!("Bearer {t}"));
    let mut headers: Vec<(&str, &str)> = vec![("content-type", "application/json")];
    if let Some(a) = auth.as_deref() {
        headers.push(("authorization", a));
    }
    d.call(
        "POST",
        &format!("/v1/objects/{handle}/resolve"),
        &headers,
        Some(b),
    )
    .await
}

// AT-4.
#[tokio::test(flavor = "multi_thread")]
async fn resolve_returns_bytes_and_audits_dest_target_cred() {
    let d = TestDaemon::start().await;
    let content = sentinel();
    let handle = d.put_ok("private", &content).await;
    let token = mint(&d, "vault_send", Scope::Some(vec!["private".into()]));
    let target = format!("chat:group/{}", d.secrets.pattern_marker);
    let r = resolve(&d, &handle, Some(&token), body("team-chat", &target)).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    assert_eq!(r.body, content, "byte-identical");
    assert_eq!(r.headers["content-type"], "text/plain");
    assert_eq!(r.headers["content-length"], "64");
    assert_eq!(r.headers["x-ovenmitt-destination"], "team-chat");
    // the target is never echoed
    let hdrs = format!("{:?}", r.headers);
    assert!(!hdrs.contains(&target));

    let entries = d.audit_entries();
    let e = entries
        .iter()
        .find(|e| e.draft.event == Event::Resolve && e.draft.outcome == Outcome::Ok)
        .unwrap();
    assert_eq!(e.draft.dest.as_deref(), Some("team-chat"));
    assert_eq!(
        e.draft.target.as_deref(),
        Some(target.as_str()),
        "target always audited (F-27)"
    );
    assert_eq!(e.draft.vault.as_deref(), Some("private"));
    assert_eq!(e.draft.handle.as_ref().unwrap().as_str(), handle);
    assert_eq!(e.draft.size, Some(64));
    assert_eq!(
        e.draft.sha256.as_deref(),
        Some(ovenmitt::crypto::sha256_hex(&content).as_str())
    );
    let id = token.split('_').nth(1).unwrap();
    assert_eq!(e.draft.caller.cred.as_deref(), Some(id));
    assert!(e.draft.caller.uid.is_some());
    // the secret never appears in the log
    let secret = token.rsplit('_').next().unwrap();
    assert!(!d.audit_text().contains(secret));
    // wildcard destination
    let r = resolve(
        &d,
        &handle,
        Some(&token),
        body("any-dm", "chat:dm/+6421000000"),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    assert_eq!(r.body, content);
    d.stop().await;
}

// AT-5 / SI-5: the truth table. Exactly the expected cells return 200.
#[tokio::test(flavor = "multi_thread")]
async fn truth_table() {
    let d = TestDaemon::start().await;
    let content = sentinel();
    let handle = d.put_ok("private", &content).await;
    let hidden = d.put_ok("hidden", b"other").await;
    let good = mint(&d, "good", Scope::Some(vec!["private".into()]));
    let wrong_vault = mint(&d, "wrong", Scope::Some(vec!["hidden".into()]));
    let all = mint(&d, "all", Scope::all());
    let revoked = mint(&d, "revoked", Scope::all());
    {
        let path = &d.config.daemon.credentials;
        let mut records = read_file(path).unwrap();
        let id = revoked.split('_').nth(1).unwrap();
        records.iter_mut().find(|r| r.id == id).unwrap().revoked =
            Some("2026-10-13T00:00:00.000Z".into());
        std::thread::sleep(std::time::Duration::from_millis(20));
        write_file(path, &records).unwrap();
    }
    let ok_target = format!("chat:group/{}", d.secrets.pattern_marker);
    let bad = "chat:group/other".to_owned();
    let malformed = format!("ovm_{}_x", "0".repeat(8));

    let cases = vec![
        Case {
            label: "no credential",
            token: None,
            handle: handle.clone(),
            dest: "team-chat",
            target: ok_target.clone(),
            expect: Err("CREDENTIAL_REQUIRED"),
        },
        Case {
            label: "malformed credential",
            token: Some(malformed.clone()),
            handle: handle.clone(),
            dest: "team-chat",
            target: ok_target.clone(),
            expect: Err("CREDENTIAL_INVALID"),
        },
        Case {
            label: "unknown credential",
            token: Some(format!("{}x", &good[..good.len() - 1])),
            handle: handle.clone(),
            dest: "team-chat",
            target: ok_target.clone(),
            expect: Err("CREDENTIAL_INVALID"),
        },
        Case {
            label: "revoked credential",
            token: Some(revoked.clone()),
            handle: handle.clone(),
            dest: "team-chat",
            target: ok_target.clone(),
            expect: Err("CREDENTIAL_INVALID"),
        },
        Case {
            label: "bad credential, bad handle: credential first",
            token: Some(malformed.clone()),
            handle: "v_000000000000".into(),
            dest: "team-chat",
            target: ok_target.clone(),
            expect: Err("CREDENTIAL_INVALID"),
        },
        Case {
            label: "good credential, missing object",
            token: Some(good.clone()),
            handle: "v_000000000000".into(),
            dest: "team-chat",
            target: ok_target.clone(),
            expect: Err("NOT_FOUND"),
        },
        Case {
            label: "wrong vault scope",
            token: Some(wrong_vault.clone()),
            handle: handle.clone(),
            dest: "team-chat",
            target: ok_target.clone(),
            expect: Err("CREDENTIAL_NOT_PERMITTED"),
        },
        Case {
            label: "wrong vault scope beats missing destination",
            token: Some(wrong_vault.clone()),
            handle: handle.clone(),
            dest: "nope",
            target: ok_target.clone(),
            expect: Err("CREDENTIAL_NOT_PERMITTED"),
        },
        Case {
            label: "missing destination",
            token: Some(good.clone()),
            handle: handle.clone(),
            dest: "nope",
            target: ok_target.clone(),
            expect: Err("DESTINATION_NOT_FOUND"),
        },
        Case {
            label: "fs destination",
            token: Some(good.clone()),
            handle: handle.clone(),
            dest: "archive",
            target: ok_target.clone(),
            expect: Err("DESTINATION_KIND_MISMATCH"),
        },
        Case {
            label: "target mismatch (literal)",
            token: Some(good.clone()),
            handle: handle.clone(),
            dest: "team-chat",
            target: bad.clone(),
            expect: Err("TARGET_NOT_ALLOWED"),
        },
        Case {
            label: "target mismatch (wildcard, extra segment)",
            token: Some(good.clone()),
            handle: handle.clone(),
            dest: "any-dm",
            target: "chat:dm/a/b".into(),
            expect: Err("TARGET_NOT_ALLOWED"),
        },
        Case {
            label: "target mismatch (wildcard, empty segment)",
            token: Some(good.clone()),
            handle: handle.clone(),
            dest: "any-dm",
            target: "chat:dm/".into(),
            expect: Err("TARGET_NOT_ALLOWED"),
        },
        Case {
            label: "target mismatch (prefix only)",
            token: Some(good.clone()),
            handle: handle.clone(),
            dest: "any-dm",
            target: "chat:dm".into(),
            expect: Err("TARGET_NOT_ALLOWED"),
        },
        Case {
            label: "empty target",
            token: Some(good.clone()),
            handle: handle.clone(),
            dest: "any-dm",
            target: String::new(),
            expect: Err("INVALID_REQUEST"),
        },
        Case {
            label: "good",
            token: Some(good.clone()),
            handle: handle.clone(),
            dest: "team-chat",
            target: ok_target.clone(),
            expect: Ok(()),
        },
        Case {
            label: "good, all-vault scope",
            token: Some(all.clone()),
            handle: handle.clone(),
            dest: "team-chat",
            target: ok_target.clone(),
            expect: Ok(()),
        },
        Case {
            label: "good, wildcard",
            token: Some(good.clone()),
            handle: handle.clone(),
            dest: "any-dm",
            target: "chat:dm/x".into(),
            expect: Ok(()),
        },
        Case {
            label: "hidden vault has no destinations",
            token: Some(all.clone()),
            handle: hidden.clone(),
            dest: "team-chat",
            target: ok_target.clone(),
            expect: Err("DESTINATION_NOT_FOUND"),
        },
    ];
    for c in &cases {
        let r = resolve(&d, &c.handle, c.token.as_deref(), body(c.dest, &c.target)).await;
        match c.expect {
            Ok(()) => {
                assert_eq!(r.status, StatusCode::OK, "{}: {}", c.label, r.text());
                assert_eq!(r.body, content, "{}", c.label);
            }
            Err(code) => {
                assert_eq!(r.code(), code, "{}: {}", c.label, r.text());
                assert!(!contains(&r.body, &content), "{}: content leaked", c.label);
                assert!(
                    !r.text().contains(&d.secrets.pattern_marker),
                    "{}: pattern leaked",
                    c.label
                );
            }
        }
    }
    // malformed JSON / unknown field / no body
    let r = resolve(&d, &handle, Some(&good), b"nope".to_vec()).await;
    assert_eq!(r.code(), "INVALID_REQUEST");
    let r = resolve(
        &d,
        &handle,
        Some(&good),
        br#"{"destination":"team-chat","target":"x","extra":1}"#.to_vec(),
    )
    .await;
    assert_eq!(r.code(), "INVALID_REQUEST");
    // bad authorization scheme
    let r = d
        .call(
            "POST",
            &format!("/v1/objects/{handle}/resolve"),
            &[("authorization", "Basic abc")],
            Some(body("team-chat", &ok_target)),
        )
        .await;
    assert_eq!(r.code(), "CREDENTIAL_INVALID");

    // every refusal above produced exactly one entry with its code
    let entries = d.audit_entries();
    let refused: Vec<&str> = entries
        .iter()
        .filter(|e| e.draft.event == Event::Resolve && e.draft.outcome == Outcome::Refused)
        .map(|e| e.draft.reason.as_deref().unwrap())
        .collect();
    let expected: Vec<&str> = cases
        .iter()
        .filter_map(|c| c.expect.err())
        .chain(["INVALID_REQUEST", "INVALID_REQUEST", "CREDENTIAL_INVALID"])
        .collect();
    assert_eq!(refused, expected);
    // refused entries carry the credential id only when one was verified
    let cred_on_required = entries
        .iter()
        .find(|e| e.draft.reason.as_deref() == Some("CREDENTIAL_REQUIRED"))
        .unwrap();
    assert_eq!(cred_on_required.draft.caller.cred, None);
    let cred_on_target = entries
        .iter()
        .find(|e| e.draft.reason.as_deref() == Some("TARGET_NOT_ALLOWED"))
        .unwrap();
    assert!(cred_on_target.draft.caller.cred.is_some());
    assert_eq!(
        cred_on_target.draft.target, None,
        "a refused target is not recorded"
    );
    d.stop().await;
}

// max_size on a send destination.
#[tokio::test(flavor = "multi_thread")]
async fn send_max_size_is_enforced() {
    let d = TestDaemon::start().await;
    let small = d.put_ok("private", b"tiny").await;
    let big = d.put_ok("private", &[1u8; 101]).await;
    let token = mint(&d, "t", Scope::all());
    let r = resolve(&d, &small, Some(&token), body("any-dm", "chat:dm/x")).await;
    assert_eq!(r.status, StatusCode::OK);
    let r = resolve(&d, &big, Some(&token), body("any-dm", "chat:dm/x")).await;
    assert_eq!(r.code(), "TOO_LARGE");
    assert!(r.body.len() < 100, "no bytes delivered");
    d.stop().await;
}

// AT-17 and SI-14 through the real CLI against a running daemon.
#[tokio::test(flavor = "multi_thread")]
async fn credential_lifecycle_via_cli() {
    let d = TestDaemon::start().await;
    let handle = d.put_ok("private", b"payload").await;
    let cfg_path = d.dir.path().join("cli.toml");
    std::fs::write(
        &cfg_path,
        format!(
            "[daemon]\ncredentials = \"{}\"\n[vault.private]\n[vault.hidden]\n",
            d.config.daemon.credentials.display()
        ),
    )
    .unwrap();
    let run = |args: &[&str]| {
        let out = Command::new(env!("CARGO_BIN_EXE_ovenmitt"))
            .arg("--config")
            .arg(&cfg_path)
            .args(args)
            .output()
            .unwrap();
        (
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    };

    // issue: token on stdout exactly once
    let (code, out, err) = run(&[
        "credential",
        "issue",
        "--name",
        "vault_send",
        "--vault",
        "private",
    ]);
    assert_eq!(code, 0, "{err}");
    let token = out.trim().to_owned();
    assert!(token.starts_with("ovm_"), "{out}");
    assert!(err.contains("shown once"), "{err}");
    let secret = token.rsplit('_').next().unwrap().to_owned();
    let id = token.split('_').nth(1).unwrap().to_owned();

    // SI-14: the secret is nowhere on disk
    for f in TestDaemon::files_under(d.dir.path()) {
        if !std::fs::metadata(&f).is_ok_and(|m| m.is_file()) {
            continue; // the socket
        }
        let bytes = std::fs::read(&f).unwrap();
        assert!(
            !contains(&bytes, secret.as_bytes()),
            "secret found in {}",
            f.display()
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&d.config.daemon.credentials)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    // works without restarting the daemon
    let target = format!("chat:group/{}", d.secrets.pattern_marker);
    let r = resolve(&d, &handle, Some(&token), body("team-chat", &target)).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());

    // list shows id/name/scope, never the secret
    let (code, out, _) = run(&["credential", "list"]);
    assert_eq!(code, 0);
    assert!(
        out.contains(&id) && out.contains("vault_send") && out.contains("private"),
        "{out}"
    );
    assert!(!out.contains(&secret));

    // bad scope refused
    let (code, _, err) = run(&["credential", "issue", "--name", "x", "--vault", "nope"]);
    assert_ne!(code, 0);
    assert!(err.contains("not a configured vault"), "{err}");

    // revoke takes effect on the next request
    std::thread::sleep(std::time::Duration::from_millis(20));
    let (code, _, err) = run(&["credential", "revoke", &id]);
    assert_eq!(code, 0, "{err}");
    let r = resolve(&d, &handle, Some(&token), body("team-chat", &target)).await;
    assert_eq!(r.code(), "CREDENTIAL_INVALID");
    let (code, _, _) = run(&["credential", "revoke", "deadbeef"]);
    assert_eq!(code, 1);
    let (code, out, _) = run(&["credential", "list"]);
    assert_eq!(code, 0);
    assert!(
        out.lines().any(|l| l.contains(&id) && !l.ends_with('-')),
        "{out}"
    );
    d.stop().await;
}

// SI-1 restated with a credential in hand: still only resolve returns bytes.
#[tokio::test(flavor = "multi_thread")]
async fn credential_does_not_unlock_any_other_route() {
    let d = TestDaemon::start().await;
    let content = sentinel();
    let handle = d.put_ok("private", &content).await;
    let token = mint(&d, "t", Scope::all());
    let auth = format!("Bearer {token}");
    for (m, p) in [
        ("GET", format!("/v1/objects/{handle}")),
        ("GET", format!("/v1/objects/{handle}/body")),
        ("GET", format!("/v1/objects/{handle}/resolve")),
        ("GET", "/v1/objects".to_owned()),
        ("POST", format!("/v1/objects/{handle}/export")),
    ] {
        let r = d.call(m, &p, &[("authorization", &auth)], None).await;
        assert!(!contains(&r.body, &content), "{m} {p} leaked content");
    }
    d.stop().await;
}
