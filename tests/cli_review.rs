#![allow(clippy::unwrap_used, clippy::expect_used, clippy::too_many_lines)]
//! `ovenmitt audit review`, `vault list`, `object stat` against a running
//! daemon (AT-11 in-process, AT-24 end to end, AT-29 operator face).

mod common;

use std::process::Command;

use common::TestDaemon;
use hyper::StatusCode;

fn run(cfg: &std::path::Path, args: &[&str]) -> (i32, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_ovenmitt"))
        .arg("--config")
        .arg(cfg)
        .args(args)
        .output()
        .unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn cli_config(d: &TestDaemon, rules: Option<&str>) -> std::path::PathBuf {
    static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let n = N.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let path = d.dir.path().join(format!("cli-{n}.toml"));
    let rules_line = rules
        .map(|r| {
            let p = d.dir.path().join(format!("review-{n}.toml"));
            std::fs::write(&p, r).unwrap();
            format!("review_rules = \"{}\"\n", p.display())
        })
        .unwrap_or_default();
    std::fs::write(
        &path,
        format!(
            "[daemon]\naudit_log = \"{}\"\ndata_dir = \"{}\"\nkeys_dir = \"{}\"\n{rules_line}[vault.private]\nexpose_names = true\nttl = \"30d\"\n[vault.private.destinations.archive]\nkind = \"fs\"\nroot = \"{}\"\n[vault.hidden]\n",
            d.audit_log.display(),
            d.data_dir.display(),
            d.keys_dir.display(),
            d.export_root.display(),
        ),
    )
    .unwrap();
    path
}

// AT-11: every refusal reported, exit 1 at default threshold, 0 at critical.
#[tokio::test(flavor = "multi_thread")]
async fn review_reports_refusals_and_exits_by_threshold() {
    let d = TestDaemon::start().await;
    let handle = d.put_ok("private", b"x").await;
    // generate refusals of several kinds
    d.call("GET", "/v1/objects/v_000000000000", &[], None).await;
    d.request("GET", "/v1/vaults", &[], None).await;
    d.call(
        "POST",
        &format!("/v1/objects/{handle}/export"),
        &[],
        Some(br#"{"destination":"archive","filename":"../x"}"#.to_vec()),
    )
    .await;
    d.call(
        "POST",
        &format!("/v1/objects/{handle}/resolve"),
        &[],
        Some(br#"{"destination":"team-chat","target":"x"}"#.to_vec()),
    )
    .await;
    // one successful export (first-time destination → medium)
    let r = d
        .call(
            "POST",
            &format!("/v1/objects/{handle}/export"),
            &[],
            Some(br#"{"destination":"archive","filename":"ok.txt"}"#.to_vec()),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK);

    let cfg = cli_config(&d, None);
    let (code, out, err) = run(&cfg, &["audit", "review"]);
    assert_eq!(code, 1, "{err}");
    assert!(out.is_empty(), "stdout empty without --json: {out}");
    for reason in [
        "NOT_FOUND",
        "PROTOCOL_UNSUPPORTED",
        "FILENAME_INVALID",
        "CREDENTIAL_REQUIRED",
    ] {
        assert!(
            err.contains(&format!("reason={reason}")),
            "missing {reason} in:\n{err}"
        );
    }
    assert!(err.contains("first_destination"), "{err}");
    assert!(err.contains("export private/archive"), "{err}");
    assert!(
        err.lines().any(|l| l.starts_with("HIGH     refusal")),
        "{err}"
    );
    // ranked: HIGH lines before MEDIUM lines
    let lines: Vec<&str> = err.lines().collect();
    let first_medium = lines.iter().position(|l| l.starts_with("MEDIUM")).unwrap();
    let last_high = lines.iter().rposition(|l| l.starts_with("HIGH")).unwrap();
    assert!(last_high < first_medium, "{err}");

    let (code, _, _) = run(&cfg, &["audit", "review", "--threshold", "critical"]);
    assert_eq!(code, 0);
    let (code, _, err) = run(&cfg, &["audit", "review", "--threshold", "warn"]);
    assert_eq!(code, 2, "{err}");

    // --json shape on stdout
    let (code, out, _) = run(&cfg, &["audit", "review", "--json"]);
    assert_eq!(code, 1);
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["threshold"], "medium");
    assert_eq!(v["exit"], 1);
    assert!(v["findings"].as_array().unwrap().len() >= 5);
    assert_eq!(v["findings"][0]["severity"], "high");

    // --since in the future: nothing to report
    let (code, _, err) = run(
        &cfg,
        &["audit", "review", "--since", "2099-01-01T00:00:00Z"],
    );
    assert_eq!(code, 0, "{err}");
    assert!(err.contains("0 finding(s)"), "{err}");
    let (code, _, _) = run(&cfg, &["audit", "review", "--since", "1h"]);
    assert_eq!(code, 1);
    let (code, _, err) = run(&cfg, &["audit", "review", "--since", "yesterday"]);
    assert_eq!(code, 2, "{err}");

    // rules file: refusals disabled → exit 0 at high threshold
    let cfg2 = cli_config(
        &d,
        Some("[rules.refusal]\nenabled = false\nseverity = \"high\"\n"),
    );
    let (code, _, err) = run(&cfg2, &["audit", "review", "--threshold", "high"]);
    assert_eq!(code, 0, "{err}");
    assert!(!err.contains("refusal"), "{err}");
    // bad rules file refuses
    let cfg3 = cli_config(&d, Some("[rules.chain]\nseverity = \"low\"\n"));
    let (code, _, err) = run(&cfg3, &["audit", "review"]);
    assert_eq!(code, 2, "{err}");
    assert!(err.contains("chain"), "{err}");

    // chain break: critical, exit 1 even at critical threshold
    let text = std::fs::read_to_string(&d.audit_log).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    let mut broken = lines.clone();
    broken.remove(1);
    let audit_log = d.audit_log.clone();
    let _keep = d.stop().await;
    std::fs::write(&audit_log, format!("{}\n", broken.join("\n"))).unwrap();
    let (code, _, err) = run(&cfg, &["audit", "review", "--threshold", "critical"]);
    assert_eq!(code, 1, "{err}");
    assert!(
        err.lines().any(|l| l.starts_with("CRITICAL chain")),
        "{err}"
    );
}

// AT-24 end to end: burst at count, not one below; churn per handle.
#[tokio::test(flavor = "multi_thread")]
async fn burst_and_churn_over_real_entries() {
    let d = TestDaemon::start().await;
    let handle = d.put_ok("private", b"x").await;
    let label = |i: usize| format!("{{\"labels\":[\"l{i}\"]}}").into_bytes();
    // 4 label writes on one handle; burst rule for label at count 5 must not
    // fire, churn at count 4 must
    for i in 0..4 {
        let r = d
            .call(
                "PATCH",
                &format!("/v1/objects/{handle}"),
                &[],
                Some(label(i)),
            )
            .await;
        assert_eq!(r.status, StatusCode::OK);
    }
    let rules = "[rules.burst]\nseverity = \"high\"\nevents = [\"label\"]\ncount = 5\nwindow = \"10m\"\n[rules.churn]\nseverity = \"medium\"\ncount = 4\nwindow = \"10m\"\n[rules.first_destination]\nenabled = false\nseverity = \"low\"\n";
    let cfg = cli_config(&d, Some(rules));
    let (code, _, err) = run(&cfg, &["audit", "review"]);
    assert_eq!(code, 1, "{err}");
    assert!(
        err.lines()
            .any(|l| l.starts_with("MEDIUM   churn") && l.contains("4 writes")),
        "{err}"
    );
    assert!(!err.contains("burst"), "{err}");
    // one more label: burst now fires too
    let r = d
        .call(
            "PATCH",
            &format!("/v1/objects/{handle}"),
            &[],
            Some(label(9)),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK);
    let (code, _, err) = run(&cfg, &["audit", "review"]);
    assert_eq!(code, 1);
    assert!(
        err.lines()
            .any(|l| l.starts_with("HIGH     burst") && l.contains("5 label in 10m")),
        "{err}"
    );
    d.stop().await;
}

// AT-29 (operator face) and R-OBJ-11.
#[tokio::test(flavor = "multi_thread")]
async fn vault_list_and_object_stat() {
    let d = TestDaemon::start().await;
    let r = d
        .put(
            "hidden",
            b"payload",
            &[
                ("x-ovenmitt-name", "secret-name.txt"),
                ("x-ovenmitt-label", "lbl"),
            ],
        )
        .await;
    assert_eq!(r.status, StatusCode::CREATED);
    let handle = r.json()["handle"].as_str().unwrap().to_owned();
    assert_eq!(r.json()["name"], serde_json::Value::Null);

    let cfg = cli_config(&d, None);
    let (code, out, err) = run(&cfg, &["vault", "list"]);
    assert_eq!(code, 0, "{err}");
    assert!(
        out.contains("private  expose_names=true") && out.contains("hidden  expose_names=false"),
        "{out}"
    );
    assert!(out.contains("archive: fs root="), "{out}");

    // object stat runs beside the live daemon and shows the hidden name
    let (code, out, err) = run(&cfg, &["object", "stat", &handle]);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("name:       secret-name.txt"), "{out}");
    assert!(out.contains("labels:     lbl"), "{out}");
    assert!(
        out.contains(&format!(
            "sha256:     {}",
            ovenmitt::crypto::sha256_hex(b"payload")
        )),
        "{out}"
    );
    // and the daemon is unaffected: the object is still there, temp untouched
    let r = d
        .call("GET", &format!("/v1/objects/{handle}"), &[], None)
        .await;
    assert_eq!(r.status, StatusCode::OK);
    let (code, _, err) = run(&cfg, &["object", "stat", "v_000000000000"]);
    assert_eq!(code, 1);
    assert!(err.contains("no such object"), "{err}");
    let (code, _, _) = run(&cfg, &["object", "stat", "nonsense"]);
    assert_eq!(code, 2);
    d.stop().await;
}
