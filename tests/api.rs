#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::too_many_lines,
    clippy::cast_sign_loss
)]
//! The HTTP API over the socket (M4): every route except resolve, the
//! error model, the protocol header, the outcome path.
//! Covers AT-1, AT-5 (non-credential cells), AT-6, AT-7, AT-14, AT-15,
//! AT-16, AT-22, AT-23, AT-25, AT-27 and the SI-6/SI-8 sentinel sweeps.

mod common;

use common::{Options, TestDaemon, contains, sentinel, sentinel_str};
use hyper::StatusCode;
use ovenmitt::audit::{Event, Outcome};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test(flavor = "multi_thread")]
async fn health_vaults_destinations() {
    let d = TestDaemon::start().await;
    // health needs no protocol header
    let r = d.request("GET", "/v1/health", &[], None).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.json()["status"], "ok");
    assert_eq!(r.headers["x-ovenmitt-protocol"], "1");

    let r = d.call("GET", "/v1/vaults", &[], None).await;
    assert_eq!(r.status, StatusCode::OK);
    let v = r.json();
    assert_eq!(v.as_array().unwrap().len(), 2);
    assert_eq!(v[0]["name"], "hidden");
    assert_eq!(v[0]["expose_names"], false);
    assert!(v[0].get("ttl").is_none());
    assert_eq!(v[1]["name"], "private");

    let r = d
        .call("GET", "/v1/vaults/private/destinations", &[], None)
        .await;
    assert_eq!(r.status, StatusCode::OK);
    let text = r.text();
    let v = r.json();
    let names: Vec<&str> = v
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, vec!["any-dm", "archive", "archive-rw", "team-chat"]);
    assert_eq!(v[1]["kind"], "fs");
    assert_eq!(v[3]["kind"], "send");
    // SI-15: no root, pattern, overwrite, max_size
    assert!(!text.contains(&d.secrets.root_marker), "{text}");
    assert!(!text.contains(&d.secrets.pattern_marker), "{text}");
    assert!(
        !text.contains("overwrite") && !text.contains("max_size"),
        "{text}"
    );

    let r = d
        .call("GET", "/v1/vaults/nope/destinations", &[], None)
        .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    assert_eq!(r.code(), "VAULT_NOT_FOUND");
    let r = d
        .call("GET", "/v1/vaults/Bad%20Name/destinations", &[], None)
        .await;
    assert_eq!(r.code(), "VAULT_NOT_FOUND");
    d.stop().await;
}

// AT-25: protocol header.
#[tokio::test(flavor = "multi_thread")]
async fn protocol_header_is_required_and_audited() {
    let d = TestDaemon::start().await;
    let before = d.audit_entries().len();
    let r = d.request("GET", "/v1/vaults", &[], None).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert_eq!(r.code(), "PROTOCOL_UNSUPPORTED");
    let r = d
        .request("GET", "/v1/vaults", &[("x-ovenmitt-protocol", "2")], None)
        .await;
    assert_eq!(r.code(), "PROTOCOL_UNSUPPORTED");
    let entries = d.audit_entries();
    assert_eq!(entries.len(), before + 2);
    for e in &entries[before..] {
        assert_eq!(e.draft.event, Event::Request);
        assert_eq!(e.draft.outcome, Outcome::Refused);
        assert_eq!(e.draft.reason.as_deref(), Some("PROTOCOL_UNSUPPORTED"));
        assert!(e.draft.caller.uid.is_some(), "peer uid recorded");
    }
    d.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn unknown_routes_and_bodies_on_bodiless_routes_are_refused() {
    let d = TestDaemon::start().await;
    let r = d.call("GET", "/v1/nope", &[], None).await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    assert_eq!(r.code(), "INVALID_REQUEST");
    let r = d
        .call("POST", "/v1/vaults", &[], Some(b"{}".to_vec()))
        .await;
    assert_eq!(r.code(), "INVALID_REQUEST");
    // a body on GET
    let r = d
        .call("GET", "/v1/vaults", &[], Some(b"junk".to_vec()))
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert_eq!(r.code(), "INVALID_REQUEST");
    // bad handle grammar
    let r = d.call("GET", "/v1/objects/not-a-handle", &[], None).await;
    assert_eq!(r.code(), "INVALID_REQUEST");
    let r = d.call("DELETE", "/v1/objects/v_XYZ", &[], None).await;
    assert_eq!(r.code(), "INVALID_REQUEST");
    let refused = d
        .audit_entries()
        .into_iter()
        .filter(|e| e.draft.outcome == Outcome::Refused)
        .count();
    assert_eq!(refused, 5);
    d.stop().await;
}

// AT-1 (wire level), AT-22.
#[tokio::test(flavor = "multi_thread")]
async fn put_stat_list_label_delete_round_trip() {
    let d = TestDaemon::start().await;
    let body = sentinel();
    let name = format!("hui-{}.txt", sentinel_str());
    let r = d
        .put(
            "private",
            &body,
            &[
                ("x-ovenmitt-name", &name),
                ("x-ovenmitt-label", "a"),
                ("x-ovenmitt-label", "w%C4%81hi%20tapu"),
                ("x-ovenmitt-remove-source-requested", "true"),
            ],
        )
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", r.text());
    let info = r.json();
    let handle = info["handle"].as_str().unwrap().to_owned();
    assert!(handle.starts_with("v_") && handle.len() == 14);
    assert_eq!(info["vault"], "private");
    assert_eq!(info["size"], 64);
    assert_eq!(info["mime"], "text/plain");
    assert_eq!(info["labels"], serde_json::json!(["a", "wāhi tapu"]));
    assert_eq!(info["name"], name);
    assert!(info.get("expires_at").is_none());
    assert!(info.get("sha256").is_none(), "hash is audit-only");
    assert!(!contains(&r.body, &body), "no plaintext in the response");

    let r = d
        .call("GET", &format!("/v1/objects/{handle}"), &[], None)
        .await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.json(), info);

    let r = d.call("GET", "/v1/objects?vault=private", &[], None).await;
    assert_eq!(r.json().as_array().unwrap().len(), 1);
    let r = d.call("GET", "/v1/objects", &[], None).await;
    assert_eq!(r.json().as_array().unwrap().len(), 1);
    let r = d.call("GET", "/v1/objects?vault=hidden", &[], None).await;
    assert_eq!(r.json().as_array().unwrap().len(), 0);
    let r = d.call("GET", "/v1/objects?vault=nope", &[], None).await;
    assert_eq!(r.code(), "VAULT_NOT_FOUND");

    // label
    let r = d
        .call(
            "PATCH",
            &format!("/v1/objects/{handle}"),
            &[("content-type", "application/json")],
            Some(br#"{"labels":["x","y"]}"#.to_vec()),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    assert_eq!(r.json()["labels"], serde_json::json!(["x", "y"]));
    let r = d
        .call(
            "PATCH",
            &format!("/v1/objects/{handle}"),
            &[],
            Some(br#"{"labels":[""]}"#.to_vec()),
        )
        .await;
    assert_eq!(r.code(), "LABEL_INVALID");
    let r = d
        .call(
            "PATCH",
            &format!("/v1/objects/{handle}"),
            &[],
            Some(b"not json".to_vec()),
        )
        .await;
    assert_eq!(r.code(), "INVALID_REQUEST");
    let r = d
        .call(
            "PATCH",
            &format!("/v1/objects/{handle}"),
            &[],
            Some(br#"{"labels":["a"],"content":"x"}"#.to_vec()),
        )
        .await;
    assert_eq!(r.code(), "INVALID_REQUEST", "unknown fields refused");

    // hidden vault: name null, operator-only
    let r = d
        .put("hidden", b"x", &[("x-ovenmitt-name", "secret.txt")])
        .await;
    assert_eq!(r.status, StatusCode::CREATED);
    assert_eq!(r.json()["name"], serde_json::Value::Null);
    assert!(r.text().contains("\"name\":null"));

    // delete
    let r = d
        .call("DELETE", &format!("/v1/objects/{handle}"), &[], None)
        .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    let r = d
        .call("GET", &format!("/v1/objects/{handle}"), &[], None)
        .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    assert_eq!(r.code(), "NOT_FOUND");
    let r = d
        .call("DELETE", &format!("/v1/objects/{handle}"), &[], None)
        .await;
    assert_eq!(r.code(), "NOT_FOUND");

    // audit: put/label/delete logged with the right fields; stat/list not
    let entries = d.audit_entries();
    let put = entries
        .iter()
        .find(|e| e.draft.event == Event::Put && e.draft.vault.as_deref() == Some("private"))
        .unwrap();
    assert_eq!(put.draft.outcome, Outcome::Ok);
    assert_eq!(put.draft.handle.as_ref().unwrap().as_str(), handle);
    assert_eq!(put.draft.size, Some(64));
    assert_eq!(
        put.draft.sha256.as_deref(),
        Some(ovenmitt::crypto::sha256_hex(&body).as_str())
    );
    assert_eq!(
        put.draft.name.as_deref(),
        Some(name.as_str()),
        "expose_names=true → name logged"
    );
    assert_eq!(put.draft.remove_source_requested, Some(true));
    let hidden_put = entries
        .iter()
        .find(|e| e.draft.event == Event::Put && e.draft.vault.as_deref() == Some("hidden"))
        .unwrap();
    assert_eq!(
        hidden_put.draft.name, None,
        "expose_names=false → name not logged"
    );
    assert!(
        entries
            .iter()
            .any(|e| e.draft.event == Event::Label && e.draft.outcome == Outcome::Ok)
    );
    let del = entries
        .iter()
        .find(|e| e.draft.event == Event::Delete && e.draft.outcome == Outcome::Ok)
        .unwrap();
    assert_eq!(
        del.draft.sha256.as_deref(),
        Some(ovenmitt::crypto::sha256_hex(&body).as_str())
    );
    let text = d.audit_text();
    assert!(!contains(text.as_bytes(), &body), "no content in the log");
    assert!(
        !text.contains("wāhi tapu") && !text.contains("\"x\",\"y\""),
        "no label text in the log"
    );
    assert!(!text.contains("secret.txt"), "hidden name not in the log");
    d.stop().await;
}

// AT-3 at wire level, AT-27.
#[tokio::test(flavor = "multi_thread")]
async fn replace_and_integrity_header() {
    let d = TestDaemon::start().await;
    let first = sentinel();
    let second = sentinel();
    let handle = d.put_ok("private", &first).await;
    let good = ovenmitt::crypto::sha256_hex(&second);
    let r = d
        .call(
            "PUT",
            &format!("/v1/objects/{handle}"),
            &[("content-type", "text/plain"), ("x-ovenmitt-sha256", &good)],
            Some(second.clone()),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    assert_eq!(r.json()["handle"], handle);
    assert_eq!(r.json()["size"], 64);
    TestDaemon::assert_absent_under(&d.data_dir, &first);
    TestDaemon::assert_absent_under(&d.data_dir, &second);

    let bad = ovenmitt::crypto::sha256_hex(b"other");
    let r = d
        .call(
            "PUT",
            &format!("/v1/objects/{handle}"),
            &[("x-ovenmitt-sha256", &bad)],
            Some(b"third".to_vec()),
        )
        .await;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(r.code(), "INTEGRITY");
    let r = d.put("private", b"x", &[("x-ovenmitt-sha256", "zz")]).await;
    assert_eq!(r.code(), "INTEGRITY");
    // object unchanged after the failed replace
    let r = d
        .call("GET", &format!("/v1/objects/{handle}"), &[], None)
        .await;
    assert_eq!(r.json()["size"], 64);
    let r = d
        .call(
            "PUT",
            "/v1/objects/v_000000000000",
            &[],
            Some(b"x".to_vec()),
        )
        .await;
    assert_eq!(r.code(), "NOT_FOUND");
    let entries = d.audit_entries();
    assert!(
        entries
            .iter()
            .any(|e| e.draft.event == Event::Replace && e.draft.outcome == Outcome::Ok)
    );
    assert!(
        entries
            .iter()
            .any(|e| e.draft.event == Event::Replace
                && e.draft.reason.as_deref() == Some("INTEGRITY"))
    );
    d.stop().await;
}

// AT-16.
#[tokio::test(flavor = "multi_thread")]
async fn max_object_size_mid_stream() {
    let d = TestDaemon::start_with(Options {
        max_object_size: Some("1KiB"),
        ..Options::default()
    })
    .await;
    let r = d.put("private", &vec![7u8; 1024], &[]).await;
    assert_eq!(r.status, StatusCode::CREATED);
    let r = d.put("private", &vec![7u8; 1025], &[]).await;
    assert_eq!(r.status, StatusCode::PAYLOAD_TOO_LARGE, "{}", r.text());
    assert_eq!(r.code(), "TOO_LARGE");
    let r = d.put("private", &vec![7u8; 5 << 20], &[]).await;
    assert_eq!(r.code(), "TOO_LARGE");
    let r = d.call("GET", "/v1/objects", &[], None).await;
    assert_eq!(r.json().as_array().unwrap().len(), 1);
    assert!(
        std::fs::read_dir(d.data_dir.join("tmp"))
            .unwrap()
            .next()
            .is_none()
    );
    d.stop().await;
}

// AT-14 (wire level), SI-9 stalled case, AT-23.
#[tokio::test(flavor = "multi_thread")]
async fn aborted_put_is_audited_and_leaves_nothing() {
    let d = TestDaemon::start().await;
    let body = sentinel();
    {
        let mut s = d.raw().await;
        let head = format!(
            "POST /v1/vaults/private/objects HTTP/1.1\r\nhost: x\r\nx-ovenmitt-protocol: 1\r\ncontent-type: text/plain\r\ncontent-length: {}\r\n\r\n",
            body.len() * 2
        );
        s.write_all(head.as_bytes()).await.unwrap();
        s.write_all(&body).await.unwrap();
        s.flush().await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        // stalled mid-body: temp exists, holds only ciphertext
        assert!(
            std::fs::read_dir(d.data_dir.join("tmp"))
                .unwrap()
                .next()
                .is_some()
        );
        TestDaemon::assert_absent_under(&d.data_dir, &body);
        drop(s); // client goes away
    }
    for _ in 0..50 {
        if std::fs::read_dir(d.data_dir.join("tmp"))
            .unwrap()
            .next()
            .is_none()
        {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert!(
        std::fs::read_dir(d.data_dir.join("tmp"))
            .unwrap()
            .next()
            .is_none()
    );
    let r = d.call("GET", "/v1/objects", &[], None).await;
    assert_eq!(r.json().as_array().unwrap().len(), 0);
    let entries = d.audit_entries();
    let ab = entries
        .iter()
        .find(|e| e.draft.event == Event::Put && e.draft.outcome == Outcome::Aborted);
    assert!(ab.is_some(), "aborted put audited: {entries:?}");
    assert_eq!(ab.unwrap().draft.reason.as_deref(), Some("ABORTED"));

    // AT-23: a refused request whose client vanishes immediately is still logged
    let before = d.audit_entries().len();
    {
        let mut s = d.raw().await;
        s.write_all(
            b"GET /v1/objects/v_000000000000 HTTP/1.1\r\nhost: x\r\nx-ovenmitt-protocol: 1\r\n\r\n",
        )
        .await
        .unwrap();
        drop(s);
    }
    for _ in 0..50 {
        if d.audit_entries().len() > before {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    let entries = d.audit_entries();
    assert_eq!(entries.len(), before + 1);
    assert_eq!(
        entries.last().unwrap().draft.reason.as_deref(),
        Some("NOT_FOUND")
    );
    d.stop().await;
}

// AT-15 at wire level.
#[tokio::test(flavor = "multi_thread")]
async fn ttl_expiry_over_the_wire() {
    let d = TestDaemon::start_with(Options {
        ttl: Some("1s"),
        sweep: "1s",
        ..Options::default()
    })
    .await;
    let handle = d.put_ok("private", b"short-lived").await;
    let r = d
        .call("GET", &format!("/v1/objects/{handle}"), &[], None)
        .await;
    assert!(r.json()["expires_at"].is_string());
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let r = d
        .call("GET", &format!("/v1/objects/{handle}"), &[], None)
        .await;
    assert_eq!(r.code(), "NOT_FOUND");
    // either the sweep or the access removed it; either way an `expire` entry exists
    for _ in 0..50 {
        if d.audit_entries()
            .iter()
            .any(|e| e.draft.event == Event::Expire)
        {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    let entries = d.audit_entries();
    let exp = entries
        .iter()
        .find(|e| e.draft.event == Event::Expire)
        .expect("expire entry");
    assert_eq!(exp.draft.handle.as_ref().unwrap().as_str(), handle);
    assert_eq!(exp.draft.size, Some(11));
    assert_eq!(
        exp.draft.sha256.as_deref(),
        Some(ovenmitt::crypto::sha256_hex(b"short-lived").as_str())
    );
    assert_eq!(exp.draft.caller.daemon, Some(true));
    d.stop().await;
}

// AT-6, AT-9, AT-10 at wire level.
#[tokio::test(flavor = "multi_thread")]
async fn export_routes() {
    let d = TestDaemon::start().await;
    let body = sentinel();
    let handle = d.put_ok("private", &body).await;
    let export = |dest: &str, name: &str| {
        serde_json::json!({"destination": dest, "filename": name})
            .to_string()
            .into_bytes()
    };
    let r = d
        .call(
            "POST",
            &format!("/v1/objects/{handle}/export"),
            &[],
            Some(export("archive", "out.txt")),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    assert_eq!(
        r.json(),
        serde_json::json!({"destination":"archive","filename":"out.txt","size":64})
    );
    assert_eq!(std::fs::read(d.export_root.join("out.txt")).unwrap(), body);

    let cases: &[(&[u8], &str)] = &[
        (&export("archive", "out.txt"), "EXISTS"),
        (&export("archive", "../x.txt"), "FILENAME_INVALID"),
        (&export("archive", ".hidden"), "FILENAME_INVALID"),
        (&export("archive", "a/b"), "FILENAME_INVALID"),
        (&export("nope", "x.txt"), "DESTINATION_NOT_FOUND"),
        (&export("team-chat", "x.txt"), "DESTINATION_KIND_MISMATCH"),
        (br#"{"destination":"archive"}"#, "INVALID_REQUEST"),
        (b"garbage", "INVALID_REQUEST"),
    ];
    for (b, code) in cases {
        let r = d
            .call(
                "POST",
                &format!("/v1/objects/{handle}/export"),
                &[],
                Some(b.to_vec()),
            )
            .await;
        assert_eq!(r.code(), *code, "{}", r.text());
    }
    let r = d
        .call(
            "POST",
            &format!("/v1/objects/{handle}/export"),
            &[],
            Some(export("archive-rw", "out.txt")),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK);
    let r = d
        .call(
            "POST",
            &format!("/v1/objects/{handle}/export"),
            &[],
            Some(export("archive-rw", "out.txt")),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "overwrite=true destination");
    let r = d
        .call(
            "POST",
            "/v1/objects/v_000000000000/export",
            &[],
            Some(export("archive", "x.txt")),
        )
        .await;
    assert_eq!(r.code(), "NOT_FOUND");

    let entries = d.audit_entries();
    let ok = entries
        .iter()
        .find(|e| e.draft.event == Event::Export && e.draft.outcome == Outcome::Ok)
        .unwrap();
    assert_eq!(ok.draft.dest.as_deref(), Some("archive"));
    assert_eq!(
        ok.draft.sha256.as_deref(),
        Some(ovenmitt::crypto::sha256_hex(&body).as_str())
    );
    assert!(entries.iter().any(|e| e.draft.event == Event::Export
        && e.draft.reason.as_deref() == Some("PATH_ESCAPE")
        || e.draft.reason.as_deref() == Some("FILENAME_INVALID")));
    d.stop().await;
}

// AT-7: read-path sweep — no route returns bytes without a credential.
// AT-13 / SI-6 / SI-8: topology and content never leak via responses or log.
#[tokio::test(flavor = "multi_thread")]
async fn no_route_returns_content_and_nothing_leaks_topology() {
    let d = TestDaemon::start().await;
    let body = sentinel();
    let handle = d.put_ok("private", &body).await;
    let export = serde_json::json!({"destination":"archive","filename":"leak-test.txt"})
        .to_string()
        .into_bytes();
    let probes: Vec<(&str, String, Option<Vec<u8>>)> = vec![
        ("GET", "/v1/health".into(), None),
        ("GET", "/v1/vaults".into(), None),
        ("GET", "/v1/vaults/private/destinations".into(), None),
        ("GET", "/v1/objects".into(), None),
        ("GET", "/v1/objects?vault=private".into(), None),
        ("GET", format!("/v1/objects/{handle}"), None),
        (
            "PATCH",
            format!("/v1/objects/{handle}"),
            Some(br#"{"labels":["z"]}"#.to_vec()),
        ),
        (
            "POST",
            format!("/v1/objects/{handle}/export"),
            Some(export.clone()),
        ),
        ("POST", format!("/v1/objects/{handle}/export"), Some(export)), // EXISTS path
        (
            "POST",
            format!("/v1/objects/{handle}/export"),
            Some(br#"{"destination":"team-chat","filename":"a"}"#.to_vec()),
        ),
        (
            "POST",
            format!("/v1/objects/{handle}/resolve"),
            Some(br#"{"destination":"team-chat","target":"x"}"#.to_vec()),
        ),
        ("GET", format!("/v1/objects/{handle}/body"), None),
        ("GET", format!("/v1/objects/{handle}/content"), None),
        ("GET", format!("/v1/objects/{handle}/download"), None),
        ("GET", format!("/v1/objects/{handle}?raw=1"), None),
        ("HEAD", format!("/v1/objects/{handle}"), None),
        ("OPTIONS", "/v1/objects".into(), None),
        ("GET", "/".into(), None),
        ("GET", "/v1".into(), None),
        ("GET", "/v2/objects".into(), None),
    ];
    for (m, p, b) in probes {
        let r = d.call(m, &p, &[], b).await;
        let all = format!("{:?}{}", r.headers, r.text());
        assert!(!contains(all.as_bytes(), &body), "{m} {p}: content leaked");
        assert!(
            !all.contains(&d.secrets.root_marker),
            "{m} {p}: root leaked: {all}"
        );
        assert!(
            !all.contains(&d.secrets.pattern_marker),
            "{m} {p}: pattern leaked: {all}"
        );
        assert!(
            !all.contains(&ovenmitt::crypto::sha256_hex(&body)),
            "{m} {p}: hash leaked"
        );
        assert!(
            !all.contains(d.data_dir.to_str().unwrap()),
            "{m} {p}: storage path leaked"
        );
    }
    let log = d.audit_text();
    assert!(!contains(log.as_bytes(), &body));
    assert!(!log.contains(&d.secrets.root_marker));
    assert!(!log.contains(&d.secrets.pattern_marker));
    assert!(!log.contains(d.data_dir.to_str().unwrap()));
    assert!(
        log.contains(&ovenmitt::crypto::sha256_hex(&body)),
        "hash IS in the log (audit-only)"
    );
    d.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn large_put_streams_and_reads_back_through_the_store() {
    let d = TestDaemon::start().await;
    let big: Vec<u8> = (0..(3 << 20) + 123).map(|i| (i % 253) as u8).collect();
    let handle = d.put_ok("private", &big).await;
    let r = d
        .call("GET", &format!("/v1/objects/{handle}"), &[], None)
        .await;
    assert_eq!(r.json()["size"], big.len());
    let export = serde_json::json!({"destination":"archive","filename":"big.bin"})
        .to_string()
        .into_bytes();
    let r = d
        .call(
            "POST",
            &format!("/v1/objects/{handle}/export"),
            &[],
            Some(export),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(std::fs::read(d.export_root.join("big.bin")).unwrap(), big);
    d.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn raw_http_is_plain_http_1_1() {
    // Sanity: the wire really is HTTP/1.1 over the socket, usable by curl.
    let d = TestDaemon::start().await;
    let reply = d
        .raw_exchange(b"GET /v1/health HTTP/1.1\r\nhost: ovenmitt\r\nconnection: close\r\n\r\n")
        .await;
    assert!(reply.starts_with("HTTP/1.1 200 OK"), "{reply}");
    assert!(reply.contains("\"status\":\"ok\""), "{reply}");
    let mut s = d.raw().await;
    s.write_all(b"GET /v1/vaults HTTP/1.1\r\nhost: x\r\nx-ovenmitt-protocol: 1\r\nconnection: close\r\n\r\n").await.unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).await.unwrap();
    assert!(out.contains("\"name\":\"private\""), "{out}");
    d.stop().await;
}
