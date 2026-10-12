#![allow(clippy::unwrap_used, clippy::expect_used, dead_code)]
//! Test harness: a daemon in-process on a temp socket, and a raw HTTP/1.1
//! client over the Unix socket (so the tests exercise the real wire, not
//! the Python client).

use std::path::PathBuf;

use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use ovenmitt::audit::Entry;
use ovenmitt::config::{Config, FsChecks};
use ovenmitt::daemon::{Prepared, prepare_with};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::oneshot;

/// A random printable sentinel; per test, never a constant (DEVELOPMENT.md §10).
pub fn sentinel() -> Vec<u8> {
    let mut b = [0u8; 64];
    getrandom::fill(&mut b).unwrap();
    b.iter().map(|x| b'a' + (x % 26)).collect()
}

pub fn sentinel_str() -> String {
    String::from_utf8(sentinel()).unwrap()
}

pub fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// Sentinels baked into the operator's topology, so leak tests can grep
/// for them (SI-6, SI-8).
pub struct Secrets {
    pub root_marker: String,
    pub pattern_marker: String,
}

pub struct TestDaemon {
    pub dir: tempfile::TempDir,
    pub socket: PathBuf,
    pub data_dir: PathBuf,
    pub keys_dir: PathBuf,
    pub audit_log: PathBuf,
    pub export_root: PathBuf,
    pub export_root_rw: PathBuf,
    pub secrets: Secrets,
    pub config: Config,
    shutdown: Option<oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<Result<(), std::io::Error>>>,
}

pub struct Options {
    pub ttl: Option<&'static str>,
    pub max_object_size: Option<&'static str>,
    pub sweep: &'static str,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            ttl: None,
            max_object_size: None,
            sweep: "1h",
        }
    }
}

impl TestDaemon {
    pub async fn start() -> Self {
        Self::start_with(Options::default()).await
    }

    pub async fn start_with(opts: Options) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root_marker = format!("rootmark{}", sentinel_str());
        let pattern_marker = format!("patmark{}", sentinel_str());
        let export_root = dir.path().join(&root_marker);
        let export_root_rw = dir.path().join(format!("{root_marker}-rw"));
        std::fs::create_dir(&export_root).unwrap();
        std::fs::create_dir(&export_root_rw).unwrap();
        let socket = dir.path().join("sock/ovenmitt.sock");
        let data_dir = dir.path().join("data");
        let keys_dir = dir.path().join("keys");
        let audit_log = dir.path().join("audit/audit.jsonl");
        let ttl = opts
            .ttl
            .map(|t| format!("ttl = \"{t}\"\n"))
            .unwrap_or_default();
        let max = opts
            .max_object_size
            .map(|m| format!("max_object_size = \"{m}\"\n"))
            .unwrap_or_default();
        let src = format!(
            r#"
[daemon]
socket = "{socket}"
data_dir = "{data}"
keys_dir = "{keys}"
audit_log = "{audit}"
credentials = "{creds}"
ttl_sweep_interval = "{sweep}"

[vault.private]
expose_names = true
{ttl}{max}
[vault.private.destinations.archive]
kind = "fs"
root = "{root}"

[vault.private.destinations.archive-rw]
kind = "fs"
root = "{root_rw}"
overwrite = true

[vault.private.destinations.team-chat]
kind = "send"
match = "chat:group/{pat}"

[vault.private.destinations.any-dm]
kind = "send"
match = "chat:dm/*"
max_size = "100B"

[vault.hidden]
expose_names = false
"#,
            socket = socket.display(),
            data = data_dir.display(),
            keys = keys_dir.display(),
            audit = audit_log.display(),
            creds = dir.path().join("credentials.toml").display(),
            sweep = opts.sweep,
            root = export_root.display(),
            root_rw = export_root_rw.display(),
            pat = pattern_marker,
        );
        let config = Config::parse(&src, FsChecks::Yes).unwrap();
        let cfg2 = config.clone();
        let prepared: Prepared = tokio::task::spawn_blocking(move || prepare_with(cfg2, "test"))
            .await
            .unwrap()
            .unwrap();
        let (tx, rx) = oneshot::channel();
        let task = tokio::spawn(prepared.serve(rx));
        // wait for the socket to accept
        for _ in 0..100 {
            if UnixStream::connect(&socket).await.is_ok() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        Self {
            dir,
            socket,
            data_dir,
            keys_dir,
            audit_log,
            export_root,
            export_root_rw,
            secrets: Secrets {
                root_marker,
                pattern_marker,
            },
            config,
            shutdown: Some(tx),
            task: Some(task),
        }
    }

    /// Stop the daemon. Returns the temp dir so a test can keep inspecting
    /// files after shutdown; dropping it removes everything.
    pub async fn stop(mut self) -> tempfile::TempDir {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(t) = self.task.take() {
            let _ = tokio::time::timeout(std::time::Duration::from_secs(5), t).await;
        }
        std::mem::replace(&mut self.dir, tempfile::tempdir().unwrap())
    }

    /// One request, one connection. Headers given as (name, value).
    pub async fn request(
        &self,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: Option<Vec<u8>>,
    ) -> Reply {
        let stream = UnixStream::connect(&self.socket).await.unwrap();
        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .unwrap();
        tokio::spawn(conn);
        let mut req = Request::builder()
            .method(method)
            .uri(path)
            .header("host", "ovenmitt");
        for (k, v) in headers {
            req = req.header(*k, *v);
        }
        let req = req
            .body(Full::new(Bytes::from(body.unwrap_or_default())))
            .unwrap();
        let resp: Response<hyper::body::Incoming> = sender.send_request(req).await.unwrap();
        let status = resp.status();
        let headers = resp.headers().clone();
        let body = resp
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec();
        Reply {
            status,
            headers,
            body,
        }
    }

    /// Request with the protocol header already set.
    pub async fn call(
        &self,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: Option<Vec<u8>>,
    ) -> Reply {
        let mut h = vec![("x-ovenmitt-protocol", "1")];
        h.extend_from_slice(headers);
        self.request(method, path, &h, body).await
    }

    pub async fn put(&self, vault: &str, body: &[u8], headers: &[(&str, &str)]) -> Reply {
        let mut h = vec![("content-type", "text/plain")];
        h.extend_from_slice(headers);
        self.call(
            "POST",
            &format!("/v1/vaults/{vault}/objects"),
            &h,
            Some(body.to_vec()),
        )
        .await
    }

    /// Put and return the handle.
    pub async fn put_ok(&self, vault: &str, body: &[u8]) -> String {
        let r = self.put(vault, body, &[]).await;
        assert_eq!(r.status, StatusCode::CREATED, "{}", r.text());
        r.json()["handle"].as_str().unwrap().to_owned()
    }

    /// A raw connection for hand-written HTTP (partial bodies, etc.).
    pub async fn raw(&self) -> UnixStream {
        UnixStream::connect(&self.socket).await.unwrap()
    }

    /// Write raw bytes and read until the server closes or `timeout`.
    pub async fn raw_exchange(&self, bytes: &[u8]) -> String {
        let mut s = self.raw().await;
        s.write_all(bytes).await.unwrap();
        let mut out = Vec::new();
        let _ =
            tokio::time::timeout(std::time::Duration::from_secs(2), s.read_to_end(&mut out)).await;
        String::from_utf8_lossy(&out).into_owned()
    }

    pub fn audit_entries(&self) -> Vec<Entry> {
        ovenmitt::audit::verify::verify_file(&self.audit_log).unwrap();
        ovenmitt::audit::verify::read_entries(&self.audit_log).unwrap()
    }

    pub fn audit_text(&self) -> String {
        std::fs::read_to_string(&self.audit_log).unwrap_or_default()
    }

    /// Every file under a directory, recursively.
    pub fn files_under(root: &std::path::Path) -> Vec<PathBuf> {
        let mut out = Vec::new();
        if let Ok(rd) = std::fs::read_dir(root) {
            for e in rd.flatten() {
                let p = e.path();
                if p.is_dir() {
                    out.extend(Self::files_under(&p));
                } else {
                    out.push(p);
                }
            }
        }
        out
    }

    pub fn assert_absent_under(root: &std::path::Path, needle: &[u8]) {
        for f in Self::files_under(root) {
            let bytes = std::fs::read(&f).unwrap();
            assert!(
                !contains(&bytes, needle),
                "sentinel found in {}",
                f.display()
            );
        }
    }
}

#[derive(Debug)]
pub struct Reply {
    pub status: StatusCode,
    pub headers: hyper::HeaderMap,
    pub body: Vec<u8>,
}

impl Reply {
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
    pub fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).unwrap_or_else(|_| panic!("not json: {}", self.text()))
    }
    pub fn code(&self) -> String {
        self.json()["error"]["code"]
            .as_str()
            .unwrap_or("")
            .to_owned()
    }
}
