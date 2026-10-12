//! Daemon startup and serve loop (DEVELOPMENT.md §5).
//!
//! Each startup step is fatal on failure with one line on stderr. The
//! order matters: the store scan decides whether a vault may be given a new
//! key; the audit chain is verified before anything is appended.

use std::path::Path;
use std::sync::Arc;

use std::os::unix::net::UnixListener as StdUnixListener;

use tokio::net::UnixListener;
use tokio::sync::oneshot;

use crate::api::{self, AppState};
use crate::audit::writer::AuditLog;
use crate::audit::{Caller, Draft, Event, Outcome};
use crate::config::{Config, FsChecks};
use crate::crypto::sha256_hex;
use crate::keys::KeyStore;
use crate::store::Store;
use crate::time::now_ms;

/// Why the daemon could not start.
#[derive(Debug, thiserror::Error)]
pub enum StartError {
    #[error("config: {0}")]
    Config(String),
    #[error("{0}")]
    Store(#[from] crate::store::StoreError),
    #[error("{0}")]
    Keys(#[from] crate::keys::KeyError),
    #[error("audit log: {0}")]
    Audit(#[from] crate::audit::writer::AuditError),
    #[error("socket {path}: {source}")]
    Socket {
        path: String,
        #[source]
        source: std::io::Error,
    },
}

/// A started daemon: everything but the serve loop.
pub struct Prepared {
    pub state: AppState,
    listener: StdUnixListener,
}

impl std::fmt::Debug for Prepared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Prepared")
    }
}

/// Steps 1–7 of the startup sequence. Fully synchronous, so it can run
/// before a runtime exists (and from a blocking thread in tests).
pub fn prepare(config_path: &Path) -> Result<Prepared, StartError> {
    let config_text = std::fs::read_to_string(config_path)
        .map_err(|e| StartError::Config(format!("cannot read {}: {e}", config_path.display())))?;
    let config = Config::parse(&config_text, FsChecks::Yes)
        .map_err(|e| StartError::Config(format!("{}:{e}", config_path.display())))?;
    let config_sha256 = sha256_hex(config_text.as_bytes());
    prepare_with(config, &config_sha256)
}

/// Same as [`prepare`] from an already-parsed config (tests).
pub fn prepare_with(config: Config, config_sha256: &str) -> Result<Prepared, StartError> {
    let now = now_ms();
    // 2–4: keys, temp sweep, index, expiry.
    let keystore = KeyStore::open(&config.daemon.keys_dir)?;
    let (store, report) = Store::open(
        &config.daemon.data_dir,
        config.vaults.clone(),
        &keystore,
        now,
    )?;
    tracing::info!(
        objects = report.objects,
        swept_tmp = report.swept_tmp,
        expired = report.expired.len(),
        "store open"
    );

    // 5–6: audit chain, start entry, expiries found at startup.
    let (audit, chain) = AuditLog::open(&config.daemon.audit_log)?;
    tracing::info!(entries = chain.entries, head = %chain.head, "audit chain verified");
    let mut start = Draft::new(Event::Start, Outcome::Ok, Caller::daemon());
    start.config_sha256 = Some(config_sha256.to_owned());
    audit.append_blocking(start)?;
    for gone in &report.expired {
        let mut d = Draft::new(Event::Expire, Outcome::Ok, Caller::daemon());
        d.vault = Some(gone.vault.clone());
        d.handle = Some(gone.handle.clone());
        d.sha256 = Some(gone.sha256.clone());
        d.size = Some(gone.size);
        audit.append_blocking(d)?;
    }

    // 7: socket.
    let listener = bind_socket(&config)?;

    Ok(Prepared {
        state: AppState {
            store,
            audit,
            config: Arc::new(config),
        },
        listener,
    })
}

fn bind_socket(config: &Config) -> Result<StdUnixListener, StartError> {
    let path = &config.daemon.socket;
    let io = |source| StartError::Socket {
        path: path.display().to_string(),
        source,
    };
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(io)?;
    }
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(io(e)),
    }
    let listener = StdUnixListener::bind(path).map_err(io)?;
    listener.set_nonblocking(true).map_err(io)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            path,
            std::fs::Permissions::from_mode(config.daemon.socket_mode),
        )
        .map_err(io)?;
        if let Some(group) = &config.daemon.socket_group {
            chgrp(path, group).map_err(io)?;
        }
    }
    Ok(listener)
}

#[cfg(unix)]
fn chgrp(path: &Path, group: &str) -> std::io::Result<()> {
    // Resolve a numeric gid or a group name via `getent`-free parsing of
    // /etc/group; the daemon image is minimal and this avoids libc bindings.
    let gid: u32 = if let Ok(g) = group.parse() {
        g
    } else {
        let groups = std::fs::read_to_string("/etc/group")?;
        groups
            .lines()
            .find_map(|l| {
                let mut f = l.split(':');
                let name = f.next()?;
                let _pw = f.next()?;
                let gid = f.next()?.parse().ok()?;
                (name == group).then_some(gid)
            })
            .ok_or_else(|| std::io::Error::other(format!("unknown group {group:?}")))?
    };
    std::os::unix::fs::chown(path, None, Some(gid))
}

impl Prepared {
    /// Step 8: serve until `shutdown` resolves. Also runs the TTL sweep.
    ///
    /// The accept loop is ours rather than `axum::serve`'s for one reason:
    /// hyper's HTTP/1 server must run with `half_close(true)`, or a client
    /// that sends a request and closes its write side before the response
    /// has its request dropped unprocessed — and with it the audit entry a
    /// refusal must leave (R-AUD-6, SI-7).
    pub async fn serve(self, shutdown: oneshot::Receiver<()>) -> Result<(), std::io::Error> {
        let state = self.state;
        let sweeper = spawn_sweeper(state.clone());

        let listener = UnixListener::from_std(self.listener)?;
        let app = api::router(state.clone());
        let socket = state.config.daemon.socket.clone();
        tracing::info!(socket = %socket.display(), "serving");

        let mut connections = tokio::task::JoinSet::new();
        let mut shutdown = std::pin::pin!(shutdown);
        loop {
            tokio::select! {
                _ = &mut shutdown => break,
                accepted = listener.accept() => {
                    let (stream, _) = match accepted {
                        Ok(a) => a,
                        Err(e) => {
                            tracing::warn!("accept failed: {e}");
                            continue;
                        }
                    };
                    let peer = api::peer::PeerInfo::of(&stream);
                    let app = app.clone();
                    connections.spawn(async move {
                        let svc = hyper::service::service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                            let mut req = req.map(axum::body::Body::new);
                            req.extensions_mut().insert(axum::extract::ConnectInfo(peer));
                            let app = app.clone();
                            async move { tower::ServiceExt::oneshot(app, req).await }
                        });
                        let conn = hyper::server::conn::http1::Builder::new()
                            .half_close(true)
                            .keep_alive(true)
                            .serve_connection(hyper_util::rt::TokioIo::new(stream), svc);
                        if let Err(e) = conn.await {
                            tracing::debug!("connection ended: {e}");
                        }
                    });
                }
                Some(_) = connections.join_next(), if !connections.is_empty() => {}
            }
        }

        // Graceful: stop accepting, give in-flight requests a bounded time.
        tracing::info!("draining {} connection(s)", connections.len());
        let drain = async { while connections.join_next().await.is_some() {} };
        if tokio::time::timeout(std::time::Duration::from_secs(30), drain)
            .await
            .is_err()
        {
            tracing::warn!("drain timed out; aborting remaining connections");
            connections.abort_all();
        }
        sweeper.stop().await;
        let _ = std::fs::remove_file(&socket);
        Ok(())
    }
}

struct Sweeper {
    stop: oneshot::Sender<()>,
    task: tokio::task::JoinHandle<()>,
}

impl Sweeper {
    async fn stop(self) {
        let _ = self.stop.send(());
        let _ = self.task.await;
    }
}

fn spawn_sweeper(state: AppState) -> Sweeper {
    let interval = state.config.daemon.ttl_sweep_interval;
    let (stop, mut stop_rx) = oneshot::channel::<()>();
    let task = tokio::spawn(async move {
        let mut tick = tokio::time::interval(interval);
        tick.tick().await; // the first tick fires immediately; skip it
        loop {
            tokio::select! {
                _ = &mut stop_rx => break,
                _ = tick.tick() => {
                    let store = state.store.clone();
                    match tokio::task::spawn_blocking(move || store.sweep_expired(now_ms())).await {
                        Ok(Ok(gone)) => {
                            for g in &gone {
                                api::outcome::log_expired(&state, g).await;
                            }
                        }
                        Ok(Err(e)) => tracing::error!("ttl sweep failed: {e}"),
                        Err(e) => tracing::error!("ttl sweep task failed: {e}"),
                    }
                }
            }
        }
    });
    Sweeper { stop, task }
}

/// Serve a prepared daemon until SIGTERM/SIGINT. Called from `main` after
/// [`prepare`] has run *outside* the runtime (it blocks on the audit
/// writer, which a runtime thread must not do).
pub async fn run_prepared(prepared: Prepared) -> Result<(), StartError> {
    let (tx, rx) = oneshot::channel();
    tokio::spawn(async move {
        let ctrl_c = tokio::signal::ctrl_c();
        #[cfg(unix)]
        {
            let mut term =
                match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::error!("cannot listen for SIGTERM: {e}");
                        let _ = ctrl_c.await;
                        let _ = tx.send(());
                        return;
                    }
                };
            tokio::select! {
                _ = ctrl_c => {},
                _ = term.recv() => {},
            }
        }
        #[cfg(not(unix))]
        {
            let _ = ctrl_c.await;
        }
        tracing::info!("shutdown requested");
        let _ = tx.send(());
    });
    prepared.serve(rx).await.map_err(|e| StartError::Socket {
        path: "serve".into(),
        source: e,
    })
}
