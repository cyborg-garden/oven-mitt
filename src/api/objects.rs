//! Object routes: put, replace, stat, list, label, delete
//! (PRD R-PUT, R-MET, R-OBJ).
//!
//! Put and replace stream: the request body is forwarded chunk by chunk to a
//! blocking task that owns the [`PutStream`] and encrypts as it goes. The
//! task commits only when it sees an explicit end marker; a dropped
//! connection closes the channel without one, the stream is dropped, and
//! the temp directory goes with it (R-OBJ-3).

use axum::body::Body;
use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use bytes::Bytes;
use futures_util::StreamExt;
use serde::Deserialize;
use tokio::sync::mpsc;

use super::error::{ApiError, Code};
use super::outcome::{Ctx, finish, log_expired};
use super::peer::PeerInfo;
use super::{AppState, blocking, json, json_body};
use crate::audit::Event;
use crate::config::valid_name;
use crate::handle::Handle;
use crate::store::{Committed, PutParams, PutStream, StoreError};
use crate::time::now_ms;

pub const H_NAME: &str = "x-ovenmitt-name";
pub const H_LABEL: &str = "x-ovenmitt-label";
pub const H_SHA256: &str = "x-ovenmitt-sha256";
pub const H_REMOVE_SOURCE: &str = "x-ovenmitt-remove-source-requested";

fn parse_handle(s: &str) -> Result<Handle, ApiError> {
    Handle::parse(s).map_err(|_| ApiError::new(Code::InvalidRequest))
}

/// Header values for names and labels are percent-encoded UTF-8, because
/// HTTP header values are ASCII and names are not.
fn decode_header(v: &header::HeaderValue) -> Result<String, ApiError> {
    let s = v
        .to_str()
        .map_err(|_| ApiError::new(Code::InvalidRequest))?;
    percent_encoding::percent_decode_str(s)
        .decode_utf8()
        .map(std::borrow::Cow::into_owned)
        .map_err(|_| ApiError::new(Code::InvalidRequest))
}

fn put_params(headers: &HeaderMap) -> Result<(PutParams, Option<bool>), ApiError> {
    let mime = headers
        .get(header::CONTENT_TYPE)
        .map(|v| v.to_str().map(str::to_owned))
        .transpose()
        .map_err(|_| ApiError::new(Code::InvalidRequest))?;
    let name = headers.get(H_NAME).map(decode_header).transpose()?;
    let labels: Vec<String> = headers
        .get_all(H_LABEL)
        .iter()
        .map(decode_header)
        .collect::<Result<_, _>>()?;
    let labels = if headers.contains_key(H_LABEL) {
        Some(labels)
    } else {
        None
    };
    let expected_sha256 = headers
        .get(H_SHA256)
        .map(|v| v.to_str().map(str::to_owned))
        .transpose()
        .map_err(|_| ApiError::new(Code::InvalidRequest))?;
    let remove_source = headers
        .get(H_REMOVE_SOURCE)
        .map(|v| v.to_str().map(|s| s.trim().eq_ignore_ascii_case("true")))
        .transpose()
        .map_err(|_| ApiError::new(Code::InvalidRequest))?;
    Ok((
        PutParams {
            name,
            mime,
            labels,
            expected_sha256,
        },
        remove_source,
    ))
}

enum Chunk {
    Data(Bytes),
    End,
}

/// Forward the body into a `PutStream` on the blocking pool and commit.
async fn stream_in(
    open: impl FnOnce() -> Result<PutStream, StoreError> + Send + 'static,
    body: Body,
) -> Result<Committed, ApiError> {
    let (tx, mut rx) = mpsc::channel::<Chunk>(8);
    let writer = tokio::task::spawn_blocking(move || -> Result<Committed, StoreError> {
        let mut stream = open()?;
        loop {
            match rx.blocking_recv() {
                Some(Chunk::Data(b)) => stream.write(&b)?,
                Some(Chunk::End) => break,
                None => return Err(StoreError::Io(std::io::Error::other("body ended early"))),
            }
        }
        stream.commit(now_ms())
    });
    let mut body = body.into_data_stream();
    let mut aborted = false;
    let mut send_failed = false;
    while let Some(next) = body.next().await {
        let Ok(chunk) = next else {
            aborted = true;
            break;
        };
        if tx.send(Chunk::Data(chunk)).await.is_err() {
            send_failed = true;
            break;
        }
    }
    if !aborted && !send_failed {
        let _ = tx.send(Chunk::End).await;
    }
    drop(tx);
    let result = writer.await.map_err(|_| ApiError::new(Code::Internal))?;
    match result {
        Ok(c) => Ok(c),
        Err(e) if aborted => {
            let _ = e;
            Err(ApiError::new(Code::Aborted))
        }
        Err(StoreError::Io(e)) if e.to_string().contains("body ended early") => {
            Err(ApiError::new(Code::Aborted))
        }
        Err(e) => Err(e.into()),
    }
}

/// `POST /v1/vaults/{vault}/objects` (R-PUT-1).
pub async fn put(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<PeerInfo>,
    Path(vault): Path<String>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let mut ctx = Ctx::op(Event::Put, peer);
    let result = put_inner(&state, &mut ctx, vault, &headers, body).await;
    finish(&state, ctx, result).await
}

async fn put_inner(
    state: &AppState,
    ctx: &mut Ctx,
    vault: String,
    headers: &HeaderMap,
    body: Body,
) -> Result<Response, ApiError> {
    if !valid_name(&vault) {
        return Err(Code::VaultNotFound.into());
    }
    ctx.draft.vault = Some(vault.clone());
    let (params, remove_source) = put_params(headers)?;
    ctx.draft.remove_source_requested = remove_source;
    let expose = state.store.vault(&vault).is_some_and(|v| v.expose_names);
    if expose {
        ctx.draft.name.clone_from(&params.name);
    }
    let store = state.store.clone();
    let v = vault.clone();
    let committed = stream_in(move || store.begin_put(&v, params), body).await?;
    ctx.draft.handle = Some(committed.info.handle.clone());
    ctx.draft.sha256 = Some(hex::encode(committed.digest.sha256));
    ctx.draft.size = Some(committed.digest.size);
    Ok((StatusCode::CREATED, axum::Json(committed.info)).into_response())
}

/// `PUT /v1/objects/{handle}` (R-OBJ-4).
pub async fn replace(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<PeerInfo>,
    Path(handle): Path<String>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let mut ctx = Ctx::op(Event::Replace, peer);
    let result = replace_inner(&state, &mut ctx, &handle, &headers, body).await;
    finish(&state, ctx, result).await
}

async fn replace_inner(
    state: &AppState,
    ctx: &mut Ctx,
    handle: &str,
    headers: &HeaderMap,
    body: Body,
) -> Result<Response, ApiError> {
    let handle = parse_handle(handle)?;
    ctx.draft.handle = Some(handle.clone());
    let (params, _) = put_params(headers)?;
    // Learn the vault (and expire-on-access) before streaming.
    let store = state.store.clone();
    let h = handle.clone();
    let current = blocking(move || store.stat(&h, now_ms())).await?;
    let current = match current {
        Ok(info) => info,
        Err(StoreError::Expired(gone)) => {
            log_expired(state, &gone).await;
            return Err(Code::NotFound.into());
        }
        Err(e) => return Err(e.into()),
    };
    ctx.draft.vault = Some(current.vault.clone());
    let expose = state
        .store
        .vault(&current.vault)
        .is_some_and(|v| v.expose_names);
    if expose {
        ctx.draft.name.clone_from(&params.name);
    }
    let store = state.store.clone();
    let h = handle.clone();
    let committed = stream_in(move || store.begin_replace(&h, params, now_ms()), body).await?;
    ctx.draft.sha256 = Some(hex::encode(committed.digest.sha256));
    ctx.draft.size = Some(committed.digest.size);
    json(&committed.info)
}

/// `GET /v1/objects/{handle}` (R-MET-1). Success is not audited.
pub async fn stat(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<PeerInfo>,
    Path(handle): Path<String>,
) -> Response {
    let mut ctx = Ctx::read(peer);
    let result = async {
        let handle = parse_handle(&handle)?;
        ctx.draft.handle = Some(handle.clone());
        let store = state.store.clone();
        match blocking(move || store.stat(&handle, now_ms())).await? {
            Ok(info) => json(&info),
            Err(StoreError::Expired(gone)) => {
                log_expired(&state, &gone).await;
                Err(Code::NotFound.into())
            }
            Err(e) => Err(e.into()),
        }
    }
    .await;
    finish(&state, ctx, result).await
}

#[derive(Debug, Deserialize)]
pub struct ListQuery {
    vault: Option<String>,
}

/// Hard cap on a single listing (R-MET-2).
pub const LIST_CAP: usize = 10_000;

/// `GET /v1/objects?vault=` (R-MET-2).
pub async fn list(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<PeerInfo>,
    Query(q): Query<ListQuery>,
) -> Response {
    let mut ctx = Ctx::read(peer);
    let result = async {
        if let Some(v) = &q.vault
            && !valid_name(v)
        {
            return Err(ApiError::new(Code::VaultNotFound));
        }
        ctx.draft.vault.clone_from(&q.vault);
        let store = state.store.clone();
        let vault = q.vault.clone();
        let infos = blocking(move || store.list(vault.as_deref(), now_ms())).await??;
        if infos.len() > LIST_CAP {
            return Err(Code::TooMany.into());
        }
        json(&infos)
    }
    .await;
    finish(&state, ctx, result).await
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LabelBody {
    labels: Vec<String>,
}

/// `PATCH /v1/objects/{handle}` (R-OBJ-8).
pub async fn label(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<PeerInfo>,
    Path(handle): Path<String>,
    body: Body,
) -> Response {
    let mut ctx = Ctx::op(Event::Label, peer);
    let result = async {
        let handle = parse_handle(&handle)?;
        ctx.draft.handle = Some(handle.clone());
        let req: LabelBody = json_body(body).await?;
        let store = state.store.clone();
        match blocking(move || store.label(&handle, req.labels, now_ms())).await? {
            Ok(info) => {
                ctx.draft.vault = Some(info.vault.clone());
                json(&info)
            }
            Err(StoreError::Expired(gone)) => {
                log_expired(&state, &gone).await;
                Err(Code::NotFound.into())
            }
            Err(e) => Err(e.into()),
        }
    }
    .await;
    finish(&state, ctx, result).await
}

/// `DELETE /v1/objects/{handle}` (R-OBJ-5).
pub async fn delete(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<PeerInfo>,
    Path(handle): Path<String>,
) -> Response {
    let mut ctx = Ctx::op(Event::Delete, peer);
    let result = async {
        let handle = parse_handle(&handle)?;
        ctx.draft.handle = Some(handle.clone());
        let store = state.store.clone();
        match blocking(move || store.delete(&handle, now_ms())).await? {
            Ok(gone) => {
                ctx.draft.vault = Some(gone.vault);
                ctx.draft.sha256 = Some(gone.sha256);
                ctx.draft.size = Some(gone.size);
                Ok(StatusCode::NO_CONTENT.into_response())
            }
            Err(StoreError::Expired(gone)) => {
                log_expired(&state, &gone).await;
                Err(Code::NotFound.into())
            }
            Err(e) => Err(e.into()),
        }
    }
    .await;
    finish(&state, ctx, result).await
}
