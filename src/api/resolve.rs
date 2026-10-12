//! `POST /v1/objects/{handle}/resolve` (PRD R-RES-1..5).
//!
//! The only route that returns object bytes, and the only one that reads
//! `Authorization`. Checks run in the R-RES-2 order so a caller learns the
//! least: an invalid credential never finds out whether the handle exists.
//! The audit entry (with destination and target) is written by the outcome
//! path *before* the first body byte leaves (R-AUD-6).

use axum::body::Body;
use axum::extract::{ConnectInfo, Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use bytes::Bytes;
use serde::Deserialize;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

use super::error::{ApiError, Code};
use super::outcome::{Ctx, finish, log_expired};
use super::peer::PeerInfo;
use super::{AppState, blocking, json_body};
use crate::audit::Event;
use crate::config::{Destination, valid_name};
use crate::handle::Handle;
use crate::store::StoreError;
use crate::time::now_ms;

pub const H_DESTINATION: &str = "x-ovenmitt-destination";
const MAX_TARGET_BYTES: usize = 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolveBody {
    destination: String,
    target: String,
}

fn bearer(headers: &HeaderMap) -> Result<Option<String>, ApiError> {
    let Some(v) = headers.get(header::AUTHORIZATION) else {
        return Ok(None);
    };
    let s = v
        .to_str()
        .map_err(|_| ApiError::new(Code::CredentialInvalid))?;
    let token = s
        .strip_prefix("Bearer ")
        .or_else(|| s.strip_prefix("bearer "))
        .ok_or_else(|| ApiError::new(Code::CredentialInvalid))?;
    Ok(Some(token.trim().to_owned()))
}

pub async fn resolve(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<PeerInfo>,
    Path(handle): Path<String>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let mut ctx = Ctx::op(Event::Resolve, peer);
    let result = resolve_inner(&state, &mut ctx, &handle, &headers, body).await;
    finish(&state, ctx, result).await
}

async fn resolve_inner(
    state: &AppState,
    ctx: &mut Ctx,
    handle: &str,
    headers: &HeaderMap,
    body: Body,
) -> Result<Response, ApiError> {
    let handle = Handle::parse(handle).map_err(|_| ApiError::new(Code::InvalidRequest))?;
    ctx.draft.handle = Some(handle.clone());

    // 1. credential present
    let token = bearer(headers)?.ok_or_else(|| ApiError::new(Code::CredentialRequired))?;
    // 2. credential valid and not revoked
    let cred = state
        .credentials
        .check(&token)
        .map_err(|_| ApiError::new(Code::CredentialInvalid))?;
    ctx.draft.caller.cred = Some(cred.id.clone());

    let req: ResolveBody = json_body(body).await?;
    if !valid_name(&req.destination) {
        return Err(Code::DestinationNotFound.into());
    }
    if req.target.is_empty()
        || req.target.len() > MAX_TARGET_BYTES
        || req.target.chars().any(char::is_control)
    {
        return Err(Code::InvalidRequest.into());
    }
    ctx.draft.dest = Some(req.destination.clone());

    // object exists (expire-on-access)
    let store = state.store.clone();
    let h = handle.clone();
    let info = match blocking(move || store.stat(&h, now_ms())).await? {
        Ok(info) => info,
        Err(StoreError::Expired(gone)) => {
            log_expired(state, &gone).await;
            return Err(Code::NotFound.into());
        }
        Err(e) => return Err(e.into()),
    };
    ctx.draft.vault = Some(info.vault.clone());

    // 3. credential scoped to the vault
    if !cred.vaults.permits(&info.vault) {
        return Err(Code::CredentialNotPermitted.into());
    }
    // 4. destination exists in that vault
    let vault = state
        .store
        .vault(&info.vault)
        .ok_or_else(|| ApiError::new(Code::VaultNotFound))?;
    let dest = vault
        .destinations
        .get(&req.destination)
        .ok_or_else(|| ApiError::new(Code::DestinationNotFound).about(&req.destination))?;
    // 5. kind is send
    let (pattern, max_size) = match dest {
        Destination::Send { pattern, max_size } => (pattern, *max_size),
        Destination::Fs { .. } => {
            return Err(ApiError::new(Code::DestinationKindMismatch).about(&req.destination));
        }
    };
    // 6. target matches
    if !pattern.matches(&req.target) {
        return Err(ApiError::new(Code::TargetNotAllowed).about(&req.destination));
    }
    // The target is audited (F-27) but never echoed in any response.
    ctx.draft.target = Some(req.target.clone());
    // 7. size limit
    if max_size.is_some_and(|m| info.size > m) {
        return Err(Code::TooLarge.into());
    }

    // Open the body and record the hash for the audit entry.
    let store = state.store.clone();
    let h = handle.clone();
    let (reader, meta) = blocking(move || store.open_body(&h, now_ms())).await??;
    ctx.draft.sha256 = state.store.operator_stat(&handle).map(|(_, p)| p.sha256);
    ctx.draft.size = Some(meta.size);

    // Stream plaintext chunks from the blocking reader into the response.
    let (tx, rx) = mpsc::channel::<Result<Bytes, std::io::Error>>(4);
    tokio::task::spawn_blocking(move || {
        let mut reader = reader;
        loop {
            match reader.next_chunk() {
                Ok(Some(chunk)) => {
                    if tx.blocking_send(Ok(Bytes::from(chunk))).is_err() {
                        break;
                    }
                }
                Ok(None) => break,
                Err(e) => {
                    let _ = tx.blocking_send(Err(std::io::Error::other(e.to_string())));
                    break;
                }
            }
        }
    });
    let body = Body::from_stream(ReceiverStream::new(rx));
    let mut resp = (StatusCode::OK, body).into_response();
    let hdrs = resp.headers_mut();
    hdrs.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(&meta.mime)
            .unwrap_or(HeaderValue::from_static("application/octet-stream")),
    );
    hdrs.insert(header::CONTENT_LENGTH, HeaderValue::from(meta.size));
    hdrs.insert(
        H_DESTINATION,
        HeaderValue::from_str(&req.destination).unwrap_or(HeaderValue::from_static("")),
    );
    Ok(resp)
}
