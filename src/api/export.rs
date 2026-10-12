//! `POST /v1/objects/{handle}/export` (PRD R-EXP). Credential-free by
//! design (F-26): the root is operator-fixed, so there is nothing for the
//! caller to lie about.

use axum::body::Body;
use axum::extract::{ConnectInfo, Path, State};
use axum::response::Response;
use serde::{Deserialize, Serialize};

use super::error::{ApiError, Code};
use super::outcome::{Ctx, finish, log_expired};
use super::peer::PeerInfo;
use super::{AppState, blocking, json, json_body};
use crate::audit::Event;
use crate::config::{Destination, valid_name};
use crate::handle::Handle;
use crate::store::StoreError;
use crate::time::now_ms;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportBody {
    destination: String,
    filename: String,
}

#[derive(Debug, Serialize)]
pub struct ExportResult {
    destination: String,
    filename: String,
    size: u64,
}

pub async fn export(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<PeerInfo>,
    Path(handle): Path<String>,
    body: Body,
) -> Response {
    let mut ctx = Ctx::op(Event::Export, peer);
    let result = export_inner(&state, &mut ctx, &handle, body).await;
    finish(&state, ctx, result).await
}

async fn export_inner(
    state: &AppState,
    ctx: &mut Ctx,
    handle: &str,
    body: Body,
) -> Result<Response, ApiError> {
    let handle = Handle::parse(handle).map_err(|_| ApiError::new(Code::InvalidRequest))?;
    ctx.draft.handle = Some(handle.clone());
    let req: ExportBody = json_body(body).await?;
    if !valid_name(&req.destination) {
        return Err(Code::DestinationNotFound.into());
    }
    ctx.draft.dest = Some(req.destination.clone());

    // Which vault is the object in? (expire-on-access applies)
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
    let vault = state
        .store
        .vault(&info.vault)
        .ok_or_else(|| ApiError::new(Code::VaultNotFound))?;
    let dest = vault
        .destinations
        .get(&req.destination)
        .ok_or_else(|| ApiError::new(Code::DestinationNotFound).about(&req.destination))?;
    let (root, overwrite) = match dest {
        Destination::Fs { root, overwrite } => (root.clone(), *overwrite),
        Destination::Send { .. } => {
            return Err(ApiError::new(Code::DestinationKindMismatch).about(&req.destination));
        }
    };

    let store = state.store.clone();
    let h = handle.clone();
    let filename = req.filename.clone();
    let exported =
        blocking(move || crate::export::export(&store, &h, &root, &filename, overwrite, now_ms()))
            .await??;
    ctx.draft.sha256 = Some(exported.sha256);
    ctx.draft.size = Some(exported.size);
    json(&ExportResult {
        destination: req.destination,
        filename: exported.filename,
        size: exported.size,
    })
}
