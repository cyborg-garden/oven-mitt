//! The HTTP API over the Unix socket (PRD §4). This file holds the one
//! routing table; a reviewer can confirm from it alone that `resolve` is
//! the only route returning object bytes and the only one reading
//! `Authorization` (SI-1).

pub mod error;
pub mod export;
pub mod objects;
pub mod outcome;
pub mod peer;
pub mod vaults;

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderValue, Method, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};

use crate::audit::writer::AuditLog;
use crate::config::Config;
use crate::store::Store;
use error::{ApiError, Code};
use outcome::{Ctx, finish};
use peer::PeerInfo;

/// Protocol version this daemon speaks (R-FAC-4).
pub const PROTOCOL: &str = "1";
pub const PROTOCOL_HEADER: &str = "x-ovenmitt-protocol";

/// Shared state for every handler.
#[derive(Clone)]
pub struct AppState {
    pub store: Arc<Store>,
    pub audit: AuditLog,
    pub config: Arc<Config>,
}

impl std::fmt::Debug for AppState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AppState")
    }
}

/// The routing table (PRD §4.2), in the PRD's order.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/v1/health", get(vaults::health))
        .route("/v1/vaults", get(vaults::list_vaults))
        .route(
            "/v1/vaults/{vault}/destinations",
            get(vaults::list_destinations),
        )
        .route("/v1/vaults/{vault}/objects", post(objects::put))
        .route(
            "/v1/objects/{handle}",
            get(objects::stat)
                .put(objects::replace)
                .patch(objects::label)
                .delete(objects::delete),
        )
        .route("/v1/objects", get(objects::list))
        .route("/v1/objects/{handle}/export", post(export::export))
        .fallback(fallback)
        .method_not_allowed_fallback(fallback)
        .layer(middleware::from_fn_with_state(state.clone(), guard))
        .layer(middleware::map_response(stamp_protocol))
        .with_state(state)
}

/// Unknown route or method: refused and audited as a `request` (R-AUD-4).
async fn fallback(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<PeerInfo>,
) -> Response {
    finish(&state, Ctx::read(peer), Err(ApiError::no_route())).await
}

/// Requests must carry `X-Ovenmitt-Protocol: 1` (R-FAC-4), and routes that
/// take no body get none (§4.1). Both are refusals, audited. `/v1/health`
/// is exempt from the header so `curl` and container healthchecks stay
/// one-liners.
async fn guard(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<PeerInfo>,
    req: Request,
    next: Next,
) -> Response {
    let path = req.uri().path();
    if path != "/v1/health" {
        let ok = req
            .headers()
            .get(PROTOCOL_HEADER)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.trim() == PROTOCOL);
        if !ok {
            return finish(
                &state,
                Ctx::read(peer),
                Err(Code::ProtocolUnsupported.into()),
            )
            .await;
        }
    }
    let bodiless = matches!(*req.method(), Method::GET | Method::DELETE | Method::HEAD);
    if bodiless {
        let has_body = req
            .headers()
            .get(header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok())
            .is_some_and(|n| n > 0)
            || req.headers().contains_key(header::TRANSFER_ENCODING);
        if has_body {
            return finish(&state, Ctx::read(peer), Err(Code::InvalidRequest.into())).await;
        }
    }
    // Run the handler on its own task so it completes — and its audit entry
    // lands — even if the client disconnects and hyper drops this future
    // (R-AUD-6, SI-7). The spawned task owns the request body.
    match tokio::spawn(next.run(req)).await {
        Ok(resp) => resp,
        Err(_) => ApiError::new(Code::Internal).into_response(),
    }
}

async fn stamp_protocol(mut resp: Response) -> Response {
    resp.headers_mut()
        .insert(PROTOCOL_HEADER, HeaderValue::from_static(PROTOCOL));
    resp
}

/// Run a blocking store call on the blocking pool.
pub(crate) async fn blocking<T, F>(f: F) -> Result<T, ApiError>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|_| ApiError::new(Code::Internal))
}

/// Parse a JSON request body into `T`, refusing anything malformed.
pub(crate) async fn json_body<T: serde::de::DeserializeOwned>(body: Body) -> Result<T, ApiError> {
    let bytes = axum::body::to_bytes(body, 64 * 1024)
        .await
        .map_err(|_| ApiError::new(Code::InvalidRequest))?;
    serde_json::from_slice(&bytes).map_err(|_| ApiError::new(Code::InvalidRequest))
}

/// `200 OK` with a JSON body, in the `Result` shape handlers return.
#[allow(clippy::unnecessary_wraps)]
pub(crate) fn json<T: serde::Serialize>(value: &T) -> Result<Response, ApiError> {
    Ok(axum::Json(value).into_response())
}
