//! The one path from a handler's result to an audit entry and an HTTP
//! response (DEVELOPMENT.md §7 "Outcome path").
//!
//! Every handler builds a [`Ctx`] as it learns things (vault, handle, dest…)
//! and returns `Result<Response, ApiError>`. [`finish`] is the only place
//! that writes the audit entry and the only place that turns an error into a
//! response, so "exactly one entry per refusal, durable before the response"
//! (SI-7, R-AUD-6) holds by construction rather than by discipline.

use axum::response::{IntoResponse, Response};

use super::AppState;
use super::error::{ApiError, Code};
use super::peer::PeerInfo;
use crate::audit::{Caller, Draft, Event, Outcome};
use crate::store::Expired;

/// What's known about an operation so far.
#[derive(Debug)]
pub struct Ctx {
    pub draft: Draft,
    /// Whether a *successful* outcome is logged. Reads (stat, list, …) are
    /// not; their refusals still are, as `request` events.
    pub log_success: bool,
}

impl Ctx {
    /// An audited operation (put, replace, delete, export, resolve, label).
    pub fn op(event: Event, peer: PeerInfo) -> Self {
        Self {
            draft: Draft::new(event, Outcome::Ok, Caller::peer(peer.uid, peer.pid)),
            log_success: true,
        }
    }

    /// A read: success is silent, refusal is logged as a `request`.
    pub fn read(peer: PeerInfo) -> Self {
        Self {
            draft: Draft::new(
                Event::Request,
                Outcome::Ok,
                Caller::peer(peer.uid, peer.pid),
            ),
            log_success: false,
        }
    }
}

/// Write the audit entry the result calls for, then build the response.
pub async fn finish(
    state: &AppState,
    mut ctx: Ctx,
    result: Result<Response, ApiError>,
) -> Response {
    match result {
        Ok(resp) => {
            if ctx.log_success {
                ctx.draft.outcome = Outcome::Ok;
                if let Err(e) = state.audit.append(ctx.draft).await {
                    tracing::error!("audit append failed: {e}");
                    return ApiError::new(Code::Internal).into_response();
                }
            }
            resp
        }
        Err(err) => {
            let outcome = if err.is_refusal() {
                Some(Outcome::Refused)
            } else if err.code == Code::Aborted {
                Some(Outcome::Aborted)
            } else {
                None
            };
            if let Some(outcome) = outcome {
                ctx.draft.outcome = outcome;
                ctx.draft.reason = Some(err.code.as_str().to_owned());
                if !ctx.log_success {
                    ctx.draft.event = Event::Request;
                }
                if let Err(e) = state.audit.append(ctx.draft).await {
                    tracing::error!("audit append failed: {e}");
                    return ApiError::new(Code::Internal).into_response();
                }
            } else {
                tracing::warn!(
                    "{}: {}",
                    err.code.as_str(),
                    err.about.as_deref().unwrap_or("")
                );
            }
            err.into_response()
        }
    }
}

/// Log an object the daemon removed because its TTL passed (R-OBJ-6).
pub async fn log_expired(state: &AppState, gone: &Expired) {
    let mut d = Draft::new(Event::Expire, Outcome::Ok, Caller::daemon());
    d.vault = Some(gone.vault.clone());
    d.handle = Some(gone.handle.clone());
    d.sha256 = Some(gone.sha256.clone());
    d.size = Some(gone.size);
    if let Err(e) = state.audit.append(d).await {
        tracing::error!("audit append (expire) failed: {e}");
    }
}
