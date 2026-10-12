//! Read-only routes: health, vault list, destination list (R-VLT-4, R-DST-4).

use axum::extract::{ConnectInfo, Path, State};
use axum::response::Response;
use serde::Serialize;

use super::error::{ApiError, Code};
use super::outcome::{Ctx, finish};
use super::peer::PeerInfo;
use super::{AppState, json};
use crate::config::{Destination, valid_name};

#[derive(Debug, Serialize)]
pub struct Health {
    status: &'static str,
    protocol: u32,
}

pub async fn health() -> axum::Json<Health> {
    axum::Json(Health {
        status: "ok",
        protocol: 1,
    })
}

/// `VaultInfo` (PRD §4.3): name, `expose_names`, `ttl` — nothing else.
#[derive(Debug, Serialize)]
pub struct VaultInfo {
    pub name: String,
    pub expose_names: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<String>,
}

fn ttl_string(d: std::time::Duration) -> String {
    let s = d.as_secs();
    if s.is_multiple_of(86_400) {
        format!("{}d", s / 86_400)
    } else if s.is_multiple_of(3600) {
        format!("{}h", s / 3600)
    } else if s.is_multiple_of(60) {
        format!("{}m", s / 60)
    } else {
        format!("{s}s")
    }
}

pub async fn list_vaults(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<PeerInfo>,
) -> Response {
    let infos: Vec<VaultInfo> = state
        .store
        .vaults()
        .values()
        .map(|v| VaultInfo {
            name: v.name.clone(),
            expose_names: v.expose_names,
            ttl: v.ttl.map(ttl_string),
        })
        .collect();
    finish(&state, Ctx::read(peer), json(&infos)).await
}

/// `DestinationInfo` (PRD §4.3): name and kind. Never root, pattern,
/// overwrite or size limit (SI-15).
#[derive(Debug, Serialize)]
pub struct DestinationInfo {
    pub name: String,
    pub kind: &'static str,
}

pub async fn list_destinations(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<PeerInfo>,
    Path(vault): Path<String>,
) -> Response {
    let result = (|| {
        if !valid_name(&vault) {
            return Err(ApiError::new(Code::VaultNotFound));
        }
        let v = state
            .store
            .vault(&vault)
            .ok_or_else(|| ApiError::new(Code::VaultNotFound))?;
        let infos: Vec<DestinationInfo> = v
            .destinations
            .iter()
            .map(|(name, d)| DestinationInfo {
                name: name.clone(),
                kind: match d {
                    Destination::Fs { .. } => "fs",
                    Destination::Send { .. } => "send",
                },
            })
            .collect();
        json(&infos)
    })();
    finish(&state, Ctx::read(peer), result).await
}
