//! Peer identity from `SO_PEERCRED` (PRD F-6). Recorded in the audit log
//! for forensics; nothing branches on it. In Docker every process in the
//! agent container shares one UID, so this cannot distinguish callers.

use tokio::net::UnixStream;

/// UID and PID of the connecting process, when the kernel tells us.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PeerInfo {
    pub uid: Option<u32>,
    pub pid: Option<u32>,
}

impl PeerInfo {
    /// Ask the kernel who is on the other end of the socket.
    pub fn of(stream: &UnixStream) -> Self {
        match stream.peer_cred() {
            Ok(cred) => Self {
                uid: Some(cred.uid()),
                pid: cred.pid().and_then(|p| u32::try_from(p).ok()),
            },
            Err(_) => Self::default(),
        }
    }
}
