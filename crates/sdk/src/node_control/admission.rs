//! Transport admission only: an allowed endpoint must still prove its application
//! credential and obtain authorization for every operation from the node writer.
use hellas_rpc::services::host_control::HostControl;
use hellas_wire::{ServiceMarker, WireCode, WireStatus};
use iroh::{
    EndpointId,
    endpoint::{AfterHandshakeOutcome, Connection, EndpointHooks, Side},
};
use std::{collections::BTreeSet, sync::Arc};

/// Explicit, bounded remote control ingress. Empty by default; there is no
/// unauthenticated enrollment listener. Install this hook on the hosting endpoint
/// and pass the same value to `NodeControl::with_remote_admission`.
#[derive(Clone, Debug, Default)]
pub struct RemoteControlAdmission {
    peers: Arc<BTreeSet<EndpointId>>,
    public: bool,
}

impl RemoteControlAdmission {
    pub fn new(peers: Vec<EndpointId>) -> Result<Self, WireStatus> {
        let count = peers.len();
        let peers: BTreeSet<_> = peers.into_iter().collect();
        if count > 128 || count != peers.len() {
            return Err(WireStatus::new(
                WireCode::InvalidArgument,
                "remote control requires at most 128 distinct endpoint keys",
            ));
        }
        Ok(Self { peers: Arc::new(peers), public: false })
    }

    /// Explicitly enable public transport ingress. Every peer must still prove
    /// its application credential and holder before any operation is dispatched.
    pub fn credential_gated() -> Self {
        Self { peers: Arc::default(), public: true }
    }

    pub fn enabled(&self) -> bool {
        self.public || !self.peers.is_empty()
    }

    pub(super) fn allows(&self, peer: EndpointId) -> bool {
        self.public || self.peers.contains(&peer)
    }
}

impl EndpointHooks for RemoteControlAdmission {
    async fn after_handshake(&self, connection: &Connection) -> AfterHandshakeOutcome {
        if connection.side() == Side::Server
            && connection.alpn() == HostControl::ALPN.as_bytes()
            && !self.allows(connection.remote_id())
        {
            AfterHandshakeOutcome::Reject {
                error_code: 403u32.into(),
                reason: b"remote control endpoint is not admitted".to_vec(),
            }
        } else {
            AfterHandshakeOutcome::accept()
        }
    }
}
