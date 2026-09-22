//! `NodeHandler` impl for `hellas serve node`.
//!
//! Surfaces self-identity + uptime via `get_node_info` and a filtered
//! view of known peers via `get_known_peers`. Backed by the
//! `PeerDirectory` the server constructs at spawn time.
//!
//! Request peer identity is enforced before handler dispatch. Handler methods
//! receive only decoded request bodies, so `get_known_peers` applies the
//! directory disclosure policy with an anonymous requester.

use std::sync::Arc;
use std::time::Instant;

use hellas_rpc::call::WithTrailer;
use hellas_rpc::pb::swarm::{
    GetKnownPeersRequest, GetKnownPeersResponse, GetNodeInfoRequest, GetNodeInfoResponse,
};
use hellas_rpc::peers::{PeerDirectory, PeerId};
use hellas_rpc::services::node::NodeHandler;
use hellas_wire::{WireCode, WireStatus};
use iroh::EndpointId;

#[derive(Clone)]
pub struct NodeHandlerImpl {
    pub node_id: EndpointId,
    pub started_at: Instant,
    pub version: &'static str,
    pub build: Arc<str>,
    pub os: Arc<str>,
    pub graffiti: Arc<[u8]>,
    pub directory: Arc<PeerDirectory>,
}

impl NodeHandlerImpl {
    pub fn new(
        node_id: EndpointId,
        build: String,
        graffiti: Vec<u8>,
        directory: Arc<PeerDirectory>,
    ) -> Self {
        Self {
            node_id,
            started_at: Instant::now(),
            version: env!("CARGO_PKG_VERSION"),
            build: Arc::from(build),
            os: Arc::from(format!(
                "{}-{}",
                std::env::consts::ARCH,
                std::env::consts::OS
            )),
            graffiti: Arc::from(graffiti),
            directory,
        }
    }
}

#[allow(refining_impl_trait)]
impl NodeHandler for NodeHandlerImpl {
    async fn get_node_info(
        &self,
        _request: GetNodeInfoRequest,
    ) -> Result<WithTrailer<GetNodeInfoResponse>, WireStatus> {
        Ok(WithTrailer::new(GetNodeInfoResponse {
            node_id: self.node_id.to_string(),
            uptime_seconds: self.started_at.elapsed().as_secs(),
            version: self.version.to_string(),
            build: self.build.as_ref().to_string(),
            os: self.os.as_ref().to_string(),
            graffiti: self.graffiti.as_ref().to_vec(),
        }))
    }

    async fn get_known_peers(
        &self,
        request: GetKnownPeersRequest,
    ) -> Result<WithTrailer<GetKnownPeersResponse>, WireStatus> {
        // Handler methods do not receive transport identity; the directory
        // disclosure policy remains the gate for anonymous requesters.
        let requester = PeerId::default();
        const DISCLOSURE_LIMIT: usize = 64;
        let peers = self
            .directory
            .known_peers(requester, &request.service_alpn, DISCLOSURE_LIMIT)
            .map_err(|e| WireStatus::new(WireCode::Internal, format!("known peers: {e}")))?;
        Ok(WithTrailer::new(GetKnownPeersResponse {
            peer_ids: peers.into_iter().map(|id| id.as_bytes().to_vec()).collect(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hellas_rpc::peers::PeerDirectoryConfig;
    use iroh::{EndpointId, SecretKey};

    fn fake_endpoint_id() -> EndpointId {
        // Reproducible synthetic id; tests don't need a real iroh endpoint.
        let key = SecretKey::from_bytes(&[0xAA; 32]);
        key.public()
    }

    #[tokio::test]
    async fn get_node_info_populates_self_identity() {
        let id = fake_endpoint_id();
        let local_peer = PeerId::from_bytes(*id.as_bytes());
        let directory = Arc::new(PeerDirectory::with_config(
            local_peer,
            PeerDirectoryConfig::default(),
        ));
        let handler = NodeHandlerImpl::new(
            id,
            "abcdef0".to_string(),
            b"test-node-graffiti".to_vec(),
            directory,
        );
        let resp = handler
            .get_node_info(GetNodeInfoRequest {})
            .await
            .expect("get_node_info");
        let WithTrailer { response, .. } = resp;
        assert_eq!(response.node_id, id.to_string());
        assert_eq!(response.build, "abcdef0");
        assert_eq!(response.graffiti, b"test-node-graffiti");
        assert!(response.os.contains('-'));
        assert!(!response.version.is_empty());
        // Uptime monotonic; just-constructed handler reports < 1s.
        assert!(response.uptime_seconds <= 1);
    }

    #[tokio::test]
    async fn get_known_peers_returns_empty_on_fresh_directory() {
        let id = fake_endpoint_id();
        let local_peer = PeerId::from_bytes(*id.as_bytes());
        let directory = Arc::new(PeerDirectory::with_config(
            local_peer,
            PeerDirectoryConfig::default(),
        ));
        let handler = NodeHandlerImpl::new(id, String::new(), Vec::new(), directory);
        let resp = handler
            .get_known_peers(GetKnownPeersRequest {
                service_alpn: "hellas.swarm.v1.Node".into(),
            })
            .await
            .expect("get_known_peers");
        let WithTrailer { response, .. } = resp;
        assert!(response.peer_ids.is_empty(), "no peers observed yet");
    }
}
