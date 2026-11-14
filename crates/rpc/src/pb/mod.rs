//! Protobuf bindings for the Hellas protocol.
//!
//! Per-package message types are generated into `OUT_DIR` by the build
//! script (`prost-build` driven by `protox`). Each `.proto` package gets a
//! Rust module here with the matching nesting (`hellas::v1`,
//! `hellas::work::v1`, …) so prost's cross-package
//! references resolve.
//!
//! Service/method markers, typed client traits, and the server dispatchers
//! live in [`services`].

#[doc(hidden)]
pub mod hellas {
    pub mod content {
        pub mod v1 {
            include!(concat!(env!("OUT_DIR"), "/hellas.content.v1.rs"));
        }
    }
    pub mod resolve {
        pub mod v1 {
            include!(concat!(env!("OUT_DIR"), "/hellas.resolve.v1.rs"));
        }
    }
    #[cfg(feature = "execute")]
    #[allow(dead_code)]
    pub mod v1 {
        include!(concat!(env!("OUT_DIR"), "/hellas.v1.rs"));
    }

    #[cfg(feature = "fetch")]
    #[allow(dead_code)]
    pub mod fetch {
        pub mod v1 {
            include!(concat!(env!("OUT_DIR"), "/hellas.fetch.v1.rs"));
        }
    }

    #[cfg(feature = "swarm")]
    #[allow(dead_code)]
    pub mod swarm {
        pub mod v1 {
            include!(concat!(env!("OUT_DIR"), "/hellas.swarm.v1.rs"));
        }
    }

    #[cfg(feature = "chain")]
    #[allow(dead_code)]
    pub mod chain {
        pub mod v1 {
            include!(concat!(env!("OUT_DIR"), "/hellas.chain.v1.rs"));
        }
    }

    #[cfg(feature = "host-control")]
    #[allow(dead_code)]
    pub mod host {
        pub mod v1 {
            include!(concat!(env!("OUT_DIR"), "/hellas.host.v1.rs"));
        }
    }

    #[cfg(feature = "work")]
    #[allow(dead_code)]
    pub mod work {
        pub mod v1 {
            include!(concat!(env!("OUT_DIR"), "/hellas.work.v1.rs"));
        }
    }
}

pub use hellas::{content::v1 as content, resolve::v1 as resolve};

/// Re-exports of the Hellas core execution types (`hellas.v1`).
#[cfg(feature = "execute")]
pub mod execute {
    pub use crate::pb::hellas::v1::*;
}

/// Re-exports of `hellas.fetch.v1`.
#[cfg(feature = "fetch")]
pub mod fetch {
    pub use crate::pb::hellas::fetch::v1::*;
}

/// Re-exports of `hellas.swarm.v1`.
#[cfg(feature = "swarm")]
pub mod swarm {
    pub use crate::pb::hellas::swarm::v1::*;
}

/// Re-exports of `hellas.chain.v1`.
#[cfg(feature = "chain")]
pub mod chain {
    pub use crate::pb::hellas::chain::v1::*;
}

/// Re-exports of authenticated local and remote `hellas.host.v1` administration.
#[cfg(feature = "host-control")]
pub mod host {
    pub use crate::pb::hellas::host::v1::*;
}

#[cfg(feature = "work")]
mod work_refusal;

/// Work messages and routing selectors.
#[cfg(feature = "work")]
pub mod work {
    pub use super::work_refusal::Refusable;
    pub use crate::pb::hellas::work::v1::*;

    impl WorkRoute {
        /// Selects a grant channel; authority still requires its pinned principal.
        pub fn grant(channel: hellas_auth::Digest) -> Self {
            Self {
                funding_kind: FundingKind::Grant as i32,
                channel_id: channel.as_bytes().to_vec(),
            }
        }

        pub fn selects_grant(&self, channel: hellas_auth::Digest) -> bool {
            self.funding_kind == FundingKind::Grant as i32 && self.channel_id == channel.as_bytes()
        }

        /// Selects a payment-funded channel without granting authority to use it.
        pub fn payment(channel_id: hellas_auth::Digest) -> Self {
            Self {
                funding_kind: FundingKind::Payment as i32,
                channel_id: channel_id.as_bytes().to_vec(),
            }
        }

        /// Checks the routing selector before any journal lookup or release.
        pub fn selects_payment(&self, channel_id: hellas_auth::Digest) -> bool {
            self.funding_kind == FundingKind::Payment as i32
                && self.channel_id == channel_id.as_bytes()
        }
    }
}

/// Service / method markers, typed client traits, and server dispatchers.
/// Emitted by `build.rs`. Each block is `#[cfg(feature = "<pkg>")]`-gated
/// so unused services don't compile.
#[allow(unused_imports, dead_code, clippy::all)]
pub mod services {
    include!(concat!(env!("OUT_DIR"), "/hellas_rpc_services.rs"));
}

#[cfg(test)]
mod id_pins {
    #[allow(unused_imports)]
    use hellas_wire::{MethodMarker, ServiceMarker};

    #[cfg(feature = "work")]
    #[test]
    fn work_ids_are_stable() {
        use super::services::work::{
            AcceptWork, AdmitCertificate, GetStanding, Open, StreamResult, Work,
        };
        // Removing GrantRefusalCode::Credential rotates Work and every method
        // whose response contains WorkRefused. Open has no refusal and stays stable.
        assert_eq!(<Work as ServiceMarker>::SERVICE_ID, 0xcc363e2b);
        assert_eq!(<Open as MethodMarker>::METHOD_ID, 0x93cb0b39);
        assert_eq!(<AcceptWork as MethodMarker>::METHOD_ID, 0x2148fd40);
        assert_eq!(<GetStanding as MethodMarker>::METHOD_ID, 0x6f6bc033);
        assert_eq!(<StreamResult as MethodMarker>::METHOD_ID, 0xe127ef67);
        assert_eq!(<AdmitCertificate as MethodMarker>::METHOD_ID, 0x7d9a26a8);
    }

    /// The handshake carrier is its own service, so its ids are its own.
    ///
    /// Pinned separately from `Work` above for the reason both are
    /// pinned at all: these two services are mounted on different ALPNs
    /// and answered by different handlers, and a build that rotated one
    /// would otherwise be caught only by whichever of them a test
    /// happened to dial.
    #[cfg(feature = "work")]
    #[test]
    fn work_setup_ids_are_stable() {
        use super::services::work_setup::{ExchangeSetup, Open, RequestOffer, WorkSetup};
        // ExchangeSetup carries WorkRefused, so removing the credential refusal
        // rotates its method and service IDs. Open and RequestOffer stay stable.
        assert_eq!(<WorkSetup as ServiceMarker>::SERVICE_ID, 0x402f81f7);
        assert_eq!(<Open as MethodMarker>::METHOD_ID, 0xcbe4ebd5);
        assert_eq!(<ExchangeSetup as MethodMarker>::METHOD_ID, 0x22ad0cc7);
        assert_eq!(<RequestOffer as MethodMarker>::METHOD_ID, 0x97c491fd);
    }

    #[cfg(feature = "host-control")]
    #[test]
    fn host_control_ids_are_stable() {
        use super::services::host_control::{
            BindProvider, GrantControl, HostControl, IssueCredential, RevokeCredential, WorkControl,
        };
        // Configure, Watch and CancelJob replace the service-specific host controls.
        assert_eq!(<HostControl as ServiceMarker>::SERVICE_ID, 0xc822b1df);
        assert_eq!(<GrantControl as MethodMarker>::METHOD_ID, 0xc0e0_b21c);
        assert_eq!(<WorkControl as MethodMarker>::METHOD_ID, 0x995d_0334);
        assert_eq!(<IssueCredential as MethodMarker>::METHOD_ID, 0xf445_91c2);
        assert_eq!(<RevokeCredential as MethodMarker>::METHOD_ID, 0xe7b1_8b70);
        assert_eq!(<BindProvider as MethodMarker>::METHOD_ID, 0xcb33_75a9);
    }

    #[cfg(feature = "chain")]
    #[test]
    fn edge_index_schema_three_ids_are_stable() {
        use super::services::edge_index::{
            EdgeIndex, GetEdgeDetail, GetWorkChannelDetail, ListEdgeEvents, ListEdges,
        };
        // Schema 3, after the response window became block time: the
        // terms no longer carry `omit_response_blocks` and the pending
        // projection reports `response_deadline_ms`, which changes the
        // descriptor the service, detail and channel IDs are derived from.
        // That is the point of pinning them: a wire-visible change must be a
        // deliberate edit here, never a silent reshuffle.
        assert_eq!(<EdgeIndex as ServiceMarker>::SERVICE_ID, 0x394c580c);
        assert_eq!(<ListEdges as MethodMarker>::METHOD_ID, 0x8bc7cf02);
        assert_eq!(<GetEdgeDetail as MethodMarker>::METHOD_ID, 0x75dbc64d);
        assert_eq!(<ListEdgeEvents as MethodMarker>::METHOD_ID, 0xec962f60);
        assert_eq!(
            <GetWorkChannelDetail as MethodMarker>::METHOD_ID,
            0x26e6be03
        );
    }

    #[cfg(feature = "chain")]
    #[test]
    fn chain_ids_are_stable() {
        use super::services::light_client::{
            GetAppliedFinalizedBlock, GetObjectProofs, GetObjects, GetStateRoot, LightClient,
            SubmitWorkResponse, SubscribeFinalized,
        };
        // Removing GetProof, which no node answered, rotates the service
        // digest. SERVICE_ID is never sent: a call opens by METHOD_ID alone,
        // and every remaining method keeps its id, so 0x34db_04b6 peers
        // interoperate.
        assert_eq!(<LightClient as ServiceMarker>::SERVICE_ID, 0x3199_ff16);
        assert_eq!(
            <GetAppliedFinalizedBlock as MethodMarker>::METHOD_ID,
            0x6d407974
        );
        assert_eq!(<GetStateRoot as MethodMarker>::METHOD_ID, 0xb484a429);
        assert_eq!(<SubmitWorkResponse as MethodMarker>::METHOD_ID, 0x78ea_f3a0);
        assert_eq!(<SubscribeFinalized as MethodMarker>::METHOD_ID, 0xc0ccad00);
        assert_eq!(<GetObjectProofs as MethodMarker>::METHOD_ID, 0x3ee7_8a2f);
        assert_eq!(<GetObjects as MethodMarker>::METHOD_ID, 0x1723_3c96);
    }
}
