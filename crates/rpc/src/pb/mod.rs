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

    #[cfg(feature = "evaluate")]
    #[allow(dead_code)]
    pub mod evaluate {
        pub mod v1 {
            include!(concat!(env!("OUT_DIR"), "/hellas.evaluate.v1.rs"));
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

/// Re-exports of the Hellas core execution types (`hellas.v1`).
#[cfg(feature = "execute")]
pub mod execute {
    pub use crate::pb::hellas::v1::*;
}

/// Re-exports of `hellas.evaluate.v1`.
#[cfg(feature = "evaluate")]
pub mod evaluate {
    pub use crate::pb::hellas::evaluate::v1::*;
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

    impl std::fmt::Debug for IssueCredentialResponse {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("IssueCredentialResponse")
                .field("credential_id", &self.credential_id)
                .finish_non_exhaustive()
        }
    }

    impl Drop for IssueCredentialResponse {
        fn drop(&mut self) {
            zeroize::Zeroize::zeroize(&mut self.secret);
        }
    }

    impl IssueCredentialResponse {
        /// Decode the bounded secret returned once by an authenticated node.
        pub fn credential(
            &self,
        ) -> Result<
            hellas_auth::authority::CredentialSecret,
            crate::authentication::AuthenticationWireError,
        > {
            use crate::authentication::AuthenticationWireError::Encoding;
            use hellas_auth::authority::{CredentialId, CredentialSecret};
            Ok(CredentialSecret::from_parts(
                CredentialId::try_from(self.credential_id.as_slice()).map_err(|_| Encoding)?,
                self.secret.as_slice().try_into().map_err(|_| Encoding)?,
            ))
        }
    }
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

/// Pinned wire IDs, end-to-end: proto file → descriptor walk → canonical
/// schema encoding → truncated Xet hash. If one of these assertions fails,
/// either the canonical encoding or the proto definition changed — both
/// rotate the ID, and deployed nodes will refuse this build's calls on
/// the affected methods. Update a pin only as a deliberate protocol break.
#[cfg(test)]
mod id_pins {
    #[allow(unused_imports)]
    use hellas_wire::{MethodMarker, ServiceMarker};

    #[cfg(feature = "work")]
    #[test]
    fn work_ids_are_stable() {
        use super::services::work::{
            AcceptWork, AdmitCertificate, DeliverResult, GetStanding, Open, StreamResult, Work,
        };
        // Session-bound standing removes its redundant request signature,
        // deliberately rotating GetStanding and Work. Open stays fixed.
        assert_eq!(<Work as ServiceMarker>::SERVICE_ID, 0x584721e6);
        assert_eq!(<Open as MethodMarker>::METHOD_ID, 0x93cb0b39);
        assert_eq!(<AcceptWork as MethodMarker>::METHOD_ID, 0x5188734e);
        assert_eq!(<GetStanding as MethodMarker>::METHOD_ID, 0x64b53882);
        assert_eq!(<DeliverResult as MethodMarker>::METHOD_ID, 0x74bb099b);
        assert_eq!(<StreamResult as MethodMarker>::METHOD_ID, 0xb2043ac5);
        assert_eq!(<AdmitCertificate as MethodMarker>::METHOD_ID, 0x07db8b8e);
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
        use super::services::work_setup::{ExchangeSetup, Open, WorkSetup};
        assert_eq!(<WorkSetup as ServiceMarker>::SERVICE_ID, 0xdfbb90af);
        assert_eq!(<Open as MethodMarker>::METHOD_ID, 0xcbe4ebd5);
        assert_eq!(<ExchangeSetup as MethodMarker>::METHOD_ID, 0x14d05693);
    }

    #[cfg(feature = "host-control")]
    #[test]
    fn host_control_ids_are_stable() {
        use super::services::host_control::{
            BindProvider, GetGatewayAccess, GrantControl, HostControl, IssueCredential,
            RevokeCredential, SetGatewayState, SetProviderState, WorkControl,
        };
        // Lifecycle requests carry their selected Auth authorization grant.
        assert_eq!(<HostControl as ServiceMarker>::SERVICE_ID, 0xb85b_3317);
        assert_eq!(<SetProviderState as MethodMarker>::METHOD_ID, 0xab3a_b173);
        assert_eq!(<SetGatewayState as MethodMarker>::METHOD_ID, 0xa909_3160);
        assert_eq!(<GetGatewayAccess as MethodMarker>::METHOD_ID, 0xce7f_5d32);
        assert_eq!(<GrantControl as MethodMarker>::METHOD_ID, 0xc0e0_b21c);
        assert_eq!(<WorkControl as MethodMarker>::METHOD_ID, 0x995d_0334);
        assert_eq!(<IssueCredential as MethodMarker>::METHOD_ID, 0xe2d6_a55b);
        assert_eq!(<RevokeCredential as MethodMarker>::METHOD_ID, 0xe7b1_8b70);
        assert_eq!(<BindProvider as MethodMarker>::METHOD_ID, 0xcb33_75a9);
    }

    #[cfg(feature = "chain")]
    #[test]
    fn edge_index_schema_three_ids_are_stable() {
        use super::services::edge_index::{
            EdgeIndex, GetEdgeDetail, GetWorkChannelDetail, ListEdgeEvents, ListEdges,
        };
        // Schema 3. These moved from their schema-2 values because removing
        // `EdgeIndexEdgeLinks`, `EdgeIndexEventsLink` and `evidence_href`
        // changes the descriptor the IDs are derived from. That is the point
        // of pinning them: a wire-visible change must be a deliberate edit
        // here, never a silent reshuffle.
        assert_eq!(<EdgeIndex as ServiceMarker>::SERVICE_ID, 0x4376d207);
        assert_eq!(<ListEdges as MethodMarker>::METHOD_ID, 0x8bc7cf02);
        assert_eq!(<GetEdgeDetail as MethodMarker>::METHOD_ID, 0x76092836);
        assert_eq!(<ListEdgeEvents as MethodMarker>::METHOD_ID, 0xec962f60);
        assert_eq!(
            <GetWorkChannelDetail as MethodMarker>::METHOD_ID,
            0x22179a2f
        );
    }

    #[cfg(feature = "chain")]
    #[test]
    fn chain_ids_are_stable() {
        use super::services::light_client::{GetStateRoot, LightClient, SubmitWorkResponse};
        assert_eq!(<LightClient as ServiceMarker>::SERVICE_ID, 0x29ad8d1a);
        assert_eq!(<GetStateRoot as MethodMarker>::METHOD_ID, 0xb484a429);
        assert_eq!(<SubmitWorkResponse as MethodMarker>::METHOD_ID, 0x78ea_f3a0);
    }
}
