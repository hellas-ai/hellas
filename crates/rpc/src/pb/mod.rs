//! Protobuf bindings for the Hellas protocol.
//!
//! Per-package message types are generated into `OUT_DIR` by the build
//! script (`prost-build` driven by `protox`). Each `.proto` package gets a
//! Rust module here with the matching nesting (`hellas::v1`,
//! `hellas::courtesy::v1`, …) so prost's `super::super::v1::Ticket`-style
//! cross-package references resolve.
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

    #[cfg(feature = "courtesy")]
    #[allow(dead_code)]
    pub mod courtesy {
        pub mod v1 {
            include!(concat!(env!("OUT_DIR"), "/hellas.courtesy.v1.rs"));
        }
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

/// Re-exports of `hellas.courtesy.v1`.
#[cfg(feature = "courtesy")]
pub mod courtesy {
    pub use crate::pb::hellas::courtesy::v1::*;
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

/// Re-exports of the local-only `hellas.host.v1` package.
#[cfg(feature = "host-control")]
pub mod host {
    pub use crate::pb::hellas::host::v1::*;
}

/// Re-exports of `hellas.work.v1`.
#[cfg(feature = "work")]
pub mod work {
    pub use crate::pb::hellas::work::v1::*;
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

    #[cfg(feature = "execute")]
    #[test]
    fn execute_ids_are_stable() {
        use super::services::execute::{Execute, RunTicket};
        assert_eq!(super::execute::Assurance::ProducerSigned as i32, 0);
        assert_eq!(super::execute::Assurance::AppleAppAttest as i32, 1);
        assert_eq!(<Execute as ServiceMarker>::SERVICE_ID, 0x2a0f_bee1);
        assert_eq!(<RunTicket as MethodMarker>::METHOD_ID, 0xc808_8d01);
    }

    #[cfg(feature = "evaluate")]
    #[test]
    fn evaluate_ids_are_stable() {
        use super::services::evaluate::{CreateTicket, Evaluate};
        assert_eq!(<Evaluate as ServiceMarker>::SERVICE_ID, 0x70872e46);
        assert_eq!(<CreateTicket as MethodMarker>::METHOD_ID, 0xcf212df5);
    }

    #[cfg(feature = "fetch")]
    #[test]
    fn fetch_ids_are_stable() {
        use super::services::fetch::{CreateTicket, Fetch, Open};
        assert_eq!(<Fetch as ServiceMarker>::SERVICE_ID, 0x4e98fdd1);
        assert_eq!(<Open as MethodMarker>::METHOD_ID, 0x55da4412);
        assert_eq!(<CreateTicket as MethodMarker>::METHOD_ID, 0x39183beb);
    }

    #[cfg(feature = "host-control")]
    #[test]
    fn cache_control_ids_are_stable() {
        use super::services::cache_control::{CacheControl, ManageCache};
        assert_eq!(<CacheControl as ServiceMarker>::SERVICE_ID, 0x506b_ebfb);
        assert_eq!(<ManageCache as MethodMarker>::METHOD_ID, 0x8bb7_91fb);
    }

    #[cfg(feature = "courtesy")]
    #[test]
    fn courtesy_ids_are_stable() {
        use super::services::courtesy::{Courtesy, Open, QuoteTokens};
        assert_eq!(<Courtesy as ServiceMarker>::SERVICE_ID, 0xa842_0437);
        assert_eq!(<Open as MethodMarker>::METHOD_ID, 0x18351e7d);
        assert_eq!(<QuoteTokens as MethodMarker>::METHOD_ID, 0x4186_3eda);
    }

    #[cfg(feature = "work")]
    #[test]
    fn work_ids_are_stable() {
        use super::services::work::{AcceptWork, AdmitCertificate, DeliverResult, Work};
        assert_eq!(<Work as ServiceMarker>::SERVICE_ID, 0xf61c_cea0);
        assert_eq!(<AcceptWork as MethodMarker>::METHOD_ID, 0xe6a7_13c2);
        assert_eq!(<DeliverResult as MethodMarker>::METHOD_ID, 0xf15a_a80e);
        assert_eq!(<AdmitCertificate as MethodMarker>::METHOD_ID, 0x0ffb_b4f9);
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
        use super::services::work_setup::{ExchangeSetup, WorkSetup};
        assert_eq!(<WorkSetup as ServiceMarker>::SERVICE_ID, 0x0235_ddf0);
        assert_eq!(<ExchangeSetup as MethodMarker>::METHOD_ID, 0x1cde_46e8);
    }

    #[cfg(feature = "chain")]
    #[test]
    fn chain_ids_are_stable() {
        use super::services::light_client::{
            GetStateRoot, GetWorkChannelSnapshot, LightClient, SubmitWorkResponse,
        };
        assert_eq!(<LightClient as ServiceMarker>::SERVICE_ID, 0x74f1_0f92);
        assert_eq!(<GetStateRoot as MethodMarker>::METHOD_ID, 0xb484a429);
        assert_eq!(
            <GetWorkChannelSnapshot as MethodMarker>::METHOD_ID,
            0xadea_9964
        );
        assert_eq!(<SubmitWorkResponse as MethodMarker>::METHOD_ID, 0x78ea_f3a0);
    }
}
