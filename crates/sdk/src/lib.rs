//! Application-facing composition facade for Hellas.
//!
//! This crate owns no protocol definitions. It gives hosts one narrow place
//! to consume the canonical RPC, transport, client, gateway, and attestation
//! crates without making a CLI binary their library boundary.

pub use hellas_attestation::{AttestationError, Attester, Binding, RootProver};
pub use hellas_rpc as rpc;
pub use hellas_wire as wire;

#[cfg(feature = "apple-verifier")]
mod counter_store;
#[cfg(feature = "apple-verifier")]
pub use counter_store::FilesystemAssertionCounterStore;

#[cfg(feature = "client")]
pub use hellas_client as client;
#[cfg(feature = "client")]
pub use iroh;
#[cfg(feature = "client")]
mod remote;
#[cfg(feature = "gateway")]
pub use hellas_gateway as gateway;
#[cfg(feature = "paid-provider")]
mod provider;
#[cfg(feature = "provider")]
pub use hellas_executor::{FetchRoute, FetchRouteEntry, FetchRoutePolicy, FetchRouteRegistry};
#[cfg(feature = "work")]
pub use hellas_kernel as kernel;
#[cfg(feature = "provider")]
pub use hellas_providers::{
    HttpProviderConfig, OpenAiResponsesFetchProvider, ResponsesFetchAdaptorFactory,
};
#[cfg(feature = "paid-provider")]
pub use provider::{
    FetchProviderOptions, OpenAiProviderOptions, ProviderError, ProviderHandle,
    start_fetch_provider, start_openai_provider,
};
#[cfg(feature = "client")]
pub use remote::ClientIdentity;

#[cfg(all(
    feature = "local-control",
    any(all(unix, not(target_os = "espidf")), windows)
))]
pub mod local {
    pub use hellas_wire::local::{LOCAL_MUX_SLOTS, LocalControlServer, connect, transport};
}

#[cfg(feature = "paid-provider")]
pub mod paid_provider;
#[cfg(feature = "work")]
pub mod work_config;

#[cfg(feature = "paid-client")]
pub mod paid_client;

#[cfg(feature = "work")]
pub mod work_provision;

#[cfg(all(test, any(feature = "paid-client", feature = "paid-provider")))]
mod test_support;

#[cfg(feature = "paid-gateway")]
pub mod paid_gateway;

#[cfg(feature = "paid-client")]
mod work_link;
#[cfg(feature = "paid-client")]
pub mod work_session;
#[cfg(feature = "paid-client")]
pub use work_session::WorkSession;
#[cfg(feature = "paid-gateway")]
mod gateway_work;
