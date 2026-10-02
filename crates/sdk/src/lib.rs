//! Application-facing composition facade for Hellas.
//!
//! This crate owns no protocol definitions. It gives hosts one narrow place
//! to consume the canonical RPC, transport, client, gateway, and attestation
//! crates without making a CLI binary their library boundary.

pub use hellas_attestation::{AttestationError, Attester, Binding, RootProver};
#[cfg(any(feature = "paid-client", feature = "paid-provider"))]
pub use hellas_chain::node::{Config as ChainNodeConfig, FullNode};
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
#[cfg(feature = "grant-provider")]
pub mod grant_provider;
#[cfg(any(feature = "paid-provider", feature = "grant-provider"))]
mod provider;
#[cfg(feature = "grant-provider")]
pub use grant_provider::{GrantProviderOptions, responses_policy};
#[cfg(feature = "provider")]
pub use hellas_executor::{FetchRoute, FetchRouteEntry, FetchRoutePolicy, FetchRouteRegistry};
#[cfg(feature = "work")]
pub use hellas_kernel as kernel;
#[cfg(feature = "provider")]
pub use hellas_providers::{
    HttpProviderConfig, OpenAiResponsesFetchProvider, ResponsesFetchAdaptorFactory,
};
#[cfg(feature = "paid-provider")]
pub use provider::PaidProviderOptions;
#[cfg(any(feature = "paid-provider", feature = "grant-provider"))]
pub use provider::{FetchProviderOptions, ProviderError, ProviderHandle, start_fetch_provider};
#[cfg(feature = "grant-provider")]
pub use provider::{OpenAiProviderOptions, start_openai_provider};
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
#[cfg(feature = "paid-work")]
pub mod work_config;
#[cfg(any(feature = "paid-provider", feature = "grant-provider"))]
pub mod work_router;

#[cfg(feature = "paid-client")]
pub mod paid_client;
#[cfg(any(feature = "paid-client", feature = "grant-client"))]
mod work_link;

#[cfg(feature = "paid-work")]
pub mod work_provision;

#[cfg(all(test, any(feature = "paid-client", feature = "paid-provider")))]
mod test_support;

#[cfg(feature = "paid-gateway")]
pub mod paid_gateway;

#[cfg(feature = "grant-client")]
pub mod grant_client;

#[cfg(feature = "grant-admin")]
pub mod grant_admin;
#[cfg(feature = "work")]
pub mod grant_config;

#[cfg(any(feature = "paid-gateway", feature = "grant-gateway"))]
mod gateway_work;
#[cfg(feature = "grant-gateway")]
pub mod grant_gateway;

#[cfg(feature = "work")]
mod resource_config;
#[cfg(feature = "work")]
pub use resource_config::ResourceConfigError;

#[cfg(all(
    test,
    any(
        feature = "paid-client",
        feature = "grant-admin",
        feature = "grant-provider"
    )
))]
mod test_identity;
