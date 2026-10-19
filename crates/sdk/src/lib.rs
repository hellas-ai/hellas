//! Application-facing composition facade for Hellas.
//!
//! This crate owns no protocol definitions. It gives hosts one narrow place
//! to consume the canonical RPC, transport, client, gateway, and attestation
//! crates without making a CLI binary their library boundary.

pub use hellas_attestation::{AttestationError, Attester, Binding, RootProver};
pub use hellas_chain::node::{Config as ChainNodeConfig, FullNode};
pub use hellas_rpc as rpc;
pub use hellas_wire as wire;
pub use hellas_work as work;

#[cfg(test)]
use hellas_work::test_support::common_node as test_node;

mod counter_store;
pub use counter_store::FilesystemAssertionCounterStore;
pub mod trust_policy;

pub use hellas_client as client;
pub use iroh;
mod remote;
pub use hellas_gateway as gateway;
pub mod grant_provider;
mod provider;
pub use grant_provider::GrantProviderOptions;
pub use hellas_executor::{FetchRoute, FetchRouteEntry, FetchRoutePolicy, FetchRouteRegistry};
pub use hellas_kernel as kernel;
pub use hellas_providers::HttpProviderConfig;
pub use provider::PaidProviderOptions;
pub use provider::{
    FetchProviderOptions, ProviderAuthority, ProviderControl, ProviderError, ProviderGrants,
    ProviderHandle, ProviderOpen, ProviderOptions, start_fetch_provider,
};
pub use remote::NodeIdentity;

pub mod local {
    pub use hellas_wire::local::{LOCAL_MUX_SLOTS, LocalControlServer, connect, transport};
}

pub mod paid_provider;
pub mod work_config;
pub mod work_router;

pub mod paid_client;
mod work_link;

pub mod work_provision;

#[cfg(test)]
mod test_support;

pub mod paid_gateway;

pub mod grant_client;

pub mod access_bundle;
mod application_handshake;
pub mod grant_config;
pub mod node_control;

mod gateway_work;
pub use gateway_work::prepare_evaluate;
pub mod grant_gateway;

mod resource_config;
pub use resource_config::ResourceConfigError;

#[cfg(test)]
mod test_identity;
