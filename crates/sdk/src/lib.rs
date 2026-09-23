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
#[cfg(feature = "provider")]
mod provider;
#[cfg(feature = "provider")]
pub use provider::{OpenAiProviderOptions, ProviderHandle, start_openai_provider};
#[cfg(feature = "client")]
pub use remote::{ClientIdentity, HellasClient, RemoteFetchRequest};

#[cfg(all(
    feature = "local-control",
    any(all(unix, not(target_os = "espidf")), windows)
))]
pub mod local {
    pub use hellas_rpc::cache::control::CacheController;
    pub use hellas_wire::local::{LOCAL_MUX_SLOTS, LocalControlServer, connect, transport};
}
