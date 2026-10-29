//! Reusable Hellas client orchestration. The optional `local` backend embeds
//! an executor; transport-neutral verification does not depend on that backend.

mod error;
#[cfg(feature = "iroh")]
pub mod iroh;
pub mod model;
#[cfg(all(feature = "iroh", feature = "work"))]
mod offer;
#[cfg(feature = "work")]
pub mod work;
#[cfg(all(feature = "iroh", feature = "work"))]
pub use offer::{PinnedOffer, UnpinnedOffer};

pub use error::{ClientError, ClientResult};
#[cfg(feature = "iroh")]
pub use iroh::{
    AppleAppAttestTrust, ProviderAddress, ProviderAddressError, ProviderTrustAnchor,
    RemoteNodeTarget, confidential_open,
};

/// Client capabilities shared by local and transport-specific orchestration.
#[derive(Clone)]
pub struct ExecutionRuntime<L = ()> {
    local: Option<L>,
    #[cfg(feature = "iroh")]
    remote: Option<iroh::RemoteRpc>,
}

impl<L> Default for ExecutionRuntime<L> {
    fn default() -> Self {
        Self {
            local: None,
            #[cfg(feature = "iroh")]
            remote: None,
        }
    }
}

impl<L> ExecutionRuntime<L> {
    /// Construct a runtime with an in-process client supplied by the caller.
    pub fn local(local: L) -> Self {
        Self {
            local: Some(local),
            #[cfg(feature = "iroh")]
            remote: None,
        }
    }

    /// Borrow the caller-supplied in-process client, if configured.
    pub fn local_state(&self) -> Option<&L> {
        self.local.as_ref()
    }
}
