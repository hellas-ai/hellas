//! Reusable Hellas client orchestration. The optional `local` backend embeds
//! an executor; transport-neutral verification does not depend on that backend.

#[cfg(feature = "iroh")]
pub mod cache;
mod error;
#[cfg(feature = "evaluate")]
mod evaluate;
#[cfg(all(feature = "iroh", feature = "evaluate"))]
pub mod execution;
mod fetch;
#[cfg(feature = "iroh")]
pub mod iroh;
mod run_ticket;
#[cfg(feature = "work")]
pub mod work;

pub use error::{ClientError, ClientResult};
#[cfg(feature = "evaluate")]
pub use evaluate::{
    EvaluateChunkVerifier, EvaluateExecutionEvent, EvaluateOutcome,
    evaluate_input_from_request_commitment, verify_evaluate_work_event,
};
pub use fetch::{
    FetchChunkVerifier, FetchExecutionEvent, FetchOutcome, ProducerTrust, validate_fetch_ticket,
    verified_fetch_input, verify_fetch_work_event,
};
#[cfg(feature = "iroh")]
pub use iroh::{AppleAppAttestTrust, ExecutionRoute, ProviderTrustAnchor, RemoteNodeTarget};
pub use run_ticket::{runner_public_key, signed_run_ticket_request};

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
