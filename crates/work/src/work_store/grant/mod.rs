//! Provider-wide grant journal and ancestor allowance ledger.
mod administration;
mod admission;
pub use admission::{AdmissionRecord, ExecutionRecord};
mod catalogue;
mod client;
mod codec;
mod delivery;
mod execution;
pub mod refusal;
pub(crate) use administration::{BindRecord, WorkMutation, WorkRecord};
pub use administration::{
    WORK_ALLOWANCE_CONFIGURE, WORK_ALLOWANCE_READ, WORK_BUDGET_CONFIGURE, WORK_GENERATION_RESET,
    WORK_OFFER_EXPORT, WORK_RESOURCE_CONFIGURE, WORK_RESOURCE_REPAIR,
};
pub use client::GrantClientStore;
pub mod ledger;
use super::channel::funding::JobOutcome;
use crate::model::grant::{ChannelClient, ChannelId, GrantJobAuthorizationV1};
use crate::model::work::PaidJobResultV1;
use hellas_auth::Signature;
use hellas_auth::authority::GrantId;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantChannelState {
    pub id: ChannelId,
    pub grant: GrantId,
    pub generation: u64,
    pub client: ChannelClient,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum GrantOutcome {
    Finished,
    Failed,
    Released,
    Indeterminate,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedResult {
    #[serde(with = "codec::record")]
    pub result: PaidJobResultV1,
    pub signature: Signature,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantTerminal {
    pub outcome: GrantOutcome,
    #[serde(with = "codec::record")]
    pub authorization: GrantJobAuthorizationV1,
    pub client_signature: Signature,
    pub provider_signature: Signature,
    pub result: Option<SignedResult>,
}
impl JobOutcome for GrantTerminal {
    fn name(&self) -> &'static str {
        match self.outcome {
            GrantOutcome::Finished => "finished",
            GrantOutcome::Failed => "failed",
            GrantOutcome::Released => "released",
            GrantOutcome::Indeterminate => "indeterminate",
        }
    }
}
mod clock;
mod state;
mod store;
pub use state::State;
pub use store::{NodeStore, OwnerApproval};

#[derive(Debug, thiserror::Error)]
pub enum NodeStoreError {
    #[error("node authority has not been initialized; explicit offline bootstrap is required")]
    Uninitialized,
    #[error("node bootstrap requires an empty state directory")]
    AlreadyInitialized,
    #[error("node has no configured Work provider")]
    MissingProvider,
    #[error("node has no configured Work machine capacity")]
    MissingMachine,
    #[error("provider already bound")]
    ProviderBound,
    #[error(transparent)]
    Authority(#[from] hellas_auth::authority::AuthorityError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("grant writer lock was poisoned")]
    WriterPoisoned,
    #[error(
        "clock advanced beyond elapsed runtime; correct system UTC or restart the node after verifying it"
    )]
    ClockJump,
    #[error("grant completion failed: {0}")]
    Completion(#[source] std::sync::Arc<NodeStoreError>),
    #[error("grant execution task failed: {0}")]
    Task(#[from] tokio::task::JoinError),
    #[error(transparent)]
    Journal(#[from] super::journal::JournalError),
    #[error(transparent)]
    Channel(#[from] super::ChannelStateError),
    #[error(transparent)]
    Grant(#[from] crate::model::grant::records::GrantError),
    #[error(transparent)]
    Ledger(#[from] ledger::LedgerError),
    #[error(transparent)]
    Resource(#[from] crate::model::grant::resource::TemplateError),
    #[error(transparent)]
    Input(#[from] crate::model::work::PaidWorkError),
    #[error("malformed grant journal state")]
    Malformed,
}

/// Comparable error categories; the error retains the detailed cause and context.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NodeStoreErrorKind {
    Uninitialized,
    AlreadyInitialized,
    MissingProvider,
    MissingMachine,
    ProviderBound,
    Authority,
    Io,
    WriterPoisoned,
    ClockJump,
    Completion,
    Task,
    Journal,
    Channel,
    Grant,
    Ledger,
    Resource,
    Input,
    Malformed,
}
impl NodeStoreError {
    pub fn kind(&self) -> NodeStoreErrorKind {
        match self {
            Self::Uninitialized => NodeStoreErrorKind::Uninitialized,
            Self::AlreadyInitialized => NodeStoreErrorKind::AlreadyInitialized,
            Self::MissingProvider => NodeStoreErrorKind::MissingProvider,
            Self::MissingMachine => NodeStoreErrorKind::MissingMachine,
            Self::ProviderBound => NodeStoreErrorKind::ProviderBound,
            Self::Authority(_) => NodeStoreErrorKind::Authority,
            Self::Io(_) => NodeStoreErrorKind::Io,
            Self::WriterPoisoned => NodeStoreErrorKind::WriterPoisoned,
            Self::ClockJump => NodeStoreErrorKind::ClockJump,
            Self::Completion(_) => NodeStoreErrorKind::Completion,
            Self::Task(_) => NodeStoreErrorKind::Task,
            Self::Journal(_) => NodeStoreErrorKind::Journal,
            Self::Channel(_) => NodeStoreErrorKind::Channel,
            Self::Grant(_) => NodeStoreErrorKind::Grant,
            Self::Ledger(_) => NodeStoreErrorKind::Ledger,
            Self::Resource(_) => NodeStoreErrorKind::Resource,
            Self::Input(_) => NodeStoreErrorKind::Input,
            Self::Malformed => NodeStoreErrorKind::Malformed,
        }
    }
}

impl From<hellas_rpc::protocol::value::BoundedCborError> for NodeStoreError {
    fn from(error: hellas_rpc::protocol::value::BoundedCborError) -> Self {
        use hellas_rpc::protocol::value::BoundedCborError;
        match error {
            BoundedCborError::OutputLimit => {
                crate::model::grant::records::GrantError::StateCapacity.into()
            }
            BoundedCborError::InputLimit | BoundedCborError::Invalid(_) => Self::Malformed,
        }
    }
}

#[cfg(test)]
mod tests;
