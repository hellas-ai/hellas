//! Provider-wide grant journal and ancestor allowance ledger.
mod client;
mod codec;
pub mod refusal;
mod users;
pub use client::GrantClientStore;
/// Evidence supplied by the authenticated live transport, never request bytes.
#[derive(Clone, Copy, Debug)]
pub struct GrantConnection {
    pub peer: [u8; 32],
    pub exporter: [u8; 32],
}
pub mod ledger;
use super::channel::funding::JobOutcome;
use hellas_rpc::Signature;
use hellas_rpc::protocol::work::PaidJobResultV1;
use hellas_rpc::protocol::work_grant::{
    ChannelId, GrantId, GrantJobAuthorizationV1, records::Principal,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantChannelState {
    pub id: ChannelId,
    pub grant: GrantId,
    pub generation: u64,
    pub client: Principal,
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
mod state;
mod store;
pub use state::State;
pub use store::GrantStore;

#[derive(Debug, thiserror::Error)]
pub enum GrantStoreError {
    #[error("grant writer is unavailable after a failed durable completion")]
    Unavailable,
    #[error(transparent)]
    Journal(#[from] super::journal::JournalError),
    #[error(transparent)]
    Channel(#[from] super::ChannelStateError),
    #[error(transparent)]
    Grant(#[from] hellas_rpc::protocol::work_grant::records::GrantError),
    #[error(transparent)]
    Ledger(#[from] ledger::LedgerError),
    #[error(transparent)]
    Resource(#[from] hellas_rpc::protocol::work_grant::resource::TemplateError),
    #[error(transparent)]
    Input(#[from] hellas_rpc::protocol::work::PaidWorkError),
    #[error("malformed grant journal state")]
    Malformed,
}
