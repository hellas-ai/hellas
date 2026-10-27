use super::channel::funding::JobOutcome;
use crate::model::grant::{ChannelClient, ChannelId, GrantJobAuthorizationV1};
use crate::model::work::PaidJobResultV1;
use hellas_auth::Signature;
use hellas_auth::authority::GrantId;
use serde::{Deserialize, Serialize};
pub mod codec;

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
