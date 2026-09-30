//! Versioned local administration records. These confer no remote authority:
//! HostControl must be mounted behind the local-owner Authorized dispatcher.
use super::{budget::Limit, records::*, standing::NodeAllowance, *};
use crate::protocol::value::{canonical_dag_cbor, decode_canonical_dag_cbor};
use serde::{Deserialize, Serialize};
use std::num::{NonZeroU16, NonZeroU64};

pub const MAX_ADMIN_BYTES: usize = 512 * 1024;
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantTerms {
    pub policies: Vec<String>,
    pub limits: Vec<Limit>,
    pub max_job_millis: NonZeroU64,
    pub max_in_flight: NonZeroU16,
    pub expires_in_millis: Option<NonZeroU64>,
    pub allow_account_backed: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum GrantCommand {
    Create {
        id: GrantId,
        principal: Principal,
        terms: GrantTerms,
    },
    Revise {
        id: GrantId,
        expected_revision: Revision,
        terms: GrantTerms,
    },
    SetState {
        id: GrantId,
        expected_revision: Revision,
        state: GrantState,
    },
    InitializeOwner {
        principal: Principal,
    },
    List,
    Inspect {
        id: GrantId,
    },
    NewGeneration {
        id: GrantId,
        expected_revision: Revision,
    },
    RepairResource {
        policy: String,
    },
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantSummary {
    pub id: GrantId,
    pub principal: PrincipalId,
    pub owner: bool,
    pub revision: Revision,
    pub state: GrantState,
    pub policies: Vec<String>,
    pub expires: Option<UnixMillis>,
    pub generation: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum GrantReply {
    Listing(Vec<GrantSummary>),
    Status {
        offer: Box<SignedOffer>,
        now: UnixMillis,
        nodes: Vec<NodeAllowance>,
    },
    Repaired,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record<T> {
    version: u8,
    body: T,
}
fn encode<T: Serialize>(body: &T) -> Result<Vec<u8>, GrantError> {
    let bytes =
        canonical_dag_cbor(&Record { version: 1, body }).map_err(|_| GrantError::Malformed)?;
    if bytes.len() > MAX_ADMIN_BYTES {
        return Err(GrantError::StateCapacity);
    }
    Ok(bytes)
}
fn decode<T: serde::de::DeserializeOwned + Serialize>(bytes: &[u8]) -> Result<T, GrantError> {
    if bytes.len() > MAX_ADMIN_BYTES {
        return Err(GrantError::StateCapacity);
    }
    let record: Record<T> = decode_canonical_dag_cbor(bytes).map_err(|_| GrantError::Malformed)?;
    if record.version != 1 {
        return Err(GrantError::Malformed);
    }
    Ok(record.body)
}
impl GrantCommand {
    pub fn encode(&self) -> Result<Vec<u8>, GrantError> {
        encode(self)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, GrantError> {
        decode(bytes)
    }
}
impl GrantReply {
    pub fn encode(&self) -> Result<Vec<u8>, GrantError> {
        encode(self)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, GrantError> {
        decode(bytes)
    }
}
