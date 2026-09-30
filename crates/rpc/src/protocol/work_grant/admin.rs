//! Versioned node administration records. Authority comes from the live
//! transport and the provider's journal, never from a command's contents.
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
    Users(UserCommand),
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
    Users(Vec<UserSummary>),
    User(Box<UserStatus>),
    Listing(Vec<GrantSummary>),
    Status {
        offer: Box<SignedOffer>,
        now: UnixMillis,
        nodes: Vec<NodeAllowance>,
    },
    Repaired,
}

/// Owner cannot be represented as a removable or demotable user.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum UserPermissions {
    Owner,
    Active { admin: bool },
    Removed,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct User {
    pub principal: Principal,
    pub revision: Revision,
    pub permissions: UserPermissions,
}
impl User {
    pub fn is_admin(&self) -> bool {
        matches!(
            self.permissions,
            UserPermissions::Owner | UserPermissions::Active { admin: true }
        )
    }
    pub fn is_active(&self) -> bool {
        self.permissions != UserPermissions::Removed
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserStatus {
    pub user: User,
    pub grants: Vec<GrantSummary>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserSummary {
    pub id: PrincipalId,
    pub revision: Revision,
    pub permissions: UserPermissions,
    pub grants: usize,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum UserCommand {
    List,
    Show {
        id: PrincipalId,
    },
    Add {
        principal: Box<Principal>,
        expected_revision: Option<Revision>,
        admin: bool,
        work: Option<(GrantId, GrantTerms)>,
    },
    Update {
        id: PrincipalId,
        expected_revision: Revision,
        admin: Option<bool>,
        work: Option<UserWork>,
    },
    Remove {
        id: PrincipalId,
        expected_revision: Revision,
    },
    Offer {
        id: PrincipalId,
        grant: GrantId,
    },
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum UserWork {
    Create {
        id: GrantId,
        terms: GrantTerms,
    },
    Revise {
        id: GrantId,
        expected_revision: Revision,
        terms: GrantTerms,
        keep_expiry: bool,
    },
    SetState {
        id: GrantId,
        expected_revision: Revision,
        state: GrantState,
    },
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
