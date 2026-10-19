//! Pure authority transitions. A host must authenticate the actor, validate each
//! service's restrictions, and durably commit the combined state before effects.
//! A successful check against this value is not a reusable execution permit.

mod administration;
mod contact;
mod credentials;
mod ownership;
mod passkey;
mod sessions;
mod state;
mod types;

pub use administration::{AdministrationCommand, AdministrationRecord, CallerRecord};
pub use contact::{ContactCard, MAX_CONTACT_NAME_BYTES};
pub use credentials::{
    AuthenticatedCaller, Credential, CredentialCommand, CredentialHolder, CredentialId,
    CredentialSecret, SessionKind,
};
pub use ownership::{Ownership, ownership_digest};
pub use passkey::PasskeyAssertion;
pub use sessions::{
    AuthenticatedSession, MAX_CHALLENGE_LIFETIME_MS, MAX_SESSION_LIFETIME_MS,
    PendingAuthentication, SessionChallenge, SessionProof,
};
pub use state::{AuthoritySnapshot, AuthorityState};
pub use types::*;

pub const GRANT_ISSUE: &str = "grant.issue";
pub const GRANT_REVOKE: &str = "grant.revoke";
pub const GRANT_ADMINISTER: &str = "grant.administer";
pub const CREDENTIAL_ISSUE: &str = "credential.issue";
pub const CREDENTIAL_REVOKE: &str = "credential.revoke";
/// The one operation a bearer credential may carry: local HTTP gateway admission.
pub const GATEWAY_INVOKE: &str = "gateway.invoke";
pub const MAX_CREDENTIALS: usize = 256;
pub const MAX_DELEGATION_DEPTH: u8 = 8;
/// Unexpired, unrevoked descendants of one node grant, including future grants.
pub const MAX_DELEGATIONS: usize = 32;
pub const MAX_GRANTS: usize = 256;
pub const MAX_PERMISSIONS: usize = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AuthorityError {
    #[error("invalid authority record")]
    Invalid,
    #[error("record belongs to another authority")]
    Audience,
    #[error("operation is not authorized")]
    Denied,
    #[error("grant is missing")]
    Missing,
    #[error("grant has been revoked")]
    Revoked,
    #[error("grant is outside its validity interval")]
    Expired,
    #[error("stale grant revision")]
    Revision,
    #[error("grant identifier already exists")]
    Duplicate,
    #[error("authority state capacity exhausted")]
    Capacity,
    #[error("authority clock moved backwards")]
    Clock,
    #[error("credential authentication failed")]
    Credential,
    #[error("operation requires a passkey session")]
    StepUp,
    #[error("secure randomness is unavailable")]
    Entropy,
}

#[cfg(test)]
mod tests;
