//! Pure authority transitions. A host must authenticate the actor, validate each
//! service's restrictions, and durably commit the combined state before effects.
//! A successful check against this value is not a reusable execution permit.

mod administration;
mod credentials;
mod sessions;
mod state;
mod types;

pub use administration::{AdministrationCommand, AdministrationRecord, CallerRecord};
pub use credentials::{
    AuthenticatedCaller, Credential, CredentialCommand, CredentialId, CredentialSecret,
};
pub use sessions::{
    AuthenticatedSession, MAX_CHALLENGE_LIFETIME_MS, MAX_SESSION_LIFETIME_MS,
    PendingAuthentication, SessionChallenge,
};
pub use state::{AuthoritySnapshot, AuthorityState};
pub use types::*;

pub const GRANT_ISSUE: &str = "grant.issue";
pub const GRANT_REVOKE: &str = "grant.revoke";
pub const GRANT_ADMINISTER: &str = "grant.administer";
pub const CREDENTIAL_ISSUE: &str = "credential.issue";
pub const CREDENTIAL_REVOKE: &str = "credential.revoke";
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
    #[error("secure randomness is unavailable")]
    Entropy,
}

#[cfg(test)]
mod tests;
