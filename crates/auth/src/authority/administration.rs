//! Audited authority transitions for the host's existing journal. These records
//! are trusted persistence inputs, never caller authentication or remote requests.
use super::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum AdministrationCommand {
    Grant(GrantCommand),
    Credential(CredentialCommand),
}

/// An exact command tied to its authenticated actor and pre-transition revision.
/// The host constructs it under its writer lock, validates service restrictions,
/// and commits it before publishing the resulting state or credential secret.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdministrationRecord {
    pub(super) caller: CallerRecord,
    pub(super) command: AdministrationCommand,
}

/// Caller metadata for trusted journal replay, never authentication evidence.
/// A service records this under the same writer lock as its checked effect.
/// Deserializing it does not authenticate a request or authorize a future effect.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallerRecord {
    pub(super) authority: AuthorityId,
    pub(super) generation: u64,
    pub(super) before: Revision,
    pub(super) actor: PrincipalId,
    pub(super) credential: CredentialId,
    pub(super) credential_revision: Revision,
    pub(super) holder: CredentialHolder,
    pub(super) session: SessionKind,
    pub(super) at: UnixMillis,
}

impl CallerRecord {
    pub const fn authority(&self) -> AuthorityId {
        self.authority
    }
    pub const fn generation(&self) -> u64 {
        self.generation
    }
    pub const fn before(&self) -> Revision {
        self.before
    }
    pub const fn actor(&self) -> PrincipalId {
        self.actor
    }
    pub const fn credential(&self) -> CredentialId {
        self.credential
    }
    pub const fn credential_revision(&self) -> Revision {
        self.credential_revision
    }
    /// The device the actor's credential is bound to, as recorded at the effect.
    pub const fn holder(&self) -> CredentialHolder {
        self.holder
    }
    pub const fn session(&self) -> SessionKind {
        self.session
    }
    pub const fn at(&self) -> UnixMillis {
        self.at
    }
}

impl AdministrationRecord {
    pub fn caller(&self) -> &CallerRecord {
        &self.caller
    }
    /// The authority revision this record commits, which is also the new revision
    /// of the grant it issues, delegates, revises or revokes.
    pub const fn revision(&self) -> Revision {
        Revision(self.caller.before.0.saturating_add(1))
    }
    pub fn command(&self) -> &AdministrationCommand {
        &self.command
    }
}
