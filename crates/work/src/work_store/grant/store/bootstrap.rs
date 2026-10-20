//! Native initialization marker and exclusive ownership across journal rotation.
use super::*;
use hellas_auth::authority::{
    AuthorityId, AuthorityState, Credential, CredentialHolder, CredentialSecret, GrantId,
    GrantSpec, NodeKey, PasskeyAssertion, RecoveryCommand, RecoveryRecord,
};
use serde::Deserialize;
use std::fs::{File, TryLockError};
use std::io::Write as _;

const MARKER: &str = "authority";
const MAX_MARKER_BYTES: u64 = 4096;

pub(super) struct IdentityLock(File);

impl Drop for IdentityLock {
    fn drop(&mut self) {
        // A fork can retain the open file description after this writer closes.
        let _ = self.0.unlock();
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Marker {
    namespace: String,
    #[serde(with = "crate::model::grant::records::network")]
    network: NetworkId,
    authority: AuthorityId,
}

/// The administration an offline bootstrap or recovery installs, approved by
/// the administrator's passkey: `assertion` signs `ownership_digest` over the
/// administrator grant, the initial credential's scope and the node key that
/// will hold the credential.
pub struct OwnerApproval {
    pub administrator: GrantSpec,
    pub credential: GrantSpec,
    pub holder: NodeKey,
    pub assertion: PasskeyAssertion,
}

impl NodeStore {
    /// Replace lost administration with the daemon stopped. Opening the private
    /// identity marker acquires the same exclusive lock held by the running host.
    /// This never creates state or finalizes/replays outstanding Work effects.
    /// Only execution-only authority grants survive; mixed, administrative and
    /// unknown service rights require explicit regrant by the recovered owner.
    /// The replacement credential's verifier is part of the same commit. Its
    /// secret is returned only after sync; lost output requires another recovery.
    pub async fn recover_offline(
        directory: &Path,
        network: NetworkId,
        expected: Revision,
        approval: OwnerApproval,
        now: UnixMillis,
    ) -> Result<(RecoveryRecord, CredentialSecret), NodeStoreError> {
        let mut store = Self::open_initialized(directory, network).await?;
        let generation = store
            .state
            .authority
            .generation()
            .checked_add(1)
            .ok_or(hellas_auth::authority::AuthorityError::Capacity)?;
        let (credential, secret) = Credential::prepare(
            approval.credential,
            CredentialHolder::Node(approval.holder),
            generation,
        )?;
        let revoke = store
            .state
            .authority
            .grants()
            .filter(|grant| {
                grant.spec().permissions.iter().any(|permission| {
                    permission.operation.as_str() != crate::grant_service::WORK_EXECUTE
                })
            })
            .map(|grant| grant.id())
            .collect();
        store
            .commit(
                now,
                Change::Recover(RecoveryCommand {
                    expected,
                    administrator: approval.administrator,
                    credential,
                    revoke,
                    owner: approval.assertion,
                }),
                true,
            )
            .await?;
        let receipt = store
            .state
            .authority
            .last_recovery()
            .cloned()
            .ok_or(NodeStoreError::Malformed)?;
        Ok((receipt, secret))
    }

    /// Explicit offline creation only. No listener may serve this node until
    /// this returns; an interrupted initialization never becomes an empty store.
    /// The requested credential scope must fit the administrator's grant. Only
    /// its verifier is journaled; ordinary open can never reproduce the secret.
    pub async fn bootstrap(
        directory: &Path,
        network: NetworkId,
        root_grant: GrantId,
        approval: OwnerApproval,
        provider: Option<ProviderEnrollmentBundle>,
        now: UnixMillis,
    ) -> Result<(Self, CredentialSecret), NodeStoreError> {
        let clock = super::super::clock::ClockBound::new();
        clock.check(now)?;
        let (credential, secret) = Credential::prepare(
            approval.credential,
            CredentialHolder::Node(approval.holder),
            1,
        )?;
        let authority = AuthorityState::bootstrap(
            root_grant,
            approval.administrator,
            credential,
            &approval.assertion,
            now,
        )?;
        let state = State::initialized(network, authority, provider.clone())?;
        let marker = Marker {
            namespace: "hellas.node.identity.v1".into(),
            network,
            authority: state.authority.authority(),
        };
        let frame = Frame {
            namespace: "hellas.node.journal.v2".into(),
            now,
            changes: vec![Change::Initialize {
                authority: state.authority.snapshot(),
                provider,
            }],
        };
        let bytes = encode(&frame)?;
        hellas_private::create_dir_all_durable(directory)?;
        if std::fs::read_dir(directory)?.next().is_some() {
            return Err(NodeStoreError::AlreadyInitialized);
        }
        hellas_private::restrict_directory(directory)?;
        let (file, temporary) =
            hellas_private::private_tempfile(directory, ".authority-", ".initializing")?
                .into_parts();
        let mut identity_lock = lock(file, &directory.join(MARKER))?;
        identity_lock.0.write_all(&encode(&marker)?)?;
        identity_lock.0.sync_all()?;
        temporary
            .persist_noclobber(directory.join(MARKER))
            .map_err(|error| NodeStoreError::Io(error.error))?;
        hellas_private::sync_directory(directory)?;
        let (mut journal, _) =
            Journal::open_latest(directory, "grants", marker.journal_id()).await?;
        journal.append(&bytes).await?;
        Ok((
            Self {
                clock,
                _identity_lock: identity_lock,
                journal,
                state,
                executions: Default::default(),
                deliveries: Default::default(),
            },
            secret,
        ))
    }

    /// Read metadata with the daemon stopped, without recovery, clock ticks,
    /// schema migration or journal writes. Uses the same identity lock as writers.
    pub async fn inspect_offline(
        directory: &Path,
        network: NetworkId,
        query: &hellas_auth::authority::InspectionQuery,
    ) -> Result<hellas_auth::authority::AuthorityInspection, NodeStoreError> {
        let (_identity_lock, marker) = read_marker(directory, network)?;
        let snapshot = inspection_snapshot(directory)?;
        let (id, replay) = Journal::inspect(snapshot.path(), "grants").await?;
        if id != marker.journal_id() {
            return Err(NodeStoreError::Malformed);
        }
        let state = restore_replay(replay, network, marker.authority)?;
        Ok(state.authority.inspect_offline(query)?)
    }

    pub(super) async fn open_initialized(
        directory: &Path,
        network: NetworkId,
    ) -> Result<Self, NodeStoreError> {
        let clock = super::super::clock::ClockBound::new();
        let (identity_lock, marker) = read_marker(directory, network)?;
        let (journal, replay) =
            Journal::open_existing(directory, "grants", marker.journal_id()).await?;
        let state = restore_replay(replay, network, marker.authority)?;
        Ok(Self {
            clock,
            _identity_lock: identity_lock,
            journal,
            state,
            executions: Default::default(),
            deliveries: Default::default(),
        })
    }
}

/// Called while the store's identity lock excludes every writer.
fn inspection_snapshot(directory: &Path) -> Result<tempfile::TempDir, NodeStoreError> {
    // The identity lock excludes live inspections. Only our scratch directories
    // can be stale; DirEntry::file_type and remove_dir_all do not follow symlinks.
    for entry in std::fs::read_dir(directory)? {
        let entry = entry?;
        if entry
            .file_name()
            .as_encoded_bytes()
            .starts_with(b".inspection-")
            && entry.file_type()?.is_dir()
        {
            std::fs::remove_dir_all(entry.path())?;
        }
    }
    // A read-only SQLite connection may create shared-memory sidecars for a
    // crash-left WAL. Replay a private copy under the identity lock so even
    // that recovery leaves every source file unchanged.
    let snapshot = tempfile::Builder::new()
        .prefix(".inspection-")
        .tempdir_in(directory)?;
    hellas_private::restrict_directory(snapshot.path())?;
    let source = Journal::path(directory, "grants");
    let target = Journal::path(snapshot.path(), "grants");
    let parent = target.parent().ok_or(NodeStoreError::Malformed)?;
    hellas_private::create_dir_all_durable(parent)?;
    hellas_private::restrict_directory(parent)?;
    for (source, target) in [
        (source.clone(), target.clone()),
        (
            source.with_extension("sqlite-wal"),
            target.with_extension("sqlite-wal"),
        ),
    ] {
        if source
            .extension()
            .is_some_and(|extension| extension == "sqlite-wal")
            && !source.try_exists()?
        {
            continue;
        }
        let mut input = hellas_private::open_regular_file_nofollow(&source)?;
        let mut output = hellas_private::private_tempfile(parent, ".copy-", ".sqlite")?;
        std::io::copy(&mut input, &mut output)?;
        output
            .persist_noclobber(target)
            .map_err(|error| error.error)?;
    }
    Ok(snapshot)
}

fn read_marker(
    directory: &Path,
    network: NetworkId,
) -> Result<(IdentityLock, Marker), NodeStoreError> {
    let path = directory.join(MARKER);
    let identity_lock = match hellas_private::open_regular_file(&path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(NodeStoreError::Uninitialized);
        }
        Err(error) => return Err(error.into()),
    };
    if !hellas_private::is_private(&identity_lock)?
        || identity_lock.metadata()?.len() > MAX_MARKER_BYTES
    {
        return Err(NodeStoreError::Malformed);
    }
    let identity_lock = lock(identity_lock, &path)?;
    let bytes = hellas_private::read_bounded(&identity_lock.0, MAX_MARKER_BYTES as usize).map_err(
        |error| {
            if error
                .get_ref()
                .is_some_and(|error| error.is::<hellas_private::ReadLimit>())
            {
                NodeStoreError::Malformed
            } else {
                error.into()
            }
        },
    )?;
    let marker: Marker = decode(&bytes)?;
    if marker.namespace != "hellas.node.identity.v1" || marker.network != network {
        return Err(NodeStoreError::Malformed);
    }
    Ok((identity_lock, marker))
}

fn restore_replay(
    replay: crate::work_store::journal::Replay,
    network: NetworkId,
    authority_id: AuthorityId,
) -> Result<State, NodeStoreError> {
    let mut records = replay.records.into_iter();
    let mut state = match replay.checkpoint {
        Some(bytes) => State::restore(decode::<Snapshot>(&bytes)?)?,
        None => {
            let bytes = records.next().ok_or(NodeStoreError::Uninitialized)?;
            let mut frame: Frame = decode(&bytes)?;
            if frame.namespace != "hellas.node.journal.v2" || frame.changes.len() != 1 {
                return Err(NodeStoreError::Malformed);
            }
            let Some(Change::Initialize {
                authority,
                provider,
            }) = frame.changes.pop()
            else {
                return Err(NodeStoreError::Malformed);
            };
            let authority = AuthorityState::restore(authority)?;
            if authority.now() != frame.now
                || authority.revision() != Revision(1)
                || authority.generation() != 1
                || authority.grants().count() != 1
                || authority.credentials().count() != 1
            {
                return Err(NodeStoreError::Malformed);
            }
            State::initialized(network, authority, provider)?
        }
    };
    if state.network() != network || state.authority.authority() != authority_id {
        return Err(NodeStoreError::Malformed);
    }
    for bytes in records {
        state.apply(&decode::<Frame>(&bytes)?)?;
    }
    Ok(state)
}

impl Marker {
    fn journal_id(&self) -> JournalId {
        let key = hellas_auth::hash_tuple(
            "hellas.node.journal-key.v1",
            &[self.network.as_bytes(), self.authority.0.as_bytes()],
        );
        JournalId {
            kind: JournalKind::Grant,
            role: Role::Provider,
            key: *key.as_bytes(),
        }
    }
}

fn lock(file: File, path: &Path) -> Result<IdentityLock, NodeStoreError> {
    match file.try_lock() {
        Ok(()) => Ok(IdentityLock(file)),
        Err(TryLockError::WouldBlock) => {
            Err(crate::work_store::journal::JournalError::Locked { path: path.into() }.into())
        }
        Err(TryLockError::Error(error)) => Err(error.into()),
    }
}

#[cfg(test)]
mod tests;
