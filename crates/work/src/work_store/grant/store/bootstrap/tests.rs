use super::*;
use crate::model::grant::budget::Limit;
use hellas_auth::authority::{self as auth, OperationId, Permission};
use hellas_auth::{
    assert_err,
    test_support::{
        actors::{AGENT, FRIEND, OPERATOR, ROOT},
        ids,
    },
};

#[tokio::test]
async fn the_authority_clock_floor_survives_reopening_at_an_older_time() {
    let directory = tempfile::tempdir().unwrap();
    let (mut store, secret) = bootstrap(directory.path()).await;
    let mut authority = store.state().authority().clone();
    let mut scope = admin();
    scope.subject = OPERATOR.principal();
    let permission = Permission {
        operation: OperationId::new("work.execute").unwrap(),
        resource: auth::ResourceId(Digest::hash(b"expired model")),
    };
    scope.permissions = [permission.clone()].into();
    scope.expires = UnixMillis(5);
    scope.issuance = None;
    let mut later = scope.clone();
    later.subject = FRIEND.principal();
    later.expires = UnixMillis(10000);
    let command = auth::GrantCommand::Issue {
        authorization: ids::ROOT_GRANT,
        id: ids::OPERATOR_GRANT,
        spec: scope,
    };
    let change = authority_change(&mut authority, &secret, command, UnixMillis(2));
    store.commit(UnixMillis(2), change, true).await.unwrap();
    // A second authority mutation persists the floor beyond the grant's expiry.
    let change = authority_change(
        &mut authority,
        &secret,
        auth::GrantCommand::Issue {
            authorization: ids::ROOT_GRANT,
            id: ids::FRIEND_GRANT,
            spec: later,
        },
        UnixMillis(6),
    );
    store.commit(UnixMillis(6), change, true).await.unwrap();
    let before = store.state().clone();
    drop(store);
    let mut store = NodeStore::open(directory.path(), network(), None, UnixMillis(1))
        .await
        .unwrap();
    assert_eq!(store.state(), &before);
    assert_eq!(store.state().authority().now(), UnixMillis(6));
    assert_err!(
        store.state().authority().authorize(
            OPERATOR.principal(),
            ids::OPERATOR_GRANT,
            &permission,
            UnixMillis(2)
        ),
        auth::AuthorityError::Expired
    );
    let caller =
        crate::test_support::passkey_caller(store.state().authority(), &secret, UnixMillis(6));
    assert_err!(
        store
            .administer_authority(
                &caller,
                auth::AdministrationCommand::Grant(auth::GrantCommand::Revoke {
                    authorization: ids::ROOT_GRANT,
                    id: ids::OPERATOR_GRANT,
                    expected: store
                        .state()
                        .authority()
                        .grant(ids::OPERATOR_GRANT)
                        .unwrap()
                        .revision(),
                }),
                UnixMillis(2)
            )
            .await,
        NodeStoreError::Authority(auth::AuthorityError::Clock)
    );
    assert_eq!(store.state(), &before);
}

fn network() -> NetworkId {
    NetworkId::new("node-fixture").unwrap()
}
fn admin() -> GrantSpec {
    crate::test_support::common_node::admin_spec(
        AuthorityId(Digest::hash(b"node-fixture")),
        ROOT.principal(),
        &[],
        (UnixMillis(1), UnixMillis(10_000)),
        (10_000, 8),
        &["work.execute"],
    )
}
async fn bootstrap(path: &Path) -> (NodeStore, CredentialSecret) {
    NodeStore::bootstrap(
        path,
        network(),
        ids::ROOT_GRANT,
        crate::test_support::common_node::approval_for(
            auth::Ownership::Bootstrap {
                root: ids::ROOT_GRANT,
            },
            admin(),
            admin(),
        ),
        None,
        UnixMillis(1),
    )
    .await
    .unwrap()
}
fn grant_change(
    authority: &mut AuthorityState,
    secret: &CredentialSecret,
    now: UnixMillis,
) -> Change {
    let mut spec = admin();
    spec.subject = OPERATOR.principal();
    spec.permissions = [Permission {
        operation: OperationId::new("work.execute").unwrap(),
        resource: auth::ResourceId(Digest::hash(b"model")),
    }]
    .into();
    spec.issuance = None;
    authority_change(
        authority,
        secret,
        auth::GrantCommand::Issue {
            authorization: ids::ROOT_GRANT,
            id: ids::OPERATOR_GRANT,
            spec,
        },
        now,
    )
}
fn authority_change(
    authority: &mut AuthorityState,
    secret: &CredentialSecret,
    command: auth::GrantCommand,
    now: UnixMillis,
) -> Change {
    let caller = crate::test_support::passkey_caller(authority, secret, now);
    let record = authority
        .record_administration(&caller, auth::AdministrationCommand::Grant(command), now)
        .unwrap();
    authority.apply_administration(&record).unwrap();
    Change::Authority(record)
}
fn machine() -> Change {
    Change::Machine {
        limits: vec![Limit {
            meter: Meter::Requests,
            window: Window::Total,
            amount: 10,
        }],
        concurrent: 2,
    }
}

#[tokio::test]
async fn uninitialized_open_does_not_create_authority() {
    let directory = tempfile::tempdir().unwrap();
    assert_err!(
        NodeStore::open(directory.path(), network(), None, UnixMillis(1)).await,
        NodeStoreError::Uninitialized
    );
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
}

#[tokio::test]
async fn bootstrap_refuses_a_foreign_credential_subject_atomically() {
    let directory = tempfile::tempdir().unwrap();
    let mut scope = admin();
    scope.subject = OPERATOR.principal();
    assert_err!(
        NodeStore::bootstrap(
            directory.path(),
            network(),
            ids::ROOT_GRANT,
            crate::test_support::common_node::approval_for(
                auth::Ownership::Bootstrap {
                    root: ids::ROOT_GRANT
                },
                admin(),
                scope
            ),
            None,
            UnixMillis(1)
        )
        .await,
        NodeStoreError::Authority(auth::AuthorityError::Invalid)
    );
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
}

#[tokio::test]
async fn a_providerless_authority_survives_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let (store, secret) = bootstrap(directory.path()).await;
    let caller =
        crate::test_support::passkey_caller(store.state().authority(), &secret, UnixMillis(1));
    assert_eq!(store.state().authority().authority(), admin().authority);
    assert_err!(store.state().provider(), NodeStoreError::MissingProvider);
    drop(store);
    let reopened = NodeStore::open(directory.path(), network(), None, UnixMillis(2))
        .await
        .unwrap();
    assert_eq!(reopened.state().authority().revision(), Revision(1));
    crate::test_support::passkey_caller(reopened.state().authority(), &secret, UnixMillis(2));
    reopened
        .state()
        .authority()
        .authorize_caller(
            &caller,
            ids::ROOT_GRANT,
            &Permission {
                operation: OperationId::new(auth::CREDENTIAL_ISSUE).unwrap(),
                resource: admin().authority.resource(),
            },
            UnixMillis(2),
        )
        .unwrap();
}

#[tokio::test]
async fn an_existing_authority_cannot_be_bootstrapped_again() {
    let directory = tempfile::tempdir().unwrap();
    drop(bootstrap(directory.path()).await);
    assert_err!(
        NodeStore::bootstrap(
            directory.path(),
            network(),
            ids::ROOT_GRANT,
            crate::test_support::common_node::approval_for(
                auth::Ownership::Bootstrap {
                    root: ids::ROOT_GRANT
                },
                admin(),
                admin()
            ),
            None,
            UnixMillis(2)
        )
        .await,
        NodeStoreError::AlreadyInitialized
    );
}

async fn configured_node(path: &Path) -> NodeStore {
    let (mut store, secret) = bootstrap(path).await;
    let grant = grant_change(
        &mut store.state().authority().clone(),
        &secret,
        UnixMillis(2),
    );
    store
        .commit_changes(UnixMillis(2), vec![grant, machine()], true)
        .await
        .unwrap();
    store
}

#[tokio::test]
async fn a_refused_composite_frame_is_atomic_on_disk() {
    let directory = tempfile::tempdir().unwrap();
    let (mut store, secret) = bootstrap(directory.path()).await;
    let before = store.state().clone();
    let invalid = vec![
        grant_change(
            &mut store.state().authority().clone(),
            &secret,
            UnixMillis(2),
        ),
        machine(),
        Change::RepairResource(auth::ResourceId(Digest::hash(b"missing"))),
    ];
    assert_err!(
        store.commit_changes(UnixMillis(2), invalid, true).await,
        NodeStoreError::Grant(crate::model::grant::records::GrantError::OutOfScope)
    );
    assert_eq!(store.state(), &before);
    drop(store);
    let store = NodeStore::open(directory.path(), network(), None, UnixMillis(1))
        .await
        .unwrap();
    assert_eq!(store.state(), &before);
}

#[tokio::test]
async fn an_initialization_frame_cannot_reset_existing_state() {
    let directory = tempfile::tempdir().unwrap();
    let mut store = configured_node(directory.path()).await;
    let before = store.state().clone();
    let reset = Change::Initialize {
        authority: AuthorityState::bootstrap(
            ids::ROOT_GRANT,
            admin(),
            Credential::prepare(admin(), ROOT.holder(), 1).unwrap().0,
            &hellas_auth::test_support::approve(
                ROOT,
                auth::Ownership::Bootstrap {
                    root: ids::ROOT_GRANT,
                },
                &admin(),
                &admin(),
                ROOT.holder(),
            ),
            UnixMillis(2),
        )
        .unwrap()
        .snapshot(),
        provider: None,
    };
    assert_err!(
        store.commit(UnixMillis(2), reset, true).await,
        NodeStoreError::Malformed
    );
    assert_eq!(store.state(), &before);
}

#[tokio::test]
async fn the_identity_lock_excludes_another_writer_across_rotation() {
    let directory = tempfile::tempdir().unwrap();
    let (mut store, _secret) = bootstrap(directory.path()).await;
    for _ in 0..2 {
        assert_err!(
            NodeStore::open(directory.path(), network(), None, UnixMillis(1)).await,
            NodeStoreError::Journal(crate::work_store::journal::JournalError::Locked { .. })
        );
        store.rotate().await.unwrap();
    }
    drop(store);
    NodeStore::open(directory.path(), network(), None, UnixMillis(2))
        .await
        .unwrap();
}

#[tokio::test]
async fn inherited_identity_descriptors_cannot_outlive_the_writer() {
    let directory = tempfile::tempdir().unwrap();
    let (store, _secret) = bootstrap(directory.path()).await;
    // A concurrent fork retains this open file description until its exec.
    let inherited = store._identity_lock.0.try_clone().unwrap();
    let before = store.state().clone();
    drop(store);
    let reopened = NodeStore::open(directory.path(), network(), None, UnixMillis(1))
        .await
        .unwrap();
    assert_eq!(reopened.state(), &before);
    drop(inherited);
}

#[derive(Clone, Copy, Debug)]
enum Damage {
    MissingMarker,
    MissingJournal,
    CorruptMarker,
}

#[tokio::test]
async fn damaged_initialization_never_opens_as_empty() {
    for damage in [
        Damage::MissingMarker,
        Damage::MissingJournal,
        Damage::CorruptMarker,
    ] {
        let directory = tempfile::tempdir().unwrap();
        drop(bootstrap(directory.path()).await);
        let journal = crate::work_store::journal::Journal::path(directory.path(), "grants");
        match damage {
            Damage::MissingMarker => std::fs::remove_file(directory.path().join(MARKER)).unwrap(),
            Damage::MissingJournal => std::fs::remove_file(&journal).unwrap(),
            Damage::CorruptMarker => {
                std::fs::write(directory.path().join(MARKER), b"broken").unwrap()
            }
        }
        let result = NodeStore::open(directory.path(), network(), None, UnixMillis(2)).await;
        match damage {
            Damage::MissingMarker => assert_err!(result, NodeStoreError::Uninitialized),
            Damage::MissingJournal => assert_err!(
                result,
                NodeStoreError::Journal(crate::work_store::journal::JournalError::Missing { .. })
            ),
            Damage::CorruptMarker => assert_err!(result, NodeStoreError::Malformed),
        }
        assert_err!(
            NodeStore::bootstrap(
                directory.path(),
                network(),
                ids::ROOT_GRANT,
                crate::test_support::common_node::approval_for(
                    auth::Ownership::Bootstrap {
                        root: ids::ROOT_GRANT
                    },
                    admin(),
                    admin()
                ),
                None,
                UnixMillis(2)
            )
            .await,
            NodeStoreError::AlreadyInitialized
        );
        if matches!(damage, Damage::MissingJournal) {
            assert!(!journal.exists());
        }
    }
}

#[tokio::test]
async fn offline_recovery_requires_initialized_exclusive_state_and_expected_revision() {
    let directory = tempfile::tempdir().unwrap();
    let mut replacement = admin();
    replacement.subject = FRIEND.principal();
    let recover = async |expected| {
        NodeStore::recover_offline(
            directory.path(),
            network(),
            expected,
            crate::test_support::common_node::approval_for(
                auth::Ownership::Recover { expected },
                replacement.clone(),
                replacement.clone(),
            ),
            UnixMillis(2),
        )
        .await
    };
    assert_err!(recover(Revision(1)).await, NodeStoreError::Uninitialized);
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
    let (store, _secret) = bootstrap(directory.path()).await;
    assert_err!(
        recover(Revision(1)).await,
        NodeStoreError::Journal(crate::work_store::journal::JournalError::Locked { .. })
    );
    let before = store.state().clone();
    drop(store);
    assert_err!(
        recover(Revision(2)).await,
        NodeStoreError::Authority(auth::AuthorityError::Revision)
    );
    let store = NodeStore::open_initialized(directory.path(), network())
        .await
        .unwrap();
    assert_eq!(store.state(), &before);
    drop(store);
    let (receipt, _) = recover(Revision(1)).await.unwrap();
    assert_eq!(receipt.generation, 2);
    let store = NodeStore::open_initialized(directory.path(), network())
        .await
        .unwrap();
    assert_eq!(store.state().authority().last_recovery(), Some(&receipt));
    assert_eq!(
        store
            .state()
            .authority()
            .grant(ids::ROOT_GRANT)
            .unwrap()
            .spec()
            .subject,
        FRIEND.principal()
    );
}

#[tokio::test]
async fn service_and_mixed_administration_are_revoked_while_execution_and_accounting_survive() {
    let directory = tempfile::tempdir().unwrap();
    let mut initial = admin();
    initial
        .issuance
        .as_mut()
        .unwrap()
        .operations
        .insert(OperationId::new("host.reboot").unwrap());
    let (mut store, secret) = NodeStore::bootstrap(
        directory.path(),
        network(),
        ids::ROOT_GRANT,
        crate::test_support::common_node::approval_for(
            auth::Ownership::Bootstrap {
                root: ids::ROOT_GRANT,
            },
            initial.clone(),
            initial,
        ),
        None,
        UnixMillis(1),
    )
    .await
    .unwrap();
    let mut mixed = admin();
    mixed.subject = FRIEND.principal();
    mixed.issuance = None;
    mixed.permissions = ["work.execute", "host.reboot"]
        .map(|op| Permission {
            operation: OperationId::new(op).unwrap(),
            resource: admin().authority.resource(),
        })
        .into();
    let mut authority = store.state().authority().clone();
    let first = grant_change(&mut authority, &secret, UnixMillis(2));
    let second = authority_change(
        &mut authority,
        &secret,
        auth::GrantCommand::Issue {
            authorization: ids::ROOT_GRANT,
            id: ids::FRIEND_GRANT,
            spec: mixed,
        },
        UnixMillis(2),
    );
    store
        .commit_changes(UnixMillis(2), vec![first, machine(), second], true)
        .await
        .unwrap();
    let before = store.state().clone();
    drop(store);
    let mut replacement = admin();
    replacement.subject = AGENT.principal();
    let (receipt, _) = NodeStore::recover_offline(
        directory.path(),
        network(),
        before.authority().revision(),
        crate::test_support::common_node::approval_for(
            auth::Ownership::Recover {
                expected: before.authority().revision(),
            },
            replacement.clone(),
            replacement,
        ),
        UnixMillis(2),
    )
    .await
    .unwrap();
    let mut store = NodeStore::open_initialized(directory.path(), network())
        .await
        .unwrap();
    assert_eq!(store.state().ledger(), before.ledger());
    assert_eq!(
        store.state().authority().grant(ids::OPERATOR_GRANT),
        before.authority().grant(ids::OPERATOR_GRANT)
    );
    assert!(
        store
            .state()
            .authority()
            .grant(ids::FRIEND_GRANT)
            .unwrap()
            .revoked()
    );
    assert_eq!(receipt.revoked, [ids::ROOT_GRANT, ids::FRIEND_GRANT].into());
    store.rotate().await.unwrap();
    let after = store.state().clone();
    drop(store);
    let store = NodeStore::open_initialized(directory.path(), network())
        .await
        .unwrap();
    assert_eq!(store.state(), &after);
    assert_eq!(store.state().authority().last_recovery(), Some(&receipt));
}

#[tokio::test]
async fn offline_recovery_changes_the_authority_once_and_journals_no_secret() {
    let directory = tempfile::tempdir().unwrap();
    let (mut store, original) = NodeStore::bootstrap(
        directory.path(),
        network(),
        ids::ROOT_GRANT,
        crate::test_support::common_node::approval_for(
            auth::Ownership::Bootstrap {
                root: ids::ROOT_GRANT,
            },
            admin(),
            admin(),
        ),
        None,
        UnixMillis(1),
    )
    .await
    .unwrap();
    store
        .commit_changes(
            UnixMillis(2),
            vec![
                grant_change(
                    &mut store.state().authority().clone(),
                    &original,
                    UnixMillis(2),
                ),
                machine(),
            ],
            true,
        )
        .await
        .unwrap();
    let before = store.state().clone();
    drop(store);
    let mut replacement = admin();
    replacement.subject = FRIEND.principal();
    let (_, replacement_secret) = NodeStore::recover_offline(
        directory.path(),
        network(),
        before.authority().revision(),
        crate::test_support::common_node::approval_for(
            auth::Ownership::Recover {
                expected: before.authority().revision(),
            },
            replacement.clone(),
            replacement,
        ),
        UnixMillis(3),
    )
    .await
    .unwrap();
    let store = NodeStore::open_initialized(directory.path(), network())
        .await
        .unwrap();
    let authority = store.state().authority();
    assert_eq!(
        crate::test_support::try_passkey_caller(authority, &original, UnixMillis(3)).map(|_| ()),
        Err(auth::AuthorityError::Credential)
    );
    assert_eq!(
        crate::test_support::try_passkey_caller(authority, &replacement_secret, UnixMillis(3))
            .map(|_| ()),
        Ok(())
    );
    // Scanned while held, so the WAL is still beside the database.
    for path in crate::test_support::all_files(&directory.path().join("journals")) {
        let bytes = std::fs::read(path).unwrap();
        for secret in [&original, &replacement_secret] {
            assert!(
                !bytes
                    .windows(32)
                    .any(|bytes| bytes == secret.expose_secret())
            );
        }
    }
}

#[tokio::test]
async fn offline_inspection_holds_identity_lock_and_preserves_journal_bytes() {
    let directory = tempfile::tempdir().unwrap();
    let (store, secret) = bootstrap(directory.path()).await;
    let query = auth::InspectionQuery::Credentials { after: None };
    assert!(
        NodeStore::inspect_offline(directory.path(), network(), &query)
            .await
            .is_err()
    );
    let expected_revision = store.state().authority().revision();
    drop(store);
    // Inspect the actual copy helper while its private files still exist.
    {
        let (_lock, _) = read_marker(directory.path(), network()).unwrap();
        let snapshot = inspection_snapshot(directory.path()).unwrap();
        for path in crate::test_support::all_files(snapshot.path()) {
            assert!(hellas_private::is_private(&std::fs::File::open(path).unwrap()).unwrap());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for path in [
                snapshot.path().to_path_buf(),
                snapshot.path().join("journals"),
            ] {
                assert_eq!(
                    std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
                    0o700
                );
            }
            for path in crate::test_support::all_files(snapshot.path()) {
                assert_eq!(
                    std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
                    0o600
                );
            }
        }
    }
    let before = inspection_files(directory.path());
    let view = NodeStore::inspect_offline(directory.path(), network(), &query)
        .await
        .unwrap();
    assert_eq!(view.revision, expected_revision);
    let auth::InspectionRecords::Credentials { records, .. } = view.records else {
        panic!("credentials")
    };
    assert!(records.iter().any(|c| c.id == secret.id()));
    assert_eq!(inspection_files(directory.path()), before);
    // Opening the live store after inspection still sees the exact same revision.
    let store = NodeStore::open_initialized(directory.path(), network())
        .await
        .unwrap();
    assert_eq!(store.state().authority().revision(), expected_revision);
}

#[tokio::test]
async fn offline_inspection_recovers_the_revision_after_a_lost_recovery_receipt() {
    let directory = tempfile::tempdir().unwrap();
    drop(bootstrap(directory.path()).await);
    let query = auth::InspectionQuery::Credentials { after: None };
    for generation in [2, 3] {
        let before = NodeStore::inspect_offline(directory.path(), network(), &query)
            .await
            .unwrap();
        let expected = before.revision;
        // Lose both the committed receipt and its unpublished credential.
        drop(
            NodeStore::recover_offline(
                directory.path(),
                network(),
                expected,
                crate::test_support::common_node::approval_for(
                    auth::Ownership::Recover { expected },
                    admin(),
                    admin(),
                ),
                UnixMillis(generation),
            )
            .await
            .unwrap(),
        );
        let after = NodeStore::inspect_offline(directory.path(), network(), &query)
            .await
            .unwrap();
        assert_eq!(after.generation, generation);
        assert!(after.revision > expected);
    }
}

fn inspection_files(directory: &Path) -> std::collections::BTreeMap<std::path::PathBuf, Vec<u8>> {
    crate::test_support::all_files(directory)
        .into_iter()
        .map(|path| {
            (
                path.strip_prefix(directory).unwrap().to_path_buf(),
                std::fs::read(path).unwrap(),
            )
        })
        .collect()
}

#[tokio::test]
async fn offline_inspection_reads_a_crash_left_wal_without_creating_source_sidecars() {
    let live = tempfile::tempdir().unwrap();
    let (mut store, secret) = bootstrap(live.path()).await;
    let database = live.path().join("journals/grants.sqlite");
    let before_commit = std::fs::read(&database).unwrap();
    let caller =
        crate::test_support::passkey_caller(store.state().authority(), &secret, UnixMillis(2));
    let mut intended = admin();
    intended.subject = FRIEND.principal();
    store
        .administer_authority(
            &caller,
            auth::AdministrationCommand::Grant(auth::GrantCommand::Issue {
                authorization: ids::ROOT_GRANT,
                id: ids::FRIEND_GRANT,
                spec: intended.clone(),
            }),
            UnixMillis(2),
        )
        .await
        .unwrap();
    // The newly committed grant is in WAL, not checkpointed into the database.
    assert_eq!(std::fs::read(database).unwrap(), before_commit);
    let crashed = tempfile::tempdir().unwrap();
    // Snapshot an idle writer before SQLite can checkpoint on clean shutdown.
    // This is the on-disk image of a process exiting without closing SQLite.
    for relative in inspection_files(live.path()).keys() {
        let target = crashed.path().join(relative);
        std::fs::create_dir_all(target.parent().unwrap()).unwrap();
        std::fs::copy(live.path().join(relative), target).unwrap();
    }
    hellas_private::restrict_directory(crashed.path()).unwrap();
    let wal = crashed.path().join("journals/grants.sqlite-wal");
    assert!(std::fs::metadata(&wal).unwrap().len() > 32);
    let shm = crashed.path().join("journals/grants.sqlite-shm");
    if shm.exists() {
        std::fs::remove_file(&shm).unwrap();
    }
    let before = inspection_files(crashed.path());
    {
        let (_lock, _) = read_marker(crashed.path(), network()).unwrap();
        let snapshot = inspection_snapshot(crashed.path()).unwrap();
        let copied_wal = snapshot.path().join("journals/grants.sqlite-wal");
        let file = std::fs::File::open(&copied_wal).unwrap();
        assert!(hellas_private::is_private(&file).unwrap());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(file.metadata().unwrap().permissions().mode() & 0o777, 0o600);
        }
        assert_eq!(
            std::fs::read(copied_wal).unwrap(),
            std::fs::read(&wal).unwrap()
        );
    }
    let view = NodeStore::inspect_offline(
        crashed.path(),
        network(),
        &auth::InspectionQuery::Grant {
            id: ids::FRIEND_GRANT,
        },
    )
    .await
    .unwrap();
    assert_eq!(view.revision, store.state().authority().revision());
    let auth::InspectionRecords::Grants { records, .. } = view.records else {
        panic!("grants")
    };
    assert_eq!(records[0].id(), ids::FRIEND_GRANT);
    assert_eq!(records[0].spec(), &intended);
    assert_eq!(inspection_files(crashed.path()), before);
    assert!(!shm.exists());
}

#[tokio::test]
async fn offline_inspection_removes_only_stale_snapshot_directories() {
    let directory = tempfile::tempdir().unwrap();
    let (store, _) = bootstrap(directory.path()).await;
    let query = auth::InspectionQuery::Grant {
        id: ids::ROOT_GRANT,
    };
    let stale = directory.path().join(".inspection-abandoned");
    std::fs::create_dir(&stale).unwrap();
    std::fs::write(stale.join("snapshot"), b"private stale data").unwrap();
    let unrelated = directory.path().join("unrelated");
    std::fs::create_dir(&unrelated).unwrap();
    std::fs::write(unrelated.join("keep"), b"unrelated data").unwrap();
    let prefixed_file = directory.path().join(".inspection-regular-file");
    std::fs::write(&prefixed_file, b"not a directory").unwrap();
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(&unrelated, directory.path().join(".inspection-link")).unwrap();
        std::os::unix::fs::symlink(&unrelated, stale.join("nested-link")).unwrap();
    }
    // Cleanup is also excluded while a writer owns the journal.
    assert!(
        NodeStore::inspect_offline(directory.path(), network(), &query)
            .await
            .is_err()
    );
    assert!(stale.exists());
    drop(store);
    NodeStore::inspect_offline(directory.path(), network(), &query)
        .await
        .unwrap();
    assert!(!stale.exists());
    assert_eq!(
        std::fs::read(unrelated.join("keep")).unwrap(),
        b"unrelated data"
    );
    assert_eq!(std::fs::read(prefixed_file).unwrap(), b"not a directory");
    #[cfg(unix)]
    assert!(
        std::fs::symlink_metadata(directory.path().join(".inspection-link"))
            .unwrap()
            .is_symlink()
    );
    assert!(std::fs::read_dir(directory.path()).unwrap().all(|entry| {
        let entry = entry.unwrap();
        !entry
            .file_name()
            .as_encoded_bytes()
            .starts_with(b".inspection-")
            || !entry.file_type().unwrap().is_dir()
    }));
}
