mod common_grant;
use common_grant::*;
use hellas_rpc::protocol::work_grant::{admin::*, budget::*, records::*, *};
use hellas_work::{grant_service::GrantService, work::WorkBackend, work_store::grant::*};
use std::{
    num::{NonZeroU16, NonZeroU64},
    sync::Arc,
};
#[derive(Clone)]
struct NoBackend;
impl WorkBackend for NoBackend {}
fn make_service(store: GrantStore) -> GrantService {
    GrantService::new(
        store,
        Arc::new(principal(2).1),
        NoBackend,
        vec![],
        Arc::new(|| UnixMillis(1000)),
    )
    .unwrap()
}
fn terms() -> GrantTerms {
    GrantTerms {
        policies: vec!["responses".into()],
        limits: vec![Limit {
            meter: Meter::Requests,
            window: Window::Total,
            amount: 2,
        }],
        max_job_millis: NonZeroU64::new(5000).unwrap(),
        max_in_flight: NonZeroU16::new(1).unwrap(),
        expires_in_millis: None,
        allow_account_backed: true,
    }
}
fn context(seed: u8) -> hellas_wire::TransportContext {
    hellas_wire::TransportContext {
        peer: Some(hellas_wire::PeerIdentity([seed; 32])),
        auth_level: hellas_wire::AuthLevel::Vouched,
        ..Default::default()
    }
}
fn user_revision(service: &GrantService, id: PrincipalId) -> Revision {
    service
        .administer(|s, _| Ok(s.state().user(id).unwrap().revision))
        .unwrap()
}
fn user_command(
    service: &GrantService,
    command: UserCommand,
) -> Result<GrantReply, GrantStoreError> {
    service.control(
        GrantCommand::Users(command),
        &[policy()],
        NonZeroU64::new(10000).unwrap(),
    )
}
#[test]
fn removing_a_user_revokes_every_permission_atomically_and_preserves_running_duties() {
    let root = tempfile::tempdir().unwrap();
    let mut store = setup(root.path());
    store
        .define(
            definition(GrantId([9; 16]), principal(1).0),
            UnixMillis(1000),
        )
        .unwrap();
    let (running, signature, input) = proposal(&store, 1);
    store
        .accept(
            running,
            signature,
            &input,
            &principal(2).1,
            UnixMillis(1000),
        )
        .unwrap();
    let work = grant_work_id(network(), &running);
    store
        .dispatch(running.channel_id, work, UnixMillis(1000))
        .unwrap();
    let (queued, signature, input) = proposal(&store, 2);
    store
        .accept(queued, signature, &input, &principal(2).1, UnixMillis(1000))
        .unwrap();
    let service = make_service(store);
    let id = principal(1).0.id();
    user_command(
        &service,
        UserCommand::Update {
            id,
            expected_revision: Revision(1),
            admin: Some(true),
            work: None,
        },
    )
    .unwrap();
    assert!(
        service
            .control_as(
                GrantCommand::Users(UserCommand::List),
                &[],
                NonZeroU64::new(1).unwrap(),
                &context(1)
            )
            .is_ok()
    );
    let mut claimed = context(1);
    claimed.auth_level = hellas_wire::AuthLevel::None;
    assert!(
        service
            .control_as(
                GrantCommand::Users(UserCommand::List),
                &[],
                NonZeroU64::new(1).unwrap(),
                &claimed
            )
            .is_err()
    );
    user_command(
        &service,
        UserCommand::Remove {
            id,
            expected_revision: Revision(2),
        },
    )
    .unwrap();
    // The same connection evidence, admitted before removal, cannot mutate after it.
    assert!(
        service
            .control_as(
                GrantCommand::Users(UserCommand::Add {
                    principal: Box::new(principal(3).0),
                    expected_revision: None,
                    admin: true,
                    work: None,
                }),
                &[],
                NonZeroU64::new(1).unwrap(),
                &context(1)
            )
            .is_err()
    );
    service
        .administer(|store, now| {
            assert_eq!(
                store.state().user(id).unwrap().permissions,
                UserPermissions::Removed
            );
            assert!(
                store
                    .state()
                    .grants()
                    .all(|g| g.state == GrantState::Revoked)
            );
            assert_eq!(store.state().ledger().active_count(BudgetNode::Machine), 1);
            store.finish(
                running.channel_id,
                work,
                GrantOutcome::Indeterminate,
                None,
                Usage::Unknown,
                now,
            )?;
            store.rotate()
        })
        .unwrap();
    drop(service);
    let store = GrantStore::open(
        root.path(),
        network(),
        principal(2).0.bundle().clone(),
        UnixMillis(1001),
    )
    .unwrap();
    assert_eq!(
        store.state().user(id).unwrap().permissions,
        UserPermissions::Removed
    );
    assert!(!store.state().allows_admin(&context(1)));
    assert_eq!(
        store
            .state()
            .ledger()
            .node(BudgetNode::Grant(GrantId([1; 16])))
            .unwrap()
            .counter(Meter::Requests, Window::Total)
            .used,
        1
    );
    let service = make_service(store);
    // Explicit re-add preserves the old revoked grants and counters.
    user_command(
        &service,
        UserCommand::Add {
            principal: Box::new(principal(1).0),
            expected_revision: Some(Revision(3)),
            admin: true,
            work: None,
        },
    )
    .unwrap();
    service
        .administer(|store, _| {
            assert!(store.state().allows_admin(&context(1)));
            assert!(
                store
                    .state()
                    .grants()
                    .all(|g| g.state == GrantState::Revoked)
            );
            assert_eq!(
                store
                    .state()
                    .ledger()
                    .node(BudgetNode::Grant(GrantId([1; 16])))
                    .unwrap()
                    .counter(Meter::Requests, Window::Total)
                    .used,
                1
            );
            Ok(())
        })
        .unwrap();
}
#[test]
fn users_are_atomic_revision_checked_and_owner_permissions_are_immutable() {
    let root = tempfile::tempdir().unwrap();
    let service = make_service(setup(root.path()));
    let owner = principal(2).0.id();
    assert!(
        user_command(
            &service,
            UserCommand::Remove {
                id: owner,
                expected_revision: Revision(1)
            }
        )
        .is_err()
    );
    assert!(
        user_command(
            &service,
            UserCommand::Update {
                id: owner,
                expected_revision: Revision(1),
                admin: Some(false),
                work: None
            }
        )
        .is_err()
    );
    let mut invalid = terms();
    invalid.policies = vec!["missing".into()];
    assert!(
        user_command(
            &service,
            UserCommand::Add {
                principal: Box::new(principal(3).0),
                expected_revision: None,
                admin: true,
                work: Some((GrantId([3; 16]), invalid)),
            }
        )
        .is_err()
    );
    service
        .administer(|store, _| {
            assert!(store.state().user(principal(3).0.id()).is_none());
            assert!(store.state().grant(GrantId([3; 16])).is_none());
            Ok(())
        })
        .unwrap();
    let id = principal(1).0.id();
    let before = service
        .administer(|store, _| Ok(store.state().clone()))
        .unwrap();
    assert!(
        user_command(
            &service,
            UserCommand::Update {
                id,
                expected_revision: Revision(1),
                admin: Some(true),
                work: Some(UserWork::SetState {
                    id: GrantId([1; 16]),
                    expected_revision: Revision(99),
                    state: GrantState::Paused
                }),
            }
        )
        .is_err()
    );
    assert_eq!(
        before,
        service
            .administer(|store, _| Ok(store.state().clone()))
            .unwrap()
    );
    user_command(
        &service,
        UserCommand::Add {
            principal: Box::new(principal(3).0),
            expected_revision: None,
            admin: true,
            work: None,
        },
    )
    .unwrap();
    service
        .administer(|store, _| {
            assert!(store.state().allows_admin(&context(3)));
            assert!(!store.state().allows_admin(&context(1)));
            assert!(
                !store
                    .state()
                    .grants()
                    .any(|g| g.kind.principal().id() == principal(3).0.id())
            );
            Ok(())
        })
        .unwrap();
    assert_eq!(user_revision(&service, owner), Revision(1));
}

#[test]
fn partial_work_revision_keeps_absolute_expiry_and_checkpoint_keeps_admin() {
    let root = tempfile::tempdir().unwrap();
    let mut store = setup(root.path());
    let mut def = store.state().grant(GrantId([1; 16])).unwrap().clone();
    def.revision = Revision(2);
    def.expires = Some(UnixMillis(2000));
    store.define(def, UnixMillis(1000)).unwrap();
    let service = make_service(store);
    let id = principal(1).0.id();
    let mut replacement = terms();
    replacement.expires_in_millis = NonZeroU64::new(9000);
    user_command(
        &service,
        UserCommand::Update {
            id,
            expected_revision: Revision(1),
            admin: Some(true),
            work: Some(UserWork::Revise {
                id: GrantId([1; 16]),
                expected_revision: Revision(2),
                terms: replacement,
                keep_expiry: true,
            }),
        },
    )
    .unwrap();
    service
        .administer(|store, _| {
            assert_eq!(
                store.state().grant(GrantId([1; 16])).unwrap().expires,
                Some(UnixMillis(2000))
            );
            store.rotate()
        })
        .unwrap();
    drop(service);
    let store = GrantStore::open(
        root.path(),
        network(),
        principal(2).0.bundle().clone(),
        UnixMillis(1001),
    )
    .unwrap();
    assert!(store.state().allows_admin(&context(1)));
    assert_eq!(store.state().user(id).unwrap().revision, Revision(2));
    assert_eq!(
        store.state().grant(GrantId([1; 16])).unwrap().expires,
        Some(UnixMillis(2000))
    );
}

#[test]
fn a_second_contact_for_the_same_transport_cannot_bypass_user_revocation() {
    let root = tempfile::tempdir().unwrap();
    let service = make_service(setup(root.path()));
    let (original, key) = principal(1);
    let mut bundle = original.bundle().clone();
    bundle.genesis.statement.installation_nonce = [99; 32];
    bundle.genesis.root_proof = hellas_rpc::RootProof::Software(
        key.sign_digest(hellas_rpc::Digest::hash(
            &bundle.genesis.statement.canonical_bytes(),
        ))
        .unwrap(),
    );
    let alias = Principal::verify(bundle).unwrap();
    assert_ne!(alias.id(), original.id());
    user_command(
        &service,
        UserCommand::Remove {
            id: original.id(),
            expected_revision: Revision(1),
        },
    )
    .unwrap();
    assert!(
        user_command(
            &service,
            UserCommand::Add {
                principal: Box::new(alias),
                expected_revision: None,
                admin: true,
                work: None
            }
        )
        .is_err()
    );
    assert!(
        service
            .administer(|store, _| Ok(!store.state().allows_admin(&context(1))))
            .unwrap()
    );
}

#[test]
fn journal_io_failure_stops_authorization_until_reopened() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("journal");
    let service = make_service(setup(&path));
    let owner = hellas_wire::TransportContext {
        auth_level: hellas_wire::AuthLevel::LocalOwner,
        ..Default::default()
    };
    assert!(
        service
            .control_as(
                GrantCommand::Users(UserCommand::List),
                &[],
                NonZeroU64::new(1).unwrap(),
                &owner
            )
            .is_ok()
    );
    // An actual filesystem failure during checkpoint installation, with the old
    // journal still intact and held open, must stop this actor's authority.
    let held = root.path().join("held");
    std::fs::rename(&path, &held).unwrap();
    std::fs::write(&path, b"not a directory").unwrap();
    assert!(service.administer(|store, _| store.rotate()).is_err());
    assert!(matches!(
        service.control_as(
            GrantCommand::Users(UserCommand::List),
            &[],
            NonZeroU64::new(1).unwrap(),
            &owner
        ),
        Err(GrantStoreError::Unavailable)
    ));
    drop(service);
    std::fs::remove_file(&path).unwrap();
    std::fs::rename(&held, &path).unwrap();
    let reopened = GrantStore::open(
        &path,
        network(),
        principal(2).0.bundle().clone(),
        UnixMillis(1001),
    )
    .unwrap();
    assert!(reopened.state().allows_admin(&owner));
    assert_eq!(
        reopened
            .state()
            .user(principal(1).0.id())
            .unwrap()
            .permissions,
        UserPermissions::Active { admin: false }
    );
}
