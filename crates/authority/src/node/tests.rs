use super::*;
use hellas_kernel::NetworkId;
use hellas_private::StoreLocation;
use {
    crate::test_support::ids, hellas_channel::test_support::Actor,
    hellas_channel::test_support::actors::*, hellas_channel::test_support::assert_err,
};

fn scope(actor: Actor) -> GrantSpec {
    crate::test_support::common_node::admin_spec(
        AuthorityId(Digest::hash(b"checked-node-fixture")),
        actor.principal(),
        &[],
        (UnixMillis(1), UnixMillis(1_000_000)),
        (1_000_000, 8),
        &[],
    )
}
fn network() -> NetworkId {
    NetworkId::new("checked-node-fixture").unwrap()
}
async fn fixture(path: &std::path::Path, admin: GrantSpec) -> (NodeCoordinator, CredentialSecret) {
    let location = StoreLocation::for_test(path);
    let (store, secret) = NodeStore::bootstrap(
        &location,
        network(),
        ids::ROOT_GRANT,
        crate::test_support::common_node::approval(
            Ownership::Bootstrap {
                root: ids::ROOT_GRANT,
                target: None,
            },
            admin,
        ),
        None,
        UnixMillis(1),
    )
    .await
    .unwrap();
    (
        NodeCoordinator::new(store, Arc::new(|| UnixMillis(10))),
        secret,
    )
}
fn issue(authorization: GrantId, id: GrantId, actor: Actor) -> GrantCommand {
    GrantCommand::Issue {
        authorization,
        id,
        spec: scope(actor),
    }
}

#[tokio::test]
async fn checked_administration_persists_caller_audit_and_rechecks_sessions_after_revocation() {
    let directory = tempfile::tempdir().unwrap();
    let (node, root_secret) = fixture(directory.path(), scope(ROOT)).await;
    let root = crate::test_support::session(&node, &root_secret).await;
    let (_, secret) = crate::test_support::credentials::issue_one(
        &node,
        &root,
        ids::ROOT_GRANT,
        scope(OPERATOR),
        OPERATOR.holder(),
    )
    .await
    .unwrap();
    let binding = Digest::hash(b"test connection");
    let pending = node.begin_authentication(binding).await.unwrap();
    let proof = SessionKey::Passkey(&OPERATOR.passkey())
        .prove(
            pending.challenge(),
            scope(ROOT).authority,
            binding,
            secret.id(),
        )
        .await
        .unwrap();
    let session = node
        .complete_authentication(pending, binding, &secret, &proof)
        .await
        .unwrap();
    let caller = node.session_caller(&session, binding).await.unwrap();
    assert_err!(
        node.grant(
            caller,
            issue(ids::OPERATOR_GRANT, ids::FRIEND_GRANT, FRIEND)
        )
        .await,
        NodeStoreError::Authority(AuthorityError::Missing)
    );
    node.grant(&root, issue(ids::ROOT_GRANT, ids::OPERATOR_GRANT, OPERATOR))
        .await
        .unwrap();
    let receipt = node
        .grant(
            caller,
            issue(ids::OPERATOR_GRANT, ids::FRIEND_GRANT, FRIEND),
        )
        .await
        .unwrap();
    assert_eq!(receipt.caller().actor(), scope(OPERATOR).subject);
    assert_eq!(receipt.caller().credential(), secret.id());
    assert_eq!(receipt.caller().credential_revision(), Revision(1));
    let revoked = node
        .revoke_credential(&root, ids::ROOT_GRANT, secret.id(), Revision(1))
        .await
        .unwrap();
    assert_err!(
        node.session_caller(&session, binding).await,
        NodeStoreError::Authority(AuthorityError::Credential)
    );
    assert_err!(
        node.grant(caller, issue(ids::OPERATOR_GRANT, ids::AGENT_GRANT, AGENT))
            .await,
        NodeStoreError::Authority(AuthorityError::Credential)
    );
    node.store.lock().await.unwrap().rotate().await.unwrap();
    drop(node);
    let location = StoreLocation::for_test(directory.path());
    let store = NodeStore::open(&location, network(), None, UnixMillis(11))
        .await
        .unwrap();
    assert_eq!(store.state().last_administration(), Some(&revoked));
    assert!(store.state().authority().grant(ids::FRIEND_GRANT).is_some());
    assert!(store.state().authority().grant(ids::AGENT_GRANT).is_none());
    assert_err!(
        crate::test_support::try_passkey_caller(store.state().authority(), &secret, UnixMillis(11)),
        AuthorityError::Credential
    );
}

#[tokio::test]
async fn unmounted_operations_cannot_be_issued() {
    let directory = tempfile::tempdir().unwrap();
    let mut admin = scope(ROOT);
    admin
        .issuance
        .as_mut()
        .unwrap()
        .operations
        .insert(OperationId::new("host.reboot").unwrap());
    let (node, secret) = fixture(directory.path(), admin).await;
    let caller = crate::test_support::session(&node, &secret).await;
    let before = node.store.lock().await.unwrap().state().clone();
    let mut unmounted = scope(OPERATOR);
    unmounted.issuance = None;
    unmounted.permissions = [Permission {
        operation: OperationId::new("host.reboot").unwrap(),
        resource: unmounted.authority.resource(),
    }]
    .into();
    let command = GrantCommand::Issue {
        authorization: ids::ROOT_GRANT,
        id: ids::OPERATOR_GRANT,
        spec: unmounted,
    };
    before
        .authority()
        .record_administration(
            &caller,
            AdministrationCommand::Grant(command.clone()),
            UnixMillis(10),
        )
        .unwrap();
    assert_err!(
        node.grant(&caller, command).await,
        NodeStoreError::Authority(AuthorityError::Denied)
    );
    assert_eq!(node.store.lock().await.unwrap().state(), &before);
    drop(node);
    let location = StoreLocation::for_test(directory.path());
    let reopened = NodeStore::open(&location, network(), None, UnixMillis(10))
        .await
        .unwrap();
    assert_eq!(reopened.state().authority(), before.authority());
    assert!(reopened.state().last_administration().is_none());
}

#[test]
fn cancelled_native_append_refuses_authentication_and_administration_until_reopen() {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            {
                let directory = tempfile::tempdir().unwrap();
                let (node, secret) = fixture(directory.path(), host_scope(ROOT)).await;
                let caller = crate::test_support::session(&node, &secret).await;
                let before = node.store.lock().await.unwrap().state().clone();
                let (prepared, retained) =
                    Credential::prepare(scope(OPERATOR), OPERATOR.holder(), caller.generation())
                        .unwrap();
                let (started, release) = node.store.lock().await.unwrap().pause_next_statement().await;
                {
                    let mut issue = Box::pin(
                        node.issue_credential(&caller, ids::ROOT_GRANT, prepared.clone()),
                    );
                    tokio::select! {
                        entered = started => entered.unwrap(),
                        result = &mut issue => panic!("administration completed before cancellation: {result:?}"),
                    }
                }
                assert_eq!(node.store.lock().await.unwrap().state(), &before);
                assert_err!(
                    crate::test_support::try_session(&node, &secret).await,
                    NodeStoreError::Journal(hellas_channel::work_store::journal::JournalError::Poisoned)
                );
                assert_err!(
                    node.begin_authentication(Digest::hash(b"new session"))
                        .await,
                    NodeStoreError::Journal(hellas_channel::work_store::journal::JournalError::Poisoned)
                );
                assert_err!(
                    node.grant(
                        &caller,
                        issue(ids::ROOT_GRANT, ids::OPERATOR_GRANT, OPERATOR)
                    )
                    .await,
                    NodeStoreError::Journal(hellas_channel::work_store::journal::JournalError::Poisoned)
                );
                assert_err!(
                    node.status(&caller, ids::ROOT_GRANT).await,
                    NodeStoreError::Journal(hellas_channel::work_store::journal::JournalError::Poisoned)
                );
                node.store.lock().await.unwrap().resume_statements(release).await;
                drop(node);
                let location = StoreLocation::for_test(directory.path());
                let reopened = NodeStore::open(&location, network(), None, UnixMillis(11))
                    .await
                    .unwrap();
                crate::test_support::passkey_caller(
                    reopened.state().authority(),
                    &secret,
                    UnixMillis(11),
                );
                // The caller retains its exact ID and secret even if cancellation
                // races the append. Reconcile that record, never guess by scope.
                if let Some(installed) = reopened.state().authority().credential(retained.id()) {
                    assert_eq!(installed, &prepared);
                    crate::test_support::passkey_caller(
                        reopened.state().authority(),
                        &retained,
                        UnixMillis(11),
                    );
                }
            }
        });
}

use crate::test_support as common;

fn host_scope(actor: Actor) -> GrantSpec {
    let mut spec = scope(actor);
    for (op, resource) in [
        (HOST_STATUS, host_resource(spec.authority)),
        (HOST_PROVIDER_BIND, host_resource(spec.authority)),
        (GATEWAY_INVOKE, host_resource(spec.authority)),
        (HOST_CONFIGURE, host_resource(spec.authority)),
    ] {
        let operation = OperationId::new(op).unwrap();
        spec.permissions.insert(Permission {
            operation: operation.clone(),
            resource,
        });
        spec.issuance.as_mut().unwrap().operations.insert(operation);
    }
    spec
}

async fn application(
    node: &NodeCoordinator,
    root: &AuthenticatedCaller,
    id: GrantId,
    actor: Actor,
    operations: &[&str],
) -> (AuthenticatedCaller, CredentialSecret) {
    let mut spec = host_scope(actor);
    spec.issuance = None;
    spec.permissions
        .retain(|p| operations.contains(&p.operation.as_str()));
    node.grant(
        root,
        GrantCommand::Issue {
            authorization: ids::ROOT_GRANT,
            id,
            spec: spec.clone(),
        },
    )
    .await
    .unwrap();
    let (_, secret) = crate::test_support::credentials::issue_one(
        node,
        root,
        ids::ROOT_GRANT,
        spec,
        actor.holder(),
    )
    .await
    .unwrap();
    let identity = actor.node_key();
    let caller = node
        .authenticate_session(&secret, crate::node::SessionKey::Node(&identity))
        .await
        .unwrap();
    (caller, secret)
}

#[tokio::test]
async fn an_owner_binds_one_verified_provider_and_may_retry_it() {
    let directory = tempfile::tempdir().unwrap();
    let (node, secret) = fixture(directory.path(), host_scope(ROOT)).await;
    let root = crate::test_support::session(&node, &secret).await;
    let provider = common::software_enrollment(2, [2; 32]);
    let (gateway, _) = application(
        &node,
        &root,
        ids::OPERATOR_GRANT,
        OPERATOR,
        &[GATEWAY_INVOKE],
    )
    .await;
    assert_err!(
        node.bind_provider(&gateway, ids::OPERATOR_GRANT, provider.clone())
            .await,
        NodeStoreError::Authority(AuthorityError::Denied)
    );
    // Binding a provider is step-up: the owner's daily session cannot.
    let daily = node
        .authenticate_session(&secret, SessionKey::Node(&ROOT.node_key()))
        .await
        .unwrap();
    assert_err!(
        node.bind_provider(&daily, ids::ROOT_GRANT, provider.clone())
            .await,
        NodeStoreError::Authority(AuthorityError::StepUp)
    );
    let mut forged = provider.clone();
    forged.genesis.statement.installation_nonce = [9; 32];
    assert_err!(
        node.bind_provider(&root, ids::ROOT_GRANT, forged).await,
        NodeStoreError::Grant(crate::model::grant::records::GrantError::Signature)
    );
    for _ in 0..2 {
        assert_eq!(
            node.bind_provider(&root, ids::ROOT_GRANT, provider.clone())
                .await
                .unwrap(),
            provider.content_id()
        );
    }
    assert_err!(
        node.bind_provider(
            &root,
            ids::ROOT_GRANT,
            common::software_enrollment(3, [3; 32])
        )
        .await,
        NodeStoreError::ProviderBound
    );
    node.check_provider(&provider).await.unwrap();
    drop((node, root, gateway));
    let location = StoreLocation::for_test(directory.path());
    let reopened = NodeStore::open(&location, network(), None, UnixMillis(10))
        .await
        .unwrap();
    assert_eq!(reopened.state().provider().unwrap(), &provider);
}

#[tokio::test]
async fn an_execution_credential_cannot_bind_a_provider() {
    let directory = tempfile::tempdir().unwrap();
    let authority = common::authority();
    let world = common::Node::bootstrap(directory.path())
        .with_allowance(common::Allowance::responses(ids::ALLOWANCE, FRIEND))
        .with_grant(
            ids::FRIEND_GRANT,
            common::Rights::new(authority, FRIEND)
                .allow(
                    crate::grant_service::WORK_EXECUTE,
                    crate::grant_service::allowance_resource(authority, ids::ALLOWANCE),
                )
                .valid_until(UnixMillis(100_000))
                .build(),
        )
        .build()
        .await
        .serve(common::common_node::NoBackend);
    let caller = world.caller(FRIEND).await;
    assert_err!(
        world
            .service
            .node()
            .bind_provider(&caller, ids::FRIEND_GRANT, common::provider_enrollment())
            .await,
        NodeStoreError::Authority(AuthorityError::Denied)
    );
}

#[tokio::test]
async fn host_reads_require_their_own_operation() {
    let directory = tempfile::tempdir().unwrap();
    let (node, secret) = fixture(directory.path(), host_scope(ROOT)).await;
    let root = crate::test_support::session(&node, &secret).await;
    let (reader, _) =
        application(&node, &root, ids::OPERATOR_GRANT, OPERATOR, &[HOST_STATUS]).await;
    let (writer, _) = application(&node, &root, ids::FRIEND_GRANT, FRIEND, &[HOST_CONFIGURE]).await;

    node.status(&reader, ids::OPERATOR_GRANT).await.unwrap();
    assert_err!(
        node.status(&writer, ids::FRIEND_GRANT).await,
        NodeStoreError::Authority(AuthorityError::Denied)
    );
    assert_err!(
        node.host_action(&reader, ids::OPERATOR_GRANT, HOST_CONFIGURE, |_| ())
            .await,
        NodeStoreError::Authority(AuthorityError::Denied)
    );
}

#[tokio::test]
async fn host_operations_require_their_named_resource() {
    let directory = tempfile::tempdir().unwrap();
    let (node, secret) = fixture(directory.path(), host_scope(ROOT)).await;
    let root = crate::test_support::session(&node, &secret).await;
    let mut wrong = host_scope(AGENT);
    wrong.issuance = None;
    wrong.permissions = [Permission {
        operation: OperationId::new(HOST_STATUS).unwrap(),
        resource: wrong.authority.resource(),
    }]
    .into();
    assert_err!(
        node.grant(
            &root,
            GrantCommand::Issue {
                authorization: ids::ROOT_GRANT,
                id: ids::AGENT_GRANT,
                spec: wrong
            }
        )
        .await,
        NodeStoreError::Authority(AuthorityError::Denied)
    );
}

#[tokio::test]
async fn queued_setting_and_revocation_use_the_same_writer_order() {
    let directory = tempfile::tempdir().unwrap();
    let (node, secret) = fixture(directory.path(), host_scope(ROOT)).await;
    let root = crate::test_support::session(&node, &secret).await;
    let (writer, app_secret) = application(
        &node,
        &root,
        ids::OPERATOR_GRANT,
        OPERATOR,
        &[HOST_CONFIGURE],
    )
    .await;
    let held = node.store.lock().await.unwrap();
    let mut revoke =
        Box::pin(node.revoke_credential(&root, ids::ROOT_GRANT, app_secret.id(), Revision(1)));
    let mut setting =
        Box::pin(node.host_action(&writer, ids::OPERATOR_GRANT, HOST_CONFIGURE, |_| ()));
    assert!(futures::poll!(&mut revoke).is_pending());
    assert!(futures::poll!(&mut setting).is_pending());
    drop(held);
    let (revoked, changed) = tokio::join!(revoke, setting);
    revoked.unwrap();
    assert_err!(
        changed,
        NodeStoreError::Authority(AuthorityError::Credential)
    );
    let (daily, secret) =
        application(&node, &root, ids::FRIEND_GRANT, FRIEND, &[HOST_CONFIGURE]).await;
    assert_err!(
        node.host_action(&daily, ids::FRIEND_GRANT, HOST_CONFIGURE, |_| ())
            .await,
        NodeStoreError::Authority(AuthorityError::StepUp)
    );
    let writer = node
        .authenticate_session(&secret, SessionKey::Passkey(&FRIEND.passkey()))
        .await
        .unwrap();
    let held = node.store.lock().await.unwrap();
    // Grant revisions are authority-wide, not per grant.
    let expected = held
        .state()
        .authority()
        .grant(ids::FRIEND_GRANT)
        .unwrap()
        .revision();
    let mut setting =
        Box::pin(node.host_action(&writer, ids::FRIEND_GRANT, HOST_CONFIGURE, |_| ()));
    let mut revoke = Box::pin(node.grant(
        &root,
        GrantCommand::Revoke {
            authorization: ids::ROOT_GRANT,
            id: ids::FRIEND_GRANT,
            expected,
        },
    ));
    assert!(futures::poll!(&mut setting).is_pending());
    assert!(futures::poll!(&mut revoke).is_pending());
    drop(held);
    let (changed, revoked) = tokio::join!(setting, revoke);
    changed.unwrap();
    revoked.unwrap();
    assert_err!(
        node.host_action(&writer, ids::FRIEND_GRANT, HOST_CONFIGURE, |_| ())
            .await,
        NodeStoreError::Authority(AuthorityError::Revoked)
    );
}

#[tokio::test]
async fn session_checks_binding_before_calling_the_authenticator_and_propagates_refusal() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct Refusing(AtomicUsize);
    #[async_trait::async_trait]
    impl crate::authenticator::Authenticator for Refusing {
        fn public_key(&self) -> Result<crate::authenticator::PublicKey, AuthorityError> {
            ROOT.passkey().public_key()
        }
        async fn assert(&self, _: Digest) -> Result<PasskeyAssertion, AuthorityError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Err(AuthorityError::Credential)
        }
    }
    let directory = tempfile::tempdir().unwrap();
    let (node, secret) = fixture(directory.path(), scope(ROOT)).await;
    let binding = Digest::hash(b"expected connection");
    let pending = node.begin_authentication(binding).await.unwrap();
    let authenticator = Refusing(AtomicUsize::new(0));
    let key = SessionKey::Passkey(&authenticator);
    assert!(
        key.prove(
            pending.challenge(),
            scope(ROOT).authority,
            Digest::hash(b"wrong"),
            secret.id()
        )
        .await
        .is_err()
    );
    assert_eq!(authenticator.0.load(Ordering::SeqCst), 0);
    assert!(matches!(
        key.prove(
            pending.challenge(),
            scope(ROOT).authority,
            binding,
            secret.id()
        )
        .await,
        Err(AuthorityError::Credential)
    ));
    assert_eq!(authenticator.0.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn configured_machine_changes_reach_work_admission() {
    use crate::model::grant::configuration::ConfiguredBudget;
    use common::{actors::*, ids, within};
    use hellas_rpc::pb::work::{GrantRefusalCode, accept_work_response::Outcome};
    let directory = tempfile::tempdir().unwrap();
    let finish = Arc::new(tokio::sync::Semaphore::new(0));
    let backend = common::backend::Backend {
        slots: Arc::new(tokio::sync::Semaphore::new(2)),
        finish: common::backend::Completion::Permits(finish.clone()),
        signer: Arc::new(PROVIDER.node_key()),
        ..common::backend::Backend::default()
    };
    let allowance = common::Allowance::responses(ids::ALLOWANCE, FRIEND);
    let policies = allowance.definition.policies.clone();
    let world = common::Node::bootstrap(directory.path())
        .with_allowance(allowance)
        .with_grant(
            ids::FRIEND_GRANT,
            common::Rights::new(common::authority(), FRIEND)
                .allow(
                    crate::grant_service::WORK_EXECUTE,
                    crate::grant_service::allowance_resource(common::authority(), ids::ALLOWANCE),
                )
                .valid_until(UnixMillis(100_000))
                .build(),
        )
        .build()
        .await
        .serve(backend.clone());
    // The host applies its own configuration; a restart with an edited one
    // reconciles again.
    let reconcile = async |max_in_flight| {
        let machine = ConfiguredBudget {
            max_in_flight: std::num::NonZeroU16::new(max_in_flight).unwrap(),
            limits: vec![],
        };
        common::common_node::apply_configuration(
            &world.service.node(),
            &common::common_node::configuration_with(machine, policies.clone()),
        )
        .await;
    };
    let work = world.work(FRIEND, ids::FRIEND_GRANT).await;
    let first = world.proposal(FRIEND, ids::ALLOWANCE, 1).await;
    assert!(matches!(
        crate::test_support::accept_grant(&work, &first.request(), &FRIEND.node_key())
            .await
            .outcome,
        Some(Outcome::Accepted(_))
    ));
    within(backend.started.notified()).await;

    reconcile(1).await;
    let second = world.proposal(FRIEND, ids::ALLOWANCE, 2).await;
    let response =
        crate::test_support::accept_grant(&work, &second.request(), &FRIEND.node_key()).await;
    let Some(Outcome::Refused(refused)) = response.outcome else {
        panic!("configured capacity did not reach Work: {response:?}")
    };
    assert_eq!(
        refused.grant.unwrap().code,
        GrantRefusalCode::Concurrency as i32
    );
    reconcile(2).await;
    assert!(matches!(
        crate::test_support::accept_grant(&work, &second.request(), &FRIEND.node_key())
            .await
            .outcome,
        Some(Outcome::Accepted(_))
    ));
    within(backend.started.notified()).await;

    finish.add_permits(2);
    within(world.service.drain()).await.unwrap();
    assert_eq!(backend.calls.load(std::sync::atomic::Ordering::SeqCst), 2);
}

#[tokio::test]
async fn runtime_budget_commands_cannot_replace_the_configured_tree() {
    use crate::model::grant::{admin::WorkControlCommand, budget::BudgetNode, records::GrantError};
    let directory = tempfile::tempdir().unwrap();
    let world = common::Node::bootstrap(directory.path())
        .build()
        .await
        .serve(common::common_node::NoBackend);
    let admin = crate::grant_service::WorkAdministration::new(
        world.service.clone(),
        std::num::NonZeroU64::new(60_000).unwrap(),
    );
    common::common_node::apply_configuration(
        &world.service.node(),
        &common::common_node::configuration(vec![common::policy()]),
    )
    .await;
    let root = world.administrator(common::actors::ROOT).await;
    let [account, pool, subject] = common::common_node::budgets(
        common::common_node::POOL,
        common::actors::FRIEND.principal(),
        vec![],
        1,
    );
    let mut machine = account.clone();
    (machine.node, machine.parent) = (BudgetNode::Machine, None);
    for definition in [machine, account] {
        assert_err!(
            admin
                .execute(
                    &root,
                    ids::ROOT_GRANT,
                    WorkControlCommand::ConfigureBudget { definition }
                )
                .await,
            NodeStoreError::Grant(GrantError::OutOfScope)
        );
    }
    // Pools and subjects remain owner-administered.
    for definition in [pool, subject] {
        admin
            .execute(
                &root,
                ids::ROOT_GRANT,
                WorkControlCommand::ConfigureBudget { definition },
            )
            .await
            .unwrap();
    }
}
