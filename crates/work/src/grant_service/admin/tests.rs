use super::*;
use crate::model::grant::budget::*;
use crate::work_store::grant::{State, *};
use crate::{grant_service::GrantService, test_support::*};
use hellas_auth::authority as auth;
use std::{num::NonZeroU64, sync::Arc};

const ROOT: auth::GrantId = auth::GrantId([0; 16]);
const ALLOWANCE: auth::GrantId = auth::GrantId([1; 16]);
use crate::test_support::common_node::NoBackend;
fn service(store: NodeStore) -> GrantService {
    GrantService::new(
        store,
        Arc::new(principal(2).1),
        NoBackend,
        vec![],
        Arc::new(|| UnixMillis(1000)),
    )
    .unwrap()
}
fn terms() -> AllowanceTerms {
    AllowanceTerms {
        policies: vec!["responses".into()],
        budget: budget(),
        max_job_millis: NonZeroU64::new(5000).unwrap(),
        enabled: true,
        allow_account_backed: true,
    }
}
async fn snapshot(service: &GrantService) -> State {
    service
        .administer(async |store, _| Ok(store.state().clone()))
        .await
        .unwrap()
}

#[tokio::test]
async fn queries_project_current_windows_without_persisting_time_or_usage() {
    let root = tempfile::tempdir().unwrap();
    let (mut store, secret) = setup_with_credential(root.path()).await;
    let application = execution_caller(&mut store, &secret, ROOT).await;
    let (job, signature, input) = proposal(&store, 1);
    accept(&mut store, &application, (job, signature, &input), 1000)
        .await
        .unwrap();
    let work = crate::model::grant::grant_work_id(network(), &job);
    dispatch(&mut store, &application, (job.channel_id, work), 1000)
        .await
        .unwrap();
    finish(
        &mut store,
        (job.channel_id, work),
        GrantOutcome::Failed,
        Usage::Unknown,
        1001,
    )
    .await
    .unwrap();
    let clock = TestClock::new(UnixMillis(1001));
    let service = GrantService::new(
        store,
        Arc::new(principal(2).1),
        NoBackend,
        vec![],
        clock.source(),
    )
    .unwrap();
    let mut admin = common_node::WorkAdmin::new(service.clone(), &secret, vec![policy()]).await;
    let before = snapshot(&service).await;
    let journal_files = || {
        let mut files: Vec<_> = crate::test_support::all_files(&root.path().join("journals"))
            .into_iter()
            .map(|path| (std::fs::read(&path).unwrap(), path))
            .collect();
        files.sort();
        files
    };
    let journal = journal_files();
    let WorkControlReply::Budget { allowance, .. } = admin
        .command(WorkControlCommand::InspectBudget {
            node: BudgetNode::Pool(common_node::POOL),
        })
        .await
        .unwrap()
    else {
        panic!("budget reply")
    };
    assert_eq!(
        allowance
            .counters
            .iter()
            .find(|c| c.meter == Meter::Requests && c.window == Window::Hour)
            .unwrap()
            .used,
        1
    );
    let now = UnixMillis(3_600_000);
    clock.set(now);
    // An hour outlives the administrator's passkey session.
    admin.caller = crate::test_support::session(&service.node(), &secret).await;
    for command in [
        WorkControlCommand::List,
        WorkControlCommand::Catalogue,
        WorkControlCommand::Inspect { id: ALLOWANCE },
        WorkControlCommand::InspectResource {
            policy: "responses".into(),
        },
    ] {
        admin.command(command).await.unwrap();
    }
    let WorkControlReply::Budget {
        now: observed,
        allowance,
        ..
    } = admin
        .command(WorkControlCommand::InspectBudget {
            node: BudgetNode::Pool(common_node::POOL),
        })
        .await
        .unwrap()
    else {
        panic!("budget reply")
    };
    assert_eq!(observed, now);
    let hourly = allowance
        .counters
        .iter()
        .find(|c| c.meter == Meter::Requests && c.window == Window::Hour)
        .unwrap();
    assert_eq!((hourly.window_id, hourly.used), (1, 0));
    assert_eq!(
        allowance
            .counters
            .iter()
            .find(|c| c.meter == Meter::Requests && c.window == Window::Total)
            .unwrap()
            .used,
        1
    );
    let WorkControlReply::Offers(offers) = admin
        .command(WorkControlCommand::Offers {
            id: Some(ALLOWANCE),
        })
        .await
        .unwrap()
    else {
        panic!("offers reply")
    };
    assert_eq!(offers[0].offer().valid_until, UnixMillis(now.0 + 300_000));
    let standing = service
        .administer(async |store, _| {
            use crate::model::grant::standing::StandingLocator;
            let locator = StandingLocator {
                provider: store.state().provider()?.content_id(),
                grant: ALLOWANCE,
                client: crate::test_support::channel_client(principal(1).0),
                generation: 0,
            };
            store.standing(locator, &principal(2).1, vec![], now)
        })
        .await
        .unwrap();
    assert_eq!(standing.now, now);
    assert_eq!(
        standing.offer.offer().valid_until,
        UnixMillis(now.0 + 300_000)
    );
    assert_eq!(
        standing.nodes[0]
            .counters
            .iter()
            .find(|c| c.meter == Meter::Requests && c.window == Window::Hour)
            .unwrap()
            .used,
        0
    );
    assert_eq!(snapshot(&service).await, before);
    assert_eq!(journal_files(), journal);
}

#[tokio::test]
async fn correcting_a_forward_clock_jump_restores_writes() {
    let root = tempfile::tempdir().unwrap();
    let (store, secret) = setup_with_credential(root.path()).await;
    let clock = TestClock::default();
    let service = GrantService::new(
        store,
        Arc::new(principal(2).1),
        NoBackend,
        vec![],
        clock.source(),
    )
    .unwrap();
    let admin = common_node::WorkAdmin::new(service.clone(), &secret, vec![policy()]).await;
    let before = snapshot(&service).await;
    clock.set(UnixMillis(u64::MAX));
    for _ in 0..3 {
        assert_err!(
            service.node().status(&admin.caller, ROOT).await,
            NodeStoreError::ClockJump
        );
        assert_err!(
            admin
                .command(WorkControlCommand::Revise {
                    id: ALLOWANCE,
                    expected_revision: auth::Revision(1),
                    terms: AllowanceTerms {
                        enabled: false,
                        ..terms()
                    },
                })
                .await,
            NodeStoreError::ClockJump
        );
        let node = service.node();
        let mut store = node.store.lock().await.unwrap();
        assert_err!(store.tick(clock.now()).await, NodeStoreError::ClockJump);
        assert_eq!(store.state(), &before);
    }
    clock.set(UnixMillis(1001));
    assert_eq!(snapshot(&service).await, before);
    admin
        .command(WorkControlCommand::Revise {
            id: ALLOWANCE,
            expected_revision: auth::Revision(1),
            terms: AllowanceTerms {
                enabled: false,
                ..terms()
            },
        })
        .await
        .unwrap();
    assert!(!snapshot(&service).await.grant(ALLOWANCE).unwrap().enabled);
}

#[tokio::test]
async fn work_administration_requires_the_mounted_operation() {
    use crate::test_support::{actors::*, ids};
    let directory = tempfile::tempdir().unwrap();
    let world = Node::bootstrap(directory.path())
        .with_allowance(Allowance::responses(ids::ALLOWANCE, FRIEND))
        .with_grant(
            ids::OPERATOR_GRANT,
            Rights::new(authority(), OPERATOR)
                .allow(
                    WORK_ALLOWANCE_READ,
                    crate::operations::Operation::named(WORK_ALLOWANCE_READ)
                        .unwrap()
                        .permission(authority(), None)
                        .unwrap()
                        .resource,
                )
                .valid_until(UnixMillis(100_000))
                .build(),
        )
        .build()
        .await
        .serve(NoBackend);
    let admin =
        common_node::WorkAdmin::new(world.service.clone(), world.secret(ROOT), vec![policy()])
            .await;
    let caller = world.caller(OPERATOR).await;
    admin
        .service
        .execute(&caller, ids::OPERATOR_GRANT, WorkControlCommand::List)
        .await
        .unwrap();
    let definition = world
        .snapshot()
        .await
        .grant(ids::ALLOWANCE)
        .unwrap()
        .clone();
    for command in [
        WorkControlCommand::Offers {
            id: Some(ids::ALLOWANCE),
        },
        WorkControlCommand::NewGeneration {
            id: ids::ALLOWANCE,
            expected_generation: 0,
        },
        WorkControlCommand::Revise {
            id: ids::ALLOWANCE,
            expected_revision: definition.revision,
            terms: AllowanceTerms {
                budget: definition.budget,
                enabled: false,
                ..terms()
            },
        },
    ] {
        assert_err!(
            admin
                .service
                .execute(&caller, ids::OPERATOR_GRANT, command)
                .await,
            NodeStoreError::Authority(auth::AuthorityError::Denied)
        );
    }
    world.service.drain().await.unwrap();
}

#[tokio::test]
async fn checked_work_mutations_persist_the_verified_caller() {
    let directory = tempfile::tempdir().unwrap();
    let (store, secret) = setup_with_credential(directory.path()).await;
    let authority = store.state().authority().clone();
    let expected = store.state().grant(ALLOWANCE).unwrap().revision;
    let service = service(store);
    let admin = common_node::WorkAdmin::new(service.clone(), &secret, vec![policy()]).await;

    admin
        .command(WorkControlCommand::Revise {
            id: ALLOWANCE,
            expected_revision: expected,
            terms: AllowanceTerms {
                enabled: false,
                ..terms()
            },
        })
        .await
        .unwrap();

    let before = snapshot(&service).await;
    assert_eq!(
        before.authority(),
        &authority,
        "Work operations cannot administer Auth grants"
    );
    let record = before.last_work_administration.as_ref().unwrap().clone();
    assert_eq!(record.caller.credential(), secret.id());
    assert_eq!(record.caller.actor(), admin.caller.subject());
    assert_eq!(record.authorization, ROOT);
    assert!(!before.grant(ALLOWANCE).unwrap().enabled);
    service
        .administer(async |store, _| store.rotate().await)
        .await
        .unwrap();
    service.drain().await.unwrap();
    drop(admin);
    drop(service);
    let store = reopen(directory.path(), 1000).await.unwrap();
    assert_eq!(
        store.state().last_work_administration.as_ref(),
        Some(&record)
    );
}

#[tokio::test]
async fn control_commands_require_the_current_revision() {
    let directory = tempfile::tempdir().unwrap();
    let (store, secret) = setup_with_credential(directory.path()).await;
    let expected = store.state().grant(ALLOWANCE).unwrap().revision;
    let service = service(store);
    let admin = common_node::WorkAdmin::new(service.clone(), &secret, vec![policy()]).await;
    assert_err!(admin.command(WorkControlCommand::Revise { id: ALLOWANCE, expected_revision: auth::Revision(0), terms: terms() }).await,
        NodeStoreError::Grant(GrantError::Revision(actual)) if actual == expected);
    assert_err!(
        admin
            .command(WorkControlCommand::NewGeneration {
                id: ALLOWANCE,
                expected_generation: 1
            })
            .await,
        NodeStoreError::Grant(GrantError::Generation)
    );
    let WorkControlReply::Resource { revision, .. } = admin
        .command(WorkControlCommand::InspectResource {
            policy: "responses".into(),
        })
        .await
        .unwrap()
    else {
        panic!("resource reply")
    };
    assert_err!(
        admin
            .command(WorkControlCommand::RepairResource {
                policy: "responses".into(),
                expected_revision: revision + 1
            })
            .await,
        NodeStoreError::Authority(auth::AuthorityError::Revision)
    );
    let WorkControlReply::Resource {
        revision: changed, ..
    } = admin
        .command(WorkControlCommand::RepairResource {
            policy: "responses".into(),
            expected_revision: revision,
        })
        .await
        .unwrap()
    else {
        panic!("resource reply")
    };
    assert_eq!(changed, revision + 1);
    service.drain().await.unwrap();
}
