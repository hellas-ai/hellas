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
impl WorkBackend for NoBackend {
    fn try_admit(
        &self,
        domain: hellas_work::work::admission::CapacityDomain,
    ) -> Result<hellas_work::work::admission::WorkPermit, hellas_work::work::BackendFault> {
        Err(hellas_work::work::admission::AdmissionError::Unsupported(domain).into())
    }
}
fn service(store: GrantStore) -> GrantService {
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
#[test]
fn local_revisions_preserve_reservations_and_pause_releases_queued_work() {
    let root = tempfile::tempdir().unwrap();
    let mut store = setup(root.path());
    let (authorization, signature, input) = proposal(&store, 1);
    store
        .accept(
            authorization,
            signature,
            &input,
            &principal(2).1,
            UnixMillis(1000),
        )
        .unwrap();
    let service = service(store);
    let invoke = |command| service.control(command, &[policy()], NonZeroU64::new(10000).unwrap());
    let GrantReply::Status { offer, nodes, .. } = invoke(GrantCommand::Revise {
        id: GrantId([1; 16]),
        expected_revision: Revision(1),
        terms: terms(),
    })
    .unwrap() else {
        panic!("status");
    };
    assert_eq!(offer.offer().grant.revision, Revision(2));
    assert_eq!(nodes[0].active, 1);
    assert_eq!(
        nodes[0]
            .counters
            .iter()
            .find(|c| c.meter == Meter::Requests && c.window == Window::Total)
            .unwrap()
            .reserved,
        1
    );
    assert!(
        invoke(GrantCommand::SetState {
            id: GrantId([1; 16]),
            expected_revision: Revision(1),
            state: GrantState::Paused
        })
        .is_err()
    );
    let GrantReply::Status { nodes, .. } = invoke(GrantCommand::SetState {
        id: GrantId([1; 16]),
        expected_revision: Revision(2),
        state: GrantState::Paused,
    })
    .unwrap() else {
        panic!("status");
    };
    assert_eq!(nodes[0].active, 0);
    assert_eq!(
        nodes[0]
            .counters
            .iter()
            .find(|c| c.meter == Meter::Requests && c.window == Window::Total)
            .unwrap()
            .reserved,
        0
    );
    let GrantReply::Status { offer, .. } = invoke(GrantCommand::NewGeneration {
        id: GrantId([1; 16]),
        expected_revision: Revision(3),
    })
    .unwrap() else {
        panic!("status");
    };
    assert_eq!(offer.offer().generation, 1);
    invoke(GrantCommand::SetState {
        id: GrantId([1; 16]),
        expected_revision: Revision(3),
        state: GrantState::Revoked,
    })
    .unwrap();
    assert!(
        invoke(GrantCommand::SetState {
            id: GrantId([1; 16]),
            expected_revision: Revision(4),
            state: GrantState::Active
        })
        .is_err()
    );
}
#[test]
fn owner_bootstrap_can_deny_all_and_principal_creation_requires_explicit_resource_consent() {
    let root = tempfile::tempdir().unwrap();
    let service = service(setup(root.path()));
    let max = NonZeroU64::new(10000).unwrap();
    let GrantReply::Status { offer, .. } = service
        .control(
            GrantCommand::InitializeOwner {
                principal: principal(3).0,
            },
            &[],
            max,
        )
        .unwrap()
    else {
        panic!("status");
    };
    assert!(offer.offer().grant.policies.is_empty());
    assert!(matches!(offer.offer().grant.kind, GrantKind::Owner(_)));
    let mut without_consent = terms();
    without_consent.allow_account_backed = false;
    assert!(
        service
            .control(
                GrantCommand::Create {
                    id: GrantId([3; 16]),
                    principal: principal(3).0,
                    terms: without_consent
                },
                &[policy()],
                max
            )
            .is_err()
    );
    assert!(
        service
            .control(
                GrantCommand::Inspect {
                    id: GrantId([3; 16])
                },
                &[policy()],
                max
            )
            .is_err()
    );
    let mut outside = terms();
    outside.policies = vec!["missing".into()];
    assert!(
        service
            .control(
                GrantCommand::Create {
                    id: GrantId([3; 16]),
                    principal: principal(3).0,
                    terms: outside
                },
                &[policy()],
                max
            )
            .is_err()
    );
    service
        .control(
            GrantCommand::Create {
                id: GrantId([3; 16]),
                principal: principal(3).0,
                terms: terms(),
            },
            &[policy()],
            max,
        )
        .unwrap();
}
