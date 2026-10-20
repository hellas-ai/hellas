use crate::model::grant::admin::WorkControlCommand;
use crate::model::work::PrivateRecord;
use crate::test_support::assert_err;
use crate::{grant_service::GrantService, node::NodeCoordinator, test_support as common};
use hellas_auth::authority::*;
use hellas_rpc::pb::work::*;
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};
use tracing::{
    Event, Metadata, Subscriber,
    field::{Field, Visit},
    span::{Attributes, Id, Record},
};

type Captured = (tracing::Level, BTreeMap<String, String>);
#[derive(Clone, Default)]
struct Events(Arc<Mutex<Vec<Captured>>>);
struct Fields(BTreeMap<String, String>);
impl Visit for Fields {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.0.insert(field.name().into(), format!("{value:?}"));
    }
    fn record_str(&mut self, field: &Field, value: &str) {
        self.0.insert(field.name().into(), value.into());
    }
}
impl Subscriber for Events {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        metadata.target() == "hellas_authority_audit"
    }
    fn new_span(&self, _: &Attributes<'_>) -> Id {
        Id::from_u64(1)
    }
    fn record(&self, _: &Id, _: &Record<'_>) {}
    fn record_follows_from(&self, _: &Id, _: &Id) {}
    fn enter(&self, _: &Id) {}
    fn exit(&self, _: &Id) {}
    fn event(&self, event: &Event<'_>) {
        let mut fields = Fields(BTreeMap::new());
        event.record(&mut fields);
        self.0
            .lock()
            .unwrap()
            .push((*event.metadata().level(), fields.0));
    }
}
impl Events {
    fn last(&self, action: &str, outcome: &str) -> BTreeMap<String, String> {
        self.0
            .lock()
            .unwrap()
            .iter()
            .rev()
            .find(|(_, event)| event["action"] == action && event["outcome"] == outcome)
            .unwrap_or_else(|| panic!("missing {action} {outcome} event"))
            .1
            .clone()
    }
}

#[tokio::test]
async fn checked_services_audit_reads_and_final_refusals_without_request_content() {
    let events = Events::default();
    let _subscriber = tracing::subscriber::set_default(events.clone());
    let directory = tempfile::tempdir().unwrap();
    let (store, secret) = common::setup_with_credential(directory.path()).await;
    let (authorization, signature, input) = common::proposal(&store, 1);
    let service = GrantService::new(
        store,
        Arc::new(common::principal(2).1),
        common::common_node::NoBackend,
        vec![],
        Arc::new(|| UnixMillis(1000)),
    )
    .unwrap();
    let admin =
        common::common_node::WorkAdmin::new(service.clone(), &secret, vec![common::policy()]).await;
    let node = service.node();
    let root = GrantId([0; 16]);
    node.status(&admin.caller, root).await.unwrap();
    admin.command(WorkControlCommand::List).await.unwrap();
    for action in [
        crate::node::HOST_STATUS,
        crate::work_store::grant::WORK_ALLOWANCE_READ,
    ] {
        let event = events.last(action, "allowed");
        assert_eq!(event["verified"], "true");
        assert_eq!(
            event["actor"],
            format!("{:?}", Some(admin.caller.subject()))
        );
        assert_eq!(event["authorization"], format!("{:?}", Some(root)));
    }
    let (work, credential) = common::common_node::execution(
        &service,
        &secret,
        &common::principal(1).1,
        authorization.grant_id,
    )
    .await;
    let caller = node
        .authenticate_session(
            &credential,
            crate::node::SessionKey::Node(&common::principal(1).1),
        )
        .await
        .unwrap();
    let before = node.status(&admin.caller, root).await.unwrap();
    assert_err!(
        node.set_machine_capacity(&caller, root, Revision(0), 1, vec![])
            .await,
        crate::work_store::grant::NodeStoreError::Authority(AuthorityError::Denied)
    );
    assert_err!(
        admin
            .service
            .execute(
                &caller,
                root,
                WorkControlCommand::ConfigureResource {
                    policy: "sensitive-resource-canary".into(),
                }
            )
            .await,
        crate::work_store::grant::NodeStoreError::Authority(AuthorityError::Denied)
    );
    assert_eq!(node.status(&admin.caller, root).await.unwrap(), before);
    for action in [
        crate::node::WORK_CAPACITY_CONFIGURE,
        crate::work_store::grant::WORK_RESOURCE_CONFIGURE,
    ] {
        let event = events.last(action, "denied");
        assert_eq!(event["verified"], "true");
        assert_eq!(event["actor"], format!("{:?}", Some(caller.subject())));
        assert_eq!(event["reason"], "permission_denied");
    }
    // Permission succeeds, but unavailable execution capacity refuses the final operation.
    let response = work
        .accept(&AcceptWorkRequest {
            route: Some(WorkRoute::grant(authorization.channel_id.0)),
            authorization: authorization.encode(),
            client_signature: signature.bytes().to_vec(),
            prepared_input: input.encode().unwrap(),
        })
        .await;
    assert!(matches!(
        response.outcome,
        Some(accept_work_response::Outcome::Refused(_))
    ));
    let event = events.last("work.accept", "denied");
    assert_eq!(event["verified"], "true");
    assert_eq!(
        event["reason"],
        GrantRefusalCode::QueueCapacity.as_str_name()
    );
    work.accept(&AcceptWorkRequest {
        authorization: b"sensitive-malformed-canary".to_vec(),
        ..Default::default()
    })
    .await;
    let event = events.last("work.accept", "denied");
    assert_eq!(event["verified"], "false");
    assert_eq!(event["reason"], GrantRefusalCode::Malformed.as_str_name());
    let recorded = format!("{:?}", events.0.lock().unwrap());
    for forbidden in [
        "sensitive-resource-canary",
        "sensitive-malformed-canary",
        "never-journal-this-body",
        "verifier",
        "signature",
        "prepared_input",
    ] {
        assert!(!recorded.contains(forbidden), "audit leaked {forbidden}");
    }
    for credential in [&secret, &credential] {
        assert!(!recorded.contains(&format!("{:?}", credential.expose_secret())));
        let hex = credential
            .expose_secret()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        assert!(!recorded.contains(&hex));
    }
    let held = node.store.lock().await.unwrap();
    {
        let mut request = Box::pin(node.status(&admin.caller, root));
        assert!(futures::poll!(&mut request).is_pending());
    }
    drop(held);
    let event = events.last(crate::node::HOST_STATUS, "cancelled");
    assert_eq!(event["verified"], "false");
    assert_eq!(event["reason"], "request_dropped");
    service.drain().await.unwrap();
}

#[tokio::test]
async fn unverified_foreign_revoked_and_wrongly_bound_evidence_cannot_name_an_actor() {
    let events = Events::default();
    let _subscriber = tracing::subscriber::set_default(events.clone());
    let directory = tempfile::tempdir().unwrap();
    let (store, secret) = common::setup_with_credential(directory.path()).await;
    let root = GrantId([0; 16]);
    let revision = store
        .state()
        .authority()
        .credential(secret.id())
        .unwrap()
        .revision();
    let node = NodeCoordinator::new(store, Arc::new(|| UnixMillis(1000)));
    let caller = crate::test_support::session(&node, &secret).await;
    let foreign_directory = tempfile::tempdir().unwrap();
    let (foreign, foreign_secret) = common::setup_with_credential(foreign_directory.path()).await;
    // Same authority ID and subject, but minted by a different writer and verifier set.
    let foreign_caller = crate::test_support::passkey_caller(
        foreign.state().authority(),
        &foreign_secret,
        UnixMillis(1000),
    );
    assert_eq!(caller.subject(), foreign_caller.subject());
    assert_err!(
        node.status(&foreign_caller, root).await,
        crate::work_store::grant::NodeStoreError::Authority(AuthorityError::Credential)
    );
    let event = events.last(crate::node::HOST_STATUS, "denied");
    assert_eq!(event["verified"], "false");
    assert_eq!(event["actor"], "None");
    assert_eq!(
        event["credential_claimed"],
        format!("{:?}", Some(foreign_secret.id()))
    );
    let binding = hellas_auth::Digest::hash(b"valid binding");
    let pending = node.begin_authentication(binding).await.unwrap();
    let signature = pending
        .challenge()
        .sign_daily(
            pending.challenge().authority,
            binding,
            secret.id(),
            &hellas_auth::test_support::actors::ROOT.node_key(),
        )
        .unwrap();
    let session = node
        .complete_authentication(pending, binding, &secret, &signature)
        .await
        .unwrap();
    assert_err!(
        node.session_caller(&session, hellas_auth::Digest::hash(b"wrong binding"))
            .await,
        crate::work_store::grant::NodeStoreError::Authority(AuthorityError::Credential)
    );
    let event = events.last("session.validate", "denied");
    assert_eq!(event["verified"], "false");
    assert_eq!(event["actor"], "None");
    node.revoke_credential(&caller, root, secret.id(), revision)
        .await
        .unwrap();
    assert_err!(
        node.status(&caller, root).await,
        crate::work_store::grant::NodeStoreError::Authority(AuthorityError::Credential)
    );
    assert_err!(
        crate::test_support::try_session(&node, &secret).await,
        crate::work_store::grant::NodeStoreError::Authority(AuthorityError::Credential)
    );
    assert_err!(
        node.session_caller(&session, binding).await,
        crate::work_store::grant::NodeStoreError::Authority(AuthorityError::Credential)
    );
    for action in [
        crate::node::HOST_STATUS,
        "session.authenticate",
        "session.validate",
    ] {
        let event = events.last(action, "denied");
        assert_eq!(event["verified"], "false");
        assert_eq!(event["actor"], "None");
        assert_eq!(
            event["credential_claimed"],
            format!("{:?}", Some(secret.id()))
        );
    }
}
