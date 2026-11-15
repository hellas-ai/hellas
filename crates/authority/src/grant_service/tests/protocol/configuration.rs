use super::*;
use crate::model::grant::records::ConfigChange;

#[tokio::test]
async fn resource_changes_keep_or_cancel_execution_and_delivery() {
    for config_change in [ConfigChange::Keep, ConfigChange::Release] {
        for completed in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let (store, secret) = setup_with_credential(dir.path()).await;
            let request = request(&store, 1);
            let a = GrantJobAuthorizationV1::decode(&request.authorization).unwrap();
            let accepted = store.state().policy_for(&a).unwrap().clone();
            let backend = Backend::default();
            let (service, work, credential) =
                service(dir.path(), store, backend.clone(), &secret).await;
            let id = accepted_id(
                crate::test_support::accept_grant(&work, &request, &principal(1).1).await,
            );
            within(backend.started.notified()).await;
            let cache = cache::cached(&service, id);
            if completed {
                backend.finish.release();
                within(service.drain()).await.unwrap();
            }
            let binding = service
                .bind_delivery(&work.access, &delivery::delivery_request(&a, id))
                .await
                .unwrap();
            service
                .administer(async |store, now| {
                    let mut changed = accepted.clone();
                    changed.revision.0 += 1;
                    changed.name = "changed".into();
                    changed.config_change = config_change;
                    store.configure_resource(changed, now).await
                })
                .await
                .unwrap();
            let release = config_change == ConfigChange::Release;
            assert_eq!(binding.cancellation().is_cancelled(), release);
            assert_eq!(cache.cancellation().is_cancelled(), release);
            assert_eq!(snapshot(&service).await.policy_for(&a).unwrap(), &accepted);
            if !release {
                // Keeping resource terms never keeps revoked authority alive.
                revoke_access(&service, &secret, &credential, AccessTarget::Grant).await;
                assert!(binding.cancellation().is_cancelled());
                assert!(cache.cancellation().is_cancelled());
            }
            if !completed {
                within(backend.cancelled.notified()).await;
                backend.finish.release();
                within(service.drain()).await.unwrap();
            }
        }
    }
}

#[tokio::test]
async fn quarantine_ends_delivery_even_when_a_resource_keeps_old_terms() {
    let dir = tempfile::tempdir().unwrap();
    let (mut store, secret) = setup_with_credential(dir.path()).await;
    let mut def = store.state().grant(GrantId([1; 16])).unwrap().clone();
    def.revision.0 += 1;
    def.policies[0].revision.0 += 1;
    use_https(&mut def.policies[0], chat_resource("https://glm.test", 8));
    let mut resource = def.policies[0].clone();
    store
        .configure_resource(resource.clone(), UnixMillis(1000))
        .await
        .unwrap();
    store.define(def, UnixMillis(1000)).await.unwrap();
    let request = request(&store, 1);
    let a = GrantJobAuthorizationV1::decode(&request.authorization).unwrap();
    let backend = Backend {
        reply: Reply::events(Reply::http(
            200,
            "application/json",
            r#"{"usage":{"prompt_tokens":3,"completion_tokens":9}}"#,
        )),
        ..Backend::default()
    };
    let (service, work, _) = service(dir.path(), store, backend.clone(), &secret).await;
    let id = accepted_id(crate::test_support::accept_grant(&work, &request, &principal(1).1).await);
    within(backend.started.notified()).await;
    let binding = service
        .bind_delivery(&work.access, &delivery::delivery_request(&a, id))
        .await
        .unwrap();
    resource.revision.0 += 1;
    resource.name = "new".into();
    service
        .administer(async |store, now| store.configure_resource(resource.clone(), now).await)
        .await
        .unwrap();
    assert!(!binding.cancellation().is_cancelled());
    backend.finish.release();
    within(service.drain()).await.unwrap();
    assert!(
        snapshot(&service)
            .await
            .resource_health(resource.resource)
            .unwrap()
            .quarantined
    );
    assert!(binding.cancellation().is_cancelled());
}

#[tokio::test]
async fn configuration_publication_blocks_grant_admission_before_authority_lookup() {
    let dir = tempfile::tempdir().unwrap();
    let (store, secret) = setup_with_credential(dir.path()).await;
    let backend = Backend::default();
    let (service, work, _) = service(dir.path(), store, backend.clone(), &secret).await;
    let node = service.node();
    let publishing = node.configuration_publication().await;
    let request = AcceptWorkRequest::default();
    let mut acceptance = Box::pin(service.accept(&work.access, &request));
    assert!(futures::poll!(&mut acceptance).is_pending());
    drop(acceptance);
    assert_eq!(backend.calls.load(Ordering::SeqCst), 0);
    drop(publishing);
    let response = service.accept(&work.access, &request).await;
    assert_eq!(refusal(response), GrantRefusalCode::Malformed);
    assert_eq!(backend.calls.load(Ordering::SeqCst), 0);
}
