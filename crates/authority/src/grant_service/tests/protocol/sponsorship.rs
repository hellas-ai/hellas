use super::*;

#[tokio::test]
async fn sponsored_terms_bind_each_channel_to_its_authenticated_actor_across_revisions() {
    use hellas_auth::authority::{AdministrationCommand, GrantCommand};
    let dir = tempfile::tempdir().unwrap();
    let (mut store, secret) = setup_with_credential(dir.path()).await;
    let root = GrantId([0; 16]);
    let terms = GrantId([1; 16]);
    let other_grant = GrantId([239; 16]);
    let now = UnixMillis(1000);
    let first = execution_caller(&mut store, &secret, root).await;
    let admin = crate::test_support::passkey_caller(store.state().authority(), &secret, now);
    let mut scope = store
        .state()
        .authority()
        .grant(JOURNAL_AUTHORIZATION)
        .unwrap()
        .spec()
        .clone();
    scope.subject = principal(3).0;
    let [other_secret] = crate::test_support::credentials::issue(
        crate::test_support::credentials::Issuer::Store(&mut store, now),
        &admin,
        root,
        Some(other_grant),
        scope.clone(),
    )
    .await;
    let other = signed_caller(
        store.state().authority(),
        &other_secret,
        &principal(3).1,
        now,
    );
    let (a, sig, input) = proposal(&store, 1);
    let (b, other_sig, other_input) = proposal_for(&store, terms, 1, principal(3).1);
    assert_ne!(a.channel_id, b.channel_id);
    assert!(store.state().channel(a.channel_id).is_none());
    assert_err!(
        store
            .accept((&other, other_grant), a, sig, &input, &principal(2).1, now)
            .await,
        NodeStoreError::Grant(crate::model::grant::records::GrantError::Unauthorized)
    );
    store
        .accept(
            (&first, JOURNAL_AUTHORIZATION),
            a,
            sig,
            &input,
            &principal(2).1,
            now,
        )
        .await
        .unwrap();
    store
        .accept(
            (&other, other_grant),
            b,
            other_sig,
            &other_input,
            &principal(2).1,
            now,
        )
        .await
        .unwrap();
    assert_eq!(
        store.state().ledger().reserved(budget(), Meter::Requests),
        2
    );
    for (job, caller, authorization) in
        [(a, &first, JOURNAL_AUTHORIZATION), (b, &other, other_grant)]
    {
        store
            .dispatch(
                (caller, authorization),
                job.channel_id,
                grant_work_id(network(), &job),
                now,
            )
            .await
            .unwrap();
    }
    let expected = store
        .state()
        .authority()
        .grant(JOURNAL_AUTHORIZATION)
        .unwrap()
        .revision();
    store
        .administer_authority(
            &admin,
            AdministrationCommand::Grant(GrantCommand::Revise {
                authorization: root,
                id: JOURNAL_AUTHORIZATION,
                expected,
                spec: scope,
            }),
            now,
        )
        .await
        .unwrap();
    store.rotate().await.unwrap();
    drop(store);
    let store = reopen(dir.path(), 1001).await.unwrap();
    assert_eq!(used(&store, budget(), Meter::Requests), 2);
    assert_eq!(
        store.state().channel_binding(a.channel_id).unwrap().client,
        hellas_channel::test_support::channel_client(principal(1).0)
    );
    assert_eq!(
        store.state().channel_binding(b.channel_id).unwrap().client,
        hellas_channel::test_support::channel_client(principal(3).0)
    );
    let service = GrantService::new(
        store,
        Arc::new(principal(2).1),
        Backend::default(),
        vec![],
        Arc::new(|| UnixMillis(1001)),
    )
    .unwrap();
    // This grant now names actor 3; it still cannot expose actor 1's channel.
    let rebound = service.for_caller(other, JOURNAL_AUTHORIZATION);
    let locator = StandingLocator {
        provider: hellas_channel::test_support::software_enrollment(2, [2; 32]).content_id(),
        grant: terms,
        client: hellas_channel::test_support::channel_client(principal(1).0),
        generation: 0,
    };
    let response = rebound
        .standing(&GetStandingRequest {
            route: Some(WorkRoute::grant(a.channel_id.0)),
            locator: locator.encode().to_vec(),
        })
        .await;
    assert!(matches!(
        response.outcome,
        Some(hellas_rpc::pb::work::get_standing_response::Outcome::Refused(_))
    ));
    let refusal = service
        .bind_delivery(
            &rebound.access,
            &delivery::delivery_request(&a, grant_work_id(network(), &a)),
        )
        .await
        .err()
        .unwrap();
    assert_eq!(
        refusal.grant.unwrap().code,
        GrantRefusalCode::Unauthorized as i32
    );
    let own = service
        .bind_delivery(
            &rebound.access,
            &delivery::delivery_request(&b, grant_work_id(network(), &b)),
        )
        .await;
    own.unwrap();
}
