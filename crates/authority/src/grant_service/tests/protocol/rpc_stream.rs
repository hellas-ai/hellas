use super::*;

#[tokio::test]
async fn portable_grant_rpc_streams_before_terminal_reserves_once_and_survives_revision() {
    use hellas_rpc::services::work::{WorkClientImpl, WorkServer};
    let dir = tempfile::tempdir().unwrap();
    let (store, secret) = setup_with_credential(dir.path()).await;
    let first = request(&store, 1);
    let second = request(&store, 2);
    let a = GrantJobAuthorizationV1::decode(&first.authorization).unwrap();
    let backend = Backend::default();
    let (service, work_service, _credential) = service(store, backend.clone(), &secret).await;
    let portable = TransportContext {
        peer: Some(PeerIdentity([9; 32])),
        auth_level: AuthLevel::None,
        ..context()
    };
    let (client, server) = transport::transport_pair_with_context(portable.clone(), portable);
    let serving = {
        let work_service = work_service.clone();
        tokio::spawn(async move {
            let handler = Arc::new(WorkServer(work_service));
            while let Ok(Some(inbound)) = server.accept().await {
                let handler = handler.clone();
                tokio::spawn(async move {
                    let _ = Dispatcher::<MuxTransport>::dispatch(handler.as_ref(), inbound).await;
                });
            }
        })
    };
    let rpc = WorkClientImpl::new(client.clone());
    let locator = StandingLocator {
        provider: crate::test_support::software_enrollment(2, [2; 32]).content_id(),
        grant: a.grant_id,
        client: crate::test_support::channel_client(principal(1).0),
        generation: 0,
    };
    let response = rpc
        .get_standing(GetStandingRequest {
            route: Some(WorkRoute::grant(a.channel_id.0)),
            locator: locator.encode().to_vec(),
        })
        .await
        .unwrap();
    assert!(matches!(
        response.outcome,
        Some(get_standing_response::Outcome::Standing(_))
    ));
    let (first, uploads) = grant_upload_requests(&first, &principal(1).1, network(), [7; 32]);
    for upload in uploads {
        rpc.upload_content(upload).await.unwrap();
    }
    let id = accepted_id(rpc.accept_work(first.clone()).await.unwrap());
    within(backend.started.notified()).await;
    assert_eq!(accepted_id(rpc.accept_work(first).await.unwrap()), id);
    let (second, uploads) = grant_upload_requests(&second, &principal(1).1, network(), [7; 32]);
    for upload in uploads {
        rpc.upload_content(upload).await.unwrap();
    }
    assert_eq!(
        refusal(rpc.accept_work(second).await.unwrap()),
        GrantRefusalCode::QueueCapacity
    );
    let mut stream = rpc
        .stream_result(delivery::delivery_request(&a, id))
        .await
        .unwrap();
    assert!(matches!(
        stream.next().await.unwrap().unwrap().outcome,
        Some(work_stream_event::Outcome::Prefix(_))
    ));
    service
        .administer(async |store, now| {
            let mut def = store.state().grant(a.grant_id).unwrap().clone();
            def.revision.0 += 1;
            def.enabled = false;
            store.define(def, now).await
        })
        .await
        .unwrap();
    backend.finish.release();
    assert!(matches!(
        stream.next().await.unwrap().unwrap().outcome,
        Some(work_stream_event::Outcome::Terminal(_))
    ));
    assert!(stream.next().await.is_none());
    stream.finish().unwrap();
    within(service.drain()).await.unwrap();
    assert_eq!(backend.calls.load(Ordering::SeqCst), 1);
    service
        .administer(async |store, _| {
            assert_eq!(
                store
                    .state()
                    .ledger()
                    .node(budget())
                    .unwrap()
                    .counter(Meter::Requests, Window::Total)
                    .used,
                1
            );
            store.rotate().await
        })
        .await
        .unwrap();
    for file in crate::test_support::all_files(dir.path()) {
        let bytes = std::fs::read(file).unwrap();
        for secret in [
            b"private-grant-result".as_slice(),
            b"never-journal-this-body",
        ] {
            assert!(!bytes.windows(secret.len()).any(|window| window == secret));
        }
    }
    serving.abort();
}
