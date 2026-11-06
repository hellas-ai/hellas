use hellas_channel::{
    model::work::{encode_transcript, result_digest, signing_hash, work_id},
    test_support::channel as fixture,
    work_store::{ChannelRecord, ChannelStore, Role},
};
use hellas_kernel::Secp256k1Verifier;
use hellas_rpc::{
    ContentRef,
    protocol::invocation::output::{FailureReason, InvocationOutput, Outcome},
};
use hellas_store::content::*;

#[tokio::test]
async fn invalid_result_leaves_exact_retained_allowance_available_for_valid_delivery() {
    let root = tempfile::tempdir().unwrap();
    let ready = fixture::ready();
    let authorization = fixture::authorization();
    let prepared = fixture::bundle(fixture::NONCE);
    let input = prepared.canonical_bytes().unwrap();
    let environment = fixture::environment().canonical_bytes().unwrap();
    let closure = hellas_channel::job::content_closure(
        &fixture::work_policy(),
        &fixture::manifest(),
        &environment,
        authorization.input_content,
    )
    .unwrap();
    let initial = Tree::new(
        closure
            .iter()
            .map(|object| (object.id().to_string(), Target::Object(*object)))
            .collect(),
    )
    .unwrap()
    .bytes();
    let facts = fixture::work_policy()
        .classify_manifest(&fixture::manifest())
        .unwrap();
    let replacement = Tree::new(
        closure
            .iter()
            .map(|object| (object.id().to_string(), Target::Object(*object)))
            .chain([(
                String::from("transcript"),
                Target::Object(ContentRef::new(
                    hellas_rpc::ContentId::from_bytes([0; 32]),
                    facts.max_spool_bytes,
                )),
            )])
            .collect(),
    )
    .unwrap()
    .bytes();
    let capacity = closure.iter().map(|object| object.bytes()).sum::<u64>()
        + initial.len() as u64
        + replacement.len() as u64
        + facts.max_spool_bytes;
    let node = DiskStore::open(
        root.path().join("content"),
        vec![],
        IndexMode::Resume,
        Some(capacity),
        Reservations::ram(hellas_channel::content::DEFAULT_MAX_STAGING_BYTES),
    )
    .await
    .unwrap();
    let verifier = Secp256k1Verifier::new();
    let mut journal = ChannelStore::open(
        root.path(),
        ready.channel().clone(),
        fixture::settlement(),
        Role::Provider,
        fixture::origin(),
        node.clone(),
        &verifier,
    )
    .await
    .unwrap();
    node.finish_recovery().await.unwrap();
    fixture::advance(&mut journal, fixture::CURSOR).await;
    let work = work_id(ready.channel(), &authorization);
    fixture::commit(
        &mut journal,
        ChannelRecord::JobProposed {
            authorization,
            client_signature: fixture::client().sign(signing_hash(work)),
            prepared_input: input.into(),
            retained_tree: None,
        },
    )
    .await;
    fixture::commit(
        &mut journal,
        ChannelRecord::JobAccepted {
            work_id: work,
            provider_signature: fixture::provider().sign(signing_hash(work)),
            retained_tree: None,
        },
    )
    .await;
    let initial_root = journal.state().retained_roots()[&work];
    fixture::commit(&mut journal, ChannelRecord::JobRunning { work_id: work }).await;
    let events = InvocationOutput {
        outcome: Outcome::Failed(FailureReason::Execution),
        artifacts: vec![],
        metadata: hellas_rpc::JsonBytes(vec![]),
    }
    .sign(&prepared.request, &fixture::provider_producer(), 1024)
    .unwrap();
    let result = hellas_channel::job::paid_terminal_result(
        ready.channel(),
        &authorization,
        &fixture::work_policy(),
        &prepared,
        &events,
    )
    .unwrap();
    let digest = signing_hash(result_digest(ready.channel(), &result));
    let transcript = encode_transcript(&events).unwrap();
    let before = node.stats().unwrap();
    let records = journal.len();
    assert!(
        journal
            .commit(
                ChannelRecord::JobResult {
                    work_id: work,
                    result,
                    provider_signature: fixture::client().sign(digest),
                    transcript: transcript.clone().into(),
                    retained_tree: None,
                },
                &verifier
            )
            .await
            .is_err()
    );
    let after = node.stats().unwrap();
    assert_eq!(
        (after.used, after.outstanding),
        (before.used, before.outstanding)
    );
    assert_eq!(after.used + after.outstanding, capacity);
    assert_eq!(journal.len(), records);
    assert_eq!(journal.state().retained_roots()[&work], initial_root);
    let valid = ChannelRecord::JobResult {
        work_id: work,
        result,
        provider_signature: fixture::provider().sign(digest),
        transcript: transcript.clone().into(),
        retained_tree: None,
    };
    journal.commit(valid.clone(), &verifier).await.unwrap();
    let finished = journal.state().retained_roots()[&work];
    assert_ne!(finished, initial_root);
    assert_eq!(node.stats().unwrap().outstanding, 0);
    assert!(node.stats().unwrap().used <= capacity);
    journal.commit(valid, &verifier).await.unwrap();
    journal
        .commit(
            ChannelRecord::JobAccepted {
                work_id: work,
                provider_signature: fixture::provider().sign(signing_hash(work)),
                retained_tree: Some(initial_root),
            },
            &verifier,
        )
        .await
        .unwrap();
    assert_eq!(journal.state().retained_roots()[&work], finished);
    let pins = node
        .pins(&Scope::Owner, "channel/", Cursor::default())
        .await
        .unwrap();
    assert_eq!(pins.pins.len(), 1);
    assert_eq!(pins.pins[0].1.target, Target::Tree(finished));
    let at = Path::new(pins.pins[0].0.clone(), String::from("transcript")).unwrap();
    let mut read = node
        .read(&Scope::Owner, &at, 0..transcript.len() as u64)
        .await
        .unwrap();
    use futures::StreamExt;
    let mut actual = Vec::new();
    while let Some(chunk) = read.bytes.next().await {
        actual.extend_from_slice(&chunk.unwrap());
    }
    assert_eq!(actual, transcript);
}

async fn pending_upload_fixture() -> (
    tempfile::TempDir,
    hellas_channel::work::WorkService,
    DiskStore,
    Vec<hellas_rpc::pb::content::UploadRequest>,
) {
    let root = tempfile::tempdir().unwrap();
    let ready = fixture::ready();
    let journal = fixture::store_at(root.path(), &ready, Role::Provider, fixture::CURSOR).await;
    let node = journal.content_store();
    let service = hellas_channel::work::WorkService::new(
        hellas_channel::work::ProviderEndpoint::new(ready.clone(), journal, fixture::provider())
            .unwrap(),
    );
    let authorization = fixture::authorization();
    let work = work_id(ready.channel(), &authorization);
    use hellas_channel::model::work::PrivateRecord;
    let request = hellas_rpc::pb::work::AcceptWorkRequest {
        route: Some(hellas_rpc::pb::work::WorkRoute::payment(
            authorization.channel_id,
        )),
        authorization: authorization.encode(),
        client_signature: fixture::client()
            .sign(signing_hash(work))
            .as_bytes()
            .to_vec(),
        prepared_input: hellas_rpc::protocol::content::encode_reference(
            authorization.input_content,
        ),
    };
    let (_, frames) = fixture::input_uploads(
        ready.channel(),
        &request,
        &fixture::bundle(fixture::NONCE).canonical_bytes().unwrap(),
    );
    (root, service, node, frames)
}

async fn wait_for_pending_cleanup(node: &DiskStore) {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while node.stats().unwrap().outstanding != 0 || node.stats().unwrap().used != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(node.collect(&Scope::Owner).await.unwrap().objects, 0);
}

#[tokio::test]
async fn dropping_an_incomplete_stream_releases_its_scope_and_reservation() {
    use futures::StreamExt;
    let (_root, service, node, frames) = pending_upload_fixture().await;
    let connection = hellas_channel::work::admission::Cancellation::new();
    let mut replies = service
        .upload_stream(
            Box::pin(futures::stream::iter(frames.into_iter().map(Ok))),
            hellas_wire::TransportContext {
                open_exporter: Some([7; 32]),
                ..Default::default()
            },
            connection.clone(),
        )
        .await
        .unwrap();
    let first = replies.next().await.unwrap().unwrap();
    assert!(first.missing && !first.complete);
    assert!(node.stats().unwrap().outstanding > 0);
    drop(replies);
    wait_for_pending_cleanup(&node).await;
    connection.cancel();
}

#[tokio::test]
async fn completed_unaccepted_upload_is_deleted_when_its_bound_connection_ends() {
    let (_root, service, node, frames) = pending_upload_fixture().await;
    let connection = hellas_channel::work::admission::Cancellation::new();
    let replies = service
        .upload_stream(
            Box::pin(futures::stream::iter(frames.into_iter().map(Ok))),
            hellas_wire::TransportContext {
                open_exporter: Some([7; 32]),
                ..Default::default()
            },
            connection.clone(),
        )
        .await;
    hellas_channel::test_support::drive_upload(replies)
        .await
        .unwrap();
    assert!(node.stats().unwrap().used > 0);
    assert!(
        node.pins(&Scope::Owner, "channel/", Cursor::default())
            .await
            .unwrap()
            .pins
            .is_empty()
    );
    connection.cancel();
    wait_for_pending_cleanup(&node).await;
}

#[tokio::test]
async fn opening_signature_replayed_on_another_connection_reserves_and_stages_nothing() {
    let (_root, service, node, frames) = pending_upload_fixture().await;
    let before = node.stats().unwrap();
    let replies = service
        .upload_stream(
            Box::pin(futures::stream::iter(frames.into_iter().map(Ok))),
            hellas_wire::TransportContext {
                open_exporter: Some([8; 32]),
                ..Default::default()
            },
            hellas_channel::work::admission::Cancellation::new(),
        )
        .await;
    assert!(replies.is_err());
    let after = node.stats().unwrap();
    assert_eq!(
        (after.used, after.outstanding),
        (before.used, before.outstanding)
    );
}

#[tokio::test]
async fn late_cleanup_of_a_dropped_upload_cannot_remove_its_successor_reservation() {
    use futures::StreamExt;
    use hellas_channel::work_close::CloseChannel;
    let (_root, service, node, frames) = pending_upload_fixture().await;
    let connection_a = hellas_channel::work::admission::Cancellation::new();
    let mut a = service
        .upload_stream(
            Box::pin(futures::stream::iter(frames.clone().into_iter().map(Ok))),
            hellas_wire::TransportContext {
                open_exporter: Some([7; 32]),
                ..Default::default()
            },
            connection_a.clone(),
        )
        .await
        .unwrap();
    a.next().await.unwrap().unwrap();
    let mut driver = service.drive().unwrap();
    let writer = driver.store().await.unwrap();
    drop(a);
    // Queue the stream cleanup first, the new opening second, and the old
    // connection's monitor last, behind the actual endpoint writer.
    tokio::task::yield_now().await;
    let connection_b = hellas_channel::work::admission::Cancellation::new();
    let mut opening_b = Box::pin(service.upload_stream(
        Box::pin(futures::stream::iter(frames.into_iter().map(Ok))),
        hellas_wire::TransportContext {
            open_exporter: Some([7; 32]),
            ..Default::default()
        },
        connection_b.clone(),
    ));
    assert!(futures::poll!(opening_b.as_mut()).is_pending());
    connection_a.cancel();
    tokio::task::yield_now().await;
    drop(writer);
    drop(driver);
    let mut b = opening_b.await.unwrap();
    service.with_state(|_| ()).await.unwrap();
    let held = node.stats().unwrap().outstanding;
    assert!(held > 0);
    let progress = b.next().await.unwrap().unwrap();
    assert!(progress.missing && !progress.complete);
    assert_eq!(node.stats().unwrap().outstanding, held);
    drop(b);
    connection_b.cancel();
    wait_for_pending_cleanup(&node).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelling_initial_admission_waits_for_its_core_effect_and_cleans_the_actual_reservation()
{
    let (_root, service, node, frames) = pending_upload_fixture().await;
    let (entered, started) = tokio::sync::oneshot::channel();
    let entered = std::sync::Arc::new(std::sync::Mutex::new(Some(entered)));
    let (release, blocked) = std::sync::mpsc::channel();
    let blocked = std::sync::Arc::new(std::sync::Mutex::new(blocked));
    let gate_scope = Scope::Owner.bind(
        move || {
            let (entered, blocked) = (entered.clone(), blocked.clone());
            async move {
                Ok(move || {
                    if let Some(entered) = entered.lock().unwrap().take() {
                        let _ = entered.send(());
                    }
                    blocked.lock().unwrap().recv().map_err(|_| Error::Denied)?;
                    Ok(())
                })
            }
        },
        std::future::pending(),
    );
    let blocker_node = node.clone();
    let blocker = tokio::spawn(async move {
        blocker_node
            .set_pin(
                &gate_scope,
                &PinName::new("gate".into()).unwrap(),
                None,
                None,
            )
            .await
    });
    started.await.unwrap();
    let connection = hellas_channel::work::admission::Cancellation::new();
    let mut opening = Box::pin(service.upload_stream(
        Box::pin(futures::stream::iter(frames.clone().into_iter().map(Ok))),
        hellas_wire::TransportContext {
            open_exporter: Some([7; 32]),
            ..Default::default()
        },
        connection.clone(),
    ));
    assert!(futures::poll!(opening.as_mut()).is_pending());
    tokio::task::yield_now().await;
    drop(opening);
    release.send(()).unwrap();
    blocker.await.unwrap().unwrap();
    // Serialize behind the actual Core effect, then behind map insertion.
    node.collect(&Scope::Owner).await.unwrap();
    service.with_state(|_| ()).await.unwrap();
    wait_for_pending_cleanup(&node).await;
    connection.cancel();
    let connection = hellas_channel::work::admission::Cancellation::new();
    let next = service
        .upload_stream(
            Box::pin(futures::stream::iter(frames.into_iter().map(Ok))),
            hellas_wire::TransportContext {
                open_exporter: Some([7; 32]),
                ..Default::default()
            },
            connection.clone(),
        )
        .await
        .unwrap();
    assert!(node.stats().unwrap().outstanding > 0);
    drop(next);
    connection.cancel();
    wait_for_pending_cleanup(&node).await;
}

#[tokio::test]
async fn a_durable_unaccepted_proposal_can_reupload_and_accept_after_reopening_without_its_body() {
    let root = tempfile::tempdir().unwrap();
    let ready = fixture::ready();
    let mut journal = fixture::store_at(root.path(), &ready, Role::Provider, fixture::CURSOR).await;
    let node = journal.content_store();
    let authorization = fixture::authorization();
    let work = work_id(ready.channel(), &authorization);
    let bytes = fixture::bundle(fixture::NONCE).canonical_bytes().unwrap();
    fixture::commit(
        &mut journal,
        ChannelRecord::JobProposed {
            authorization,
            client_signature: fixture::client().sign(signing_hash(work)),
            prepared_input: bytes.into(),
            retained_tree: None,
        },
    )
    .await;
    drop(journal);
    node.close().await;
    drop(node);
    let node = DiskStore::open(
        root.path().join("content"),
        vec![],
        IndexMode::Resume,
        None,
        Reservations::ram(hellas_channel::content::DEFAULT_MAX_STAGING_BYTES),
    )
    .await
    .unwrap();
    let journal = ChannelStore::open(
        root.path(),
        ready.channel().clone(),
        fixture::settlement(),
        Role::Provider,
        fixture::origin(),
        node.clone(),
        &Secp256k1Verifier::new(),
    )
    .await
    .unwrap();
    assert!(
        journal
            .state()
            .job_by_id(work)
            .unwrap()
            .prepared_input()
            .is_empty()
    );
    node.finish_recovery().await.unwrap();
    assert_eq!(
        (
            node.stats().unwrap().used,
            node.stats().unwrap().outstanding
        ),
        (0, 0)
    );
    let service = hellas_channel::work::WorkService::new(
        hellas_channel::work::ProviderEndpoint::new(ready.clone(), journal, fixture::provider())
            .unwrap(),
    );
    use hellas_channel::model::work::PrivateRecord;
    let request = hellas_rpc::pb::work::AcceptWorkRequest {
        route: Some(hellas_rpc::pb::work::WorkRoute::payment(
            authorization.channel_id,
        )),
        authorization: authorization.encode(),
        client_signature: fixture::client()
            .sign(signing_hash(work))
            .as_bytes()
            .to_vec(),
        prepared_input: hellas_rpc::protocol::content::encode_reference(
            authorization.input_content,
        ),
    };
    let accepted = fixture::accept_uploaded_service(&service, &request).await;
    assert!(
        matches!(
            accepted.outcome,
            Some(hellas_rpc::pb::work::accept_work_response::Outcome::Accepted(_))
        ),
        "{accepted:?}"
    );
    assert_eq!(
        node.pins(&Scope::Owner, "channel/", Cursor::default())
            .await
            .unwrap()
            .pins
            .len(),
        1
    );
}

#[tokio::test]
async fn abandoning_an_unaccepted_scope_also_drops_its_cached_prepared_body_charge() {
    let root = tempfile::tempdir().unwrap();
    let ready = fixture::ready();
    let mut journal = fixture::store_at(root.path(), &ready, Role::Provider, fixture::CURSOR).await;
    let node = journal.content_store();
    let authorization = fixture::authorization();
    let work = work_id(ready.channel(), &authorization);
    let input = fixture::bundle(fixture::NONCE).canonical_bytes().unwrap();
    fixture::seed_content(&mut journal, authorization, input.into()).await;
    let (_, scope) = journal
        .open_content(
            work,
            hellas_rpc::Retention::Retain,
            vec![],
            fixture::work_policy().limits.max_upload_bytes,
        )
        .await
        .unwrap();
    let body = node
        .open_staged(&scope, authorization.input_content)
        .await
        .unwrap()
        .unwrap()
        .read_all(authorization.input_content, &node.ram_pool())
        .await
        .unwrap();
    journal
        .commit(
            ChannelRecord::JobProposed {
                authorization,
                client_signature: fixture::client().sign(signing_hash(work)),
                prepared_input: body,
                retained_tree: None,
            },
            &Secp256k1Verifier::new(),
        )
        .await
        .unwrap();
    assert_eq!(node.ram_pool().held(), authorization.input_content.bytes());
    let service = hellas_channel::work::WorkService::new(
        hellas_channel::work::ProviderEndpoint::new(ready.clone(), journal, fixture::provider())
            .unwrap(),
    );
    use hellas_channel::model::work::PrivateRecord;
    let wire = hellas_rpc::pb::work::AcceptWorkRequest {
        route: Some(hellas_rpc::pb::work::WorkRoute::payment(
            authorization.channel_id,
        )),
        authorization: authorization.encode(),
        client_signature: fixture::client()
            .sign(signing_hash(work))
            .as_bytes()
            .to_vec(),
        prepared_input: hellas_rpc::protocol::content::encode_reference(
            authorization.input_content,
        ),
    };
    let (_, frames) = fixture::fixture_uploads(ready.channel(), &wire);
    let connection = hellas_channel::work::admission::Cancellation::new();
    let stream = service
        .upload_stream(
            Box::pin(futures::stream::iter(frames.into_iter().map(Ok))),
            hellas_wire::TransportContext {
                open_exporter: Some([7; 32]),
                ..Default::default()
            },
            connection.clone(),
        )
        .await
        .unwrap();
    drop(stream);
    wait_for_pending_cleanup(&node).await;
    assert_eq!(node.ram_pool().held(), 0);
    connection.cancel();
}

#[tokio::test]
async fn correctly_signed_other_connection_cannot_take_over_an_active_proposal_upload() {
    use futures::StreamExt;
    use hellas_channel::work::admission::Cancellation;
    use hellas_rpc::pb::content as pb;
    let (_root, service, node, frames) = pending_upload_fixture().await;
    let connection_a = Cancellation::new();
    let mut a = service
        .upload_stream(
            Box::pin(futures::stream::iter(frames.clone().into_iter().map(Ok))),
            hellas_wire::TransportContext {
                open_exporter: Some([7; 32]),
                ..Default::default()
            },
            connection_a.clone(),
        )
        .await
        .unwrap();
    a.next().await.unwrap().unwrap();
    let held = node.stats().unwrap().outstanding;
    let mut frames_b = frames;
    let Some(pb::upload_request::Part::Open(open)) = &mut frames_b[0].part else {
        panic!()
    };
    let opening = open.work.as_mut().unwrap();
    opening.binding_signature = fixture::client()
        .sign(signing_hash(hellas_channel::job::opening_digest(
            opening, &[8; 32],
        )))
        .as_bytes()
        .to_vec();
    let context_b = hellas_wire::TransportContext {
        open_exporter: Some([8; 32]),
        ..Default::default()
    };
    let connection_b = Cancellation::new();
    assert!(
        service
            .upload_stream(
                Box::pin(futures::stream::iter(frames_b.clone().into_iter().map(Ok))),
                context_b.clone(),
                connection_b.clone()
            )
            .await
            .is_err()
    );
    assert_eq!(node.stats().unwrap().outstanding, held);
    drop(a);
    wait_for_pending_cleanup(&node).await;
    let mut b = service
        .upload_stream(
            Box::pin(futures::stream::iter(frames_b.into_iter().map(Ok))),
            context_b,
            connection_b.clone(),
        )
        .await
        .unwrap();
    b.next().await.unwrap().unwrap();
    connection_a.cancel();
    // Serialize behind A's old monitor; B remains the current scope.
    service.with_state(|_| ()).await.unwrap();
    assert!(node.stats().unwrap().outstanding > 0);
    while let Some(progress) = b.next().await {
        progress.unwrap();
    }
    connection_b.cancel();
    wait_for_pending_cleanup(&node).await;
}

#[tokio::test]
async fn accepted_work_releases_disconnected_upload_claim_before_completion() {
    use hellas_channel::work::admission::Cancellation;
    use prost::Message;
    let (_root, service, _node, frames) = pending_upload_fixture().await;
    let Some(hellas_rpc::pb::content::upload_request::Part::Open(open)) = &frames[0].part else {
        panic!()
    };
    let request = hellas_rpc::pb::work::AcceptWorkRequest::decode(
        open.work.as_ref().unwrap().signed_opening.as_slice(),
    )
    .unwrap();
    let connection = Cancellation::new();
    hellas_channel::test_support::drive_upload(
        service
            .upload_stream(
                Box::pin(futures::stream::iter(frames.into_iter().map(Ok))),
                hellas_wire::TransportContext {
                    open_exporter: Some([7; 32]),
                    ..Default::default()
                },
                connection.clone(),
            )
            .await,
    )
    .await
    .unwrap();
    let response = service.accept(&request).await;
    assert!(
        matches!(
            response.outcome,
            Some(hellas_rpc::pb::work::accept_work_response::Outcome::Accepted(_))
        ),
        "{response:?}"
    );
    assert_eq!(service.content_upload_count().unwrap(), 1);
    connection.cancel();
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while service.content_upload_count().unwrap() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let work = work_id(fixture::ready().channel(), &fixture::authorization());
    let _input = service
        .begin_run(work, &service.readiness().await.unwrap())
        .await
        .unwrap();
    service.end_run(work).await.unwrap();
    assert_eq!(service.content_upload_count().unwrap(), 0);
}

#[tokio::test]
async fn owner_lifecycle_pin_policy_survives_acceptance_pin_move_and_boot_recovery() {
    for role in [Role::Client, Role::Provider] {
        let root = tempfile::tempdir().unwrap();
        let ready = fixture::ready();
        let mut journal = fixture::store_at(root.path(), &ready, role, fixture::CURSOR).await;
        let node = journal.content_store();
        let authorization = fixture::authorization();
        let work = work_id(ready.channel(), &authorization);
        let bytes = fixture::bundle(fixture::NONCE).canonical_bytes().unwrap();
        fixture::seed_content(&mut journal, authorization, bytes.clone().into()).await;
        fixture::commit(
            &mut journal,
            ChannelRecord::JobProposed {
                authorization,
                client_signature: fixture::client().sign(signing_hash(work)),
                prepared_input: bytes.clone().into(),
                retained_tree: None,
            },
        )
        .await;
        if role == Role::Provider {
            fixture::commit(
                &mut journal,
                ChannelRecord::JobAccepted {
                    work_id: work,
                    provider_signature: fixture::provider().sign(signing_hash(work)),
                    retained_tree: None,
                },
            )
            .await;
        }
        let (name, old) = node
            .pins(&Scope::Owner, "channel/", Cursor::default())
            .await
            .unwrap()
            .pins
            .remove(0);
        node.set_pin(
            &Scope::Owner,
            &name,
            Some(&old),
            Some(PinValue {
                policy: PinPolicy::Owner,
                ..old.clone()
            }),
        )
        .await
        .unwrap();
        fixture::commit(
            &mut journal,
            ChannelRecord::JobAccepted {
                work_id: work,
                provider_signature: fixture::provider().sign(signing_hash(work)),
                retained_tree: None,
            },
        )
        .await;
        let pins = node
            .pins(&Scope::Owner, "channel/", Cursor::default())
            .await
            .unwrap()
            .pins;
        assert_eq!(pins.len(), 1);
        assert_eq!(pins[0].1.policy, PinPolicy::Owner);
        let closure = hellas_channel::job::content_closure(
            &fixture::work_policy(),
            &fixture::manifest(),
            &fixture::environment().canonical_bytes().unwrap(),
            authorization.input_content,
        )
        .unwrap();
        let (local, scope) = journal
            .open_content(
                work,
                authorization.retention,
                closure.clone(),
                fixture::work_policy().limits.max_upload_bytes,
            )
            .await
            .unwrap();
        assert!(
            local
                .open_verified(&scope, authorization.input_content, None)
                .await
                .unwrap()
                .is_none()
        );
        drop(local);
        drop(journal);
        node.close().await;
        drop(node);
        let node = DiskStore::open(
            root.path().join("content"),
            vec![],
            IndexMode::Resume,
            None,
            Reservations::ram(hellas_channel::content::DEFAULT_MAX_STAGING_BYTES),
        )
        .await
        .unwrap();
        let mut journal = ChannelStore::open(
            root.path(),
            ready.channel().clone(),
            fixture::settlement(),
            role,
            fixture::origin(),
            node.clone(),
            &Secp256k1Verifier::new(),
        )
        .await
        .unwrap();
        node.finish_recovery().await.unwrap();
        let pins = node
            .pins(&Scope::Owner, "channel/", Cursor::default())
            .await
            .unwrap()
            .pins;
        assert_eq!(pins.len(), 1);
        assert_eq!(pins[0].1.policy, PinPolicy::Owner);
        let (local, scope) = journal
            .open_content(
                work,
                authorization.retention,
                closure,
                fixture::work_policy().limits.max_upload_bytes,
            )
            .await
            .unwrap();
        assert!(
            local
                .open_verified(&scope, authorization.input_content, None)
                .await
                .unwrap()
                .is_none()
        );
    }
}

#[tokio::test]
async fn reopening_a_channel_on_a_ready_node_preserves_its_scope_and_spent_output_allowance() {
    let root = tempfile::tempdir().unwrap();
    let ready = fixture::ready();
    let mut journal = fixture::store_at(root.path(), &ready, Role::Provider, fixture::CURSOR).await;
    let node = journal.content_store();
    let authorization = fixture::authorization();
    let work = work_id(ready.channel(), &authorization);
    let input = fixture::bundle(fixture::NONCE).canonical_bytes().unwrap();
    fixture::seed_content(&mut journal, authorization, input.clone().into()).await;
    fixture::commit(
        &mut journal,
        ChannelRecord::JobProposed {
            authorization,
            client_signature: fixture::client().sign(signing_hash(work)),
            prepared_input: input.into(),
            retained_tree: None,
        },
    )
    .await;
    fixture::commit(
        &mut journal,
        ChannelRecord::JobAccepted {
            work_id: work,
            provider_signature: fixture::provider().sign(signing_hash(work)),
            retained_tree: None,
        },
    )
    .await;
    let closure = hellas_channel::job::content_closure(
        &fixture::work_policy(),
        &fixture::manifest(),
        &fixture::environment().canonical_bytes().unwrap(),
        authorization.input_content,
    )
    .unwrap();
    let (local, scope) = journal
        .open_content(
            work,
            authorization.retention,
            closure.clone(),
            fixture::work_policy().limits.max_upload_bytes,
        )
        .await
        .unwrap();
    let output = b"private output still being built";
    node.stage_output(&scope, ContentRef::for_bytes(output))
        .await
        .unwrap()
        .copy_from(std::io::Cursor::new(output.to_vec()), &node.ram_pool())
        .await
        .unwrap();
    let before = node.stats().unwrap();
    drop(journal);
    let mut reopened = ChannelStore::open_existing(
        root.path(),
        ready.channel().clone(),
        fixture::settlement(),
        Role::Provider,
        fixture::origin(),
        node.clone(),
        &Secp256k1Verifier::new(),
    )
    .await
    .unwrap();
    let after = node.stats().unwrap();
    assert_eq!(
        (after.used, after.outstanding),
        (before.used, before.outstanding)
    );
    assert!(
        local
            .open_verified(&scope, authorization.input_content, None)
            .await
            .unwrap()
            .is_some()
    );
    let (_, again) = reopened
        .open_content(
            work,
            authorization.retention,
            closure,
            fixture::work_policy().limits.max_upload_bytes,
        )
        .await
        .unwrap();
    let reservation = |scope: &Scope| match scope.kind {
        ScopeKind::Work { reservation, .. } => reservation,
        _ => panic!(),
    };
    assert_eq!(reservation(&again), reservation(&scope));
    assert!(
        node.stage_output(&again, ContentRef::for_bytes(output))
            .await
            .unwrap()
            .complete()
    );
}
