use super::*;
use crate::test_support::{compute::Compute, ids};
use hellas_channel::test_support::actors::*;

async fn compute_node(path: &std::path::Path, oversized: bool) -> (TestNode, Proposal) {
    let compute = Compute;
    let mut allowance = compute.allowance(ids::ALLOWANCE, FRIEND);
    if oversized {
        allowance.definition.policies[0]
            .invocation_policy
            .limits
            .max_output_bytes = 64 << 20;
    }
    let node = Node::bootstrap(path)
        .with_capacity(Capacity::new(4))
        .with_allowance(allowance)
        .with_grant(
            ids::FRIEND_GRANT,
            Rights::new(authority(), FRIEND)
                .allow(
                    crate::grant_service::WORK_EXECUTE,
                    crate::grant_service::allowance_resource(authority(), ids::ALLOWANCE),
                )
                .valid_until(UnixMillis(100_000))
                .build(),
        )
        .build()
        .await;
    let proposal = compute.proposal(&node, FRIEND, ids::ALLOWANCE, 1);
    (node, proposal)
}

#[tokio::test]
async fn small_compute_grant_runs_and_settles_one_request_without_tokens_or_device_time() {
    let directory = tempfile::tempdir().unwrap();
    let (node, proposal) = compute_node(directory.path(), false).await;
    let private_input = proposal.input.canonical_bytes().unwrap();
    let backend = Backend {
        signer: Arc::new(PROVIDER.node_key()),
        ..Backend::default()
    };
    let world = node.serve(backend.clone());
    let work = world.work(FRIEND, ids::FRIEND_GRANT).await;
    let id = accepted_id(
        crate::test_support::accept_grant(&work, &proposal.request(), &FRIEND.node_key()).await,
    );
    within(backend.started.notified()).await;
    backend.finish.release();
    let mut stream = work.stream(delivery::delivery_request(&proposal.authorization, id));
    let mut transcript = Vec::new();
    loop {
        let event = within(stream.next())
            .await
            .expect("compute stream terminal")
            .unwrap();
        match event.outcome {
            Some(work_stream_event::Outcome::Prefix(bytes)) => {
                transcript.extend(decode_transcript(&bytes, 1 << 20).unwrap())
            }
            Some(work_stream_event::Outcome::Terminal(terminal)) => {
                transcript
                    .extend(decode_transcript(&terminal.terminal_transcript, 1 << 20).unwrap());
                assert_eq!(
                    PaidJobResultV1::decode(&terminal.result).unwrap().outcome,
                    ResultOutcome::Finished
                );
                break;
            }
            other => panic!("compute grant was refused: {other:?}"),
        }
    }
    assert!(stream.next().await.is_none());
    within(world.service.drain()).await.unwrap();
    assert_eq!(backend.calls.load(Ordering::SeqCst), 1);
    assert_eq!(world.used(BudgetNode::Machine, Meter::Requests).await, 1);
    for meter in [Meter::InputTokens, Meter::OutputTokens, Meter::DeviceMillis] {
        assert_eq!(world.used(BudgetNode::Machine, meter).await, 0);
    }
    let output = encode_transcript(&transcript).unwrap();
    for path in hellas_channel::test_support::all_files(directory.path()) {
        let bytes = std::fs::read(path).unwrap();
        assert!(
            !bytes
                .windows(private_input.len())
                .any(|w| w == private_input)
        );
        assert!(!bytes.windows(output.len()).any(|w| w == output));
    }
    assert_eq!(world.service.content.stats().unwrap().used, 0);
    assert_eq!(world.service.content.ram_pool().held(), 0);
}

#[tokio::test]
async fn oversized_compute_grant_is_refused_before_reserving_capacity_or_journaling_acceptance() {
    let directory = tempfile::tempdir().unwrap();
    let (node, proposal) = compute_node(directory.path(), true).await;
    let backend = Backend {
        signer: Arc::new(PROVIDER.node_key()),
        ..Backend::default()
    };
    let world = node.serve(backend.clone());
    let work = world.work(FRIEND, ids::FRIEND_GRANT).await;
    let before = world.snapshot().await;
    assert_eq!(
        refusal(
            crate::test_support::accept_grant(&work, &proposal.request(), &FRIEND.node_key()).await
        ),
        GrantRefusalCode::StateCapacity
    );
    assert_eq!(world.snapshot().await, before);
    assert_eq!(backend.calls.load(Ordering::SeqCst), 0);
    assert_eq!(backend.slots.available_permits(), 1);
    assert_eq!(world.used(BudgetNode::Machine, Meter::Requests).await, 0);
    within(world.service.drain()).await.unwrap();
}

fn no_closure_payloads_on_disk(root: &std::path::Path, objects: &[Vec<u8>]) {
    for path in hellas_channel::test_support::all_files(root) {
        let bytes = std::fs::read(&path).unwrap();
        for object in objects {
            let variants = [
                object.clone(),
                hellas_rpc::protocol::value::canonical_dag_cbor(object).unwrap(),
                serde_json::to_vec(object).unwrap(),
            ];
            for needle in variants {
                assert!(
                    !bytes.windows(needle.len()).any(|window| window == needle),
                    "grant closure bytes reached {}",
                    path.display()
                );
            }
        }
    }
}

#[tokio::test]
async fn unseen_grant_program_closure_reaches_only_the_ram_backend_and_never_files_or_database_rows()
 {
    use hellas_rpc::pb::content as pb;
    use hellas_rpc::protocol::content::encode_reference;
    use hellas_rpc::protocol::invocation::compute::{Environment, NamedAsset};
    use hellas_store::content::{ContentStore as _, Cursor, Scope};
    let directory = tempfile::tempdir().unwrap();
    let (node, mut proposal) = compute_node(directory.path(), false).await;
    let source = b"grant-private-program-source-7321".to_vec();
    let asset = b"grant-private-asset-body-9362".to_vec();
    let environment = Environment {
        sources: vec![ContentRef::for_bytes(&source)],
        assets: vec![NamedAsset {
            name: "private-asset-name-1928".into(),
            object: ContentRef::for_bytes(&asset),
        }],
    };
    let root = environment.canonical_bytes().unwrap();
    let manifest = environment
        .manifest(&hellas_channel::test_support::channel::evaluator())
        .unwrap();
    let mut invocation_request = proposal.input.request.clone();
    invocation_request.execution_environment = manifest.content_id();
    proposal.input = hellas_rpc::protocol::invocation::PreparedInvocation::new(
        invocation_request,
        &manifest,
        proposal.input.input.clone(),
        proposal.input.application_policy.0.clone(),
    )
    .unwrap();
    proposal.authorization.environment_commitment = manifest.content_id();
    proposal.authorization.input_content =
        ContentRef::for_bytes(&proposal.input.canonical_bytes().unwrap());
    proposal.authorization.prepared_input_digest =
        hellas_channel::job::bound_prepared_input_digest(
            network(),
            proposal.authorization.channel_id.0,
            &proposal.input,
        )
        .unwrap();
    proposal.authorization.request_commitment = proposal.input.request.commitment().unwrap();
    proposal.signature = FRIEND.node_key().sign_digest(proposal.work()).unwrap();
    let prepared = proposal.input.canonical_bytes().unwrap();
    let objects = vec![source, asset, root.clone(), prepared];
    let expected = objects.clone();
    let inspected = Arc::new(AtomicUsize::new(0));
    let observed = inspected.clone();
    let backend = Backend {
        signer: Arc::new(PROVIDER.node_key()),
        inspect_content: Some(Arc::new(move |input, content| {
            let expected = expected.clone();
            let observed = observed.clone();
            Box::pin(async move {
                assert!(!input.request.retain);
                assert_eq!(content.0.retention(), Retention::Ephemeral);
                assert!(matches!(
                    content.0,
                    hellas_store::content::LocalStore::Job(_)
                ));
                for bytes in &expected {
                    let reference = ContentRef::for_bytes(bytes);
                    let reader = content
                        .0
                        .open_verified(&content.1, reference, None)
                        .await
                        .unwrap()
                        .unwrap();
                    let actual = reader
                        .read_all(reference, &content.0.ram_pool())
                        .await
                        .unwrap();
                    assert_eq!(actual.as_ref(), bytes.as_slice());
                }
                assert!(
                    content
                        .0
                        .open_verified(
                            &content.1,
                            ContentRef::for_bytes(b"not in the signed closure"),
                            None,
                        )
                        .await
                        .is_err()
                );
                observed.fetch_add(1, Ordering::SeqCst);
            })
        })),
        ..Backend::default()
    };
    let world = node.serve(backend.clone());
    let work = world.work(FRIEND, ids::FRIEND_GRANT).await;
    let before = world.snapshot().await;
    let rows = world.service.node().writer().await.unwrap().journal_len();
    let a = proposal.authorization;
    let id = proposal.work();
    let mut request = proposal.request();
    request.prepared_input = encode_reference(a.input_content);
    let mut frames = hellas_channel::test_support::upload_frames(
        &request,
        manifest.canonical_bytes(),
        root,
        &objects[3],
        |opening| {
            FRIEND
                .node_key()
                .sign_digest(hellas_channel::job::opening_digest(opening, &[7; 32]))
                .unwrap()
                .bytes()
                .to_vec()
        },
    );
    for bytes in &objects[..2] {
        let mut object_frames = hellas_channel::test_support::upload_frames(
            &request,
            vec![],
            vec![],
            bytes,
            |_| vec![],
        );
        let Some(pb::upload_request::Part::Open(open)) = &mut object_frames[0].part else {
            unreachable!()
        };
        open.work = None;
        frames.extend(object_frames);
    }
    let (send, receive) = futures::channel::mpsc::unbounded();
    send.unbounded_send(Ok(frames.remove(0))).unwrap();
    let connection = hellas_channel::work::admission::Cancellation::new();
    let _stop = hellas_channel::work::admission::CancelOnFailure(vec![connection.clone()]);
    let mut replies = work
        .upload_stream(Box::pin(receive), context(), connection)
        .await
        .unwrap();
    let mut frames = frames.into_iter();
    loop {
        let reply = replies.next().await.unwrap().unwrap();
        if reply.complete {
            assert_eq!(world.snapshot().await, before);
            assert_eq!(
                world.service.node().writer().await.unwrap().journal_len(),
                rows,
                "uploading a grant closure writes no authority row"
            );
            assert_eq!(world.service.content.stats().unwrap().used, 0);
            assert!(
                world
                    .service
                    .content
                    .pins(&Scope::Owner, "", Cursor::default())
                    .await
                    .unwrap()
                    .pins
                    .is_empty()
            );
            no_closure_payloads_on_disk(directory.path(), &objects);
        }
        match frames.find(|frame| {
            !reply.complete || matches!(frame.part, Some(pb::upload_request::Part::Open(_)))
        }) {
            Some(frame) => send.unbounded_send(Ok(frame)).unwrap(),
            None => {
                drop(send);
                hellas_channel::test_support::drive_upload(Ok(replies))
                    .await
                    .unwrap();
                break;
            }
        }
    }
    assert_eq!(accepted_id(work.accept(&request).await), id);
    within(backend.started.notified()).await;
    assert_eq!(inspected.load(Ordering::SeqCst), 1);
    no_closure_payloads_on_disk(directory.path(), &objects);
    backend.finish.release();
    within(world.service.drain()).await.unwrap();
    assert_eq!(backend.calls.load(Ordering::SeqCst), 1);
    assert_eq!(world.used(BudgetNode::Machine, Meter::Requests).await, 1);
    no_closure_payloads_on_disk(directory.path(), &objects);
}
