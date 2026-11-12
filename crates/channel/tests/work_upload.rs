//! Paid application boundaries over generic Content.Upload. Store partition,
//! paging, reservation and malformed-chunk cases live in the shared store suite.
use hellas_auth::Digest;
use hellas_channel::{
    model::{
        setup::ReadyChannel,
        work::{PaidJobAuthorizationV2, PrivateRecord as _, signing_hash, work_id},
    },
    test_support::{channel::*, drive_upload, upload_frames},
    work::{
        ClientChannel as _, ClientEndpoint, ClientService, JobProposal, ProviderEndpoint,
        RunAdmission, WorkService, admission::Cancellation,
    },
    work_store::{ChannelRecord, ChannelStore, Role},
};
use hellas_kernel::{Secp256k1Verifier, Sig};
use hellas_rpc::{
    ContentRef,
    pb::{
        content as pb,
        work::{AcceptWorkRequest, accept_work_response},
    },
    protocol::invocation::{Artifact, PreparedInvocation},
};
use hellas_store::content::*;
use hellas_wire::TransportContext;

async fn service(root: &std::path::Path, ready: &ReadyChannel) -> (WorkService, DiskStore) {
    let journal = store_at(root, ready, Role::Provider, CURSOR).await;
    let node = journal.content_store();
    (
        WorkService::new(ProviderEndpoint::new(ready.clone(), journal, provider()).unwrap()),
        node,
    )
}
async fn proposal(
    root: &std::path::Path,
    ready: &ReadyChannel,
    mut input: PreparedInvocation,
    source: &(LocalStore, Scope),
) -> (ClientService, AcceptWorkRequest, Vec<u8>) {
    let endpoint = ClientEndpoint::new(
        ready.clone(),
        store_at(root, ready, Role::Client, CURSOR).await,
        client(),
    )
    .unwrap();
    let mut endpoint = client_service(endpoint, ready.clone()).await;
    input.application_policy =
        hellas_rpc::JsonBytes(ready.invocation_policy().canonical_bytes().unwrap());
    let bytes = input.canonical_bytes().unwrap();
    let request = endpoint
        .propose(
            &JobProposal {
                prepared_input: input,
                deadlines: deadlines(),
            },
            source,
            None,
        )
        .await
        .unwrap();
    (endpoint, request, bytes)
}
async fn upload(
    service: &WorkService,
    frames: Vec<pb::UploadRequest>,
    connection: &Cancellation,
) -> std::result::Result<usize, hellas_wire::WireStatus> {
    use futures::StreamExt;
    let mut frames = frames.into_iter();
    let (send, receive) = futures::channel::mpsc::unbounded();
    send.unbounded_send(Ok(frames.next().unwrap())).unwrap();
    let mut replies = service
        .upload_stream(
            Box::pin(receive),
            TransportContext {
                open_exporter: Some([7; 32]),
                ..Default::default()
            },
            connection.clone(),
        )
        .await?;
    let mut payload_frames = 0;
    loop {
        let reply = replies.next().await.expect("one answer per frame")?;
        // A present object needs only Open. Respect the server's answer rather
        // than sending a declaration or payload after it has already completed.
        let next = frames.find(|frame| {
            !reply.complete || matches!(frame.part, Some(pb::upload_request::Part::Open(_)))
        });
        match next {
            Some(frame) => {
                if matches!(frame.part, Some(pb::upload_request::Part::Chunk(_))) {
                    payload_frames += 1;
                }
                send.unbounded_send(Ok(frame)).unwrap();
            }
            None => {
                drop(send);
                drive_upload(Ok(replies)).await?;
                return Ok(payload_frames);
            }
        }
    }
}
async fn claims_released(service: &WorkService) {
    tokio::time::timeout(hellas_channel::test_support::HANG_GUARD, async {
        while service.content_upload_count().await.unwrap() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}
async fn shutdown(service: WorkService, node: DiskStore) {
    assert_eq!(service.content_upload_count().await.unwrap(), 0);
    drop(service);
    node.close().await;
    drop(node);
}
fn frames(
    request: &AcceptWorkRequest,
    manifest: Vec<u8>,
    root: Vec<u8>,
    input: &[u8],
) -> Vec<pb::UploadRequest> {
    upload_frames(request, manifest, root, input, |opening| {
        client()
            .sign(signing_hash(hellas_channel::job::opening_digest(
                opening, &[7; 32],
            )))
            .as_bytes()
            .to_vec()
    })
}
fn append_object(frames: &mut Vec<pb::UploadRequest>, request: &AcceptWorkRequest, bytes: &[u8]) {
    let mut object = upload_frames(request, vec![], vec![], bytes, |_| vec![]);
    let Some(pb::upload_request::Part::Open(open)) = &mut object[0].part else {
        unreachable!()
    };
    open.work = None;
    frames.extend(object);
}

#[tokio::test]
async fn foreign_first_object_and_opening_replayed_under_another_job_stage_nothing() {
    use prost::Message;
    let root = tempfile::tempdir().unwrap();
    let ready = ready();
    let (service, node) = service(&root.path().join("provider"), &ready).await;
    let (_, request, bytes) = proposal(
        &root.path().join("client"),
        &ready,
        bundle(1),
        &program_content().await,
    )
    .await;
    let (_, original) = input_uploads(ready.channel(), &request, &bytes);
    let before = node.stats().unwrap();
    for foreign in [true, false] {
        let mut frames = original.clone();
        let Some(pb::upload_request::Part::Open(open)) = &mut frames[0].part else {
            unreachable!()
        };
        if foreign {
            let reference = ContentRef::for_bytes(b"foreign");
            open.object = Some(pb::ContentRef {
                id: reference.id().as_bytes().to_vec(),
                bytes: reference.bytes(),
            });
        } else {
            let mut other = request.clone();
            let mut authorization = PaidJobAuthorizationV2::decode(&other.authorization).unwrap();
            authorization.proposal_nonce += 1;
            other.authorization = authorization.encode();
            other.client_signature = client()
                .sign(signing_hash(work_id(ready.channel(), &authorization)))
                .as_bytes()
                .to_vec();
            // The job authorization remains valid, but the old opening signature
            // cannot be replayed with the substituted job.
            open.work.as_mut().unwrap().signed_opening = other.encode_to_vec();
        }
        assert!(
            upload(&service, frames, &Cancellation::new())
                .await
                .is_err()
        );
        claims_released(&service).await;
        let after = node.stats().unwrap();
        assert_eq!(
            (after.used, after.outstanding),
            (before.used, before.outstanding)
        );
    }
    assert!(
        service
            .with_state(|state| state.jobs().next().is_none())
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn close_clears_completed_staging_and_refuses_further_uploads() {
    let root = tempfile::tempdir().unwrap();
    let ready = ready();
    let (service, node) = service(&root.path().join("provider"), &ready).await;
    let (_, request, bytes) = proposal(
        &root.path().join("client"),
        &ready,
        bundle(1),
        &program_content().await,
    )
    .await;
    let (_, frames) = input_uploads(ready.channel(), &request, &bytes);
    let connection = Cancellation::new();
    upload(&service, frames.clone(), &connection).await.unwrap();
    assert!(node.stats().unwrap().used > 0);
    service.prepare_close().await.unwrap();
    claims_released(&service).await;
    assert_eq!(node.stats().unwrap().outstanding, 0);
    assert_eq!(node.stats().unwrap().used, 0);
    connection.cancel();
    assert!(
        upload(&service, frames, &Cancellation::new())
            .await
            .is_err()
    );
    assert!(
        node.pins(&Scope::Owner, "channel/", Cursor::default())
            .await
            .unwrap()
            .pins
            .is_empty()
    );
}

#[tokio::test]
async fn failed_cosign_journal_append_never_pins_and_reupload_after_restart_recovers() {
    use sqlx::Connection as _;
    let root = tempfile::tempdir().unwrap();
    let ready = ready();
    let provider_root = root.path().join("provider");
    let (initial, node) = service(&provider_root, &ready).await;
    shutdown(initial, node).await;
    let path = std::fs::read_dir(provider_root.join("journals"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| path.extension().is_some_and(|ext| ext == "sqlite"))
        .unwrap();
    let options = sqlx::sqlite::SqliteConnectOptions::new().filename(&path);
    let mut database = sqlx::SqliteConnection::connect_with(&options)
        .await
        .unwrap();
    let tag = ChannelRecord::JobAccepted {
        work_id: Digest::hash(b"tag"),
        provider_signature: Sig::from_bytes([0; 64]),
        retained_tree: None,
    }
    .encode()[0];
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!("CREATE TRIGGER reject_cosign BEFORE INSERT ON record WHEN hex(substr(NEW.payload,1,1)) = '{tag:02X}' BEGIN SELECT RAISE(ABORT, 'injected cosign storage failure'); END"))).execute(&mut database).await.unwrap();
    database.close().await.unwrap();
    let (service, node) = self::service(&provider_root, &ready).await;
    let (mut caller, request, bytes) = proposal(
        &root.path().join("client"),
        &ready,
        bundle(1),
        &program_content().await,
    )
    .await;
    let (_, frames) = input_uploads(ready.channel(), &request, &bytes);
    let connection = Cancellation::new();
    upload(&service, frames.clone(), &connection).await.unwrap();
    let authorization = PaidJobAuthorizationV2::decode(&request.authorization).unwrap();
    let job = JobId {
        channel: ready.channel().id(),
        id: work_id(ready.channel(), &authorization),
    };
    let scope = node.open_work(job, vec![], 0).await.unwrap();
    let ScopeKind::Work { reservation, .. } = scope.kind else {
        panic!("work scope")
    };
    assert!(matches!(
        service.accept(&request).await.outcome,
        Some(accept_work_response::Outcome::Refused(_))
    ));
    assert!(
        node.pins(&Scope::Owner, "channel/", Cursor::default())
            .await
            .unwrap()
            .pins
            .is_empty()
    );
    assert!(
        service
            .with_state(
                |state| state.jobs().all(|job| job.provider_signature().is_none())
                    && state.retained_roots().is_empty()
            )
            .await
            .unwrap()
    );
    let held = node.stats().unwrap();
    let ram = node.ram_pool().held();
    let files = hellas_channel::test_support::all_files(&provider_root.join("content"));
    let staged: Vec<_> = files
        .into_iter()
        .filter(|path| path.components().any(|part| part.as_os_str() == "staging"))
        .map(|path| {
            let bytes = std::fs::read(&path).unwrap();
            (path, bytes)
        })
        .collect();
    assert!(
        !staged.is_empty(),
        "uncertain acceptance has real staged bytes"
    );
    connection.cancel();
    claims_released(&service).await;
    let ScopeKind::Work {
        reservation: current,
        ..
    } = node.open_work(job, vec![], 0).await.unwrap().kind
    else {
        panic!("work scope")
    };
    assert_eq!(current, reservation);
    assert_eq!(node.stats().unwrap().used, held.used);
    assert_eq!(node.stats().unwrap().outstanding, held.outstanding);
    assert_eq!(node.ram_pool().held(), ram);
    for (path, bytes) in &staged {
        assert_eq!(std::fs::read(path).unwrap(), *bytes);
    }
    assert!(
        upload(&service, frames.clone(), &Cancellation::new())
            .await
            .is_err()
    );
    {
        use hellas_channel::work_close::CloseChannel as _;
        let mut driver = service.drive().unwrap();
        let mut store = driver.store().await.unwrap();
        let result = store
            .commit(
                ChannelRecord::JobAccepted {
                    work_id: job.id,
                    provider_signature: Sig::from_bytes([0; 64]),
                    retained_tree: None,
                },
                &Secp256k1Verifier::new(),
            )
            .await;
        assert!(matches!(
            result,
            Err(hellas_channel::work_store::WorkStoreError::Journal(
                hellas_channel::work_store::journal::JournalError::Poisoned
            ))
        ));
    }
    assert_eq!(node.stats().unwrap().outstanding, held.outstanding);
    shutdown(service, node).await;
    let mut database = sqlx::SqliteConnection::connect_with(&options)
        .await
        .unwrap();
    sqlx::raw_sql("DROP TRIGGER reject_cosign")
        .execute(&mut database)
        .await
        .unwrap();
    database.close().await.unwrap();
    let (service, node) = self::service(&provider_root, &ready).await;
    assert_eq!(
        node.stats().unwrap().outstanding,
        0,
        "canonical reopen discards the proposal that never cosigned"
    );
    for (path, _) in &staged {
        assert!(!path.exists());
    }
    let connection = Cancellation::new();
    upload(&service, frames, &connection).await.unwrap();
    let response = service.accept(&request).await;
    caller
        .client()
        .await
        .unwrap()
        .accepted(&response)
        .await
        .unwrap();
    assert_eq!(
        node.pins(&Scope::Owner, "channel/", Cursor::default())
            .await
            .unwrap()
            .pins
            .len(),
        1
    );
    connection.cancel();
    claims_released(&service).await;
}

#[tokio::test]
async fn twelve_mib_compute_input_retries_accepts_reopens_and_reuses_verified_content() {
    use futures::StreamExt;
    let root = tempfile::tempdir().unwrap();
    let mut input = bundle(4);
    input.input.artifacts.push(Artifact::new(
        "input",
        "catena.bytes.v1",
        vec![0xa5; 12 * 1024 * 1024],
    ));
    input.request.input = input.input.content_id().unwrap();
    let mut policy = work_policy();
    policy.limits.max_upload_bytes = 13 * 1024 * 1024;
    let ready = ready_of(&descriptor_with(policy.clone()), CURSOR);
    input.application_policy =
        hellas_rpc::JsonBytes(ready.invocation_policy().canonical_bytes().unwrap());
    let provider_root = root.path().join("provider");
    let (service, node) = service(&provider_root, &ready).await;
    let source = program_content().await;
    let (mut caller, request, bytes) =
        proposal(&root.path().join("client"), &ready, input.clone(), &source).await;
    let (_, frames) = input_uploads(ready.channel(), &request, &bytes);
    let connection = Cancellation::new();
    let mut partial = service
        .upload_stream(
            Box::pin(futures::stream::iter(frames.clone().into_iter().map(Ok))),
            TransportContext {
                open_exporter: Some([7; 32]),
                ..Default::default()
            },
            connection.clone(),
        )
        .await
        .unwrap();
    let input_ref = ContentRef::for_bytes(&bytes);
    let mut input_open = false;
    let mut acknowledged = false;
    for frame in &frames {
        let reply = partial.next().await.unwrap().unwrap();
        if let Some(pb::upload_request::Part::Open(open)) = &frame.part {
            input_open = open.object.as_ref().unwrap().id == input_ref.id().as_bytes();
        }
        if input_open && matches!(frame.part, Some(pb::upload_request::Part::Chunk(_))) {
            assert!(reply.next_chunk > 0 && !reply.complete);
            acknowledged = true;
            break;
        }
    }
    assert!(
        acknowledged,
        "interrupt after a real prepared-input chunk ACK"
    );
    drop(partial);
    connection.cancel();
    claims_released(&service).await;
    shutdown(service, node).await;
    let (service, node) = self::service(&provider_root, &ready).await;
    let connection = Cancellation::new();
    upload(&service, frames, &connection).await.unwrap();
    assert!(
        node.pins(&Scope::Owner, "channel/", Cursor::default())
            .await
            .unwrap()
            .pins
            .is_empty()
    );
    let response = service.accept(&request).await;
    let work = caller
        .client()
        .await
        .unwrap()
        .accepted(&response)
        .await
        .unwrap();
    connection.cancel();
    claims_released(&service).await;
    shutdown(service, node).await;
    let node = content_store(&provider_root).await;
    let mut journal = ChannelStore::open(
        &hellas_private::StoreLocation::for_test(&provider_root),
        ready.channel().clone(),
        settlement(),
        Role::Provider,
        origin(),
        node.clone(),
        &Secp256k1Verifier::new(),
    )
    .await
    .unwrap();
    node.finish_recovery().await.unwrap();
    journal.load_retained_content(work).await.unwrap();
    assert_eq!(
        journal.state().job_by_id(work).unwrap().prepared_input(),
        bytes
    );
    journal.rotate().await.unwrap();
    drop(journal);
    node.close().await;
    drop(node);
    let (service, node) = self::service(&provider_root, &ready).await;
    let RunAdmission::Invoke(admitted) = service.begin_run(work, &ready).await.unwrap() else {
        panic!("accepted retained input dispatches after restart")
    };
    let (store, scope) = admitted.content();
    assert_eq!(
        hellas_channel::content::read(
            store,
            scope,
            ContentRef::for_bytes(&bytes),
            bytes.len() as u64
        )
        .await
        .unwrap(),
        bytes
    );
    drop(admitted);
    service.end_run(work).await.unwrap();
    // Two 12 MiB uploads and three restarts can outlive one certified age on
    // a loaded host; propose the next job from a fresh read.
    let fresh = ready_of(&descriptor_with(policy), CURSOR + 1);
    hellas_channel::test_support::channel::refresh(&caller, &service, &fresh, CURSOR + 1).await;
    let next = caller
        .propose(
            &JobProposal {
                prepared_input: input,
                deadlines: deadlines(),
            },
            &source,
            None,
        )
        .await
        .unwrap();
    let (_, frames) = input_uploads(ready.channel(), &next, &bytes);
    let connection = Cancellation::new();
    assert_eq!(
        upload(&service, frames, &connection).await.unwrap(),
        0,
        "cached root and input complete on Open, without any payload transfer"
    );
    assert!(matches!(
        service.accept(&next).await.outcome,
        Some(accept_work_response::Outcome::Accepted(_))
    ));
    connection.cancel();
    claims_released(&service).await;
    assert_eq!(
        node.pins(&Scope::Owner, "channel/", Cursor::default())
            .await
            .unwrap()
            .pins
            .len(),
        2
    );
}

#[tokio::test]
async fn unseen_program_requires_complete_verified_source_and_asset_closure() {
    use hellas_rpc::protocol::invocation::compute::{Environment, NamedAsset};
    for fault in ["missing", "corrupt", "complete", "jobs-pin"] {
        let root = tempfile::tempdir().unwrap();
        let ready = ready();
        let provider_root = root.path().join("provider");
        let (service, node) = service(&provider_root, &ready).await;
        let source = b"unseen source program bytes";
        let asset = if fault == "jobs-pin" {
            vec![0x42; ready.invocation_policy().limits.max_upload_bytes as usize + 1]
        } else {
            b"unseen signed program asset bytes".to_vec()
        };
        let environment = Environment {
            sources: vec![ContentRef::for_bytes(source)],
            assets: vec![NamedAsset {
                name: "weights.bin".into(),
                object: ContentRef::for_bytes(&asset),
            }],
        };
        let manifest = environment
            .manifest(&hellas_channel::test_support::channel::evaluator())
            .unwrap();
        let program_root = environment.canonical_bytes().unwrap();
        let source_store = program_content().await;
        for body in [program_root.as_slice(), source.as_slice(), asset.as_slice()] {
            if fault != "jobs-pin" || body == program_root.as_slice() {
                hellas_channel::content::upload_object(&source_store.0, body)
                    .await
                    .unwrap();
            }
            if fault == "jobs-pin" {
                hellas_channel::content::upload_bytes(
                    &node,
                    &Scope::Owner,
                    body,
                    Some(PinTarget {
                        name: PinName::new(format!(
                            "preloaded/{}",
                            ContentRef::for_bytes(body).id()
                        ))
                        .unwrap(),
                        policy: PinPolicy::Jobs,
                    }),
                )
                .await
                .unwrap();
            }
        }
        let base = bundle(1);
        let mut invocation = base.request;
        invocation.execution_environment = manifest.content_id();
        let input = PreparedInvocation::new(
            invocation,
            &manifest,
            base.input,
            ready.invocation_policy().canonical_bytes().unwrap(),
        )
        .unwrap();
        let (_, request, bytes) =
            proposal(&root.path().join("client"), &ready, input, &source_store).await;
        let mut frames = frames(
            &request,
            manifest.canonical_bytes(),
            program_root.clone(),
            &bytes,
        );
        append_object(&mut frames, &request, source);
        if fault != "missing" {
            append_object(&mut frames, &request, &asset);
            if fault == "corrupt" {
                let Some(pb::upload_request::Part::Chunk(chunk)) =
                    &mut frames.last_mut().unwrap().part
                else {
                    unreachable!()
                };
                chunk[0] ^= 1;
            }
        }
        let connection = Cancellation::new();
        let uploaded = upload(&service, frames, &connection).await;
        assert_eq!(
            uploaded.is_err(),
            matches!(fault, "missing" | "corrupt"),
            "{fault}: {uploaded:?}"
        );
        let response = service.accept(&request).await;
        if matches!(fault, "missing" | "corrupt") {
            assert!(
                matches!(
                    response.outcome,
                    Some(accept_work_response::Outcome::Refused(_))
                ),
                "{fault}: {response:?}"
            );
            assert!(
                node.pins(&Scope::Owner, "channel/", Cursor::default())
                    .await
                    .unwrap()
                    .pins
                    .is_empty()
            );
        } else {
            assert!(
                matches!(
                    response.outcome,
                    Some(accept_work_response::Outcome::Accepted(_))
                ),
                "{fault}: {response:?}"
            );
        }
        connection.cancel();
        claims_released(&service).await;
        shutdown(service, node).await;
        let (service, _node) = self::service(&provider_root, &ready).await;
        if matches!(fault, "complete" | "jobs-pin") {
            let authorization = PaidJobAuthorizationV2::decode(&request.authorization).unwrap();
            let work = work_id(ready.channel(), &authorization);
            let RunAdmission::Invoke(input) = service.begin_run(work, &ready).await.unwrap() else {
                panic!("accepted closure dispatches after restart")
            };
            let (store, scope) = input.content();
            for body in [
                program_root.as_slice(),
                source.as_slice(),
                asset.as_slice(),
                bytes.as_slice(),
            ] {
                assert_eq!(
                    hellas_channel::content::read(
                        store,
                        scope,
                        ContentRef::for_bytes(body),
                        body.len() as u64
                    )
                    .await
                    .unwrap(),
                    body
                );
            }
            drop(input);
            service.end_run(work).await.unwrap();
        } else {
            assert!(
                service
                    .with_state(|state| state.retained_roots().is_empty())
                    .await
                    .unwrap()
            );
        }
    }
}

#[tokio::test]
async fn durable_expiry_before_cleanup_releases_unaccepted_payloads_on_reopen() {
    use hellas_channel::work_store::{TerminalOutcome, journal::Journal};
    let root = tempfile::tempdir().unwrap();
    let ready = ready();
    let authorization = authorization();
    let work = work_id(ready.channel(), &authorization);
    let body = bundle(NONCE).canonical_bytes().unwrap();
    let mut store = store_at(root.path(), &ready, Role::Provider, CURSOR).await;
    let node = store.content_store();
    seed_content(&mut store, authorization, body.clone().into()).await;
    store
        .commit(
            ChannelRecord::JobProposed {
                authorization,
                client_signature: client().sign(signing_hash(work)),
                prepared_input: body.into(),
                retained_tree: None,
            },
            &Secp256k1Verifier::new(),
        )
        .await
        .unwrap();
    assert!(node.stats().unwrap().used > 0);
    drop(store);
    node.close().await;
    drop(node);
    let stem = Journal::stems(&hellas_private::StoreLocation::for_test(root.path()))
        .unwrap()
        .pop()
        .unwrap();
    let (header, _) =
        Journal::inspect(&hellas_private::StoreLocation::for_test(root.path()), &stem)
            .await
            .unwrap();
    let (mut journal, _) = Journal::open_existing(
        &hellas_private::StoreLocation::for_test(root.path()),
        &stem,
        header,
    )
    .await
    .unwrap();
    let expired = authorization.acceptance_deadline + 1;
    journal
        .append(
            &ChannelRecord::JobTerminated {
                work_id: work,
                outcome: TerminalOutcome::Expired {
                    deadline: authorization.acceptance_deadline,
                    height: expired,
                    payload: payload_at(expired),
                },
            }
            .encode(),
        )
        .await
        .unwrap();
    journal
        .append(
            &ChannelRecord::Anchored {
                height: expired,
                payload: payload_at(expired),
                certified_at_ms: hellas_channel::test_support::channel::now_ms(),
                pending: None,
            }
            .encode(),
        )
        .await
        .unwrap();
    journal.close().await;
    drop(journal);
    // The durable expiry exists without ChannelStore having performed cleanup.
    // Repeat boot and collection to prove the recovered result is stable.
    for _ in 0..2 {
        let node = content_store(root.path()).await;
        let store = ChannelStore::open(
            &hellas_private::StoreLocation::for_test(root.path()),
            ready.channel().clone(),
            settlement(),
            Role::Provider,
            origin(),
            node.clone(),
            &Secp256k1Verifier::new(),
        )
        .await
        .unwrap();
        node.finish_recovery().await.unwrap();
        assert!(store.state().jobs().next().is_none());
        assert!(store.state().terminal_by_id(work).is_some());
        assert!(store.state().retained_roots().is_empty());
        node.collect(&Scope::Owner).await.unwrap();
        assert_eq!(
            (
                node.stats().unwrap().used,
                node.stats().unwrap().outstanding
            ),
            (0, 0)
        );
        assert!(
            node.pins(&Scope::Owner, "channel/", Cursor::default())
                .await
                .unwrap()
                .pins
                .is_empty()
        );
        drop(store);
        node.close().await;
    }
}

#[tokio::test]
async fn a_valid_second_proposal_cannot_replace_the_first_completed_unaccepted_share() {
    let root = tempfile::tempdir().unwrap();
    let ready = ready();
    let (service, node) = service(&root.path().join("provider"), &ready).await;
    let source = program_content().await;
    let (mut caller, first, bytes) =
        proposal(&root.path().join("client-a"), &ready, bundle(1), &source).await;
    let (_, frames) = input_uploads(ready.channel(), &first, &bytes);
    let connection = Cancellation::new();
    upload(&service, frames, &connection).await.unwrap();
    let before = node.stats().unwrap();
    let (_, second, second_body) =
        proposal(&root.path().join("client-b"), &ready, bundle(2), &source).await;
    let mut second = second;
    let mut authorization = PaidJobAuthorizationV2::decode(&second.authorization).unwrap();
    authorization.proposal_nonce += 1;
    second.authorization = authorization.encode();
    second.client_signature = client()
        .sign(signing_hash(work_id(ready.channel(), &authorization)))
        .as_bytes()
        .to_vec();
    let (_, frames) = input_uploads(ready.channel(), &second, &second_body);
    // input_uploads signs this second opening independently, including its new
    // authorization and the same actual transport exporter.
    assert!(
        upload(&service, frames, &Cancellation::new())
            .await
            .is_err()
    );
    let after = node.stats().unwrap();
    assert_eq!(
        (after.used, after.outstanding),
        (before.used, before.outstanding)
    );
    let work = caller
        .client()
        .await
        .unwrap()
        .accepted(&service.accept(&first).await)
        .await
        .unwrap();
    assert!(
        service
            .with_state(
                |state| state.job_by_id(work).unwrap().authorization().input_content
                    == ContentRef::for_bytes(&bytes)
                    && state.jobs().len() == 1
            )
            .await
            .unwrap()
    );
    connection.cancel();
    claims_released(&service).await;
    let RunAdmission::Invoke(input) = service.begin_run(work, &ready).await.unwrap() else {
        panic!("first upload is unchanged and executable")
    };
    let (store, scope) = input.content();
    assert_eq!(
        hellas_channel::content::read(
            store,
            scope,
            ContentRef::for_bytes(&bytes),
            bytes.len() as u64
        )
        .await
        .unwrap(),
        bytes
    );
    drop(input);
    service.end_run(work).await.unwrap();
}

#[tokio::test]
async fn paid_upload_termination_cancels_a_blocked_ack_and_releases_its_ram() {
    use futures::StreamExt as _;
    use hellas_channel::test_support::transport::{CarrierGate, transport_pair_with_server_gate};
    use hellas_rpc::services::content::{ContentClientImpl, Upload};
    use hellas_wire::{StreamTransport as _, mux::MuxTransport};
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    for end in ["close", "cancel", "deadline"] {
        tokio::time::timeout(hellas_channel::test_support::HANG_GUARD, async {
            let root = tempfile::tempdir().unwrap();
            let ready = ready_of(&descriptor_with(fetch_policy()), CURSOR);
            let (service, node) = service(&root.path().join("provider"), &ready).await;
            let (_, request, bytes) = proposal(
                &root.path().join("client"),
                &ready,
                fetch_bundle(1),
                &program_content().await,
            )
            .await;
            let (_, frames) = input_uploads(ready.channel(), &request, &bytes);
            let gate = Arc::new(CarrierGate {
                remaining: AtomicUsize::new(0),
                sent: AtomicUsize::new(0),
                blocked: tokio::sync::Notify::new(),
                ready: Default::default(),
            });
            let (transport, server) = transport_pair_with_server_gate(
                TransportContext {
                    open_exporter: Some([7; 32]),
                    ..Default::default()
                },
                gate.clone(),
            );
            let connection = Cancellation::new();
            let serving = tokio::spawn({
                let service = service.clone();
                let connection = connection.clone();
                async move {
                    let inbound = server.accept().await.unwrap().unwrap();
                    let context = inbound.context.clone();
                    hellas_rpc::call::dispatch_bidi_streaming::<MuxTransport, Upload, _, _, _>(
                        inbound,
                        |requests| async move {
                            service
                                .upload_stream(Box::pin(requests), context, connection)
                                .await
                        },
                    )
                    .await
                }
            });
            let mut call = ContentClientImpl::new(transport).upload().await.unwrap();
            call.send(frames.into_iter().next().unwrap()).await.unwrap();
            gate.blocked.notified().await;
            assert!(
                node.ram_pool().held() > 0,
                "the suspended session owns its input allowance"
            );
            assert_eq!(gate.sent.load(Ordering::SeqCst), 0);
            match end {
                "cancel" => connection.cancel(),
                "close" => {
                    service.prepare_close().await.unwrap();
                }
                "deadline" => {
                    hellas_channel::test_support::channel::observe_service(
                        &service,
                        deadlines().acceptance + 1,
                        hellas_kernel::PendingSlot::Absent,
                    )
                    .await;
                }
                _ => unreachable!(),
            }
            // No carrier credit or readiness notification is supplied here.
            assert!(serving.await.unwrap().is_err());
            while let Some(reply) = call.next().await {
                assert!(reply.is_err());
            }
            assert!(call.finish().is_err());
            claims_released(&service).await;
            assert_eq!(node.ram_pool().held(), 0);
            assert_eq!(node.stats().unwrap().outstanding, 0);
            assert_eq!(gate.sent.load(Ordering::SeqCst), 0);
        })
        .await
        .unwrap();
    }
}
