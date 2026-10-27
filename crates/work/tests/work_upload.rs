use hellas_auth::Digest;
use hellas_kernel::{PendingSlot, Secp256k1Verifier};
use hellas_rpc::{
    ContentId, ContentRef,
    pb::work::{AcceptWorkRequest, UploadContentRequest, accept_work_response},
    protocol::{
        artifacts::{
            InputAddressed as _, OutputAddressed as _, SourceRef, TextExecution, TokenIds,
        },
        content_upload::{CONTENT_CHUNK_BYTES, chunk_digest},
    },
};
use hellas_wire::TransportContext;
use hellas_work::{
    content::{ContentError, UploadQuota, UploadStore},
    model::{
        prepared_input::PreparedPaidInputV1,
        setup::{ObservedChannel, ReadyChannel},
        work::{
            EvaluatePolicyV2, PaidJobAuthorizationV2, PrivateRecord as _, signing_hash, work_id,
        },
    },
    test_support::paid::*,
    work::{ClientEndpoint, JobProposal, ProviderEndpoint, WorkService},
    work_store::{ChannelStore, Role},
};

fn ready(policy: EvaluatePolicyV2) -> ReadyChannel {
    descriptor_with(policy)
        .check_ready(&ObservedChannel {
            height: CURSOR,
            bond: Some(&bond_object()),
            payment: Some(&payment_object()),
            lease: lease_over(bond_edge(), payment_edge()),
            pending: PendingSlot::Absent,
        })
        .unwrap()
}
async fn service(root: &std::path::Path, ready: &ReadyChannel) -> WorkService {
    WorkService::new(
        ProviderEndpoint::new(
            ready.clone(),
            store_at(root, ready, Role::Provider, CURSOR).await,
            provider(),
        )
        .unwrap(),
    )
}
async fn proposal(
    root: &std::path::Path,
    ready: &ReadyChannel,
    input: PreparedPaidInputV1,
) -> (ClientEndpoint, AcceptWorkRequest, Vec<u8>) {
    let mut client = ClientEndpoint::new(
        ready.clone(),
        store_at(root, ready, Role::Client, CURSOR).await,
        client(),
    )
    .unwrap();
    let bytes = input.encode().unwrap();
    let request = client
        .propose(&JobProposal {
            prepared_input: input.into(),
            deadlines: deadlines(),
        })
        .await
        .unwrap();
    (client, request, bytes)
}
fn chunk(
    request: &AcceptWorkRequest,
    object: ContentRef,
    offset: u64,
    bytes: &[u8],
    exporter: [u8; 32],
) -> UploadContentRequest {
    let a = PaidJobAuthorizationV2::decode(&request.authorization).unwrap();
    let id = work_id(ready(work_policy()).channel(), &a);
    let signature = client().sign(signing_hash(chunk_digest(
        a.channel_id,
        id,
        object,
        offset,
        bytes,
        &exporter,
    )));
    UploadContentRequest {
        route: request.route.clone(),
        authorization: request.authorization.clone(),
        client_signature: request.client_signature.clone(),
        content_id: object.id().as_bytes().to_vec(),
        total_bytes: object.bytes(),
        offset,
        chunk: bytes.to_vec(),
        chunk_signature: signature.as_bytes().to_vec(),
    }
}
fn context(exporter: [u8; 32]) -> TransportContext {
    TransportContext {
        open_exporter: Some(exporter),
        ..Default::default()
    }
}
fn object(bytes: &[u8]) -> ContentRef {
    ContentRef::new(ContentId::hash(bytes), bytes.len() as u64)
}

#[tokio::test]
async fn a_foreign_first_object_and_a_chunk_replayed_under_another_valid_job_stage_nothing() {
    let root = tempfile::tempdir().unwrap();
    let r = ready(work_policy());
    let provider = service(&root.path().join("provider"), &r).await;
    let (_, request, bytes) = proposal(&root.path().join("client"), &r, bundle(1)).await;
    let quota = UploadQuota::new(bytes.len() as u64);
    provider.set_upload_quota(quota.clone()).await.unwrap();
    let foreign = chunk(&request, object(b"foreign"), 0, b"f", [3; 32]);
    assert!(
        provider
            .upload(&foreign, &context([3; 32]))
            .await
            .unwrap()
            .refused
            .is_some()
    );
    assert!(
        std::fs::read_dir(root.path().join("provider"))
            .unwrap()
            .all(|entry| !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .ends_with(".staging"))
    );
    let mut other = request.clone();
    let mut a = PaidJobAuthorizationV2::decode(&request.authorization).unwrap();
    a.proposal_nonce += 1;
    let id = work_id(r.channel(), &a);
    other.authorization = a.encode();
    other.client_signature = client().sign(signing_hash(id)).as_bytes().to_vec();
    let signed_a = chunk(&request, object(&bytes), 0, &bytes[..10], [3; 32]);
    let mut replayed = chunk(&other, object(&bytes), 0, &bytes[..10], [3; 32]);
    replayed.chunk_signature = signed_a.chunk_signature;
    assert!(
        provider
            .upload(&replayed, &context([3; 32]))
            .await
            .unwrap()
            .refused
            .is_some()
    );
    // A different channel can reserve the entire quota: neither rejected
    // first object consumed staging bytes or a proposal slot.
    let mut probe = UploadStore::memory(Digest::hash(b"other channel"), quota);
    probe
        .stage(
            Digest::hash(b"work"),
            object(&bytes),
            50,
            bytes.len() as u64,
            0,
            &[],
        )
        .unwrap();
}

#[tokio::test]
async fn close_clears_staging_and_cannot_be_followed_by_another_upload() {
    let root = tempfile::tempdir().unwrap();
    let r = ready(work_policy());
    let provider = service(&root.path().join("provider"), &r).await;
    let (_, request, bytes) = proposal(&root.path().join("client"), &r, bundle(1)).await;
    let upload = chunk(&request, object(&bytes), 0, &bytes[..10], [3; 32]);
    assert!(
        provider
            .upload(&upload, &context([3; 32]))
            .await
            .unwrap()
            .refused
            .is_none()
    );
    let directory = std::fs::read_dir(root.path().join("provider"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| path.to_string_lossy().ends_with(".staging"))
        .unwrap();
    provider.prepare_close().await.unwrap();
    assert_eq!(std::fs::read_dir(&directory).unwrap().count(), 0);
    assert!(
        provider
            .upload(&upload, &context([3; 32]))
            .await
            .unwrap()
            .refused
            .is_some()
    );
    assert_eq!(std::fs::read_dir(directory).unwrap().count(), 0);
}

#[tokio::test]
async fn unaccepted_compute_payloads_and_atomic_write_debris_are_collected_after_crash() {
    use hellas_kernel::Sig;
    use hellas_work::work_store::ChannelRecord;
    let root = tempfile::tempdir().unwrap();
    let r = ready(work_policy());
    let provider_root = root.path().join("provider");
    let provider = service(&provider_root, &r).await;
    let (_, request, bytes) = proposal(&root.path().join("client"), &r, bundle(1)).await;
    let upload = chunk(&request, object(&bytes), 0, &bytes, [3; 32]);
    assert!(
        provider
            .upload(&upload, &context([3; 32]))
            .await
            .unwrap()
            .refused
            .is_none()
    );
    drop(provider);
    let staging = std::fs::read_dir(&provider_root)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| path.to_string_lossy().ends_with(".staging"))
        .unwrap();
    let stem = staging
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .trim_end_matches(".staging");
    let payloads = provider_root.join(format!("{stem}.payloads"));
    std::fs::create_dir_all(&payloads).unwrap();
    // A body written before its proposal journal append is unreferenced.
    std::fs::write(payloads.join(object(&bytes).id().to_string()), &bytes).unwrap();
    std::fs::write(payloads.join(".orphan.pending"), &bytes).unwrap();
    std::fs::write(staging.join(".proposal.crash.pending"), &bytes).unwrap();
    let mut store = ChannelStore::open(
        &provider_root,
        r.channel().clone(),
        settlement(),
        Role::Provider,
        origin(),
        &Secp256k1Verifier::new(),
    )
    .await
    .unwrap();
    assert_eq!(std::fs::read_dir(&payloads).unwrap().count(), 0);
    assert!(!staging.join(".proposal.crash.pending").exists());
    let a = PaidJobAuthorizationV2::decode(&request.authorization).unwrap();
    store
        .commit(
            ChannelRecord::JobProposed {
                authorization: a,
                client_signature: Sig::from_bytes(
                    request.client_signature.clone().try_into().unwrap(),
                ),
                prepared_input: bytes.clone(),
            },
            &Secp256k1Verifier::new(),
        )
        .await
        .unwrap();
    assert_eq!(std::fs::read_dir(&payloads).unwrap().count(), 1);
    drop(store); // Crash after JobProposed, before JobAccepted.
    let mut store = ChannelStore::open(
        &provider_root,
        r.channel().clone(),
        settlement(),
        Role::Provider,
        origin(),
        &Secp256k1Verifier::new(),
    )
    .await
    .unwrap();
    advance(&mut store, a.acceptance_deadline + 1).await;
    assert_eq!(std::fs::read_dir(&payloads).unwrap().count(), 0);
    assert_eq!(std::fs::read_dir(&staging).unwrap().count(), 0);
    drop(store);
    // No proposal was installed before the first atomic staging rename.
    std::fs::write(staging.join(".proposal.first.pending"), &bytes).unwrap();
    let _store = ChannelStore::open(
        &provider_root,
        r.channel().clone(),
        settlement(),
        Role::Provider,
        origin(),
        &Secp256k1Verifier::new(),
    )
    .await
    .unwrap();
    assert_eq!(std::fs::read_dir(staging).unwrap().count(), 0);
}

#[tokio::test]
async fn failed_cosign_journal_append_cannot_publish_content_and_retry_recovers() {
    use hellas_kernel::Sig;
    use hellas_work::work_store::ChannelRecord;
    use sqlx::Connection as _;
    let root = tempfile::tempdir().unwrap();
    let r = ready(work_policy());
    let provider_root = root.path().join("provider");
    drop(store_at(&provider_root, &r, Role::Provider, CURSOR).await);
    let path = std::fs::read_dir(provider_root.join("journals"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.extension().is_some_and(|ext| ext == "sqlite"))
        .unwrap();
    let options = sqlx::sqlite::SqliteConnectOptions::new().filename(&path);
    let mut database = sqlx::SqliteConnection::connect_with(&options)
        .await
        .unwrap();
    let tag = ChannelRecord::JobAccepted {
        work_id: Digest::hash(b"tag"),
        provider_signature: Sig::from_bytes([0; 64]),
    }
    .encode()[0];
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!("CREATE TRIGGER reject_cosign BEFORE INSERT ON record WHEN hex(substr(NEW.payload,1,1)) = '{tag:02X}' BEGIN SELECT RAISE(ABORT, 'injected cosign storage failure'); END")))
        .execute(&mut database).await.unwrap();
    database.close().await.unwrap();
    let provider = service(&provider_root, &r).await;
    let (_, request, bytes) = proposal(&root.path().join("client"), &r, bundle(1)).await;
    let reference = object(&bytes);
    let content = provider.uploaded_content().await.unwrap();
    assert!(
        provider
            .upload(
                &chunk(&request, reference, 0, &bytes, [3; 32]),
                &context([3; 32])
            )
            .await
            .unwrap()
            .refused
            .is_none()
    );
    assert!(matches!(
        provider.accept(&request).await.outcome,
        Some(accept_work_response::Outcome::Refused(_))
    ));
    assert!(
        !content.have(reference.id().digest()),
        "a failed durable co-signature must leave content unpublished"
    );
    assert!(!provider_root.join("content").exists());
    drop(provider);
    let mut database = sqlx::SqliteConnection::connect_with(&options)
        .await
        .unwrap();
    sqlx::raw_sql("DROP TRIGGER reject_cosign")
        .execute(&mut database)
        .await
        .unwrap();
    database.close().await.unwrap();
    let provider = service(&provider_root, &r).await;
    assert!(matches!(
        provider.accept(&request).await.outcome,
        Some(accept_work_response::Outcome::Accepted(_))
    ));
    assert!(
        provider
            .uploaded_content()
            .await
            .unwrap()
            .have(reference.id().digest())
    );
}

#[tokio::test]
async fn signed_chunks_bind_connection_job_offset_and_closure_and_publish_only_after_cosign() {
    let root = tempfile::tempdir().unwrap();
    let r = ready(work_policy());
    let service = service(&root.path().join("provider"), &r).await;
    let (_client, request, bytes) = proposal(&root.path().join("client"), &r, bundle(1)).await;
    let reference = object(&bytes);
    let store = service.uploaded_content().await.unwrap();
    let mut upload = chunk(&request, reference, 0, &bytes[..10], [3; 32]);
    assert!(
        service
            .upload(&upload, &context([4; 32]))
            .await
            .unwrap()
            .refused
            .is_some()
    );
    upload.offset = 1;
    assert!(
        service
            .upload(&upload, &context([3; 32]))
            .await
            .unwrap()
            .refused
            .is_some()
    );
    upload = chunk(&request, reference, 0, &bytes[..10], [3; 32]);
    assert_eq!(
        service
            .upload(&upload, &context([3; 32]))
            .await
            .unwrap()
            .next_offset,
        10
    );
    let foreign = object(b"another object");
    assert!(
        service
            .upload(
                &chunk(&request, foreign, 0, b"", [3; 32]),
                &context([3; 32])
            )
            .await
            .unwrap()
            .refused
            .is_some()
    );
    let rest = chunk(&request, reference, 10, &bytes[10..], [3; 32]);
    assert_eq!(
        service
            .upload(&rest, &context([3; 32]))
            .await
            .unwrap()
            .next_offset,
        bytes.len() as u64
    );
    assert!(!store.have(reference.id().digest()));
    assert!(!root.path().join("provider/content").exists());
    let mut inline = request.clone();
    inline.prepared_input = bytes.clone();
    assert!(matches!(
        service.accept(&inline).await.outcome,
        Some(accept_work_response::Outcome::Refused(_))
    ));
    assert!(
        !store.have(reference.id().digest()),
        "inline acceptance cannot publish content"
    );
    assert!(matches!(
        service.accept(&request).await.outcome,
        Some(accept_work_response::Outcome::Accepted(_))
    ));
    assert!(store.have(reference.id().digest()));
    let probe = chunk(&request, reference, 0, b"", [7; 32]);
    assert_eq!(
        service
            .upload(&probe, &context([7; 32]))
            .await
            .unwrap()
            .next_offset,
        reference.bytes()
    );
}

#[tokio::test]
async fn wrong_hash_limits_and_second_proposal_never_publish_or_overwrite_staging() {
    let root = tempfile::tempdir().unwrap();
    let mut policy = work_policy();
    policy.max_upload_bytes = 10;
    let r = ready(policy);
    let service = service(&root.path().join("provider"), &r).await;
    let (_, request, bytes) = proposal(&root.path().join("client"), &r, bundle(1)).await;
    assert!(
        service
            .upload(
                &chunk(&request, object(&bytes), 0, b"", [3; 32]),
                &context([3; 32])
            )
            .await
            .unwrap()
            .refused
            .is_some()
    );
    assert!(!root.path().join("provider/content").exists());
    assert!(
        std::fs::read_dir(root.path().join("provider"))
            .unwrap()
            .all(|entry| !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .ends_with(".staging"))
    );

    let r = ready(work_policy());
    let service = self::service(&root.path().join("provider2"), &r).await;
    let (_, first, bytes) = proposal(&root.path().join("client2"), &r, bundle(1)).await;
    let (_, second, second_bytes) = proposal(&root.path().join("client3"), &r, bundle(2)).await;
    service
        .upload(
            &chunk(&first, object(&bytes), 0, &bytes[..10], [3; 32]),
            &context([3; 32]),
        )
        .await
        .unwrap();
    assert!(
        service
            .upload(
                &chunk(&second, object(&second_bytes), 0, b"", [3; 32]),
                &context([3; 32])
            )
            .await
            .unwrap()
            .refused
            .is_some()
    );
    let mut bad = bytes[10..].to_vec();
    bad[0] ^= 1;
    assert!(
        service
            .upload(
                &chunk(&first, object(&bytes), 10, &bad, [3; 32]),
                &context([3; 32])
            )
            .await
            .unwrap()
            .refused
            .is_some()
    );
    assert!(
        !service
            .uploaded_content()
            .await
            .unwrap()
            .have(object(&bytes).id().digest())
    );
}

#[test]
fn shared_quota_resume_gc_and_ephemeral_storage_enforce_real_byte_and_disk_bounds() {
    let root = tempfile::tempdir().unwrap();
    let quota = UploadQuota::new(16);
    let mut first = UploadStore::durable(root.path(), "first", Digest::hash(b"first")).unwrap();
    first.set_quota(quota.clone()).unwrap();
    let mut second = UploadStore::memory(Digest::hash(b"second"), quota.clone());
    let bytes = b"0123456789";
    let work = Digest::hash(b"proposal");
    first
        .stage(work, object(bytes), 50, 10, 0, &bytes[..4])
        .unwrap();
    assert!(matches!(
        second.stage(work, object(bytes), 50, 10, 0, b""),
        Err(ContentError::StagingLimit(16))
    ));
    let directory = first.directory().unwrap().to_owned();
    drop(first);
    let mut resumed = UploadStore::durable(root.path(), "first", Digest::hash(b"first")).unwrap();
    resumed.set_quota(quota).unwrap();
    assert_eq!(
        resumed.stage(work, object(bytes), 50, 10, 0, b"").unwrap(),
        4
    );
    assert_eq!(
        resumed
            .stage(work, object(bytes), 50, 10, 4, &bytes[4..])
            .unwrap(),
        10
    );
    resumed.gc(51, false).unwrap();
    assert_eq!(std::fs::read_dir(directory).unwrap().count(), 0);
    second.stage(work, object(bytes), 50, 10, 0, bytes).unwrap();
    assert!(second.directory().is_none());
    second.gc(51, false).unwrap();
    assert!(!second.is_staged());
}

#[tokio::test]
async fn twelve_mib_compute_input_resumes_accepts_reopens_and_reuses_content() {
    let root = tempfile::tempdir().unwrap();
    let tokens = TokenIds::from(vec![u32::MAX; (12 * 1024 * 1024) / 5]);
    let execution = TextExecution::new(
        SourceRef::output(identity_artifact().output_id()),
        tokens.output_id(),
        text_policy().output_id(),
    );
    let mut request = evaluate_request(4);
    request.text_execution = execution.input_id().digest();
    let input = PreparedPaidInputV1::new(
        &request,
        &manifest(),
        &execution,
        &tokens,
        &text_policy(),
        &identity_artifact(),
    );
    let mut policy = work_policy();
    policy.max_prompt_tokens = tokens.as_slice().len() as u32;
    policy.max_encoded_prepared_input = 13 * 1024 * 1024;
    policy.max_upload_bytes = u64::from(policy.max_encoded_prepared_input);
    let r = ready(policy);
    let provider_root = root.path().join("provider");
    let mut service = service(&provider_root, &r).await;
    let (mut caller, acceptance, bytes) =
        proposal(&root.path().join("client"), &r, input.clone()).await;
    let reference = object(&bytes);
    for (index, bytes) in bytes.chunks(CONTENT_CHUNK_BYTES).enumerate() {
        let offset = (index * CONTENT_CHUNK_BYTES) as u64;
        if index == 2 {
            drop(service);
            service = self::service(&provider_root, &r).await;
            assert_eq!(
                service
                    .upload(
                        &chunk(&acceptance, reference, 0, b"", [8; 32]),
                        &context([8; 32])
                    )
                    .await
                    .unwrap()
                    .next_offset,
                offset
            );
        }
        service
            .upload(
                &chunk(&acceptance, reference, offset, bytes, [8; 32]),
                &context([8; 32]),
            )
            .await
            .unwrap();
    }
    let content = service.uploaded_content().await.unwrap();
    assert!(!content.have(reference.id().digest()));
    let accepted = service.accept(&acceptance).await;
    assert!(matches!(
        accepted.outcome,
        Some(accept_work_response::Outcome::Accepted(_))
    ));
    caller.accepted(&accepted).await.unwrap();
    assert!(content.have(reference.id().digest()));
    drop(service);
    let mut store = ChannelStore::open(
        &provider_root,
        r.channel().clone(),
        settlement(),
        Role::Provider,
        origin(),
        &Secp256k1Verifier::new(),
    )
    .await
    .unwrap();
    assert_eq!(store.state().jobs().next().unwrap().prepared_input(), bytes);
    store.rotate().await.unwrap();
    drop(store);
    let service = self::service(&provider_root, &r).await;
    assert_eq!(
        service
            .with_state(|state| state.jobs().next().unwrap().prepared_input().to_vec())
            .await
            .unwrap(),
        bytes
    );
    assert_eq!(
        service
            .upload(
                &chunk(&acceptance, reference, 0, b"", [9; 32]),
                &context([9; 32])
            )
            .await
            .unwrap()
            .next_offset,
        reference.bytes()
    );
    let next = caller
        .propose(&JobProposal {
            prepared_input: input.into(),
            deadlines: deadlines(),
        })
        .await
        .unwrap();
    assert_ne!(next.authorization, acceptance.authorization);
    let cached = service
        .upload(
            &chunk(&next, reference, 0, b"", [10; 32]),
            &context([10; 32]),
        )
        .await
        .unwrap();
    assert!(cached.refused.is_none());
    assert_eq!(cached.next_offset, reference.bytes());
    let staging = std::fs::read_dir(&provider_root)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| path.to_string_lossy().ends_with(".staging"))
        .unwrap();
    assert_eq!(
        std::fs::metadata(staging.join("proposal")).unwrap().len(),
        80,
        "only proposal metadata is staged for the fresh job; zero body bytes were uploaded"
    );
    let mut third = next.clone();
    let mut auth = PaidJobAuthorizationV2::decode(&third.authorization).unwrap();
    auth.proposal_nonce += 1;
    third.authorization = auth.encode();
    third.client_signature = client()
        .sign(signing_hash(work_id(r.channel(), &auth)))
        .as_bytes()
        .to_vec();
    assert!(
        service
            .upload(
                &chunk(&third, reference, 0, b"", [10; 32]),
                &context([10; 32])
            )
            .await
            .unwrap()
            .refused
            .is_some()
    );
    let response = service.accept(&next).await;
    assert!(matches!(
        response.outcome,
        Some(accept_work_response::Outcome::Accepted(_))
    ));
    assert_eq!(std::fs::read_dir(staging).unwrap().count(), 0);
}
