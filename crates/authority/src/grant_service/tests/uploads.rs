use super::*;
use hellas_channel::content::UploadQuota;
use hellas_rpc::{
    ContentRef, pb::work::UploadContentRequest, protocol::content_upload::chunk_digest,
};

async fn fixture(
    root: &std::path::Path,
    quota: UploadQuota,
) -> (GrantService, GrantWork, AcceptWorkRequest, Vec<u8>) {
    fixture_clock(root, quota, Arc::new(|| UnixMillis(1000))).await
}
async fn fixture_clock(
    root: &std::path::Path,
    quota: UploadQuota,
    clock: GrantClock,
) -> (GrantService, GrantWork, AcceptWorkRequest, Vec<u8>) {
    let (store, secret) = common::setup_with_credential(root).await;
    let (a, signature, input) = common::proposal(&store, 1);
    let bytes = input.canonical_bytes().unwrap();
    let request = AcceptWorkRequest {
        route: Some(WorkRoute::grant(a.channel_id.0)),
        authorization: a.encode(),
        client_signature: signature.bytes().to_vec(),
        prepared_input: bytes.clone(),
    };
    let service = GrantService::new(
        store,
        Arc::new(common::principal(2).1),
        Backend::default(),
        vec![],
        clock,
    )
    .unwrap()
    .with_upload_quota(quota);
    let (work, _) =
        common::common_node::execution(&service, &secret, &common::principal(1).1, a.grant_id)
            .await;
    (service, work, request, bytes)
}
fn context() -> TransportContext {
    TransportContext {
        open_exporter: Some([7; 32]),
        ..Default::default()
    }
}
fn signed(
    request: &AcceptWorkRequest,
    reference: ContentRef,
    offset: u64,
    bytes: &[u8],
) -> UploadContentRequest {
    let a = GrantJobAuthorizationV1::decode(&request.authorization).unwrap();
    let id = grant_work_id(common::network(), &a);
    let sig = common::principal(1)
        .1
        .sign_digest(chunk_digest(
            a.channel_id.0,
            id,
            reference,
            offset,
            bytes,
            &[7; 32],
        ))
        .unwrap();
    UploadContentRequest {
        program_root: hellas_rpc::protocol::invocation::PreparedInvocation::from_canonical_bytes(
            &request.prepared_input,
            hellas_channel::content::MAX_CONTENT_BYTES,
        )
        .ok()
        .map(|input| hellas_channel::test_support::channel::program_root(&input))
        .unwrap_or_default(),
        program_manifest:
            hellas_rpc::protocol::invocation::PreparedInvocation::from_canonical_bytes(
                &request.prepared_input,
                hellas_channel::content::MAX_CONTENT_BYTES,
            )
            .unwrap()
            .manifest()
            .unwrap()
            .canonical_bytes(),
        route: request.route.clone(),
        authorization: request.authorization.clone(),
        client_signature: request.client_signature.clone(),
        content_id: reference.id().as_bytes().to_vec(),
        total_bytes: reference.bytes(),
        offset,
        chunk: bytes.to_vec(),
        chunk_signature: sig.bytes().to_vec(),
    }
}
fn assert_no_payload_files(root: &std::path::Path, bytes: &[u8]) {
    for entry in std::fs::read_dir(root).unwrap() {
        let path = entry.unwrap().path();
        assert!(!path.to_string_lossy().ends_with(".staging"));
        assert!(!path.to_string_lossy().ends_with(".payloads"));
        if path.is_dir() {
            assert_no_payload_files(&path, bytes);
        } else {
            assert!(
                !std::fs::read(path)
                    .unwrap()
                    .windows(bytes.len())
                    .any(|window| window == bytes)
            );
        }
    }
}

#[tokio::test]
async fn an_idle_partial_grant_upload_expires_without_another_request_or_mutation() {
    use std::sync::atomic::{AtomicU64, Ordering};
    let root = tempfile::tempdir().unwrap();
    let now = Arc::new(AtomicU64::new(1000));
    let clock = now.clone();
    let quota = UploadQuota::new(1 << 20);
    let (service, work, mut request, bytes) = fixture_clock(
        root.path(),
        quota.clone(),
        Arc::new(move || UnixMillis(clock.load(Ordering::Acquire))),
    )
    .await;
    let mut a = GrantJobAuthorizationV1::decode(&request.authorization).unwrap();
    a.acceptance_deadline_ms = UnixMillis(1001);
    request.authorization = a.encode();
    request.client_signature = common::principal(1)
        .1
        .sign_digest(grant_work_id(common::network(), &a))
        .unwrap()
        .bytes()
        .to_vec();
    assert!(
        work.upload(
            &signed(&request, a.input_content, 0, &bytes[..10]),
            &context()
        )
        .await
        .unwrap()
        .refused
        .is_none()
    );
    now.store(1002, Ordering::Release);
    within(async {
        loop {
            if !service
                .inner
                .lock()
                .unwrap()
                .uploads
                .get(&a.channel_id.0)
                .unwrap()
                .is_staged()
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await;
    assert_no_payload_files(root.path(), &bytes);
    let mut probe = hellas_channel::content::UploadStore::memory(
        Digest::hash(b"quota after expiry"),
        quota,
        hellas_store::ContentStore::new(),
    );
    let all = vec![0; 1 << 20];
    probe
        .stage(
            Digest::hash(b"work"),
            ContentRef::for_bytes(&all),
            50,
            hellas_rpc::Retention::Ephemeral,
            all.len() as u64,
            0,
            &[],
        )
        .unwrap();
}

#[tokio::test]
async fn grant_and_paid_handlers_share_quota_and_drain_releases_ephemeral_staging() {
    use hellas_channel::model::setup::ObservedChannel;
    use hellas_channel::test_support::channel as paid;
    use hellas_channel::work::{ProviderEndpoint, WorkService};
    let root = tempfile::tempdir().unwrap();
    let paid_bytes = paid::bundle_bytes(1);
    let (grants, work, request, bytes) =
        fixture(&root.path().join("grants"), UploadQuota::default()).await;
    let quota = UploadQuota::new(paid_bytes.len().max(bytes.len()) as u64);
    let access = work.access.clone();
    drop(work);
    let grants = grants.with_upload_quota(quota.clone());
    let work = GrantWork {
        service: grants.clone(),
        access,
    };
    let ready = paid::descriptor()
        .check_ready(&ObservedChannel {
            height: paid::CURSOR,
            bond: Some(&paid::bond_object()),
            payment: Some(&paid::payment_object()),
            lease: paid::lease_over(paid::bond_edge(), paid::payment_edge()),
            pending: hellas_kernel::PendingSlot::Absent,
        })
        .unwrap();
    let paid = WorkService::new(
        ProviderEndpoint::new(
            ready.clone(),
            paid::store_at(
                &root.path().join("paid"),
                &ready,
                hellas_channel::work_store::Role::Provider,
                paid::CURSOR,
            )
            .await,
            paid::provider(),
        )
        .unwrap(),
    );
    paid.set_upload_quota(quota.clone()).await.unwrap();
    let a = hellas_channel::job::propose(
        ready.channel(),
        &paid::work_policy(),
        &paid::payment_policy(),
        &paid::bundle(1),
        1,
        paid::deadlines(),
    )
    .unwrap();
    let id = hellas_channel::model::work::work_id(ready.channel(), &a);
    let req = AcceptWorkRequest {
        route: Some(WorkRoute::payment(a.channel_id)),
        authorization: a.encode(),
        client_signature: paid::client()
            .sign(hellas_channel::model::work::signing_hash(id))
            .as_bytes()
            .to_vec(),
        prepared_input: paid_bytes.clone(),
    };
    let (_, uploads) = paid::input_uploads(ready.channel(), &req, &paid_bytes);
    assert!(
        paid.upload(&uploads[0], &context())
            .await
            .unwrap()
            .refused
            .is_none()
    );
    // Each object fits alone; their sum exceeds this shared node cap.
    let reference = ContentRef::for_bytes(&bytes);
    let denied = work
        .upload(&signed(&request, reference, 0, &bytes[..10]), &context())
        .await
        .unwrap();
    assert_eq!(
        GrantRefusalCode::try_from(denied.refused.unwrap().grant.unwrap().code).unwrap(),
        GrantRefusalCode::StateCapacity
    );
    paid.prepare_close().await.unwrap();
    assert!(
        work.upload(&signed(&request, reference, 0, &bytes[..10]), &context())
            .await
            .unwrap()
            .refused
            .is_none()
    );
    assert_no_payload_files(&root.path().join("grants"), &bytes);
    let upload = signed(&request, ContentRef::for_bytes(&bytes), 0, &bytes[..10]);
    grants.drain().await.unwrap();
    assert!(grants.inner.lock().unwrap().uploads.is_empty());
    assert_eq!(
        GrantRefusalCode::try_from(
            work.upload(&upload, &context())
                .await
                .unwrap()
                .refused
                .unwrap()
                .grant
                .unwrap()
                .code
        )
        .unwrap(),
        GrantRefusalCode::QueueCapacity
    );
    let mut probe = hellas_channel::content::UploadStore::memory(
        Digest::hash(b"another channel"),
        quota,
        hellas_store::ContentStore::new(),
    );
    let entire_cap = vec![0; paid_bytes.len().max(bytes.len())];
    probe
        .stage(
            Digest::hash(b"work"),
            ContentRef::for_bytes(&entire_cap),
            50,
            hellas_rpc::Retention::Ephemeral,
            entire_cap.len() as u64,
            0,
            &entire_cap,
        )
        .unwrap();
}

#[tokio::test]
async fn malformed_first_grant_chunks_release_quota_and_cannot_retain_the_writer() {
    let root = tempfile::tempdir().unwrap();
    let quota = UploadQuota::new(1 << 20);
    let (service, work, request, bytes) = fixture(root.path(), quota.clone()).await;
    let a = GrantJobAuthorizationV1::decode(&request.authorization).unwrap();
    let bad_offset = signed(&request, a.input_content, 1, &bytes[..1]);
    assert!(
        work.upload(&bad_offset, &context())
            .await
            .unwrap()
            .refused
            .is_some()
    );
    assert!(
        !service
            .inner
            .lock()
            .unwrap()
            .uploads
            .get(&a.channel_id.0)
            .unwrap()
            .is_staged()
    );
    let malformed = b"not a prepared input";
    let mut bad = request.clone();
    let mut authorization = a;
    authorization.input_content = ContentRef::for_bytes(malformed);
    bad.authorization = authorization.encode();
    bad.client_signature = common::principal(1)
        .1
        .sign_digest(grant_work_id(common::network(), &authorization))
        .unwrap()
        .bytes()
        .to_vec();
    assert!(
        work.upload(
            &signed(&bad, authorization.input_content, 0, malformed),
            &context()
        )
        .await
        .unwrap()
        .refused
        .is_some()
    );
    assert!(
        !service
            .inner
            .lock()
            .unwrap()
            .uploads
            .get(&a.channel_id.0)
            .unwrap()
            .is_staged()
    );
    assert_no_payload_files(root.path(), &bytes);
    // Leave a valid unfinished upload with a deadline in the future. Its
    // idle GC timer must not keep the provider's journal lease alive.
    let mut future = request.clone();
    let mut future_auth = a;
    future_auth.acceptance_deadline_ms = UnixMillis(9000);
    future_auth.terminal_deadline_ms = UnixMillis(10000);
    future_auth.delivery_deadline_ms = UnixMillis(11000);
    future.authorization = future_auth.encode();
    future.client_signature = common::principal(1)
        .1
        .sign_digest(grant_work_id(common::network(), &future_auth))
        .unwrap()
        .bytes()
        .to_vec();
    assert!(
        work.upload(
            &signed(&future, a.input_content, 0, &bytes[..10]),
            &context()
        )
        .await
        .unwrap()
        .refused
        .is_none()
    );
    drop(work);
    drop(service);
    let _reopened = tokio::time::timeout(
        Duration::from_millis((future_auth.acceptance_deadline_ms.0 - 1000) / 4),
        NodeStore::open(
            root.path(),
            common::network(),
            Some(common::software_enrollment(2, [2; 32])),
            UnixMillis(1000),
        ),
    )
    .await
    .unwrap()
    .unwrap();
}
