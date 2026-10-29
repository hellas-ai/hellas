use super::*;
use hellas_auth::authority::{CredentialSecret, SessionProof};

struct Fixture {
    service: GrantService,
    work: crate::grant_service::GrantWork,
    request: AcceptWorkRequest,
    chunks: Vec<UploadContentRequest>,
    clock: TestClock,
    secret: CredentialSecret,
    credential: CredentialSecret,
}
impl Fixture {
    async fn new(path: &std::path::Path) -> Self {
        let (store, secret) = setup_with_credential(path).await;
        let request = request(&store, 1);
        let clock = TestClock::default();
        let service = GrantService::new(
            store,
            Arc::new(principal(2).1),
            Backend::default(),
            vec![],
            clock.source(),
        )
        .unwrap();
        let (_, credential) =
            common_node::execution(&service, &secret, &principal(1).1, GrantId([1; 16])).await;
        let work = Self::session(&service, &credential, Digest::hash(b"binding")).await;
        let (request, chunks) =
            grant_upload_requests(&request, &principal(1).1, network(), [7; 32]);
        for chunk in &chunks {
            assert!(
                work.upload(chunk, &context())
                    .await
                    .unwrap()
                    .refused
                    .is_none()
            );
        }
        Self {
            service,
            work,
            request,
            chunks,
            clock,
            secret,
            credential,
        }
    }
    async fn session(
        service: &GrantService,
        credential: &CredentialSecret,
        binding: Digest,
    ) -> crate::grant_service::GrantWork {
        let node = service.node();
        let store = node.writer().await.unwrap();
        let authority = store.state().authority();
        let original = Digest::hash(b"binding");
        let pending = authority
            .begin_authentication(original, UnixMillis(1000))
            .unwrap();
        let proof: SessionProof = pending
            .challenge()
            .sign_daily(
                authority.authority(),
                original,
                credential.id(),
                &principal(1).1,
            )
            .unwrap();
        let session = pending
            .complete(authority, original, credential, &proof, UnixMillis(1000))
            .unwrap();
        service.for_session(session, binding, common_node::EXECUTION_AUTHORIZATION)
    }
    fn staged(&self) -> bool {
        let a = GrantJobAuthorizationV1::decode(&self.request.authorization).unwrap();
        self.service
            .inner
            .lock()
            .unwrap()
            .uploads
            .get(&a.channel_id.0)
            .is_some_and(|uploads| uploads.has_stage(grant_work_id(network(), &a)))
    }
}

#[derive(Clone, Copy, Debug)]
enum Denial {
    Policy,
    Paused,
    Generation,
    Grant,
    Credential,
    Deadline,
    PermissionExpiry,
    Malformed,
}

#[tokio::test]
async fn conclusive_accept_and_upload_refusals_release_the_authenticated_stage() {
    for upload in [false, true] {
        for denial in [
            Denial::Policy,
            Denial::Paused,
            Denial::Generation,
            Denial::Grant,
            Denial::Credential,
            Denial::Deadline,
            Denial::PermissionExpiry,
            Denial::Malformed,
        ] {
            let dir = tempfile::tempdir().unwrap();
            let mut f = Fixture::new(dir.path()).await;
            assert!(f.staged());
            let expected = match denial {
                Denial::Policy | Denial::Paused => {
                    let node = f.service.node();
                    let mut store = node.writer().await.unwrap();
                    let mut def = store.state().grant(GrantId([1; 16])).unwrap().clone();
                    def.revision.0 += 1;
                    if matches!(denial, Denial::Policy) {
                        def.policies[0].revision.0 += 1;
                        store
                            .configure_resource(def.policies[0].clone(), f.clock.now())
                            .await
                            .unwrap();
                    } else {
                        def.enabled = false;
                    }
                    store.define(def, f.clock.now()).await.unwrap();
                    if matches!(denial, Denial::Policy) {
                        GrantRefusalCode::StaleRevision
                    } else {
                        GrantRefusalCode::Paused
                    }
                }
                Denial::Generation => {
                    f.service
                        .node()
                        .writer()
                        .await
                        .unwrap()
                        .bump_generation(GrantId([1; 16]), f.clock.now())
                        .await
                        .unwrap();
                    GrantRefusalCode::StaleGeneration
                }
                Denial::Grant | Denial::Credential => {
                    revoke_access(
                        &f.service,
                        &f.secret,
                        &f.credential,
                        if matches!(denial, Denial::Grant) {
                            AccessTarget::Grant
                        } else {
                            AccessTarget::Credential
                        },
                    )
                    .await;
                    if matches!(denial, Denial::Grant) {
                        GrantRefusalCode::Revoked
                    } else {
                        GrantRefusalCode::Unauthorized
                    }
                }
                Denial::Deadline => {
                    // The upload timer has not elapsed; acceptance itself must discard it.
                    f.clock.set(UnixMillis(2001));
                    GrantRefusalCode::Expired
                }
                Denial::PermissionExpiry => {
                    set_execution_expiry(&f.service, &f.secret, UnixMillis(1100)).await;
                    f.clock.set(UnixMillis(1101));
                    GrantRefusalCode::Expired
                }
                Denial::Malformed => {
                    if upload {
                        f.chunks.last_mut().unwrap().program_manifest = vec![0];
                    } else {
                        f.request.prepared_input = vec![0];
                    }
                    GrantRefusalCode::Malformed
                }
            };
            let refused = if upload {
                f.work
                    .upload(f.chunks.last().unwrap(), &context())
                    .await
                    .unwrap()
                    .refused
                    .unwrap()
            } else {
                let response = f.work.accept(&f.request).await;
                let Some(accept_work_response::Outcome::Refused(refused)) = response.outcome else {
                    panic!("{denial:?}");
                };
                refused
            };
            assert_eq!(
                GrantRefusalCode::try_from(refused.grant.unwrap().code).unwrap(),
                expected,
                "{denial:?}, upload={upload}"
            );
            assert!(
                !f.staged(),
                "{denial:?}, upload={upload}: refused proposal kept its stage"
            );
            within(f.service.drain()).await.unwrap();
        }
    }
}

#[tokio::test]
async fn quota_refusal_releases_staging_for_the_next_proposal_without_waiting() {
    let dir = tempfile::tempdir().unwrap();
    let f = Fixture::new(dir.path()).await;
    f.service
        .node()
        .writer()
        .await
        .unwrap()
        .configure_machine(
            vec![Limit {
                meter: Meter::Requests,
                window: Window::Total,
                amount: 0,
            }],
            4,
            f.clock.now(),
        )
        .await
        .unwrap();
    assert_eq!(
        refusal(f.work.accept(&f.request).await),
        GrantRefusalCode::Budget
    );
    assert!(!f.staged());
    let next = {
        let node = f.service.node();
        let mut store = node.writer().await.unwrap();
        store
            .configure_machine(vec![], 4, f.clock.now())
            .await
            .unwrap();
        request(&store, 2)
    };
    accepted_id(accept_grant(&f.work, &next, &principal(1).1).await);
    within(f.service.drain()).await.unwrap();
}

#[tokio::test]
async fn unowned_and_uncertain_refusals_preserve_the_original_stage() {
    let dir = tempfile::tempdir().unwrap();
    let f = Fixture::new(dir.path()).await;
    let mut bad = f.request.clone();
    bad.client_signature = principal(2)
        .1
        .sign_digest(Digest::hash(b"forged"))
        .unwrap()
        .bytes()
        .to_vec();
    assert_eq!(
        refusal(f.work.accept(&bad).await),
        GrantRefusalCode::Unauthorized
    );
    assert!(f.staged());
    let wrong = f.service.for_caller(
        crate::test_support::session(&f.service.node(), &f.secret).await,
        common_node::EXECUTION_AUTHORIZATION,
    );
    assert_eq!(
        refusal(wrong.accept(&f.request).await),
        GrantRefusalCode::Unauthorized
    );
    assert!(f.staged());
    let wrong_binding = Fixture::session(
        &f.service,
        &f.credential,
        Digest::hash(b"different transport"),
    )
    .await;
    assert_eq!(
        refusal(wrong_binding.accept(&f.request).await),
        GrantRefusalCode::Unauthorized
    );
    assert!(f.staged());
    let mut chunk = f.chunks.last().unwrap().clone();
    chunk.chunk_signature = bad.client_signature.clone();
    assert!(
        f.work
            .upload(&chunk, &context())
            .await
            .unwrap()
            .refused
            .is_some()
    );
    assert!(
        f.staged(),
        "forged chunk cannot clear a valid signed proposal"
    );
    assert!(
        f.work
            .upload(
                f.chunks.last().unwrap(),
                &TransportContext {
                    open_exporter: Some([8; 32]),
                    ..context()
                }
            )
            .await
            .unwrap()
            .refused
            .is_some()
    );
    assert!(f.staged());
    let other = request(&f.service.node().writer().await.unwrap(), 2);
    let (wire, chunks) = grant_upload_requests(&other, &principal(1).1, network(), [7; 32]);
    assert!(
        f.work
            .upload(&chunks[0], &context())
            .await
            .unwrap()
            .refused
            .is_some()
    );
    assert!(
        f.staged(),
        "a different signed work ID cannot discard the original"
    );
    assert_eq!(
        refusal(f.work.accept(&wire).await),
        GrantRefusalCode::Malformed
    );
    assert!(f.staged());
    f.service.inner.lock().unwrap().status =
        crate::grant_service::ServiceStatus::Failed(Arc::new(NodeStoreError::WriterPoisoned));
    assert!(f.staged());
    assert_eq!(
        refusal(f.work.accept(&f.request).await),
        GrantRefusalCode::StorageUnavailable
    );
    assert!(f.staged(), "uncertain acceptance remains recoverable");
    assert_eq!(
        GrantRefusalCode::try_from(
            f.work
                .upload(f.chunks.last().unwrap(), &context())
                .await
                .unwrap()
                .refused
                .unwrap()
                .grant
                .unwrap()
                .code
        )
        .unwrap(),
        GrantRefusalCode::StorageUnavailable
    );
    assert!(f.staged());
}
