//! One paid job, end to end, from the client's side: proposed,
//! computed by a real provider endpoint, delivered, authenticated, and
//! paid for.
//!
//! Both endpoints are real and hold real journals, and the exchange runs
//! over a real multiplexed transport, framed and routed by method id.

#![cfg(feature = "work")]

use hellas_channel::test_support::channel::serve_work as serve;
use hellas_channel::test_support::channel::{
    CURSOR, PRICE, accept, authorization, client, payload_at, provider, ready, run_to_result,
    store_at,
};

use hellas_channel::work::{ClientChannel as _, ClientEndpoint, ProviderEndpoint, WorkService};
use hellas_channel::work_close::{
    BlockSourceError, CloseChannel as _, FinalizedBlocks, FinalizedWork,
};
use hellas_channel::work_store::{JobPhase, JobState, Role};
use hellas_client::work::payment::pay_for_result;
use hellas_client::work::{CollectResultError, CollectResultOutcome, collect_result};
use hellas_wire::mux::MuxTransport;

// ── Fixture ───────────────────────────────────────────────────────────

fn temp() -> tempfile::TempDir {
    match tempfile::tempdir() {
        Ok(dir) => dir,
        Err(error) => panic!("a temporary directory: {error}"),
    }
}

// ── Transport plumbing ────────────────────────────────────────────────

fn session() -> hellas_wire::TransportContext {
    hellas_wire::TransportContext {
        open_exporter: Some([0x5e; 32]),
        ..hellas_wire::TransportContext::default()
    }
}

fn transport_pair() -> (MuxTransport, MuxTransport) {
    hellas_channel::test_support::transport::transport_pair_with_context(session(), session())
}

/// A finalized-block source over the same synthetic empty chain the
/// fixture's `advance` walks, up to `tip`.
///
/// The client's post-answer catch-up reads this. A `tip` at the fixture
/// cursor makes the catch-up a no-op; a `tip` past a deadline is a
/// reproduction that stalled while the chain moved on.
struct Blocks {
    tip: u64,
}

impl FinalizedBlocks for Blocks {
    async fn latest_height(&self) -> Result<Option<u64>, BlockSourceError> {
        Ok(Some(self.tip))
    }

    async fn block_at(&self, height: u64) -> Result<Option<FinalizedWork>, BlockSourceError> {
        if height == 0 || height > self.tip {
            return Ok(None);
        }
        Ok(Some(FinalizedWork {
            height,
            parent: payload_at(height.saturating_sub(1)),
            payload: payload_at(height),
            txs: Vec::new(),
        }))
    }
}

/// A source that yields no block past the fixture cursor, so the
/// post-answer catch-up moves nothing.
fn still() -> Blocks {
    Blocks { tip: CURSOR }
}

// ── The whole path ────────────────────────────────────────────────────

/// The normal paid-work path authenticates and pays a provider result
/// without constructing or invoking a reproduction engine.
#[tokio::test]
async fn an_authenticated_answer_is_paid_without_reexecution() {
    let client_root = temp();
    let provider_root = temp();
    let ready = ready();
    let mut client_store = store_at(client_root.path(), &ready, Role::Client, CURSOR).await;
    let mut provider_store = store_at(provider_root.path(), &ready, Role::Provider, CURSOR).await;
    let id = accept(&mut [&mut client_store, &mut provider_store]).await;
    let provider_endpoint = ProviderEndpoint::new(ready.clone(), provider_store, provider())
        .expect("the provider endpoint binds");
    let service = WorkService::new(provider_endpoint);
    let mut endpoint = ClientEndpoint::new(ready.clone(), client_store, client())
        .expect("the client endpoint binds");
    run_to_result(&service, &ready, id).await;

    let (transport, server) = transport_pair();
    let serving = serve(server, service.clone());
    let collected = collect_result(transport, &mut endpoint, &ready, &still(), id).await;
    serving.abort();
    assert!(
        matches!(collected, Ok(CollectResultOutcome::Collected(_))),
        "the authenticated answer is collected: {collected:?}",
    );
    assert_eq!(
        endpoint.state().jobs().next().map(JobState::phase),
        Some(JobPhase::Ready),
        "ordinary collection does not claim an independent match",
    );
    endpoint
        .verified(id, &hellas_channel::test_support::channel::bundle(1))
        .await
        .expect("the client records its result check");

    let (transport, server) = transport_pair();
    let serving = serve(server, service.clone());
    let credited = pay_for_result(transport, &mut endpoint, id).await;
    serving.abort();
    assert_eq!(credited.ok(), Some(PRICE));
    assert_eq!(endpoint.state().ledger().credited_cumulative(), PRICE);
}

/// Ordinary collection uses a post-delivery finalized-height
/// barrier and will not return a stale payable result.
#[tokio::test]
async fn ordinary_collection_refuses_a_stale_payment_boundary() {
    let client_root = temp();
    let provider_root = temp();
    let ready = ready();
    let mut client_store = store_at(client_root.path(), &ready, Role::Client, CURSOR).await;
    let mut provider_store = store_at(provider_root.path(), &ready, Role::Provider, CURSOR).await;
    let id = accept(&mut [&mut client_store, &mut provider_store]).await;
    let authorization = authorization();
    let provider_endpoint = ProviderEndpoint::new(ready.clone(), provider_store, provider())
        .expect("the provider endpoint binds");
    let service = WorkService::new(provider_endpoint);
    let mut endpoint = ClientEndpoint::new(ready.clone(), client_store, client())
        .expect("the client endpoint binds");
    run_to_result(&service, &ready, id).await;

    let stale = Blocks {
        tip: authorization.payment_deadline.saturating_add(1),
    };
    let (transport, server) = transport_pair();
    let serving = serve(server, service);
    let collected = collect_result(transport, &mut endpoint, &ready, &stale, id).await;
    serving.abort();
    assert!(
        matches!(collected, Err(CollectResultError::Stale { .. })),
        "the stale result is refused: {collected:?}",
    );
    assert!(endpoint.state().last_payment().is_none());
}

/// A payment signed before a crash is re-sent after it, and credited
/// once.
///
/// The client dies between fsyncing its certificate and sending it —
/// the one window where its journal holds a payment no provider has
/// seen. What comes back is not a second signature: it is the same
/// bytes, off the disk of a process that never made them.
#[tokio::test]
async fn a_payment_signed_before_a_crash_is_re_sent_after_it() {
    let client_root = temp();
    let provider_root = temp();
    let ready = ready();
    let mut client_store = store_at(client_root.path(), &ready, Role::Client, CURSOR).await;
    let mut provider_store = store_at(provider_root.path(), &ready, Role::Provider, CURSOR).await;
    let id = accept(&mut [&mut client_store, &mut provider_store]).await;
    let Ok(provider_endpoint) = ProviderEndpoint::new(ready.clone(), provider_store, provider())
    else {
        panic!("the provider endpoint binds");
    };
    let service = WorkService::new(provider_endpoint);
    let Ok(mut endpoint) = ClientEndpoint::new(ready.clone(), client_store, client()) else {
        panic!("the client endpoint binds");
    };
    run_to_result(&service, &ready, id).await;

    let (transport, server) = transport_pair();
    let serving = serve(server, service.clone());
    let collected = collect_result(transport, &mut endpoint, &ready, &still(), id).await;
    serving.abort();
    assert!(
        matches!(collected, Ok(CollectResultOutcome::Collected(_))),
        "the answer is collected: {collected:?}",
    );
    endpoint
        .verified(id, &hellas_channel::test_support::channel::bundle(1))
        .await
        .expect("the client records its result check");

    // Signed, and then the process is gone before a byte of the
    // certificate leaves it.
    let signed = endpoint.pay(id).await;
    assert!(signed.is_ok(), "the client signs its payment: {signed:?}");
    endpoint
        .store()
        .await
        .unwrap()
        .content_store()
        .close()
        .await;
    drop(endpoint);
    {
        assert_eq!(
            service
                .with_state(|state| state.ledger().credited_cumulative())
                .await
                .expect("the endpoint is reachable"),
            0,
            "and the provider has seen nothing",
        );
    }

    let recovered = store_at(client_root.path(), &ready, Role::Client, CURSOR).await;
    let Ok(mut endpoint) = ClientEndpoint::new(ready.clone(), recovered, client()) else {
        panic!("the client endpoint rebinds");
    };
    let (transport, server) = transport_pair();
    let serving = serve(server, service.clone());
    let credited = pay_for_result(transport, &mut endpoint, id).await;
    serving.abort();
    assert_eq!(credited.ok(), Some(PRICE));
    assert_eq!(
        service
            .with_state(|state| state.ledger().credited_cumulative())
            .await
            .expect("the endpoint is reachable"),
        PRICE,
    );
}

/// A retained Compute proposal whose weights the provider already holds is
/// not an unfinished upload.
///
/// The model package deliberately leaves weight assets out of the client's
/// content: they are ordinary provider-held objects, not bytes this caller
/// can produce. Retaining the signed closure must therefore probe the
/// provider before reading anything, and a restart must rebuild exactly the
/// client-supplied share rather than demand the whole closure locally.
#[cfg(feature = "models")]
#[tokio::test]
async fn a_retained_model_job_resumes_with_provider_held_weights() {
    model_job_restart(true).await;
}

#[cfg(feature = "models")]
#[tokio::test]
async fn a_retained_model_proposal_reuploads_its_share_after_upload_connection_loss() {
    model_job_restart(false).await;
}

#[cfg(feature = "models")]
async fn model_job_restart(provider_held: bool) {
    tokio::time::timeout(
        std::time::Duration::from_secs(30),
        model_job_restart_inner(provider_held),
    )
    .await
    .expect("the model proposal recovery completes");
}

#[cfg(feature = "models")]
async fn model_job_restart_inner(provider_held: bool) {
    use futures::StreamExt as _;
    use hellas_channel::model::work::{PaidJobAuthorizationV2, PrivateRecord as _, work_id};
    use hellas_channel::test_support::channel::{advance, deadlines, origin, settlement};
    use hellas_channel::work::{JobProposal, propose_work, resume_work_proposal};
    use hellas_channel::work_store::ChannelStore;
    use hellas_client::model::{ModelPackage, ModelRequest};
    use hellas_kernel::Secp256k1Verifier;
    use hellas_rpc::protocol::invocation::{
        InvocationInput, InvocationRequest, PreparedInvocation,
    };
    use hellas_rpc::{Assurance, ContentRef, JsonBytes};
    use hellas_store::content::{
        DiskStore, IndexMode, PinName, PinPolicy, PinTarget, Reservations, Scope,
    };
    use hellas_wire::MethodMarker as _;
    use hellas_wire::StreamTransport as _;
    use std::sync::Arc;

    let client_root = temp();
    let provider_root = temp();
    let ready = ready();
    let fixture =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/model/package/mini-qwen3.gguf");

    let package = ModelPackage::open(&fixture)
        .await
        .expect("the miniature Qwen model opens");
    let job = package
        .render_job(&ModelRequest::Text {
            prompt_ids: &[2, 1],
            max_new: 2,
            stops: &[0, 0],
        })
        .await
        .expect("the model renders a Compute job");

    let weights = std::fs::read(&fixture).expect("the model weights are readable");
    let [weights_asset] = &job.environment.assets[..] else {
        panic!("the model job names exactly one weight asset");
    };
    assert_eq!(weights_asset.object, ContentRef::for_bytes(&weights));
    assert!(
        job.content
            .0
            .open_verified(&job.content.1, weights_asset.object, None)
            .await
            .unwrap()
            .is_none(),
        "the client deliberately does not hold the provider's weights"
    );

    let weights_store = DiskStore::open(
        provider_root.path().join("content"),
        vec![],
        IndexMode::Resume,
        None,
        Reservations::ram(hellas_channel::content::DEFAULT_MAX_STAGING_BYTES),
    )
    .await
    .unwrap();
    let mut provider_store = ChannelStore::open(
        provider_root.path(),
        ready.channel().clone(),
        settlement(),
        Role::Provider,
        origin(),
        weights_store.clone(),
        &Secp256k1Verifier::new(),
    )
    .await
    .expect("the provider journal opens");
    weights_store.finish_recovery().await.unwrap();
    if provider_held {
        hellas_channel::content::upload_bytes(
            &weights_store,
            &Scope::Owner,
            &weights,
            Some(PinTarget {
                name: PinName::new("provider/weights".into()).unwrap(),
                policy: PinPolicy::Jobs,
            }),
        )
        .await
        .unwrap();
    }
    advance(&mut provider_store, CURSOR).await;

    let policy = ready.invocation_policy();
    let manifest = job
        .environment
        .manifest()
        .expect("the environment has a manifest");
    let input = InvocationInput {
        artifacts: job.inputs.clone(),
        parameters: JsonBytes(job.plan.canonical_bytes().expect("the plan encodes")),
    };
    let request = InvocationRequest {
        execution_environment: manifest.content_id(),
        input: input.content_id().expect("the input commits"),
        runner_public_key: hellas_auth::PublicKey::Secp256k1(provider().party_key().to_bytes()),
        nonce: [7; 32],
        assurance: Assurance::ProducerSigned,
        retain: true,
    };
    let proposal = JobProposal {
        prepared_input: PreparedInvocation::new(
            request,
            &manifest,
            input,
            policy.canonical_bytes().expect("the policy encodes"),
        )
        .expect("the model job is a prepared invocation"),
        deadlines: deadlines(),
    };
    let content = job.content.clone();
    if !provider_held {
        hellas_channel::content::upload_object(&content.0, &weights)
            .await
            .unwrap();
    }

    // The provider accepts the upload and journals its co-signature, but
    // the reply never reaches the client: the client keeps a half-signed
    // job with a complete upload, which is exactly the state a restart
    // must resume.
    struct LostAccept {
        service: WorkService,
        accept: bool,
        completed: Arc<std::sync::atomic::AtomicBool>,
    }
    impl hellas_rpc::services::work::WorkHandler for LostAccept {
        async fn accept_work(
            &self,
            request: hellas_rpc::pb::work::AcceptWorkRequest,
            context: hellas_wire::TransportContext,
        ) -> Result<
            impl Into<hellas_rpc::call::WithTrailer<hellas_rpc::pb::work::AcceptWorkResponse>> + Send,
            hellas_wire::WireStatus,
        > {
            // Retained proposals first probe for a prior durable acceptance.
            // Inject loss only after the real Content upload has completed.

            let authorization = PaidJobAuthorizationV2::decode(&request.authorization).unwrap();
            let id = self
                .service
                .with_state(|state| work_id(state.channel(), &authorization))
                .await
                .unwrap();
            if !self.service.completed_content_upload(id).unwrap() {
                return self
                    .service
                    .accept_work(request, context)
                    .await
                    .map(Into::into);
            }
            self.completed
                .store(true, std::sync::atomic::Ordering::Release);
            if self.accept {
                let _ = self.service.accept_work(request, context).await?;
            }
            Err::<hellas_rpc::call::WithTrailer<hellas_rpc::pb::work::AcceptWorkResponse>, _>(
                hellas_wire::WireStatus::internal("the acceptance reply was lost"),
            )
        }

        async fn get_standing(
            &self,
            request: hellas_rpc::pb::work::GetStandingRequest,
            context: hellas_wire::TransportContext,
        ) -> Result<
            impl Into<hellas_rpc::call::WithTrailer<hellas_rpc::pb::work::GetStandingResponse>> + Send,
            hellas_wire::WireStatus,
        > {
            self.service.get_standing(request, context).await
        }
        async fn stream_result(
            &self,
            request: hellas_rpc::pb::work::StreamResultRequest,
            context: hellas_wire::TransportContext,
        ) -> Result<
            hellas_rpc::call::ResponseStream<hellas_rpc::pb::work::WorkStreamEvent>,
            hellas_wire::WireStatus,
        > {
            self.service.stream_result(request, context).await
        }
        async fn admit_certificate(
            &self,
            request: hellas_rpc::pb::work::AdmitCertificateRequest,
            context: hellas_wire::TransportContext,
        ) -> Result<
            impl Into<hellas_rpc::call::WithTrailer<hellas_rpc::pb::work::AdmitCertificateResponse>>
            + Send,
            hellas_wire::WireStatus,
        > {
            self.service.admit_certificate(request, context).await
        }
    }

    let service = WorkService::new(
        ProviderEndpoint::new(ready.clone(), provider_store, provider())
            .expect("the provider endpoint binds"),
    );
    let mut endpoint = hellas_channel::test_support::channel::client_service(
        ClientEndpoint::new(
            ready.clone(),
            store_at(client_root.path(), &ready, Role::Client, CURSOR).await,
            client(),
        )
        .expect("the client endpoint binds"),
        ready.clone(),
    )
    .await;
    let (transport, server_transport) = transport_pair();
    let probes = Arc::new(std::sync::Mutex::new(std::collections::BTreeMap::new()));
    let completed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let serving = tokio::spawn({
        let service = service.clone();
        let probes = probes.clone();
        let completed = completed.clone();
        async move {
            let dispatcher = Arc::new(hellas_rpc::services::work::WorkServer(LostAccept {
                service: service.clone(),
                accept: provider_held,
                completed,
            }));
            let mut tasks = tokio::task::JoinSet::new();
            let cancellation = hellas_channel::work::admission::Cancellation::new();
            let _stop =
                hellas_channel::work::admission::CancelOnFailure(vec![cancellation.clone()]);
            while let Ok(Some(inbound)) = server_transport.accept().await {
                let dispatcher = dispatcher.clone();
                let service = service.clone();
                let probes = probes.clone();
                let cancellation = cancellation.clone();
                tasks.spawn(async move {
                    if inbound.method_id == hellas_rpc::services::content::Upload::METHOD_ID {
                        let context = inbound.context.clone();
                        let _ = hellas_rpc::call::dispatch_bidi_streaming::<
                            MuxTransport, hellas_rpc::services::content::Upload, _, _, _,
                        >(inbound, |requests| async move {
                            let requests = requests.map(move |request| {
                                if let Ok(hellas_rpc::pb::content::UploadRequest {
                                    part: Some(hellas_rpc::pb::content::upload_request::Part::Open(open)),
                                }) = &request {
                                    *probes.lock().unwrap().entry(open.object.as_ref().unwrap().id.clone()).or_default() += 1;
                                }
                                request
                            });
                            service.upload_stream(Box::pin(requests), context, cancellation).await
                        }).await;
                    } else {
                        let _ = hellas_wire::Dispatcher::<MuxTransport>::dispatch(dispatcher.as_ref(), inbound).await;
                    }
                });
            }
        }
    });

    let failed = propose_work(transport, &mut endpoint, &proposal, &content).await;

    serving.abort();
    let _ = serving.await;
    assert!(
        matches!(
            &failed,
            Err(hellas_channel::work::ProposeError::Transport(status))
                if status.code() == hellas_wire::WireCode::Internal
        ),
        "the upload completes and only the acceptance reply is lost: {failed:?}",
    );
    assert!(
        completed.load(std::sync::atomic::Ordering::Acquire),
        "inject reply loss only after validated upload EOF"
    );
    assert_eq!(
        probes
            .lock()
            .unwrap()
            .get(weights_asset.object.id().as_bytes().as_slice()),
        Some(&1)
    );
    assert!(
        probes.lock().unwrap().values().all(|count| *count == 1),
        "retaining client content must not probe assets a second time"
    );
    let id = endpoint
        .client()
        .await
        .unwrap()
        .state()
        .jobs()
        .next()
        .expect("the proposal is journaled")
        .work_id();
    assert_eq!(
        endpoint
            .client()
            .await
            .unwrap()
            .state()
            .job_by_id(id)
            .map(JobState::phase),
        Some(JobPhase::HalfSigned),
    );
    assert_eq!(
        service
            .with_state(|state| state.job_by_id(id).map(JobState::phase))
            .await
            .expect("the provider is reachable"),
        provider_held.then_some(JobPhase::Accepted),
        "the failure is after acceptance only for the provider-held case",
    );
    let client_node = endpoint
        .client()
        .await
        .unwrap()
        .store()
        .await
        .unwrap()
        .content_store();
    client_node.close().await;
    drop(endpoint);
    weights_store.close().await;
    drop(service);
    drop(content);
    drop(weights_store);

    // The unaccepted provider's carrier has ended, so its private staging is
    // abandoned. The signed client's exact retained share must survive this.
    // The reopened journal rebuilds the client's share from its own store.
    let store = store_at(client_root.path(), &ready, Role::Client, CURSOR).await;
    let recovered = store
        .recoverable_content(id)
        .expect("the retained closure reads")
        .expect("the client-supplied objects survived");
    let recovered_weights = recovered
        .0
        .open_verified(&recovered.1, weights_asset.object, None)
        .await;
    if provider_held {
        assert!(
            matches!(
                recovered_weights,
                Ok(None) | Err(hellas_store::content::Error::Denied)
            ),
            "a provider-held weight is not claimed as locally retained"
        );
    } else {
        let actual = recovered_weights
            .unwrap()
            .unwrap()
            .read_all(weights_asset.object, &recovered.0.ram_pool())
            .await
            .unwrap();
        assert_eq!(
            actual.as_ref(),
            weights.as_slice(),
            "the client reuploads from its own retained copy after restart"
        );
    }
    let weights_store = DiskStore::open(
        provider_root.path().join("content"),
        vec![],
        IndexMode::Resume,
        None,
        Reservations::ram(hellas_channel::content::DEFAULT_MAX_STAGING_BYTES),
    )
    .await
    .unwrap();
    let mut provider_store = ChannelStore::open(
        provider_root.path(),
        ready.channel().clone(),
        settlement(),
        Role::Provider,
        origin(),
        weights_store.clone(),
        &Secp256k1Verifier::new(),
    )
    .await
    .expect("the provider journal reopens");
    weights_store.finish_recovery().await.unwrap();
    if !provider_held {
        assert_eq!(
            weights_store.stats().unwrap().used,
            0,
            "the disconnected, unaccepted upload has no durable authority"
        );
    }
    advance(&mut provider_store, CURSOR).await;
    let service = WorkService::new(
        ProviderEndpoint::new(ready.clone(), provider_store, provider())
            .expect("the provider endpoint rebinds"),
    );
    let mut endpoint =
        ClientEndpoint::new(ready.clone(), store, client()).expect("the client endpoint rebinds");
    let (transport, server) = transport_pair();
    let serving = serve(server, service);

    let resumed = resume_work_proposal(transport, &mut endpoint, id, &recovered).await;

    serving.abort();
    let _ = serving.await;
    assert_eq!(resumed.expect("the retained proposal is accepted"), id);
    assert_eq!(
        endpoint
            .client()
            .await
            .unwrap()
            .state()
            .job_by_id(id)
            .map(JobState::phase),
        Some(JobPhase::Accepted),
    );
    assert_eq!(
        endpoint
            .client()
            .await
            .unwrap()
            .state()
            .job_book()
            .pending_proposal(),
        None
    );
}
