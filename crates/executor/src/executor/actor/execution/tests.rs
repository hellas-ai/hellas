use super::*;
#[cfg(feature = "evaluate")]
use crate::ArtifactStoreConfig;
use crate::ExecutorError;
#[cfg(feature = "evaluate")]
use crate::GpuConfig;
use crate::fetch::{FetchTranscriptStore, MemoryFetchTranscriptStore};
use crate::fetch_policy::MemoryFetchQuotaStore;
use crate::{
    CallerAccess, Executor, ExecutorMetrics, ExecutorSpawnConfig, FetchAccessPolicy,
    FetchAdaptorError, FetchAdaptorFactory, FetchAdaptorSession, FetchProjector, FetchProvider,
    FetchProviderFuture, FetchProviderResponse, FetchProviderResponseHead, FetchProviderStream,
    FetchQuotaStoreBackend, FetchRequestView, FetchRoute, FetchRouteGrant, FetchRoutePolicy,
    FetchTranscriptStoreBackend, MockFetchProvider, PreparedFetchRequest, ProjectedFetch,
    SpendLimit,
};
use futures_util::stream;
use hellas_rpc::ProducerSigningKey;
use hellas_rpc::fetch::build_input_events;
use hellas_rpc::pb::fetch::FetchRequest;
use hellas_rpc::policy::ExecutePolicy;
use hellas_rpc::stream::input_event_to_pb;
#[cfg(feature = "evaluate")]
use hellas_store::ContentStore;
use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use tokio::sync::Notify;
use tokio::time::{Duration, timeout};

#[derive(Clone, Debug, Default)]
struct TestFetchAdaptorFactory;

impl FetchAdaptorFactory for TestFetchAdaptorFactory {
    fn execution_environment(&self) -> hellas_rpc::ContentId {
        test_environment()
    }

    fn create(&self, request: &crate::FetchCall) -> Result<FetchAdaptorSession, FetchAdaptorError> {
        Ok(FetchAdaptorSession {
            request_view: FetchRequestView::from_call(request),
            provider_request: PreparedFetchRequest::new(request, request.body.clone()),
            projector: Box::new(TestFetchProjector {
                terminal_seen: false,
            }),
        })
    }
}

#[derive(Clone, Debug)]
struct FixedViewFetchAdaptorFactory {
    view: FetchRequestView,
}

impl FetchAdaptorFactory for FixedViewFetchAdaptorFactory {
    fn execution_environment(&self) -> hellas_rpc::ContentId {
        test_environment()
    }

    fn create(&self, request: &crate::FetchCall) -> Result<FetchAdaptorSession, FetchAdaptorError> {
        Ok(FetchAdaptorSession {
            request_view: self.view.clone(),
            provider_request: PreparedFetchRequest::new(request, request.body.clone()),
            projector: Box::new(TestFetchProjector {
                terminal_seen: false,
            }),
        })
    }
}

#[derive(Clone, Debug)]
struct InvalidTerminalFetchAdaptorFactory {
    view: FetchRequestView,
}

impl FetchAdaptorFactory for InvalidTerminalFetchAdaptorFactory {
    fn execution_environment(&self) -> hellas_rpc::ContentId {
        test_environment()
    }

    fn create(&self, request: &crate::FetchCall) -> Result<FetchAdaptorSession, FetchAdaptorError> {
        Ok(FetchAdaptorSession {
            request_view: self.view.clone(),
            provider_request: PreparedFetchRequest::new(request, request.body.clone()),
            projector: Box::new(InvalidTerminalFetchProjector),
        })
    }
}

struct InvalidTerminalFetchProjector;

impl FetchProjector for InvalidTerminalFetchProjector {
    fn project(&mut self, _bytes: &[u8]) -> Result<Vec<ProjectedFetch>, FetchAdaptorError> {
        Ok(vec![ProjectedFetch::Terminal(vec![0xff])])
    }

    fn finish(&mut self) -> Result<Vec<ProjectedFetch>, FetchAdaptorError> {
        Err(FetchAdaptorError::failed(
            "invalid-terminal fixture received no provider body",
        ))
    }
}

struct TestFetchProjector {
    terminal_seen: bool,
}

impl FetchProjector for TestFetchProjector {
    fn project(&mut self, bytes: &[u8]) -> Result<Vec<ProjectedFetch>, FetchAdaptorError> {
        if bytes.strip_prefix(b"terminal:").is_some() {
            self.terminal_seen = true;
            let event = hellas_rpc::output::OutputEvent::Finished {
                stop_reason: hellas_rpc::output::StopReason::EndOfText,
                usage: None,
            };
            let payload = hellas_rpc::fetch::encode_fetch_terminal_payload(&event)
                .map_err(|error| FetchAdaptorError::failed(error.to_string()))?;
            Ok(vec![ProjectedFetch::Terminal(payload)])
        } else {
            Ok(vec![ProjectedFetch::Event(bytes.to_vec())])
        }
    }

    fn finish(&mut self) -> Result<Vec<ProjectedFetch>, FetchAdaptorError> {
        if self.terminal_seen {
            Ok(Vec::new())
        } else {
            Err(FetchAdaptorError::failed(
                "test stream ended without terminal".to_string(),
            ))
        }
    }
}

#[derive(Clone, Default)]
struct ReleasableFetchProvider {
    released: Arc<AtomicBool>,
    notify: Arc<Notify>,
    calls: Arc<AtomicUsize>,
}

impl ReleasableFetchProvider {
    fn release(&self) {
        self.released.store(true, Ordering::SeqCst);
        self.notify.notify_waiters();
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl FetchProvider for ReleasableFetchProvider {
    fn execution_environment(&self) -> hellas_rpc::ContentId {
        test_environment()
    }

    fn run(&self, _request: PreparedFetchRequest) -> FetchProviderFuture<'_> {
        let released = Arc::clone(&self.released);
        let notify = Arc::clone(&self.notify);
        let calls = Arc::clone(&self.calls);
        Box::pin(async move {
            calls.fetch_add(1, Ordering::SeqCst);
            while !released.load(Ordering::SeqCst) {
                notify.notified().await;
            }
            Ok(FetchProviderResponse {
                head: FetchProviderResponseHead::default(),
                stream: Box::pin(stream::iter([
                    Ok(b"event:ok".to_vec()),
                    Ok(b"terminal:done".to_vec()),
                ])) as FetchProviderStream,
            })
        })
    }
}

#[derive(Clone, Default)]
struct TerminalThenPanicFetchProvider {
    polls: Arc<AtomicUsize>,
}

impl TerminalThenPanicFetchProvider {
    fn polls(&self) -> usize {
        self.polls.load(Ordering::SeqCst)
    }
}

impl FetchProvider for TerminalThenPanicFetchProvider {
    fn execution_environment(&self) -> hellas_rpc::ContentId {
        test_environment()
    }

    fn run(&self, _request: PreparedFetchRequest) -> FetchProviderFuture<'_> {
        let polls = Arc::clone(&self.polls);
        let mut first = true;
        Box::pin(async move {
            Ok(FetchProviderResponse {
                head: FetchProviderResponseHead::default(),
                stream: Box::pin(stream::poll_fn(move |_| {
                    polls.fetch_add(1, Ordering::SeqCst);
                    if std::mem::take(&mut first) {
                        std::task::Poll::Ready(Some(Ok(b"terminal:done".to_vec())))
                    } else {
                        panic!("upstream was polled after its terminal event")
                    }
                })) as FetchProviderStream,
            })
        })
    }
}

fn key() -> ProducerSigningKey {
    ProducerSigningKey::from_secret_bytes([7; 32]).expect("valid test key")
}

fn test_assurance() -> hellas_rpc::Assurance {
    hellas_rpc::Assurance::ProducerSigned
}

fn test_genesis() -> Vec<u8> {
    b"genesis".to_vec()
}

fn test_environment() -> hellas_rpc::ContentId {
    hellas_rpc::ContentId::from_bytes([9; 32])
}

fn fetch_request(
    key: &ProducerSigningKey,
    service: &str,
    method: &str,
    body: &[u8],
) -> FetchRequest {
    fetch_request_and_commitment(key, service, method, body).0
}

fn fetch_request_and_commitment(
    key: &ProducerSigningKey,
    service: &str,
    method: &str,
    body: &[u8],
) -> (FetchRequest, InputCommitment) {
    let events = build_input_events(
        service,
        method,
        body,
        test_environment(),
        test_assurance(),
        key,
    )
    .unwrap();
    let input_commitment = hellas_rpc::fetch::verify_input_events(&events)
        .unwrap()
        .input_commitment;
    (
        FetchRequest {
            input: events.iter().map(input_event_to_pb).collect(),
        },
        input_commitment,
    )
}

fn run_ticket_request(
    ticket: hellas_rpc::pb::execute::Ticket,
    key: &ProducerSigningKey,
) -> RunTicketRequest {
    hellas_rpc::run_ticket::sign_run_ticket(ticket, key).expect("test run ticket signs")
}

async fn run_one(
    handle: &crate::ExecutorHandle,
    ticket: hellas_rpc::pb::execute::Ticket,
    key: &ProducerSigningKey,
) -> (Vec<WorkChunk>, WorkFinished) {
    let outcome = handle
        .run_ticket_handle(run_ticket_request(ticket, key))
        .await
        .unwrap();
    drain_outcome(outcome.events).await
}

async fn drain_outcome(
    mut outcome: crate::executor::ExecuteEventReceiver,
) -> (Vec<WorkChunk>, WorkFinished) {
    let mut chunks = Vec::new();
    loop {
        let event = outcome.recv().await.unwrap().unwrap();
        match event.kind.unwrap() {
            work_event::Kind::Chunk(chunk) => chunks.push(chunk),
            work_event::Kind::Finished(finished) => return (chunks, finished),
            work_event::Kind::Failed(failed) => {
                panic!("expected finished event, got failure: {failed:?}")
            }
        }
    }
}

fn test_routes(
    service: &str,
    method: &str,
    provider: Arc<dyn FetchProvider>,
    adaptor_factory: Arc<dyn FetchAdaptorFactory>,
) -> crate::FetchRouteRegistry {
    let mut registry = crate::FetchRouteRegistry::new();
    registry
        .register(
            FetchRoute::new(service, method),
            crate::FetchRouteEntry::new(provider, adaptor_factory, FetchRoutePolicy::default())
                .expect("test provider and adaptor identities match"),
        )
        .unwrap();
    registry
}

async fn spawn_fetch_executor(
    provider: Arc<dyn FetchProvider>,
    fetch_max_in_flight: usize,
    fetch_queue_capacity: usize,
) -> crate::ExecutorHandle {
    spawn_fetch_executor_with_bounds(
        provider,
        fetch_max_in_flight,
        fetch_queue_capacity,
        hellas_rpc::DEFAULT_FETCH_REPLAY_MAX_IN_FLIGHT,
        FetchTranscriptStoreBackend::memory(),
        Default::default(),
    )
    .await
}

async fn spawn_fetch_executor_with_bounds(
    provider: Arc<dyn FetchProvider>,
    fetch_max_in_flight: usize,
    fetch_queue_capacity: usize,
    fetch_replay_max_in_flight: usize,
    fetch_store: FetchTranscriptStoreBackend,
    output_cache: hellas_rpc::cache::CacheOptions,
) -> crate::ExecutorHandle {
    let producer_key = key();
    let caller_key = producer_key.public_key();
    Executor::spawn_configured(ExecutorSpawnConfig {
        output_cache,
        execute_policy: ExecutePolicy::Any,
        queue_capacity: 1,
        metrics: Arc::new(ExecutorMetrics::default()),
        producer_key: Arc::new(producer_key),
        provider_genesis: Arc::new(test_genesis()),
        assurance: test_assurance(),
        fetch_access_policy: FetchAccessPolicy::trusted_callers([caller_key]),
        fetch_routes: test_routes("echo", "run", provider, Arc::new(TestFetchAdaptorFactory)),
        fetch_max_in_flight,
        fetch_queue_capacity,
        fetch_replay_max_in_flight,
        fetch_store,
        #[cfg(feature = "evaluate")]
        artifact_store: ArtifactStoreConfig::memory(),
        #[cfg(feature = "evaluate")]
        content_store: ContentStore::new(),
        #[cfg(feature = "evaluate")]
        gpu_config: GpuConfig::default(),
    })
    .await
    .unwrap()
}

fn quota_request_view() -> FetchRequestView {
    FetchRequestView {
        service: "echo".to_string(),
        method: "run".to_string(),
        model: None,
        max_output_units: Some(90),
    }
}

async fn spawn_quota_fetch_executor(
    provider: Arc<dyn FetchProvider>,
    adaptor_factory: Arc<dyn FetchAdaptorFactory>,
    fetch_store: FetchTranscriptStoreBackend,
) -> crate::ExecutorHandle {
    spawn_quota_fetch_executor_with_store(
        provider,
        adaptor_factory,
        fetch_store,
        FetchQuotaStoreBackend::memory(),
    )
    .await
}

async fn spawn_quota_fetch_executor_with_store(
    provider: Arc<dyn FetchProvider>,
    adaptor_factory: Arc<dyn FetchAdaptorFactory>,
    fetch_store: FetchTranscriptStoreBackend,
    quota_store: FetchQuotaStoreBackend,
) -> crate::ExecutorHandle {
    let signing_key = key();
    let mut caller = CallerAccess::allow_all(signing_key.public_key());
    caller.spend = Some(SpendLimit {
        max_units: 100,
        window: Duration::from_secs(60),
    });
    Executor::spawn_configured(ExecutorSpawnConfig {
        output_cache: Default::default(),
        execute_policy: ExecutePolicy::Any,
        queue_capacity: 1,
        metrics: Arc::new(ExecutorMetrics::default()),
        producer_key: Arc::new(key()),
        provider_genesis: Arc::new(test_genesis()),
        assurance: test_assurance(),
        fetch_access_policy: FetchAccessPolicy::with_quota_store([caller], quota_store),
        fetch_routes: test_routes("echo", "run", provider, adaptor_factory),
        fetch_max_in_flight: 1,
        fetch_queue_capacity: 1,
        fetch_replay_max_in_flight: hellas_rpc::DEFAULT_FETCH_REPLAY_MAX_IN_FLIGHT,
        fetch_store,
        #[cfg(feature = "evaluate")]
        artifact_store: ArtifactStoreConfig::memory(),
        #[cfg(feature = "evaluate")]
        content_store: ContentStore::new(),
        #[cfg(feature = "evaluate")]
        gpu_config: GpuConfig::default(),
    })
    .await
    .unwrap()
}

async fn run_failed(
    handle: &crate::ExecutorHandle,
    ticket: hellas_rpc::pb::execute::Ticket,
    key: &ProducerSigningKey,
) -> WorkFailed {
    let outcome = handle
        .run_ticket_handle(run_ticket_request(ticket, key))
        .await
        .unwrap()
        .events;
    receive_failed(outcome).await
}

async fn receive_failed(mut outcome: crate::executor::ExecuteEventReceiver) -> WorkFailed {
    loop {
        let event = outcome.recv().await.unwrap().unwrap();
        match event.kind.unwrap() {
            work_event::Kind::Chunk(_) => {}
            work_event::Kind::Finished(finished) => {
                panic!("expected failed event, got finished: {finished:?}")
            }
            work_event::Kind::Failed(failed) => return failed,
        }
    }
}

#[tokio::test]
async fn fetch_execution_streams_mock_provider_and_replays_completed_transcript() {
    let signing_key = key();
    let input = br#"{"hello":"world"}"#;
    let provider = MockFetchProvider::new(test_environment());
    provider.insert(
        "echo",
        "run",
        input,
        [
            b"event:one".to_vec(),
            b"event:two".to_vec(),
            b"terminal:done".to_vec(),
        ],
    );
    let request = fetch_request(&signing_key, "echo", "run", input);
    let handle = Executor::spawn_with_fetch_routes(
        ExecutePolicy::Any,
        1,
        key(),
        test_genesis(),
        test_assurance(),
        test_routes(
            "echo",
            "run",
            Arc::new(provider.clone()),
            Arc::new(TestFetchAdaptorFactory),
        ),
    )
    .unwrap();
    let ticket = handle.create_fetch_ticket(request).await.unwrap().response;

    let (chunks, first) = run_one(&handle, ticket.clone(), &signing_key).await;
    let (replay_chunks, replayed) = run_one(&handle, ticket, &signing_key).await;

    assert_eq!(chunks.len(), 2);
    assert_eq!(replay_chunks, chunks);
    for (index, expected_payload) in [b"event:one".as_slice(), b"event:two"]
        .into_iter()
        .enumerate()
    {
        let chunk_event = chunks[index]
            .output_event
            .as_ref()
            .expect("fetch chunk should carry signed output event");
        assert_eq!(chunk_event.payload, expected_payload);
    }
    let first_terminal = first
        .terminal_output_event
        .as_ref()
        .expect("fetch completion should carry its terminal event");
    assert_eq!(
        decode_fetch_terminal_payload(&first_terminal.payload)
            .unwrap()
            .billable_units(),
        0
    );
    assert_eq!(replayed.terminal_output_event, first.terminal_output_event);
    assert_eq!(provider.calls("echo", "run", input), 1);
}

#[tokio::test]
async fn inference_cache_bypasses_unrelated_fetch_only_in_record_mode() {
    use hellas_rpc::cache::{CacheOptions, CachePolicy, CacheStore, MemoryCacheStore};
    for policy in [CachePolicy::Record, CachePolicy::ReplayOnly] {
        let signing_key = key();
        let body = br#"{"hello":"uncacheable"}"#;
        let provider = MockFetchProvider::new(test_environment());
        provider.insert("echo", "run", body, [b"terminal:done".to_vec()]);
        let store = Arc::new(MemoryCacheStore::default());
        let handle = spawn_fetch_executor_with_bounds(
            Arc::new(provider.clone()),
            1,
            1,
            1,
            FetchTranscriptStoreBackend::memory(),
            CacheOptions {
                policy,
                store: Some(store.clone()),
            },
        )
        .await;
        let ticket = handle
            .create_fetch_ticket(fetch_request(&signing_key, "echo", "run", body))
            .await
            .unwrap()
            .response;
        if policy == CachePolicy::Record {
            run_one(&handle, ticket, &signing_key).await;
            assert_eq!(provider.calls("echo", "run", body), 1);
        } else {
            let error = handle
                .run_ticket_handle(run_ticket_request(ticket, &signing_key))
                .await
                .unwrap_err();
            assert!(matches!(error, ExecutorError::PolicyDenied(_)));
            assert_eq!(provider.calls("echo", "run", body), 0);
        }
        assert!(store.list().unwrap().is_empty());
    }
}

#[tokio::test]
async fn inference_cache_reuses_fetch_across_callers_with_fresh_signatures() {
    use hellas_rpc::cache::{CacheOptions, CachePolicy, CacheStore, MemoryCacheStore};
    use hellas_rpc::output::{OutputEvent, TextChannel};

    struct InferenceAdaptor;
    impl FetchAdaptorFactory for InferenceAdaptor {
        fn execution_environment(&self) -> hellas_rpc::ContentId {
            hellas_rpc::FetchEnvironment::OpenAiResponses.manifest_id()
        }

        fn create(
            &self,
            request: &crate::FetchCall,
        ) -> Result<FetchAdaptorSession, FetchAdaptorError> {
            TestFetchAdaptorFactory.create(request)
        }
    }

    let environment = hellas_rpc::FetchEnvironment::OpenAiResponses.manifest_id();
    let body = br#"{"model":"fixture","input":"hello"}"#;
    let provider = MockFetchProvider::new(environment);
    provider.insert(
        "openai",
        "responses",
        body,
        [
            hellas_rpc::fetch::encode_fetch_event_payload(&OutputEvent::TextDelta {
                index: 0,
                delta: "cached".into(),
                channel: TextChannel::Output,
            })
            .unwrap(),
            b"terminal:done".to_vec(),
        ],
    );
    let callers = [
        key(),
        ProducerSigningKey::from_secret_bytes([3; 32]).unwrap(),
    ];
    let store = Arc::new(MemoryCacheStore::default());
    let handle = Executor::spawn_configured(ExecutorSpawnConfig {
        output_cache: CacheOptions {
            policy: CachePolicy::Record,
            store: Some(store.clone()),
        },
        execute_policy: ExecutePolicy::Any,
        queue_capacity: 1,
        metrics: Arc::new(ExecutorMetrics::default()),
        producer_key: Arc::new(key()),
        provider_genesis: Arc::new(test_genesis()),
        assurance: test_assurance(),
        fetch_access_policy: FetchAccessPolicy::trusted_callers(
            callers.iter().map(ProducerSigningKey::public_key),
        ),
        fetch_routes: test_routes(
            "openai",
            "responses",
            Arc::new(provider.clone()),
            Arc::new(InferenceAdaptor),
        ),
        fetch_max_in_flight: 2,
        fetch_queue_capacity: 2,
        fetch_replay_max_in_flight: 2,
        fetch_store: FetchTranscriptStoreBackend::memory(),
        #[cfg(feature = "evaluate")]
        artifact_store: ArtifactStoreConfig::memory(),
        #[cfg(feature = "evaluate")]
        content_store: ContentStore::new(),
        #[cfg(feature = "evaluate")]
        gpu_config: GpuConfig::default(),
    })
    .await
    .unwrap();

    let mut runs = Vec::new();
    for caller in &callers {
        let input = build_input_events(
            "openai",
            "responses",
            body,
            environment,
            test_assurance(),
            caller,
        )
        .unwrap();
        let commitment = hellas_rpc::fetch::verify_input_events(&input)
            .unwrap()
            .input_commitment;
        let ticket = handle
            .create_fetch_ticket(FetchRequest {
                input: input.iter().map(input_event_to_pb).collect(),
            })
            .await
            .unwrap()
            .response;
        let handle = handle.clone();
        runs.push(async move {
            let (chunks, finished) = run_one(&handle, ticket, caller).await;
            let mut output = chunks
                .into_iter()
                .map(|chunk| {
                    hellas_rpc::stream::output_event_from_pb(chunk.output_event.unwrap()).unwrap()
                })
                .collect::<Vec<_>>();
            output.push(
                hellas_rpc::stream::output_event_from_pb(finished.terminal_output_event.unwrap())
                    .unwrap(),
            );
            hellas_rpc::fetch::verify_output_events(commitment, test_assurance(), &output).unwrap();
            (commitment, output)
        });
    }
    let results = futures_util::future::join_all(runs).await;
    assert_ne!(results[0].0, results[1].0);
    assert_ne!(results[0].1, results[1].1);
    assert!(
        hellas_rpc::fetch::verify_output_events(results[1].0, test_assurance(), &results[0].1)
            .is_err()
    );
    assert_eq!(provider.calls("openai", "responses", body), 1);
    assert_eq!(store.list().unwrap().len(), 1);
}

#[tokio::test]
async fn live_fetch_larger_than_buffer_succeeds_for_a_draining_consumer() {
    let signing_key = key();
    let input = br#"{"hello":"many-events"}"#;
    let provider = MockFetchProvider::new(test_environment());
    let event_count = PER_EXECUTION_CHANNEL_CAPACITY * 2;
    let mut response = (0..event_count)
        .map(|_| b"event".to_vec())
        .collect::<Vec<_>>();
    response.push(b"terminal:done".to_vec());
    provider.insert("echo", "run", input, response);
    let request = fetch_request(&signing_key, "echo", "run", input);
    let handle = Executor::spawn_with_fetch_routes(
        ExecutePolicy::Any,
        1,
        key(),
        test_genesis(),
        test_assurance(),
        test_routes(
            "echo",
            "run",
            Arc::new(provider),
            Arc::new(TestFetchAdaptorFactory),
        ),
    )
    .unwrap();
    let ticket = handle.create_fetch_ticket(request).await.unwrap().response;

    let (chunks, _) = timeout(
        Duration::from_secs(1),
        run_one(&handle, ticket, &signing_key),
    )
    .await
    .unwrap();
    assert_eq!(chunks.len(), event_count);
}

#[tokio::test]
async fn fetch_execution_reports_unprogrammed_mock_provider_failure() {
    let signing_key = key();
    let input = br#"{"hello":"world"}"#;
    let provider = MockFetchProvider::new(test_environment());
    let request = fetch_request(&signing_key, "echo", "run", input);
    let handle = Executor::spawn_with_fetch_routes(
        ExecutePolicy::Any,
        1,
        key(),
        test_genesis(),
        test_assurance(),
        test_routes(
            "echo",
            "run",
            Arc::new(provider.clone()),
            Arc::new(TestFetchAdaptorFactory),
        ),
    )
    .unwrap();
    let ticket = handle.create_fetch_ticket(request).await.unwrap().response;

    let failed = run_failed(&handle, ticket, &signing_key).await;

    assert_eq!(failed.position, 0);
    assert!(failed.error.contains("mock fetch response not programmed"));
    assert_eq!(provider.calls("echo", "run", input), 1);
}

#[tokio::test]
async fn provider_failure_charges_the_maximum_spend_for_the_window() {
    let signing_key = key();
    let provider = MockFetchProvider::new(test_environment());
    let handle = spawn_quota_fetch_executor(
        Arc::new(provider),
        Arc::new(FixedViewFetchAdaptorFactory {
            view: quota_request_view(),
        }),
        FetchTranscriptStoreBackend::memory(),
    )
    .await;
    let first = fetch_request(&signing_key, "echo", "run", br#"{"request":1}"#);
    let second = fetch_request(&signing_key, "echo", "run", br#"{"request":2}"#);
    let first_ticket = handle.create_fetch_ticket(first).await.unwrap().response;
    let second_ticket = handle.create_fetch_ticket(second).await.unwrap().response;

    let failed = run_failed(&handle, first_ticket, &signing_key).await;
    assert!(failed.error.contains("mock fetch response not programmed"));

    let error = handle
        .run_ticket_handle(run_ticket_request(second_ticket, &signing_key))
        .await
        .unwrap_err();
    assert!(matches!(error, ExecutorError::QuotaExceeded { .. }));
}

#[tokio::test]
async fn invalid_terminal_charges_the_maximum_spend_for_the_window() {
    let signing_key = key();
    let provider = MockFetchProvider::new(test_environment());
    let first_body = br#"{"request":"invalid-terminal"}"#;
    provider.insert("echo", "run", first_body, [b"provider-body".to_vec()]);
    let handle = spawn_quota_fetch_executor(
        Arc::new(provider),
        Arc::new(InvalidTerminalFetchAdaptorFactory {
            view: quota_request_view(),
        }),
        FetchTranscriptStoreBackend::memory(),
    )
    .await;
    let first = fetch_request(&signing_key, "echo", "run", first_body);
    let second = fetch_request(
        &signing_key,
        "echo",
        "run",
        br#"{"request":"after-invalid-terminal"}"#,
    );
    let first_ticket = handle.create_fetch_ticket(first).await.unwrap().response;
    let second_ticket = handle.create_fetch_ticket(second).await.unwrap().response;

    let failed = run_failed(&handle, first_ticket, &signing_key).await;
    assert!(failed.error.contains("invalid quote request"));

    let error = handle
        .run_ticket_handle(run_ticket_request(second_ticket, &signing_key))
        .await
        .unwrap_err();
    assert!(matches!(error, ExecutorError::QuotaExceeded { .. }));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn complete_output_failure_keeps_actual_spend_and_running_evidence() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/hellas-fetch-completion-failure")
        .join(uuid::Uuid::new_v4().to_string());
    let signing_key = key();
    let provider = ReleasableFetchProvider::default();
    let handle = spawn_quota_fetch_executor(
        Arc::new(provider.clone()),
        Arc::new(FixedViewFetchAdaptorFactory {
            view: quota_request_view(),
        }),
        FetchTranscriptStoreBackend::fs(&root),
    )
    .await;
    let first = fetch_request(
        &signing_key,
        "echo",
        "run",
        br#"{"request":"completion-store-failure"}"#,
    );
    let second = fetch_request(
        &signing_key,
        "echo",
        "run",
        br#"{"request":"after-completion-store-failure"}"#,
    );
    let first_ticket = handle.create_fetch_ticket(first).await.unwrap().response;
    let second_ticket = handle.create_fetch_ticket(second).await.unwrap().response;
    let first_outcome = handle
        .run_ticket_handle(run_ticket_request(first_ticket, &signing_key))
        .await
        .unwrap();
    timeout(Duration::from_secs(1), async {
        while provider.calls() == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();

    std::fs::write(root.join(".retained-transcript-capacity"), b"invalid\n")
        .expect("corrupt completion-store metadata after provider dispatch");
    provider.release();
    let failed = receive_failed(first_outcome.events).await;
    assert!(failed.error.contains("capacity metadata"));

    std::fs::write(
        root.join(".retained-transcript-capacity"),
        format!(
            "{}\n",
            hellas_rpc::DEFAULT_FETCH_RETAINED_TRANSCRIPT_CAPACITY
        ),
    )
    .expect("restore completion-store metadata");
    let second_outcome = handle
        .run_ticket_handle(run_ticket_request(second_ticket, &signing_key))
        .await
        .unwrap();
    timeout(Duration::from_secs(2), drain_outcome(second_outcome.events))
        .await
        .unwrap();
    assert_eq!(provider.calls(), 2);

    drop(handle);
    let _ = std::fs::remove_dir_all(root);
}

#[tokio::test]
async fn ambiguous_admission_write_is_cancelled_without_calling_provider() {
    let signing_key = key();
    let caller_id = hellas_rpc::ProducerId::from_public_key(&signing_key.public_key());
    let provider = ReleasableFetchProvider::default();
    let transcript_store = MemoryFetchTranscriptStore::default();
    let quota_store = MemoryFetchQuotaStore::default();
    quota_store.fail_put_after_write_number(1);
    let handle = spawn_quota_fetch_executor_with_store(
        Arc::new(provider.clone()),
        Arc::new(FixedViewFetchAdaptorFactory {
            view: quota_request_view(),
        }),
        FetchTranscriptStoreBackend::Memory(transcript_store.clone()),
        FetchQuotaStoreBackend::Memory(quota_store.clone()),
    )
    .await;
    let (request, input) = fetch_request_and_commitment(
        &signing_key,
        "echo",
        "run",
        br#"{"request":"ambiguous-admission"}"#,
    );
    let ticket = handle.create_fetch_ticket(request).await.unwrap().response;

    let error = handle
        .run_ticket_handle(run_ticket_request(ticket, &signing_key))
        .await
        .unwrap_err();

    assert!(error.to_string().contains("post-write failure 1"));
    assert_eq!(provider.calls(), 0);
    assert!(!transcript_store.has_running(input).unwrap());
    assert_eq!(quota_store.puts(), 2);
    assert_eq!(quota_store.entry_count(caller_id), 0);
}

#[tokio::test]
async fn ambiguous_running_marker_write_is_rolled_back_before_quota_cancellation() {
    let signing_key = key();
    let caller_id = hellas_rpc::ProducerId::from_public_key(&signing_key.public_key());
    let provider = ReleasableFetchProvider::default();
    let transcript_store = MemoryFetchTranscriptStore::default();
    transcript_store.fail_next_running_put_after_write();
    let quota_store = MemoryFetchQuotaStore::default();
    let handle = spawn_quota_fetch_executor_with_store(
        Arc::new(provider.clone()),
        Arc::new(FixedViewFetchAdaptorFactory {
            view: quota_request_view(),
        }),
        FetchTranscriptStoreBackend::Memory(transcript_store.clone()),
        FetchQuotaStoreBackend::Memory(quota_store.clone()),
    )
    .await;
    let (request, input) = fetch_request_and_commitment(
        &signing_key,
        "echo",
        "run",
        br#"{"request":"ambiguous-marker"}"#,
    );
    let ticket = handle.create_fetch_ticket(request).await.unwrap().response;

    let error = handle
        .run_ticket_handle(run_ticket_request(ticket, &signing_key))
        .await
        .unwrap_err();

    assert!(
        error
            .to_string()
            .contains("running-marker post-write failure")
    );
    assert_eq!(provider.calls(), 0);
    assert!(!transcript_store.has_running(input).unwrap());
    assert_eq!(transcript_store.running_removals(), 1);
    assert_eq!(quota_store.puts(), 2);
    assert_eq!(quota_store.entry_count(caller_id), 0);
}

#[tokio::test]
async fn quota_reconciliation_is_a_barrier_before_successful_transcript_publication() {
    let signing_key = key();
    let body = br#"{"request":"accounting-barrier"}"#;
    let provider = MockFetchProvider::new(test_environment());
    provider.insert("echo", "run", body, [b"terminal:done".to_vec()]);
    let transcript_store = MemoryFetchTranscriptStore::default();
    let quota_store = MemoryFetchQuotaStore::default();
    // Admission and activation are puts 1 and 2. Reconciliation is put 3.
    quota_store.fail_put_number(3);
    let handle = spawn_quota_fetch_executor_with_store(
        Arc::new(provider.clone()),
        Arc::new(FixedViewFetchAdaptorFactory {
            view: quota_request_view(),
        }),
        FetchTranscriptStoreBackend::Memory(transcript_store.clone()),
        FetchQuotaStoreBackend::Memory(quota_store.clone()),
    )
    .await;
    let (request, input) = fetch_request_and_commitment(&signing_key, "echo", "run", body);
    let ticket = handle.create_fetch_ticket(request).await.unwrap().response;

    let failure = run_failed(&handle, ticket, &signing_key).await;

    assert!(failure.error.contains("quota reconciliation failed"));
    assert_eq!(provider.calls("echo", "run", body), 1);
    assert!(!transcript_store.has_completed(input).unwrap());
    assert!(transcript_store.has_running(input).unwrap());
    assert_eq!(quota_store.puts(), 4);
}

#[tokio::test]
async fn startup_settles_orphaned_dispatched_quota_for_one_fresh_window() {
    let signing_key = key();
    let quota_store = MemoryFetchQuotaStore::default();
    let mut caller = CallerAccess::allow_all(signing_key.public_key());
    caller.spend = Some(SpendLimit {
        max_units: 100,
        window: Duration::from_secs(60),
    });
    let mut previous = FetchAccessPolicy::with_quota_store(
        [caller],
        FetchQuotaStoreBackend::Memory(quota_store.clone()),
    );
    let admission = previous
        .authorize_admission(
            &signing_key.public_key(),
            &quota_request_view(),
            1_000,
            "previous-process".to_string(),
            InputCommitment::from_digest(Digest::from_bytes([4; 32])),
            &FetchRoutePolicy::default(),
        )
        .unwrap();
    previous
        .activate_reservation(admission.reservation.as_ref())
        .unwrap();
    drop(previous);

    let provider = ReleasableFetchProvider::default();
    let handle = spawn_quota_fetch_executor_with_store(
        Arc::new(provider.clone()),
        Arc::new(FixedViewFetchAdaptorFactory {
            view: quota_request_view(),
        }),
        FetchTranscriptStoreBackend::memory(),
        FetchQuotaStoreBackend::Memory(quota_store),
    )
    .await;
    let request = fetch_request(
        &signing_key,
        "echo",
        "run",
        br#"{"request":"fresh-process"}"#,
    );
    let ticket = handle.create_fetch_ticket(request).await.unwrap().response;

    let error = handle
        .run_ticket_handle(run_ticket_request(ticket, &signing_key))
        .await
        .unwrap_err();

    assert!(matches!(
        error,
        ExecutorError::QuotaExceeded {
            retry_after_ms: Some(_),
            ..
        }
    ));
    assert_eq!(provider.calls(), 0);
}

#[tokio::test]
async fn ambiguous_activation_write_never_calls_provider_and_cleans_running_marker() {
    let signing_key = key();
    let caller_id = hellas_rpc::ProducerId::from_public_key(&signing_key.public_key());
    let provider = ReleasableFetchProvider::default();
    let transcript_store = MemoryFetchTranscriptStore::default();
    let quota_store = MemoryFetchQuotaStore::default();
    // Admission is put 1. Put 2 persists Dispatched, then simulates losing
    // its acknowledgement. Cleanup must therefore accept Dispatched.
    quota_store.fail_put_after_write_number(2);
    let handle = spawn_quota_fetch_executor_with_store(
        Arc::new(provider.clone()),
        Arc::new(FixedViewFetchAdaptorFactory {
            view: quota_request_view(),
        }),
        FetchTranscriptStoreBackend::Memory(transcript_store.clone()),
        FetchQuotaStoreBackend::Memory(quota_store.clone()),
    )
    .await;
    let (request, input) = fetch_request_and_commitment(
        &signing_key,
        "echo",
        "run",
        br#"{"request":"ambiguous-activation"}"#,
    );
    let ticket = handle.create_fetch_ticket(request).await.unwrap().response;

    let error = handle
        .run_ticket_handle(run_ticket_request(ticket, &signing_key))
        .await
        .unwrap_err();

    assert!(error.to_string().contains("post-write failure 2"));
    assert_eq!(provider.calls(), 0);
    assert!(!transcript_store.has_running(input).unwrap());
    assert_eq!(transcript_store.running_removals(), 1);
    assert_eq!(quota_store.puts(), 4);
    assert_eq!(quota_store.entry_count(caller_id), 0);
}

#[tokio::test]
async fn failed_activation_cleanup_retries_without_retouching_fetch_state() {
    let signing_key = key();
    let provider = ReleasableFetchProvider::default();
    let transcript_store = MemoryFetchTranscriptStore::default();
    let quota_store = MemoryFetchQuotaStore::default();
    quota_store.fail_put_after_write_number(2);
    // Cancelling intent is put 3. Marker rollback succeeds, but the paired
    // ledger removal (put 4)
    // fails. The retained retry must remember that state is already clean.
    quota_store.fail_put_number(4);
    let handle = spawn_quota_fetch_executor_with_store(
        Arc::new(provider.clone()),
        Arc::new(FixedViewFetchAdaptorFactory {
            view: quota_request_view(),
        }),
        FetchTranscriptStoreBackend::Memory(transcript_store.clone()),
        FetchQuotaStoreBackend::Memory(quota_store.clone()),
    )
    .await;
    let (first, first_input) = fetch_request_and_commitment(
        &signing_key,
        "echo",
        "run",
        br#"{"request":"cleanup-retry"}"#,
    );
    let first_ticket = handle.create_fetch_ticket(first).await.unwrap().response;

    let first_error = handle
        .run_ticket_handle(run_ticket_request(first_ticket, &signing_key))
        .await
        .unwrap_err();
    assert!(first_error.to_string().contains("post-write failure 2"));
    assert_eq!(provider.calls(), 0);
    assert!(!transcript_store.has_running(first_input).unwrap());
    assert_eq!(transcript_store.running_removals(), 1);
    assert_eq!(quota_store.puts(), 4);

    // A later admission rewrites Cancelling at put 5 and releases it at
    // put 6. Its own reserve/activation are puts 7 and 8; success proves the old
    // Dispatched entry was retired instead of silently leaked.
    let second = fetch_request(
        &signing_key,
        "echo",
        "run",
        br#"{"request":"after-cleanup-retry"}"#,
    );
    let second_ticket = handle.create_fetch_ticket(second).await.unwrap().response;
    let second_outcome = handle
        .run_ticket_handle(run_ticket_request(second_ticket, &signing_key))
        .await
        .unwrap();
    timeout(Duration::from_secs(1), async {
        while provider.calls() == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(provider.calls(), 1);
    assert_eq!(quota_store.puts(), 8);
    assert_eq!(
        transcript_store.running_removals(),
        1,
        "quota retry must not repeat an already-successful state rollback"
    );

    provider.release();
    timeout(Duration::from_secs(2), drain_outcome(second_outcome.events))
        .await
        .unwrap();
}

#[tokio::test]
async fn fetch_execution_drops_upstream_immediately_after_terminal() {
    let provider = TerminalThenPanicFetchProvider::default();
    let input_commitment = InputCommitment::from_digest(Digest::from_bytes([5; 32]));
    let call = crate::FetchCall::new(
        "echo",
        "run",
        hellas_rpc::JsonBytes::new(br#"{"hello":"world"}"#.to_vec()),
        input_commitment,
    );
    let request = PreparedFetchRequest::new(&call, call.body.clone());
    let (sender, _receiver) = mpsc::channel(PER_EXECUTION_CHANNEL_CAPACITY);
    let signing_key = key();

    let result = run_fetch_provider(
        Arc::new(provider.clone()),
        request,
        Box::new(TestFetchProjector {
            terminal_seen: false,
        }),
        input_commitment,
        test_assurance(),
        &signing_key,
        sender,
    )
    .await;
    let Ok(run) = result else {
        panic!("terminal-only Fetch provider unexpectedly failed");
    };

    assert_eq!(provider.polls(), 1);
    assert_eq!(run.output_events.len(), 1);
}

#[tokio::test]
async fn fetch_projection_rejects_event_buffered_after_terminal() {
    let signing_key = key();
    let input_commitment = InputCommitment::from_digest(Digest::from_bytes([6; 32]));
    let mut builder =
        FetchOutputTranscriptBuilder::new(input_commitment, test_assurance(), &signing_key);
    let mut terminal = None;
    let mut projection_budget = FetchProjectionBudget::default();
    let mut position = 0;
    let (sender, _receiver) = mpsc::channel(PER_EXECUTION_CHANNEL_CAPACITY);

    let result = process_projected_fetch(
        vec![
            ProjectedFetch::Terminal(vec![1]),
            ProjectedFetch::Event(vec![2]),
        ],
        &mut builder,
        &mut terminal,
        &mut projection_budget,
        &mut position,
        &sender,
    )
    .await;
    let Err(error) = result else {
        panic!("event buffered after terminal unexpectedly passed projection");
    };

    assert!(error.error.to_string().contains("event after terminal"));
    assert_eq!(projection_budget.events, 1);
}

#[tokio::test(start_paused = true)]
async fn fetch_projection_preserves_one_permit_for_failure_terminal() {
    let signing_key = key();
    let input_commitment = InputCommitment::from_digest(Digest::from_bytes([8; 32]));
    let mut builder =
        FetchOutputTranscriptBuilder::new(input_commitment, test_assurance(), &signing_key);
    let mut terminal = None;
    let mut projection_budget = FetchProjectionBudget::default();
    let mut position = 0;
    let (sender, mut receiver) = mpsc::channel(PER_EXECUTION_CHANNEL_CAPACITY);
    for _ in 0..PER_EXECUTION_CHANNEL_CAPACITY - 1 {
        sender
            .try_send(Ok(WorkEvent {
                kind: Some(work_event::Kind::Chunk(WorkChunk { output_event: None })),
            }))
            .unwrap();
    }
    assert_eq!(sender.capacity(), 1);

    let error = process_projected_fetch(
        vec![ProjectedFetch::Event(b"never-signed".to_vec())],
        &mut builder,
        &mut terminal,
        &mut projection_budget,
        &mut position,
        &sender,
    )
    .await
    .unwrap_err();

    assert!(error.error.to_string().contains("did not drain"));
    assert_eq!(position, 0);
    assert_eq!(projection_budget.events, 0);
    assert_eq!(projection_budget.signed_payload_bytes, 0);
    send_fetch_failed(&sender, position, error.error.to_string());
    assert_eq!(sender.capacity(), 0);
    for _ in 0..PER_EXECUTION_CHANNEL_CAPACITY - 1 {
        assert!(matches!(
            receiver.recv().await.unwrap().unwrap().kind,
            Some(work_event::Kind::Chunk(_))
        ));
    }
    assert!(matches!(
        receiver.recv().await.unwrap().unwrap().kind,
        Some(work_event::Kind::Failed(WorkFailed { position: 0, .. }))
    ));
}

#[tokio::test(start_paused = true)]
async fn fetch_projection_waits_for_temporary_backpressure_then_delivers_in_order() {
    let signing_key = key();
    let input = InputCommitment::from_digest(Digest::from_bytes([8; 32]));
    let mut builder = FetchOutputTranscriptBuilder::new(input, test_assurance(), &signing_key);
    let mut terminal = None;
    let mut budget = FetchProjectionBudget::default();
    let mut position = 0;
    let (sender, mut receiver) = mpsc::channel(2);
    sender
        .try_send(Ok(WorkEvent {
            kind: Some(work_event::Kind::Chunk(WorkChunk { output_event: None })),
        }))
        .unwrap();
    let delayed_reader = async {
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert!(receiver.recv().await.unwrap().unwrap().kind.is_some());
        let event = receiver.recv().await.unwrap().unwrap();
        assert!(matches!(
            event.kind,
            Some(work_event::Kind::Chunk(WorkChunk {
                output_event: Some(_)
            }))
        ));
    };
    let deliver = process_projected_fetch(
        vec![ProjectedFetch::Event(b"delayed".to_vec())],
        &mut builder,
        &mut terminal,
        &mut budget,
        &mut position,
        &sender,
    );
    let (result, ()) = tokio::join!(deliver, delayed_reader);
    let Ok(reached_terminal) = result else {
        panic!("temporary backpressure truncated the response");
    };
    assert!(!reached_terminal);
    assert_eq!(position, 7);
    assert_eq!(budget.events, 1);
}

#[tokio::test]
async fn retained_replay_waits_for_a_consumer_without_losing_events() {
    let signing_key = key();
    let input_commitment = InputCommitment::from_digest(Digest::from_bytes([10; 32]));
    let mut builder =
        FetchOutputTranscriptBuilder::new(input_commitment, test_assurance(), &signing_key);
    for _ in 0..PER_EXECUTION_CHANNEL_CAPACITY {
        builder.push_event(vec![1]).unwrap();
    }
    let terminal = hellas_rpc::fetch::encode_fetch_terminal_payload(
        &hellas_rpc::output::OutputEvent::Finished {
            stop_reason: hellas_rpc::output::StopReason::EndOfText,
            usage: None,
        },
    )
    .unwrap();
    let output_events = builder.finish(terminal).unwrap();
    let outcome = fetch_finished_outcome(
        ExecutionProvenance {
            commitment_id: [11; 32],
        },
        &output_events,
    )
    .await
    .unwrap();
    let mut receiver = outcome.events;

    timeout(Duration::from_secs(1), async {
        while receiver.len() < PER_EXECUTION_CHANNEL_CAPACITY {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(receiver.len(), PER_EXECUTION_CHANNEL_CAPACITY);
    for _ in 0..PER_EXECUTION_CHANNEL_CAPACITY {
        assert!(matches!(
            receiver.recv().await.unwrap().unwrap().kind,
            Some(work_event::Kind::Chunk(_))
        ));
    }
    assert!(matches!(
        receiver.recv().await.unwrap().unwrap().kind,
        Some(work_event::Kind::Finished(_))
    ));
    assert!(receiver.recv().await.is_none());
}

#[tokio::test]
async fn retained_replay_larger_than_buffer_succeeds_for_a_draining_consumer() {
    let signing_key = key();
    let input_commitment = InputCommitment::from_digest(Digest::from_bytes([12; 32]));
    let mut builder =
        FetchOutputTranscriptBuilder::new(input_commitment, test_assurance(), &signing_key);
    let event_count = PER_EXECUTION_CHANNEL_CAPACITY * 2;
    for _ in 0..event_count {
        builder.push_event(vec![1]).unwrap();
    }
    let terminal = hellas_rpc::fetch::encode_fetch_terminal_payload(
        &hellas_rpc::output::OutputEvent::Finished {
            stop_reason: hellas_rpc::output::StopReason::EndOfText,
            usage: None,
        },
    )
    .unwrap();
    let output_events = builder.finish(terminal).unwrap();
    let outcome = fetch_finished_outcome(
        ExecutionProvenance {
            commitment_id: [13; 32],
        },
        &output_events,
    )
    .await
    .unwrap();
    let mut receiver = outcome.events;
    let mut chunks = 0;

    timeout(Duration::from_secs(1), async {
        loop {
            match receiver.recv().await.unwrap().unwrap().kind.unwrap() {
                work_event::Kind::Chunk(_) => chunks += 1,
                work_event::Kind::Finished(_) => break,
                work_event::Kind::Failed(failed) => {
                    panic!("draining replay failed: {}", failed.error)
                }
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(chunks, event_count);
}

#[test]
fn fetch_projection_budget_caps_event_count_and_payload_bytes() {
    let mut event_budget = FetchProjectionBudget {
        events: MAX_FETCH_OUTPUT_EVENTS - 2,
        signed_payload_bytes: 0,
    };
    event_budget.record_event(0).unwrap();
    let event_error = event_budget.record_event(0).unwrap_err();
    assert!(
        event_error
            .to_string()
            .contains(&format!("{}-event limit", MAX_FETCH_OUTPUT_EVENTS - 1))
    );
    assert_eq!(event_budget.events, MAX_FETCH_OUTPUT_EVENTS - 1);
    event_budget.record_terminal(0).unwrap();
    assert_eq!(event_budget.events, MAX_FETCH_OUTPUT_EVENTS);

    let mut payload_budget = FetchProjectionBudget {
        events: 0,
        signed_payload_bytes: MAX_FETCH_OUTPUT_PAYLOAD_BYTES - 1,
    };
    payload_budget.record_event(1).unwrap();
    let payload_error = payload_budget.record_event(1).unwrap_err();
    assert!(payload_error.to_string().contains(&format!(
        "{MAX_FETCH_OUTPUT_PAYLOAD_BYTES}-byte signed payload limit"
    )));
    assert_eq!(
        payload_budget.signed_payload_bytes,
        MAX_FETCH_OUTPUT_PAYLOAD_BYTES
    );
}

#[tokio::test]
async fn projected_payload_limit_is_reported_as_work_failed() {
    let signing_key = key();
    let input = br#"{"hello":"large"}"#;
    let provider = MockFetchProvider::new(test_environment());
    provider.insert(
        "echo",
        "run",
        input,
        [
            vec![b'x'; MAX_FETCH_OUTPUT_PAYLOAD_BYTES + 1],
            b"terminal:done".to_vec(),
        ],
    );
    let request = fetch_request(&signing_key, "echo", "run", input);
    let handle = Executor::spawn_with_fetch_routes(
        ExecutePolicy::Any,
        1,
        key(),
        test_genesis(),
        test_assurance(),
        test_routes(
            "echo",
            "run",
            Arc::new(provider),
            Arc::new(TestFetchAdaptorFactory),
        ),
    )
    .unwrap();
    let ticket = handle.create_fetch_ticket(request).await.unwrap().response;

    let failed = run_failed(&handle, ticket, &signing_key).await;

    assert_eq!(failed.position, 0);
    assert!(failed.error.contains(&format!(
        "{MAX_FETCH_OUTPUT_PAYLOAD_BYTES}-byte signed payload limit"
    )));
}

#[tokio::test]
async fn fetch_quote_missing_route_does_not_poison_ticket_state() {
    let signing_key = key();
    let provider = MockFetchProvider::new(test_environment());
    let handle = spawn_fetch_executor(Arc::new(provider), 1, 1).await;
    let request = fetch_request(&signing_key, "missing", "run", br#"{"hello":"world"}"#);

    for _ in 0..2 {
        let err = handle
            .create_fetch_ticket(request.clone())
            .await
            .unwrap_err();
        assert!(matches!(err, ExecutorError::PolicyDenied(_)));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn run_ticket_with_recovered_running_marker_reports_indeterminate() {
    use crate::fetch::{FetchRunningRecord, FetchTranscriptStore, FsFetchTranscriptStore};

    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/hellas-fetch-actor-indeterminate")
        .join(uuid::Uuid::new_v4().simple().to_string());
    let signing_key = key();
    let events = build_input_events(
        "echo",
        "run",
        br#"{"hello":"crash"}"#,
        test_environment(),
        test_assurance(),
        &signing_key,
    )
    .unwrap();
    let input = hellas_rpc::fetch::verify_input_events(&events)
        .unwrap()
        .input_commitment;

    // Simulate a previous process that crashed mid-run: only the durable
    // running marker survives; the transient quote store is empty.
    let marker_store = FsFetchTranscriptStore::new(dir.join("fetch-transcripts"));
    marker_store.init().unwrap();
    marker_store
        .put_running(
            input,
            &FetchRunningRecord {
                service: "echo".to_string(),
                method: "run".to_string(),
                caller_public_key: String::new(),
                started_at_unix_ms: 0,
                idempotency_key: input.digest().to_string(),
            },
        )
        .unwrap();

    let handle = Executor::spawn_configured(ExecutorSpawnConfig {
        output_cache: Default::default(),
        execute_policy: ExecutePolicy::Any,
        queue_capacity: 1,
        metrics: Arc::new(ExecutorMetrics::default()),
        producer_key: Arc::new(key()),
        provider_genesis: Arc::new(test_genesis()),
        assurance: test_assurance(),
        fetch_access_policy: FetchAccessPolicy::trusted_callers([signing_key.public_key()]),
        fetch_routes: test_routes(
            "echo",
            "run",
            Arc::new(MockFetchProvider::new(test_environment())),
            Arc::new(TestFetchAdaptorFactory),
        ),
        fetch_max_in_flight: 1,
        fetch_queue_capacity: 1,
        fetch_replay_max_in_flight: hellas_rpc::DEFAULT_FETCH_REPLAY_MAX_IN_FLIGHT,
        fetch_store: FetchTranscriptStoreBackend::fs(dir.join("fetch-transcripts")),
        #[cfg(feature = "evaluate")]
        artifact_store: ArtifactStoreConfig::memory(),
        #[cfg(feature = "evaluate")]
        content_store: ContentStore::new(),
        #[cfg(feature = "evaluate")]
        gpu_config: GpuConfig::default(),
    })
    .await
    .unwrap();

    let ticket = crate::state::quote_ticket(
        hellas_rpc::RequestCommitment::from_digest(input.digest()),
        &test_genesis(),
        test_assurance(),
    )
    .unwrap()
    .1;
    let err = handle
        .run_ticket_handle(run_ticket_request(ticket, &signing_key))
        .await
        .unwrap_err();

    assert!(
        err.to_string().contains("indeterminate"),
        "expected indeterminate, got: {err}"
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn fetch_policy_denial_does_not_start_provider() {
    let signing_key = key();
    let caller_key = signing_key.public_key();
    let provider = ReleasableFetchProvider::default();
    let policy = FetchAccessPolicy::new([CallerAccess::explicit(
        caller_key,
        [FetchRouteGrant {
            route: FetchRoute::new("codex", "responses"),
            policy: FetchRoutePolicy {
                allowed_models: Some(BTreeSet::from(["allowed-model".to_string()])),
                max_output_units: Some(8),
            },
        }],
    )]);
    let projector = FixedViewFetchAdaptorFactory {
        view: FetchRequestView {
            service: "codex".to_string(),
            method: "responses".to_string(),
            model: Some("denied-model".to_string()),
            max_output_units: Some(4),
        },
    };
    let handle = Executor::spawn_configured(ExecutorSpawnConfig {
        output_cache: Default::default(),
        execute_policy: ExecutePolicy::Any,
        queue_capacity: 1,
        metrics: Arc::new(ExecutorMetrics::default()),
        producer_key: Arc::new(key()),
        provider_genesis: Arc::new(test_genesis()),
        assurance: test_assurance(),
        fetch_access_policy: policy,
        fetch_routes: test_routes(
            "codex",
            "responses",
            Arc::new(provider.clone()),
            Arc::new(projector),
        ),
        fetch_max_in_flight: 1,
        fetch_queue_capacity: 1,
        fetch_replay_max_in_flight: hellas_rpc::DEFAULT_FETCH_REPLAY_MAX_IN_FLIGHT,
        fetch_store: FetchTranscriptStoreBackend::memory(),
        #[cfg(feature = "evaluate")]
        artifact_store: ArtifactStoreConfig::memory(),
        #[cfg(feature = "evaluate")]
        content_store: ContentStore::new(),
        #[cfg(feature = "evaluate")]
        gpu_config: GpuConfig::default(),
    })
    .await
    .unwrap();
    let request = fetch_request(&signing_key, "codex", "responses", br#"{"model":"x"}"#);
    let ticket = handle.create_fetch_ticket(request).await.unwrap().response;

    let err = handle
        .run_ticket_handle(run_ticket_request(ticket, &signing_key))
        .await
        .unwrap_err();

    assert!(matches!(err, ExecutorError::PolicyDenied(_)));
    assert_eq!(provider.calls(), 0);
}

#[tokio::test]
async fn retained_capacity_refusal_never_starts_provider() {
    let signing_key = key();
    let provider = ReleasableFetchProvider::default();
    let handle = spawn_fetch_executor_with_bounds(
        Arc::new(provider.clone()),
        1,
        1,
        1,
        FetchTranscriptStoreBackend::memory_with_capacity(0),
        Default::default(),
    )
    .await;
    let request = fetch_request(&signing_key, "echo", "run", br#"{"n":1}"#);
    let ticket = handle.create_fetch_ticket(request).await.unwrap().response;

    let error = handle
        .run_ticket_handle(run_ticket_request(ticket, &signing_key))
        .await
        .unwrap_err();

    assert!(matches!(&error, ExecutorError::ResourceExhausted(_)));
    assert!(
        error
            .to_string()
            .contains("retained Fetch transcript capacity of 0 is exhausted")
    );
    assert_eq!(provider.calls(), 0);
}

#[tokio::test]
async fn queued_retained_capacity_refusal_fails_and_discards_ticket() {
    let signing_key = key();
    let provider = ReleasableFetchProvider::default();
    let handle = spawn_fetch_executor_with_bounds(
        Arc::new(provider.clone()),
        1,
        1,
        1,
        FetchTranscriptStoreBackend::memory_with_capacity(1),
        Default::default(),
    )
    .await;
    let first = fetch_request(&signing_key, "echo", "run", br#"{"n":1}"#);
    let second = fetch_request(&signing_key, "echo", "run", br#"{"n":2}"#);
    let first_ticket = handle.create_fetch_ticket(first).await.unwrap().response;
    let second_ticket = handle
        .create_fetch_ticket(second.clone())
        .await
        .unwrap()
        .response;
    let first_outcome = handle
        .run_ticket_handle(run_ticket_request(first_ticket, &signing_key))
        .await
        .unwrap();
    let second_outcome = handle
        .run_ticket_handle(run_ticket_request(second_ticket, &signing_key))
        .await
        .unwrap();

    provider.release();
    timeout(Duration::from_secs(2), drain_outcome(first_outcome.events))
        .await
        .unwrap();
    let failed = timeout(Duration::from_secs(2), async move {
        let mut events = second_outcome.events;
        loop {
            let event = events.recv().await.unwrap().unwrap();
            if let Some(work_event::Kind::Failed(failed)) = event.kind {
                break failed;
            }
        }
    })
    .await
    .unwrap();

    assert!(
        failed
            .error
            .contains("retained Fetch transcript capacity of 1 is exhausted")
    );
    assert_eq!(provider.calls(), 1);
    // Dispatch refusal removed the dead Queued entry: the same signed
    // request can be quoted again, then fails synchronously at admission
    // rather than getting stuck as AlreadyQueued.
    let retried_ticket = handle.create_fetch_ticket(second).await.unwrap().response;
    let retried = handle
        .run_ticket_handle(run_ticket_request(retried_ticket, &signing_key))
        .await
        .unwrap_err();
    assert!(matches!(retried, ExecutorError::ResourceExhausted(_)));
    assert_eq!(provider.calls(), 1);
}

#[tokio::test]
async fn replay_slot_lives_until_terminal_is_drained_or_receiver_is_dropped() {
    let signing_key = key();
    let input = br#"{"replay":"bounded"}"#;
    let provider = MockFetchProvider::new(test_environment());
    provider.insert("echo", "run", input, [b"terminal:done".to_vec()]);
    let transcript_store = MemoryFetchTranscriptStore::default();
    let handle = spawn_fetch_executor_with_bounds(
        Arc::new(provider.clone()),
        1,
        1,
        1,
        FetchTranscriptStoreBackend::Memory(transcript_store.clone()),
        Default::default(),
    )
    .await;
    let ticket = handle
        .create_fetch_ticket(fetch_request(&signing_key, "echo", "run", input))
        .await
        .unwrap()
        .response;
    run_one(&handle, ticket.clone(), &signing_key).await;

    let unauthorized_key = ProducerSigningKey::from_secret_bytes([8; 32]).expect("valid test key");
    let completed_loads = transcript_store.completed_loads();
    let replay_verifications = transcript_store.replay_verifications();
    let unauthorized = handle
        .run_ticket_handle(run_ticket_request(ticket.clone(), &unauthorized_key))
        .await
        .unwrap_err();
    assert!(
        matches!(unauthorized, ExecutorError::PolicyDenied(_)),
        "{unauthorized:?}"
    );
    assert_eq!(transcript_store.completed_loads(), completed_loads + 1);
    assert_eq!(
        transcript_store.replay_verifications(),
        replay_verifications,
        "a mismatched untrusted caller claim must reject before signature work"
    );

    let replay = handle
        .run_ticket_handle(run_ticket_request(ticket.clone(), &signing_key))
        .await
        .unwrap();
    assert_eq!(
        transcript_store.replay_verifications(),
        replay_verifications + 1,
        "a matching claim still requires complete transcript verification"
    );
    timeout(Duration::from_secs(1), async {
        while replay.events.is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let completed_loads = transcript_store.completed_loads();
    let replay_verifications = transcript_store.replay_verifications();
    let refused = handle
        .run_ticket_handle(run_ticket_request(ticket.clone(), &signing_key))
        .await
        .unwrap_err();
    assert!(matches!(refused, ExecutorError::ResourceExhausted(_)));
    assert_eq!(transcript_store.completed_loads(), completed_loads);
    assert_eq!(
        transcript_store.replay_verifications(),
        replay_verifications
    );

    // Draining the already-buffered terminal releases the first slot.
    drain_outcome(replay.events).await;
    let drained_retry = timeout(Duration::from_secs(1), async {
        loop {
            match handle
                .run_ticket_handle(run_ticket_request(ticket.clone(), &signing_key))
                .await
            {
                Ok(outcome) => break outcome,
                Err(ExecutorError::ResourceExhausted(_)) => tokio::task::yield_now().await,
                Err(error) => panic!("unexpected replay error: {error}"),
            }
        }
    })
    .await
    .unwrap();
    drain_outcome(drained_retry.events).await;

    // Dropping an undrained receiver is the other release path.
    let dropped = timeout(Duration::from_secs(1), async {
        loop {
            match handle
                .run_ticket_handle(run_ticket_request(ticket.clone(), &signing_key))
                .await
            {
                Ok(outcome) => break outcome,
                Err(ExecutorError::ResourceExhausted(_)) => tokio::task::yield_now().await,
                Err(error) => panic!("unexpected replay error: {error}"),
            }
        }
    })
    .await
    .unwrap();
    drop(dropped.events);
    let after_drop = timeout(Duration::from_secs(1), async {
        loop {
            match handle
                .run_ticket_handle(run_ticket_request(ticket.clone(), &signing_key))
                .await
            {
                Ok(outcome) => break outcome,
                Err(ExecutorError::ResourceExhausted(_)) => tokio::task::yield_now().await,
                Err(error) => panic!("unexpected replay error: {error}"),
            }
        }
    })
    .await
    .unwrap();
    drain_outcome(after_drop.events).await;
    assert_eq!(provider.calls("echo", "run", input), 1);
}

#[tokio::test]
async fn fetch_queue_full_leaves_ticket_retryable() {
    let signing_key = key();
    let provider = ReleasableFetchProvider::default();
    let handle = spawn_fetch_executor(Arc::new(provider.clone()), 1, 0).await;
    let first = fetch_request(&signing_key, "echo", "run", br#"{"n":1}"#);
    let second = fetch_request(&signing_key, "echo", "run", br#"{"n":2}"#);
    let first_ticket = handle.create_fetch_ticket(first).await.unwrap().response;
    let second_ticket = handle.create_fetch_ticket(second).await.unwrap().response;

    let first_outcome = handle
        .run_ticket_handle(run_ticket_request(first_ticket, &signing_key))
        .await
        .unwrap();
    let error = handle
        .run_ticket_handle(run_ticket_request(second_ticket.clone(), &signing_key))
        .await
        .unwrap_err();
    assert!(matches!(error, ExecutorError::QueueFull { capacity: 0 }));

    provider.release();
    let (_, first_finished) = timeout(Duration::from_secs(2), drain_outcome(first_outcome.events))
        .await
        .unwrap();
    assert!(first_finished.terminal_output_event.is_some());

    let (chunks, second_finished) = timeout(
        Duration::from_secs(2),
        run_one(&handle, second_ticket, &signing_key),
    )
    .await
    .unwrap();
    assert_eq!(chunks.len(), 1);
    assert!(second_finished.terminal_output_event.is_some());
    assert_eq!(provider.calls(), 2);
}

#[tokio::test]
async fn fetch_queue_dispatches_after_active_completion() {
    let signing_key = key();
    let provider = ReleasableFetchProvider::default();
    let handle = spawn_fetch_executor(Arc::new(provider.clone()), 1, 1).await;
    let first = fetch_request(&signing_key, "echo", "run", br#"{"n":1}"#);
    let second = fetch_request(&signing_key, "echo", "run", br#"{"n":2}"#);
    let first_ticket = handle.create_fetch_ticket(first).await.unwrap().response;
    let second_ticket = handle.create_fetch_ticket(second).await.unwrap().response;

    let first_outcome = handle
        .run_ticket_handle(run_ticket_request(first_ticket, &signing_key))
        .await
        .unwrap();
    let second_outcome = handle
        .run_ticket_handle(run_ticket_request(second_ticket, &signing_key))
        .await
        .unwrap();

    provider.release();
    let (_, first_finished) = timeout(Duration::from_secs(2), drain_outcome(first_outcome.events))
        .await
        .unwrap();
    let (second_chunks, second_finished) =
        timeout(Duration::from_secs(2), drain_outcome(second_outcome.events))
            .await
            .unwrap();

    assert!(first_finished.terminal_output_event.is_some());
    assert_eq!(second_chunks.len(), 1);
    assert!(second_finished.terminal_output_event.is_some());
    assert_eq!(provider.calls(), 2);
}

#[cfg(feature = "otel")]
#[tokio::test]
async fn queued_fetch_preserves_each_request_parent_when_dispatched_later() {
    use opentelemetry::trace::TracerProvider;
    use opentelemetry_sdk::trace::{InMemorySpanExporter, SdkTracerProvider};
    use tracing::Instrument;
    use tracing_subscriber::prelude::*;

    struct TracedProvider(ReleasableFetchProvider);
    impl FetchProvider for TracedProvider {
        fn execution_environment(&self) -> hellas_rpc::ContentId {
            test_environment()
        }
        fn run(&self, request: PreparedFetchRequest) -> FetchProviderFuture<'_> {
            Box::pin(
                self.0
                    .run(request)
                    .instrument(tracing::info_span!("test.fetch.provider")),
            )
        }
    }

    let exporter = InMemorySpanExporter::default();
    let tracer_provider = SdkTracerProvider::builder()
        .with_simple_exporter(exporter.clone())
        .build();
    // This fixture uses Tokio's current-thread runtime, including the actor
    // and the detached provider tasks. No process-global subscriber is changed.
    let subscriber = tracing_subscriber::registry()
        .with(tracing_opentelemetry::layer().with_tracer(tracer_provider.tracer("test")));
    let _subscriber = tracing::subscriber::set_default(subscriber);
    let signing_key = key();
    let provider = ReleasableFetchProvider::default();
    let handle = spawn_fetch_executor(Arc::new(TracedProvider(provider.clone())), 1, 1).await;
    let first_ticket = handle
        .create_fetch_ticket(fetch_request(&signing_key, "echo", "run", br#"{"n":1}"#))
        .await
        .unwrap()
        .response;
    let second_ticket = handle
        .create_fetch_ticket(fetch_request(&signing_key, "echo", "run", br#"{"n":2}"#))
        .await
        .unwrap()
        .response;

    let first_parent = tracing::info_span!(parent: None, "test.first.request");
    let second_parent = tracing::info_span!(parent: None, "test.queued.request");
    let first_outcome = handle
        .run_ticket_handle(run_ticket_request(first_ticket, &signing_key))
        .instrument(first_parent.clone())
        .await
        .unwrap();
    timeout(Duration::from_secs(2), async {
        while provider.calls() != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let second_outcome = handle
        .run_ticket_handle(run_ticket_request(second_ticket, &signing_key))
        .instrument(second_parent.clone())
        .await
        .unwrap();
    assert_eq!(
        provider.calls(),
        1,
        "the second request must actually be queued"
    );
    drop(first_parent);
    drop(second_parent);

    provider.release();
    for outcome in [first_outcome, second_outcome] {
        let (_, finished) = timeout(Duration::from_secs(2), drain_outcome(outcome.events))
            .await
            .unwrap();
        assert!(finished.terminal_output_event.is_some());
    }
    assert_eq!(provider.calls(), 2);
    // Each provider task sends its completion after the terminal event. Wait
    // for those tasks to release their retained parent spans before inspecting.
    timeout(Duration::from_secs(2), async {
        while exporter.get_finished_spans().unwrap().len() < 4 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    tracer_provider.force_flush().unwrap();
    let spans = exporter.get_finished_spans().unwrap();
    assert_eq!(spans.len(), 4);
    let parents = ["test.first.request", "test.queued.request"]
        .map(|name| spans.iter().find(|span| span.name == name).unwrap());
    assert_ne!(
        parents[0].span_context.trace_id(),
        parents[1].span_context.trace_id()
    );
    for parent in parents {
        assert_eq!(
            spans
                .iter()
                .filter(|span| {
                    span.name == "test.fetch.provider"
                        && span.parent_span_id == parent.span_context.span_id()
                        && span.span_context.trace_id() == parent.span_context.trace_id()
                })
                .count(),
            1,
            "provider execution must retain its own admission parent"
        );
    }
    tracer_provider.shutdown().unwrap();
}
