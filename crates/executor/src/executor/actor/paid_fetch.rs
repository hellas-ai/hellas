//! Paid Fetch runs have their own durable admission in hellas-work. Bodies
//! remain in memory; neither Courtesy replay nor its transcript store is used.

use std::sync::Arc;

use hellas_rpc::OutputEventEnvelope;
use hellas_work::work::PreparedFetchInput;
use tokio::sync::{mpsc, oneshot};
use tracing::Instrument as _;

use super::Executor;
use crate::ExecutorError;
use crate::executor::ExecutorCompletion;
use crate::fetch_policy::FetchRoute;
use crate::fetch_provider::FetchCall;

impl Executor {
    /// Admits one journaled paid Fetch, or refuses it before any provider
    /// work begins.
    ///
    /// Capacity refusal is deliberately fail-fast: the work layer journals it
    /// as that job's terminal failure rather than queueing, unlike paid
    /// Evaluate, which waits for a dispatch slot. A paid burst beyond
    /// `fetch_max_in_flight` therefore ends the excess jobs, so operators
    /// should size the limit for paid bursts, not for average load.
    pub(super) fn start_paid_fetch(
        &mut self,
        input: PreparedFetchInput,
        progress: Option<hellas_work::work::PaidProgress>,
        reply: oneshot::Sender<Result<Vec<OutputEventEnvelope>, ExecutorError>>,
        span: tracing::Span,
    ) {
        let prepared = self.prepare_paid_fetch(input);
        let (entry, session, request, policy) = match prepared {
            Ok(prepared) => prepared,
            Err(error) => {
                let _ = reply.send(Err(error));
                return;
            }
        };
        self.active_fetches += 1;
        let completion = self.completion_tx.clone();
        let key = Arc::clone(&self.provider.producer_key);
        let task = async move {
            let (sender, mut receiver) =
                mpsc::channel(super::execution::PER_EXECUTION_CHANNEL_CAPACITY);
            let run = super::execution::run_fetch_provider(
                entry.provider,
                session.provider_request,
                session.projector,
                request.input_commitment,
                request.assurance,
                &key,
                sender,
            );
            let drain = async move {
                while let Some(event) = receiver.recv().await {
                    let event =
                        event.map_err(|error| ExecutorError::Execution(error.to_string()))?;
                    if let Some(hellas_rpc::pb::execute::work_event::Kind::Chunk(chunk)) =
                        event.kind
                        && let Some(progress) = &progress
                    {
                        let event = chunk.output_event.ok_or_else(|| {
                            ExecutorError::Execution(
                                "paid Fetch chunk omitted its signature".into(),
                            )
                        })?;
                        let event = hellas_rpc::stream::output_event_from_pb(event)
                            .map_err(|error| ExecutorError::Execution(error.to_string()))?;
                        progress(event)
                            .map_err(|error| ExecutorError::Execution(error.to_string()))?;
                    }
                }
                Ok::<_, ExecutorError>(())
            };
            let (result, drained) = tokio::join!(run, drain);
            let result = drained.and_then(|()| {
                result
                    .map_err(|failure| {
                        // The peer receives the sanitized message below; the
                        // operator needs the position and cause to tell
                        // upstream, transport and projection faults apart.
                        tracing::warn!(
                            position = failure.position,
                            error = %failure.error,
                            "paid fetch upstream or projection failed"
                        );
                        ExecutorError::Execution("paid fetch upstream or projection failed".into())
                    })
                    .and_then(|run| {
                        hellas_rpc::protocol::work_fetch::check_fetch_output_limits(
                            &policy,
                            &run.output_events,
                        )
                        .map_err(|_| {
                            ExecutorError::Execution(
                                "paid fetch output exceeds its signed limits".into(),
                            )
                        })?;
                        Ok(run.output_events)
                    })
            });
            let _ = completion
                .send(ExecutorCompletion::PaidFetch { reply, result })
                .await;
        };
        tokio::spawn(task.instrument(span));
    }

    fn prepare_paid_fetch(
        &self,
        input: PreparedFetchInput,
    ) -> Result<
        (
            crate::FetchRouteEntry,
            crate::FetchAdaptorSession,
            hellas_rpc::fetch::FetchInput,
            hellas_rpc::protocol::work_fetch::PaidFetchPolicyV1,
        ),
        ExecutorError,
    > {
        if self.active_fetches >= self.fetch_max_in_flight {
            return Err(ExecutorError::ResourceExhausted(
                "fetch concurrency limit reached".into(),
            ));
        }
        let policy = *input.policy();
        let parts = input.into_parts();
        let request = hellas_rpc::fetch::verify_input_events(&parts.fetch_input_transcript)
            .map_err(|_| ExecutorError::InvalidQuoteRequest("invalid paid fetch input".into()))?;
        if request.retention != hellas_rpc::Retention::Ephemeral
            || request.assurance != self.provider.assurance
            || request.execution_environment != parts.manifest.content_id()
        {
            return Err(ExecutorError::InvalidQuoteRequest(
                "paid fetch contract mismatch".into(),
            ));
        }
        let route = FetchRoute::new(&request.service, &request.method);
        let entry = self.fetch_routes.entry(&route).cloned().ok_or_else(|| {
            ExecutorError::InvalidQuoteRequest("paid fetch route is unavailable".into())
        })?;
        if entry.execution_environment() != request.execution_environment {
            return Err(ExecutorError::InvalidQuoteRequest(
                "paid fetch route manifest mismatch".into(),
            ));
        }
        let call = FetchCall::new(
            &request.service,
            &request.method,
            request.body.clone(),
            request.input_commitment,
        );
        let session = entry.adaptor_factory.create(&call).map_err(|_| {
            ExecutorError::InvalidQuoteRequest("paid fetch adaptor rejected request".into())
        })?;
        entry
            .capabilities
            .validate(&session.request_view)
            .map_err(|_| {
                ExecutorError::PolicyDenied("paid fetch exceeds route capabilities".into())
            })?;
        Ok((entry, session, request, policy))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::Duration;

    use futures_util::stream;
    use hellas_rpc::fetch::{
        FetchTerminalPayload, build_input_events_with_retention, decode_fetch_event_payload,
        decode_fetch_terminal_payload, encode_fetch_event_payload, encode_fetch_terminal_payload,
        verify_input_events, verify_output_events,
    };
    use hellas_rpc::output::{OutputEvent, StopReason, TextChannel};
    use hellas_rpc::protocol::work_fetch::{PaidFetchPolicyV1, PreparedPaidFetchInputParts};
    use hellas_rpc::{
        Assurance, ContentId, Digest, FetchEnvironment, InputCommitment, InputEventEnvelope,
        ProducerSigningKey, Retention,
    };
    use hellas_work::work::PaidProgress;
    use tokio::sync::Notify;
    use tokio::time::timeout;

    use super::*;
    use crate::ExecutorSpawnConfig;
    use crate::executor::{ExecutorHandle, ExecutorOwedRequest};
    use crate::fetch_policy::FetchRoutePolicy;
    use crate::fetch_projection::{
        FetchAdaptorError, FetchAdaptorFactory, FetchAdaptorSession, FetchProjector,
        FetchRequestView, ProjectedFetch,
    };
    use crate::fetch_provider::{
        FetchProvider, FetchProviderFuture, FetchProviderResponse, FetchProviderResponseHead,
        FetchProviderStream, MockFetchProvider, PreparedFetchRequest,
    };
    use crate::fetch_registry::{FetchRouteEntry, FetchRouteRegistry};

    const SERVICE: &str = "openai";
    const METHOD: &str = "responses";
    const BODY: &[u8] = br#"{"input":"paid"}"#;

    fn environment() -> FetchEnvironment {
        FetchEnvironment::OpenAiResponses
    }

    fn signing_key() -> ProducerSigningKey {
        ProducerSigningKey::from_secret_bytes([7; 32]).expect("valid test key")
    }

    fn input_events(retention: Retention, assurance: Assurance) -> Vec<InputEventEnvelope> {
        build_input_events_with_retention(
            SERVICE,
            METHOD,
            BODY,
            environment().manifest_id(),
            assurance,
            &signing_key(),
            retention,
        )
        .expect("test input transcript builds")
    }

    fn policy() -> PaidFetchPolicyV1 {
        PaidFetchPolicyV1 {
            allowed_environment: environment().manifest_id(),
            route_commitment: Digest::from_bytes([3; 32]),
            max_request_body_bytes: 4096,
            max_output_events: 64,
            max_output_bytes: 16384,
            max_spool_bytes: 65536,
            max_encoded_result_frame: 65536,
            max_encoded_prepared_input: 65536,
            dispatch_margin_blocks: 4,
            delivery_margin_blocks: 2,
            oracle_grace_blocks: 6,
            fixed_price: 7,
        }
    }

    fn prepared_input(events: Vec<InputEventEnvelope>) -> PreparedFetchInput {
        PreparedFetchInput::new(
            PreparedPaidFetchInputParts {
                fetch_input_transcript: events,
                manifest: environment().manifest(),
            },
            policy(),
        )
    }

    struct StubFetchAdaptorFactory {
        environment: ContentId,
        reject: bool,
    }

    impl FetchAdaptorFactory for StubFetchAdaptorFactory {
        fn execution_environment(&self) -> ContentId {
            self.environment
        }

        fn create(&self, request: &FetchCall) -> Result<FetchAdaptorSession, FetchAdaptorError> {
            if self.reject {
                return Err(FetchAdaptorError::failed(
                    "stub adaptor rejects the request",
                ));
            }
            Ok(FetchAdaptorSession {
                request_view: FetchRequestView::from_call(request),
                provider_request: PreparedFetchRequest::new(request, request.body.clone()),
                projector: Box::new(StubFetchProjector { projected: false }),
            })
        }
    }

    struct StubFetchProjector {
        projected: bool,
    }

    impl FetchProjector for StubFetchProjector {
        fn project(&mut self, _bytes: &[u8]) -> Result<Vec<ProjectedFetch>, FetchAdaptorError> {
            if std::mem::replace(&mut self.projected, true) {
                return Ok(Vec::new());
            }
            let event = encode_fetch_event_payload(&OutputEvent::TextDelta {
                index: 0,
                delta: "paid-output".to_string(),
                channel: TextChannel::Output,
            })
            .map_err(|error| FetchAdaptorError::failed(error.to_string()))?;
            let terminal = encode_fetch_terminal_payload(&OutputEvent::Finished {
                stop_reason: StopReason::EndOfText,
                usage: None,
            })
            .map_err(|error| FetchAdaptorError::failed(error.to_string()))?;
            Ok(vec![
                ProjectedFetch::Event(event),
                ProjectedFetch::Terminal(terminal),
            ])
        }

        fn finish(&mut self) -> Result<Vec<ProjectedFetch>, FetchAdaptorError> {
            Ok(Vec::new())
        }
    }

    #[derive(Clone)]
    struct BlockingFetchProvider {
        environment: ContentId,
        started: Arc<AtomicUsize>,
        released: Arc<AtomicBool>,
        notify: Arc<Notify>,
    }

    impl BlockingFetchProvider {
        fn new(environment: ContentId) -> Self {
            Self {
                environment,
                started: Arc::new(AtomicUsize::new(0)),
                released: Arc::new(AtomicBool::new(false)),
                notify: Arc::new(Notify::new()),
            }
        }

        fn started(&self) -> usize {
            self.started.load(Ordering::SeqCst)
        }

        fn release(&self) {
            self.released.store(true, Ordering::SeqCst);
            self.notify.notify_waiters();
        }
    }

    impl FetchProvider for BlockingFetchProvider {
        fn execution_environment(&self) -> ContentId {
            self.environment
        }

        fn run(&self, _request: PreparedFetchRequest) -> FetchProviderFuture<'_> {
            let started = Arc::clone(&self.started);
            let released = Arc::clone(&self.released);
            let notify = Arc::clone(&self.notify);
            Box::pin(async move {
                started.fetch_add(1, Ordering::SeqCst);
                while !released.load(Ordering::SeqCst) {
                    notify.notified().await;
                }
                Ok(FetchProviderResponse {
                    head: FetchProviderResponseHead::default(),
                    stream: Box::pin(stream::iter([Ok(b"chunk".to_vec())])) as FetchProviderStream,
                })
            })
        }
    }

    fn routes(
        provider: Arc<dyn FetchProvider>,
        adaptor_factory: Arc<dyn FetchAdaptorFactory>,
        capabilities: FetchRoutePolicy,
    ) -> FetchRouteRegistry {
        let mut registry = FetchRouteRegistry::new();
        registry
            .register(
                FetchRoute::new(SERVICE, METHOD),
                FetchRouteEntry::new(provider, adaptor_factory, capabilities)
                    .expect("test provider and adaptor identities match"),
            )
            .expect("test route registers");
        registry
    }

    fn stub_adaptor(environment: ContentId) -> Arc<dyn FetchAdaptorFactory> {
        Arc::new(StubFetchAdaptorFactory {
            environment,
            reject: false,
        })
    }

    async fn spawn_executor(
        routes: FetchRouteRegistry,
        fetch_max_in_flight: usize,
    ) -> ExecutorHandle {
        let mut config = ExecutorSpawnConfig::fetch_only(
            Arc::new(signing_key()),
            Arc::new(b"paid-fetch-tests".to_vec()),
            Assurance::ProducerSigned,
            routes,
        );
        config.fetch_max_in_flight = fetch_max_in_flight;
        Executor::spawn_configured(config)
            .await
            .expect("test executor spawns")
    }

    async fn spawn_stub_executor(provider: MockFetchProvider) -> ExecutorHandle {
        spawn_executor(
            routes(
                Arc::new(provider),
                stub_adaptor(environment().manifest_id()),
                FetchRoutePolicy::default(),
            ),
            1,
        )
        .await
    }

    async fn run_paid_fetch(
        handle: &ExecutorHandle,
        input: PreparedFetchInput,
        progress: Option<PaidProgress>,
    ) -> Result<Vec<OutputEventEnvelope>, ExecutorError> {
        let (reply, receive) = oneshot::channel();
        handle
            .owed_tx
            .send(ExecutorOwedRequest::RunPaidFetch {
                span: tracing::Span::none(),
                input: Box::new(input),
                progress,
                reply,
            })
            .await
            .expect("owed ingress remains open");
        timeout(Duration::from_secs(5), receive)
            .await
            .expect("paid fetch answers within the test budget")
            .expect("actor answers the paid fetch")
    }

    fn commitment_of(events: &[InputEventEnvelope]) -> InputCommitment {
        verify_input_events(events)
            .expect("test input verifies")
            .input_commitment
    }

    #[tokio::test]
    async fn paid_fetch_rejects_a_tampered_input_transcript() {
        let handle = spawn_stub_executor(MockFetchProvider::new(environment().manifest_id())).await;
        let mut events = input_events(Retention::Ephemeral, Assurance::ProducerSigned);
        let foreign = build_input_events_with_retention(
            SERVICE,
            METHOD,
            BODY,
            environment().manifest_id(),
            Assurance::ProducerSigned,
            &ProducerSigningKey::from_secret_bytes([8; 32]).expect("valid foreign key"),
            Retention::Ephemeral,
        )
        .expect("foreign transcript builds");
        // Both halves are well formed; the spliced terminal event fails
        // signature verification under the transcript's signer.
        *events.last_mut().expect("input transcript has events") = foreign
            .last()
            .expect("foreign transcript has events")
            .clone();

        let result = run_paid_fetch(&handle, prepared_input(events), None).await;

        assert!(
            matches!(result, Err(ExecutorError::InvalidQuoteRequest(error)) if error == "invalid paid fetch input")
        );
    }

    #[tokio::test]
    async fn paid_fetch_rejects_retained_input() {
        let handle = spawn_stub_executor(MockFetchProvider::new(environment().manifest_id())).await;
        let events = input_events(Retention::Retain, Assurance::ProducerSigned);

        let result = run_paid_fetch(&handle, prepared_input(events), None).await;

        assert!(
            matches!(result, Err(ExecutorError::InvalidQuoteRequest(error)) if error == "paid fetch contract mismatch")
        );
    }

    #[tokio::test]
    async fn paid_fetch_rejects_mismatched_assurance() {
        let handle = spawn_stub_executor(MockFetchProvider::new(environment().manifest_id())).await;
        let events = input_events(Retention::Ephemeral, Assurance::AppleAppAttest);

        let result = run_paid_fetch(&handle, prepared_input(events), None).await;

        assert!(
            matches!(result, Err(ExecutorError::InvalidQuoteRequest(error)) if error == "paid fetch contract mismatch")
        );
    }

    #[tokio::test]
    async fn paid_fetch_rejects_a_manifest_other_than_the_signed_environment() {
        let handle = spawn_stub_executor(MockFetchProvider::new(environment().manifest_id())).await;
        // The transcript is valid but signs another environment than the
        // bundled manifest commits to.
        let events = build_input_events_with_retention(
            SERVICE,
            METHOD,
            BODY,
            ContentId::from_bytes([8; 32]),
            Assurance::ProducerSigned,
            &signing_key(),
            Retention::Ephemeral,
        )
        .expect("foreign environment transcript builds");

        let result = run_paid_fetch(&handle, prepared_input(events), None).await;

        assert!(
            matches!(result, Err(ExecutorError::InvalidQuoteRequest(error)) if error == "paid fetch contract mismatch")
        );
    }

    #[tokio::test]
    async fn paid_fetch_rejects_an_unregistered_route() {
        let handle = spawn_executor(FetchRouteRegistry::new(), 1).await;
        let events = input_events(Retention::Ephemeral, Assurance::ProducerSigned);

        let result = run_paid_fetch(&handle, prepared_input(events), None).await;

        assert!(
            matches!(result, Err(ExecutorError::InvalidQuoteRequest(error)) if error == "paid fetch route is unavailable")
        );
    }

    #[tokio::test]
    async fn paid_fetch_rejects_a_route_for_another_environment() {
        let other = ContentId::from_bytes([8; 32]);
        let handle = spawn_executor(
            routes(
                Arc::new(MockFetchProvider::new(other)),
                stub_adaptor(other),
                FetchRoutePolicy::default(),
            ),
            1,
        )
        .await;
        let events = input_events(Retention::Ephemeral, Assurance::ProducerSigned);

        let result = run_paid_fetch(&handle, prepared_input(events), None).await;

        assert!(
            matches!(result, Err(ExecutorError::InvalidQuoteRequest(error)) if error == "paid fetch route manifest mismatch")
        );
    }

    #[tokio::test]
    async fn paid_fetch_rejects_an_adaptor_refusal_without_reaching_the_provider() {
        let provider = MockFetchProvider::new(environment().manifest_id());
        let handle = spawn_executor(
            routes(
                Arc::new(provider.clone()),
                Arc::new(StubFetchAdaptorFactory {
                    environment: environment().manifest_id(),
                    reject: true,
                }),
                FetchRoutePolicy::default(),
            ),
            1,
        )
        .await;
        let events = input_events(Retention::Ephemeral, Assurance::ProducerSigned);

        let result = run_paid_fetch(&handle, prepared_input(events), None).await;

        assert!(
            matches!(result, Err(ExecutorError::InvalidQuoteRequest(error)) if error == "paid fetch adaptor rejected request")
        );
        assert_eq!(provider.calls(SERVICE, METHOD, BODY), 0);
    }

    #[tokio::test]
    async fn paid_fetch_rejects_a_request_beyond_route_capabilities() {
        let capabilities = FetchRoutePolicy {
            allowed_models: Some(BTreeSet::from(["gpt-5".to_string()])),
            max_output_units: None,
        };
        let handle = spawn_executor(
            routes(
                Arc::new(MockFetchProvider::new(environment().manifest_id())),
                stub_adaptor(environment().manifest_id()),
                capabilities,
            ),
            1,
        )
        .await;
        let events = input_events(Retention::Ephemeral, Assurance::ProducerSigned);

        let result = run_paid_fetch(&handle, prepared_input(events), None).await;

        assert!(
            matches!(result, Err(ExecutorError::PolicyDenied(error)) if error == "paid fetch exceeds route capabilities")
        );
    }

    #[tokio::test]
    async fn paid_fetch_at_capacity_fails_fast_instead_of_queueing() {
        let provider = BlockingFetchProvider::new(environment().manifest_id());
        let handle = spawn_executor(
            routes(
                Arc::new(provider.clone()),
                stub_adaptor(environment().manifest_id()),
                FetchRoutePolicy::default(),
            ),
            1,
        )
        .await;
        let first_events = input_events(Retention::Ephemeral, Assurance::ProducerSigned);
        let first_commitment = commitment_of(&first_events);
        let first = tokio::spawn({
            let handle = handle.clone();
            async move { run_paid_fetch(&handle, prepared_input(first_events), None).await }
        });
        timeout(Duration::from_secs(5), async {
            while provider.started() == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("first paid fetch reaches the provider");

        // The single slot is occupied: the refusal must arrive while the
        // first fetch is still blocked, not after it drains.
        let second = run_paid_fetch(
            &handle,
            prepared_input(input_events(
                Retention::Ephemeral,
                Assurance::ProducerSigned,
            )),
            None,
        )
        .await;
        assert!(
            matches!(second, Err(ExecutorError::ResourceExhausted(error)) if error == "fetch concurrency limit reached")
        );

        provider.release();
        let output = first
            .await
            .expect("first paid fetch task completes")
            .expect("first paid fetch succeeds");
        assert_eq!(provider.started(), 1);
        verify_output_events(first_commitment, Assurance::ProducerSigned, &output)
            .expect("first paid fetch output verifies");
    }

    #[tokio::test]
    async fn paid_fetch_streams_signed_progress_and_returns_signed_output() {
        let provider = MockFetchProvider::new(environment().manifest_id());
        provider.insert(SERVICE, METHOD, BODY, [b"chunk".to_vec()]);
        let handle = spawn_stub_executor(provider.clone()).await;
        let events = input_events(Retention::Ephemeral, Assurance::ProducerSigned);
        let input_commitment = commitment_of(&events);
        let progressed = Arc::new(AtomicUsize::new(0));
        let progress: PaidProgress = {
            let progressed = Arc::clone(&progressed);
            Arc::new(move |event| {
                assert_eq!(
                    event.event().body().kind(),
                    hellas_rpc::fetch::OUTPUT_EVENT_KIND
                );
                progressed.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
        };

        let output = run_paid_fetch(&handle, prepared_input(events), Some(progress))
            .await
            .expect("paid fetch succeeds");

        assert_eq!(progressed.load(Ordering::SeqCst), 1);
        assert_eq!(provider.calls(SERVICE, METHOD, BODY), 1);
        let verified = verify_output_events(input_commitment, Assurance::ProducerSigned, &output)
            .expect("paid fetch output verifies");
        assert_eq!(verified.producer_key, signing_key().public_key());
        let (payloads, terminal) = verified.output_event_payloads();
        let [payload] = payloads else {
            panic!("one streamed event before the terminal")
        };
        assert!(matches!(
            decode_fetch_event_payload(payload),
            Ok(OutputEvent::TextDelta { .. })
        ));
        assert!(matches!(
            decode_fetch_terminal_payload(terminal),
            Ok(FetchTerminalPayload::Finished { .. })
        ));
    }
}
