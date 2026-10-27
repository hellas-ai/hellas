//! Bounded Fetch projection independent of transcript signing.
use crate::executor::FetchProviderFailure;
use crate::fetch_projection::{FetchProjector, ProjectedFetch};
use crate::fetch_provider::{
    FetchProvider, FetchProviderError, FetchProviderStream, PreparedFetchRequest,
};
use futures_core::Stream;
use futures_util::{StreamExt, stream};
use hellas_rpc::fetch::{MAX_FETCH_OUTPUT_EVENTS, MAX_FETCH_OUTPUT_PAYLOAD_BYTES};
use std::{collections::VecDeque, sync::Arc};

#[derive(Debug, Default)]
struct FetchProjectionBudget {
    events: usize,
    signed_payload_bytes: usize,
}

impl FetchProjectionBudget {
    fn record_event(&mut self, payload_len: usize) -> Result<u64, FetchProviderError> {
        let streamed_event_limit = MAX_FETCH_OUTPUT_EVENTS
            .checked_sub(1)
            .expect("Fetch output limit includes one terminal event");
        self.record(payload_len, streamed_event_limit)
    }

    fn record_terminal(&mut self, payload_len: usize) -> Result<(), FetchProviderError> {
        self.record(payload_len, MAX_FETCH_OUTPUT_EVENTS)
            .map(|_| ())
    }

    fn record(
        &mut self,
        payload_len: usize,
        event_limit: usize,
    ) -> Result<u64, FetchProviderError> {
        let events = self.events.checked_add(1).ok_or_else(|| {
            FetchProviderError::failed(format!(
                "fetch projection exceeded the {event_limit}-event limit"
            ))
        })?;
        let signed_payload_bytes = self
            .signed_payload_bytes
            .checked_add(payload_len)
            .ok_or_else(|| {
                FetchProviderError::failed(format!(
                    "fetch projection exceeded the {MAX_FETCH_OUTPUT_PAYLOAD_BYTES}-byte signed payload limit"
                ))
            })?;
        if events > event_limit {
            return Err(FetchProviderError::failed(format!(
                "fetch projection exceeded the {event_limit}-event limit"
            )));
        }
        if signed_payload_bytes > MAX_FETCH_OUTPUT_PAYLOAD_BYTES {
            return Err(FetchProviderError::failed(format!(
                "fetch projection exceeded the {MAX_FETCH_OUTPUT_PAYLOAD_BYTES}-byte signed payload limit"
            )));
        }

        self.events = events;
        self.signed_payload_bytes = signed_payload_bytes;
        u64::try_from(payload_len)
            .map_err(|_| FetchProviderError::failed("fetch output position overflow"))
    }
}

struct Projection {
    provider: Arc<dyn FetchProvider>,
    request: Option<PreparedFetchRequest>,
    projector: Box<dyn FetchProjector>,
    response: Option<FetchProviderStream>,
    pending: VecDeque<ProjectedFetch>,
    budget: FetchProjectionBudget,
    position: u64,
    body_finished: bool,
    done: bool,
}
impl Projection {
    fn failure(&self, error: FetchProviderError) -> FetchProviderFailure {
        FetchProviderFailure {
            position: self.position,
            error,
        }
    }
    fn projection_failure(&self, error: crate::FetchAdaptorError) -> FetchProviderFailure {
        self.failure(FetchProviderError::failed(format!(
            "fetch projection failed: {error}"
        )))
    }
}

/// Pulling one item applies backpressure to the provider without a second queue.
/// Dropping this stream also drops the response body and projector.
pub(crate) fn project_fetch(
    provider: Arc<dyn FetchProvider>,
    request: PreparedFetchRequest,
    projector: Box<dyn FetchProjector>,
) -> impl Stream<Item = Result<ProjectedFetch, FetchProviderFailure>> + Send {
    let state = Projection {
        provider,
        request: Some(request),
        projector,
        response: None,
        pending: VecDeque::new(),
        budget: FetchProjectionBudget::default(),
        position: 0,
        body_finished: false,
        done: false,
    };
    stream::try_unfold(state, |mut state| async move {
        loop {
            if state.done {
                return Ok(None);
            }
            if let Some(item) = state.pending.pop_front() {
                match &item {
                    ProjectedFetch::Event(payload) => {
                        let bytes = state
                            .budget
                            .record_event(payload.len())
                            .map_err(|error| state.failure(error))?;
                        state.position = state.position.checked_add(bytes).ok_or_else(|| {
                            state.failure(FetchProviderError::failed(
                                "fetch output position overflow",
                            ))
                        })?;
                    }
                    ProjectedFetch::Terminal(payload) => {
                        state
                            .budget
                            .record_terminal(payload.len())
                            .map_err(|error| state.failure(error))?;
                        if let Some(next) = state.pending.front() {
                            let error = match next {
                                ProjectedFetch::Event(_) => {
                                    "fetch projection emitted an event after terminal"
                                }
                                ProjectedFetch::Terminal(_) => {
                                    "fetch projection emitted multiple terminal events"
                                }
                            };
                            return Err(state.failure(FetchProviderError::failed(error)));
                        }
                        // End the provider connection before handing over its terminal.
                        state.response = None;
                        state.done = true;
                    }
                }
                return Ok(Some((item, state)));
            }
            if let Some(request) = state.request.take() {
                let response = state
                    .provider
                    .run(request)
                    .await
                    .map_err(|error| state.failure(error))?;
                state.pending = state
                    .projector
                    .begin(response.head)
                    .map_err(|error| state.projection_failure(error))?
                    .into();
                state.response = Some(response.stream);
                continue;
            }
            if state.body_finished {
                return Err(state.failure(FetchProviderError::failed(
                    "fetch provider ended without terminal event",
                )));
            }
            match state
                .response
                .as_mut()
                .expect("provider started")
                .next()
                .await
            {
                Some(chunk) => {
                    let chunk = chunk.map_err(|error| state.failure(error))?;
                    state.pending = state
                        .projector
                        .project(&chunk)
                        .map_err(|error| state.projection_failure(error))?
                        .into();
                }
                None => {
                    state.response = None;
                    state.body_finished = true;
                    state.pending = state
                        .projector
                        .finish()
                        .map_err(|error| state.projection_failure(error))?
                        .into();
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fetch_provider::{
        FetchProviderFuture, FetchProviderResponse, FetchProviderResponseHead,
    };
    use crate::{FetchAdaptorError, FetchCall, MockFetchProvider};
    use hellas_auth::Digest;
    use hellas_rpc::{ContentId, InputCommitment, JsonBytes};
    use std::{
        pin::Pin,
        sync::atomic::{AtomicBool, AtomicUsize, Ordering},
        task::{Context, Poll},
    };

    #[derive(Clone)]
    struct Projector {
        head: Vec<ProjectedFetch>,
        tail: Vec<ProjectedFetch>,
        finishes: Arc<AtomicUsize>,
    }
    impl FetchProjector for Projector {
        fn begin(
            &mut self,
            _: FetchProviderResponseHead,
        ) -> Result<Vec<ProjectedFetch>, FetchAdaptorError> {
            Ok(std::mem::take(&mut self.head))
        }
        fn project(&mut self, bytes: &[u8]) -> Result<Vec<ProjectedFetch>, FetchAdaptorError> {
            Ok(vec![ProjectedFetch::Event(bytes.to_vec())])
        }
        fn finish(&mut self) -> Result<Vec<ProjectedFetch>, FetchAdaptorError> {
            self.finishes.fetch_add(1, Ordering::SeqCst);
            Ok(std::mem::take(&mut self.tail))
        }
    }
    impl crate::FetchAdaptorFactory for Projector {
        fn execution_environment(&self) -> ContentId {
            hellas_channel::test_support::test_responses_contract().manifest_id()
        }
        fn create(
            &self,
            call: &FetchCall,
        ) -> Result<crate::FetchAdaptorSession, FetchAdaptorError> {
            Ok(crate::FetchAdaptorSession {
                request_view: crate::FetchRequestView::from_call(call),
                provider_request: PreparedFetchRequest::new(call, call.body.clone()),
                projector: Box::new(self.clone()),
            })
        }
    }
    fn projector(
        head: Vec<ProjectedFetch>,
        tail: Vec<ProjectedFetch>,
    ) -> (Box<dyn FetchProjector>, Arc<AtomicUsize>) {
        let finishes = Arc::new(AtomicUsize::new(0));
        (
            Box::new(Projector {
                head,
                tail,
                finishes: finishes.clone(),
            }),
            finishes,
        )
    }
    fn request() -> PreparedFetchRequest {
        PreparedFetchRequest::new(
            &FetchCall::new(
                "http",
                "fetch",
                JsonBytes(b"{}".to_vec()),
                InputCommitment::from_digest(Digest::from_bytes([5; 32])),
            ),
            JsonBytes(b"{}".to_vec()),
        )
    }
    fn provider(chunks: Vec<Vec<u8>>) -> Arc<MockFetchProvider> {
        let provider = Arc::new(MockFetchProvider::new(
            hellas_channel::test_support::test_responses_contract().manifest_id(),
        ));
        provider.insert("http", "fetch", b"{}".to_vec(), chunks);
        provider
    }
    fn ok(next: Option<Result<ProjectedFetch, FetchProviderFailure>>) -> ProjectedFetch {
        next.expect("expected projected item")
            .unwrap_or_else(|failure| panic!("{}", failure.error))
    }

    #[tokio::test]
    async fn projection_preserves_exact_bytes_and_finishes_once() {
        let provider = provider(vec![vec![0, 255, 1], vec![9, 8]]);
        let (projector, finishes) = projector(vec![], vec![ProjectedFetch::Terminal(vec![7, 6])]);
        let mut projected = Box::pin(project_fetch(provider.clone(), request(), projector));
        assert_eq!(
            ok(projected.next().await),
            ProjectedFetch::Event(vec![0, 255, 1])
        );
        assert_eq!(
            ok(projected.next().await),
            ProjectedFetch::Event(vec![9, 8])
        );
        assert_eq!(
            ok(projected.next().await),
            ProjectedFetch::Terminal(vec![7, 6])
        );
        assert!(projected.next().await.is_none());
        assert_eq!(finishes.load(Ordering::SeqCst), 1);
        assert_eq!(provider.calls("http", "fetch", b"{}".to_vec()), 1);
    }

    struct TrackedBody {
        dropped: Arc<AtomicBool>,
        polls: Arc<AtomicUsize>,
    }
    impl Stream for TrackedBody {
        type Item = Result<Vec<u8>, FetchProviderError>;
        fn poll_next(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            if self.polls.fetch_add(1, Ordering::SeqCst) == 0 {
                Poll::Ready(Some(Ok(hellas_rpc::fetch::encode_fetch_event_payload(
                    &hellas_rpc::output::OutputEvent::TextDelta {
                        index: 0,
                        delta: "x".into(),
                        channel: hellas_rpc::output::TextChannel::Output,
                    },
                )
                .unwrap())))
            } else {
                Poll::Pending
            }
        }
    }
    impl Drop for TrackedBody {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::SeqCst);
        }
    }
    struct TrackedProvider {
        dropped: Arc<AtomicBool>,
        polls: Arc<AtomicUsize>,
    }
    impl FetchProvider for TrackedProvider {
        fn execution_environment(&self) -> ContentId {
            hellas_channel::test_support::test_responses_contract().manifest_id()
        }
        fn run(&self, _: PreparedFetchRequest) -> FetchProviderFuture<'_> {
            Box::pin(async {
                Ok(FetchProviderResponse {
                    head: Default::default(),
                    stream: Box::pin(TrackedBody {
                        dropped: self.dropped.clone(),
                        polls: self.polls.clone(),
                    }),
                })
            })
        }
    }
    fn tracked() -> Arc<TrackedProvider> {
        Arc::new(TrackedProvider {
            dropped: Arc::new(AtomicBool::new(false)),
            polls: Arc::new(AtomicUsize::new(0)),
        })
    }

    #[tokio::test]
    async fn a_terminal_from_the_response_head_closes_the_body_before_delivery() {
        let provider = tracked();
        let (projector, finishes) = projector(vec![ProjectedFetch::Terminal(vec![1])], vec![]);
        let mut projected = Box::pin(project_fetch(provider.clone(), request(), projector));
        assert_eq!(
            ok(projected.next().await),
            ProjectedFetch::Terminal(vec![1])
        );
        assert!(provider.dropped.load(Ordering::SeqCst));
        assert_eq!(provider.polls.load(Ordering::SeqCst), 0);
        assert_eq!(finishes.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn pulling_and_dropping_projection_controls_the_provider_body() {
        let provider = tracked();
        let (projector, _) = projector(vec![], vec![]);
        let mut projected = Box::pin(project_fetch(provider.clone(), request(), projector));
        assert_eq!(
            ok(projected.next().await),
            ProjectedFetch::Event(
                hellas_rpc::fetch::encode_fetch_event_payload(
                    &hellas_rpc::output::OutputEvent::TextDelta {
                        index: 0,
                        delta: "x".into(),
                        channel: hellas_rpc::output::TextChannel::Output
                    }
                )
                .unwrap()
            )
        );
        assert_eq!(provider.polls.load(Ordering::SeqCst), 1);
        assert!(!provider.dropped.load(Ordering::SeqCst));
        drop(projected);
        assert!(provider.dropped.load(Ordering::SeqCst));

        use crate::{
            Executor, ExecutorSpawnConfig, FetchRoute, FetchRouteEntry, FetchRouteRegistry,
        };
        use hellas_channel::{
            content::{EphemeralContent, InvocationContent},
            work::{
                Admitted, WorkBackend,
                admission::{Cancellation, CapacityDomain, WorkAdmission},
            },
        };
        use hellas_rpc::{
            Assurance, Retention,
            protocol::invocation::{
                Admission, InvocationPolicy, Limits,
                fetch::{self, FetchAdmission, FetchLimits, FetchRoutePolicy},
                output::{FailureReason, Outcome},
            },
        };
        let key = Arc::new(hellas_auth::ProducerSigningKey::generate());
        let caller = hellas_auth::ProducerSigningKey::generate();
        let contract = hellas_channel::test_support::test_responses_contract();
        let mut policy = InvocationPolicy {
            admissions: vec![Admission::Fetch {
                admission: FetchAdmission {
                    contract: contract.clone(),
                    route: FetchRoutePolicy::sealed_route("http", "fetch").unwrap(),
                    limits: FetchLimits {
                        max_request_body_bytes: 1024,
                        max_output_events: 1024,
                        max_spool_bytes: 1 << 20,
                        max_encoded_result_frame: 1 << 16,
                        max_encoded_prepared_input: 1 << 16,
                    },
                },
            }],
            limits: Limits {
                max_upload_bytes: 1 << 20,
                max_output_bytes: 1 << 16,
                max_steps: 1,
                execution_timeout_ms: 30_000,
            },
        };
        let prepare = |policy: &InvocationPolicy| {
            let events = hellas_rpc::fetch::build_input_events_with_nonce(
                "http",
                "fetch",
                b"{}",
                contract.manifest_id(),
                Assurance::ProducerSigned,
                &caller,
                Retention::Ephemeral,
                [1; 32],
            )
            .unwrap();
            fetch::prepare(
                &events,
                &contract,
                key.public_key(),
                policy.canonical_bytes().unwrap(),
                [1; 32],
            )
            .unwrap()
        };
        let limits = policy.limits;
        let ticket = |input, admission| {
            Admitted::new(
                input,
                limits,
                CapacityDomain::Fetch,
                InvocationContent::Ephemeral(EphemeralContent::default()),
                admission,
            )
        };
        let factory = Arc::new(Projector {
            head: vec![],
            tail: vec![],
            finishes: Arc::new(AtomicUsize::new(0)),
        });
        let provider = tracked();
        let mut routes = FetchRouteRegistry::new();
        routes
            .register(
                FetchRoute::new("http", "fetch"),
                FetchRouteEntry::new(provider.clone(), factory.clone(), Default::default())
                    .unwrap(),
            )
            .unwrap();
        let mut config = ExecutorSpawnConfig::new(key.clone(), Assurance::ProducerSigned, routes);
        config.fetch_max_in_flight = 1;
        let executor = Executor::spawn_configured(config).await.unwrap();
        let (entered, started) = tokio::sync::oneshot::channel();
        let entered = std::sync::Mutex::new(Some(entered));
        let running = executor.clone();
        let input = ticket(prepare(&policy), WorkAdmission::payment());
        let first = tokio::spawn(async move {
            running
                .execute_stream(
                    input,
                    Arc::new(move |_| {
                        if let Some(entered) = entered.lock().unwrap().take() {
                            let _ = entered.send(());
                        }
                        Ok(())
                    }),
                )
                .await
        });
        if started.await.is_err() {
            panic!(
                "first Fetch ended before its prefix: {:?}",
                first.await.unwrap()
            );
        }
        let polls = provider.polls.load(Ordering::SeqCst);
        for revoked in [true, false] {
            let dispatched = Arc::new(AtomicBool::new(false));
            let observed = dispatched.clone();
            let cancel = Cancellation::new();
            let admission = WorkAdmission::grant(
                executor.try_admit(CapacityDomain::Fetch).unwrap(),
                std::time::Instant::now()
                    + if revoked {
                        std::time::Duration::from_secs(30)
                    } else {
                        std::time::Duration::ZERO
                    },
                cancel.clone(),
                async move {
                    observed.store(true, Ordering::SeqCst);
                    Ok(())
                },
            );
            let mut second = Box::pin(executor.execute(ticket(prepare(&policy), admission)));
            if revoked {
                assert!(matches!(futures_util::poll!(&mut second), Poll::Pending));
            }
            assert!(
                !dispatched.load(Ordering::SeqCst),
                "queued grant was charged before a worker became active"
            );
            if revoked {
                cancel.cancel();
            }
            assert!(second.await.is_err());
            assert!(!dispatched.load(Ordering::SeqCst));
            assert_eq!(
                provider.polls.load(Ordering::SeqCst),
                polls,
                "queued grant invoked the provider"
            );
        }
        first.abort();
        assert!(first.await.unwrap_err().is_cancelled());

        // Each admitted bound must leave a terminal before any prefix escapes.
        for (events_cap, frame_cap, spool_cap, bytes) in [
            (1, 1 << 16, 1 << 20, 1),
            (1024, 1024, 1 << 20, 8192),
            (1024, 1 << 16, 4096, 8192),
        ] {
            policy.admissions.truncate(1);
            let Admission::Fetch { admission } = &mut policy.admissions[0] else {
                unreachable!()
            };
            admission.limits.max_output_events = events_cap;
            admission.limits.max_encoded_result_frame = frame_cap;
            admission.limits.max_spool_bytes = spool_cap;
            if spool_cap == 4096 {
                let mut complementary = policy.admissions[0].clone();
                let Admission::Fetch { admission } = &mut complementary else {
                    unreachable!()
                };
                admission.limits.max_output_events = 1;
                admission.limits.max_spool_bytes = 1 << 20;
                policy.admissions.push(complementary);
            }
            let provider = Arc::new(MockFetchProvider::new(contract.manifest_id()));
            provider.insert(
                "http",
                "fetch",
                b"{}".to_vec(),
                [hellas_rpc::fetch::encode_fetch_event_payload(
                    &hellas_rpc::output::OutputEvent::TextDelta {
                        index: 0,
                        delta: "x".repeat(bytes),
                        channel: hellas_rpc::output::TextChannel::Output,
                    },
                )
                .unwrap()],
            );
            let mut routes = FetchRouteRegistry::new();
            routes
                .register(
                    FetchRoute::new("http", "fetch"),
                    FetchRouteEntry::new(provider.clone(), factory.clone(), Default::default())
                        .unwrap(),
                )
                .unwrap();
            let executor = Executor::spawn_configured(ExecutorSpawnConfig::new(
                key.clone(),
                Assurance::ProducerSigned,
                routes,
            ))
            .await
            .unwrap();
            let input = prepare(&policy);
            let published = Arc::new(AtomicUsize::new(0));
            let observed = published.clone();
            let events = executor
                .execute_stream(
                    ticket(input.clone(), WorkAdmission::payment()),
                    Arc::new(move |_| {
                        observed.fetch_add(1, Ordering::SeqCst);
                        Ok(())
                    }),
                )
                .await
                .unwrap();
            assert_eq!(
                published.load(Ordering::SeqCst),
                0,
                "over-bound prefix was published"
            );
            let verified = input
                .verify_output(&policy, &caller.public_key(), &key.public_key(), &events)
                .unwrap();
            assert_eq!(
                verified.output.outcome,
                Outcome::Failed(FailureReason::OutputLimit)
            );
            assert_eq!(events.len(), 1);
            assert_eq!(provider.calls("http", "fetch", b"{}".to_vec()), 1);
        }
        let mut wide = policy.admissions[0].clone();
        let Admission::Fetch { admission } = &mut wide else {
            unreachable!()
        };
        admission.limits.max_output_events = 1024;
        admission.limits.max_spool_bytes = 1 << 20;
        let terminal = hellas_rpc::fetch::encode_fetch_terminal_payload(
            &hellas_rpc::output::OutputEvent::Finished {
                stop_reason: hellas_rpc::output::StopReason::EndOfText,
                usage: None,
            },
        )
        .unwrap();
        let factory = Arc::new(Projector {
            head: vec![],
            tail: vec![ProjectedFetch::Terminal(terminal)],
            finishes: Arc::new(AtomicUsize::new(0)),
        });
        for tiny_spool in [false, true] {
            for reverse in [false, true] {
                let mut narrow = wide.clone();
                let Admission::Fetch { admission } = &mut narrow else {
                    unreachable!()
                };
                if tiny_spool {
                    admission.limits.max_spool_bytes = 1;
                } else {
                    admission.limits.max_output_events = 1;
                }
                policy.admissions = if reverse {
                    vec![wide.clone(), narrow]
                } else {
                    vec![narrow, wide.clone()]
                };
                let provider = Arc::new(MockFetchProvider::new(contract.manifest_id()));
                provider.insert(
                    "http",
                    "fetch",
                    b"{}".to_vec(),
                    [hellas_rpc::fetch::encode_fetch_event_payload(
                        &hellas_rpc::output::OutputEvent::TextDelta {
                            index: 0,
                            delta: "ok".into(),
                            channel: hellas_rpc::output::TextChannel::Output,
                        },
                    )
                    .unwrap()],
                );
                let mut routes = FetchRouteRegistry::new();
                routes
                    .register(
                        FetchRoute::new("http", "fetch"),
                        FetchRouteEntry::new(provider.clone(), factory.clone(), Default::default())
                            .unwrap(),
                    )
                    .unwrap();
                let executor = Executor::spawn_configured(ExecutorSpawnConfig::new(
                    key.clone(),
                    Assurance::ProducerSigned,
                    routes,
                ))
                .await
                .unwrap();
                let input = prepare(&policy);
                let events = executor
                    .execute(ticket(input.clone(), WorkAdmission::payment()))
                    .await
                    .unwrap();
                let verified = input
                    .verify_output(&policy, &caller.public_key(), &key.public_key(), &events)
                    .unwrap();
                assert!(
                    verified.output.is_success(),
                    "later complete Fetch admission was ignored"
                );
                assert_eq!(events.len(), 2);
                assert_eq!(provider.calls("http", "fetch", b"{}".to_vec()), 1);
            }
        }
    }

    #[tokio::test]
    async fn terminal_projection_cannot_hide_later_items_or_end_without_a_terminal() {
        for after in [
            ProjectedFetch::Event(vec![3]),
            ProjectedFetch::Terminal(vec![3]),
        ] {
            let (projector, _) = projector(
                vec![
                    ProjectedFetch::Event(vec![1]),
                    ProjectedFetch::Terminal(vec![2]),
                    after,
                ],
                vec![],
            );
            let mut projected = Box::pin(project_fetch(provider(vec![]), request(), projector));
            assert_eq!(ok(projected.next().await), ProjectedFetch::Event(vec![1]));
            let failure = projected
                .next()
                .await
                .expect("bad suffix must be refused")
                .expect_err("suffix accepted");
            assert_eq!(failure.position, 1);
        }
        let (projector, _) = projector(vec![], vec![]);
        let mut projected = Box::pin(project_fetch(provider(vec![vec![1]]), request(), projector));
        assert_eq!(ok(projected.next().await), ProjectedFetch::Event(vec![1]));
        let failure = projected
            .next()
            .await
            .expect("missing terminal must be refused")
            .expect_err("missing terminal accepted");
        assert!(failure.error.to_string().contains("without terminal"));
        assert_eq!(failure.position, 1);
    }

    #[tokio::test]
    async fn projection_limits_refuse_before_releasing_the_excess_item() {
        let (projector, _) = projector(
            vec![ProjectedFetch::Event(vec![1]); MAX_FETCH_OUTPUT_EVENTS],
            vec![ProjectedFetch::Terminal(vec![])],
        );
        let mut projected = Box::pin(project_fetch(provider(vec![]), request(), projector));
        for _ in 0..MAX_FETCH_OUTPUT_EVENTS - 1 {
            assert_eq!(ok(projected.next().await), ProjectedFetch::Event(vec![1]));
        }
        assert!(
            projected
                .next()
                .await
                .expect("event bound missing")
                .is_err()
        );
        let (projector, _) = self::projector(
            vec![ProjectedFetch::Event(vec![
                1;
                MAX_FETCH_OUTPUT_PAYLOAD_BYTES
                    + 1
            ])],
            vec![ProjectedFetch::Terminal(vec![])],
        );
        let mut projected = Box::pin(project_fetch(provider(vec![]), request(), projector));
        let failure = projected
            .next()
            .await
            .expect("byte bound missing")
            .expect_err("oversize event accepted");
        assert_eq!(failure.position, 0);
    }
}
