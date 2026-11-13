use super::*;
use crate::{Presentation, WorkEvent, WorkFetchRequest, WorkGatewayError, WorkShutdownError};
use futures::{StreamExt, future::BoxFuture};

struct Fake {
    backends: Mutex<Vec<BackendInfo>>,
    calls: Mutex<Vec<String>>,
    committed: bool,
}
impl Fake {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            backends: Mutex::new(
                ["a", "b", "c"]
                    .map(|id| BackendInfo {
                        id: id.into(),
                        evaluator: None,
                        max_in_flight: 4,
                        in_flight: 0,
                        down: false,
                    })
                    .into(),
            ),
            calls: Default::default(),
            committed: false,
        })
    }
}
impl WorkExecutionBackend for Fake {
    fn backends(&self) -> Vec<BackendInfo> {
        self.backends.lock().unwrap().clone()
    }
    fn fetch(
        &self,
        backend: &str,
        _request_job: Arc<crate::jobs::Job>,
        _: WorkFetchRequest,
    ) -> Result<crate::WorkFetchStream, WorkGatewayError> {
        self.calls.lock().unwrap().push(backend.into());
        let event = if backend == "a" {
            let error = WorkGatewayError::Unreachable("offline".into());
            Err(if self.committed {
                error
            } else {
                WorkGatewayError::PreProposal(Box::new(error))
            })
        } else {
            Ok(WorkEvent::Accepted(
                hellas_rpc::provenance::ExecutionProvenance {
                    commitment_id: [1; 32],
                    provider: hellas_auth::PublicKey::Secp256k1([2; 33]),
                },
            ))
        };
        Ok(Box::pin(futures::stream::iter([event])))
    }
    fn drain(&self) -> BoxFuture<'_, Result<(), WorkShutdownError>> {
        Box::pin(async { Ok(()) })
    }
}
fn row(backends: &[&str], model: Option<&str>) -> Route {
    Route {
        backends: backends.iter().map(|id| (*id).into()).collect(),
        presentation: Presentation::Responses {
            service: "test".into(),
            method: "responses".into(),
            models: model.into_iter().map(str::to_owned).collect(),
            overrides: Default::default(),
        },
    }
}
fn choose(
    routing: &Arc<Routing>,
    model: Option<&str>,
    session: Option<&str>,
) -> Result<Selection, Unavailable> {
    routing
        .select(
            "/v1/responses",
            "POST",
            Hints {
                model: model.map(str::to_owned),
                session: session.map(|id| ("session-id".into(), id.into())),
                ..Default::default()
            },
            None,
            crate::test_support::job(),
        )
        .map(|(_, selection)| selection)
}
fn order_of(mut selection: Selection) -> Vec<String> {
    std::iter::from_fn(|| selection.next()).collect()
}

#[test]
fn routes_match_exact_keys_and_order_by_load_then_rotating_ties() {
    let work = Fake::new();
    let routing = Routing::new(
        vec![row(&["b", "a", "c"], Some("model"))],
        work.clone(),
        Default::default(),
    )
    .unwrap();
    assert_eq!(
        choose(&routing, None, None).err().unwrap().status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        choose(&routing, Some("missing"), None)
            .err()
            .unwrap()
            .status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        routing
            .select(
                "/v1/responses",
                "GET",
                Default::default(),
                None,
                crate::test_support::job()
            )
            .err()
            .unwrap()
            .status,
        StatusCode::NOT_FOUND
    );
    let mut first = choose(&routing, Some("model"), None).unwrap();
    assert_eq!(first.next().as_deref(), Some("b"));
    first.accept("b");
    assert_eq!(
        order_of(choose(&routing, Some("model"), None).unwrap()),
        ["a", "c", "b"]
    );
    work.backends.lock().unwrap()[0].in_flight = 1;
    assert_eq!(
        order_of(choose(&routing, Some("model"), None).unwrap()),
        ["c", "b", "a"]
    );
    work.backends.lock().unwrap()[2].down = true;
    assert_eq!(
        order_of(choose(&routing, Some("model"), None).unwrap()),
        ["b", "a", "c"]
    );
    for backend in work.backends.lock().unwrap().iter_mut() {
        backend.in_flight = 4;
    }
    assert_eq!(
        choose(&routing, Some("model"), None).err().unwrap().status,
        StatusCode::SERVICE_UNAVAILABLE
    );
}
#[test]
fn duplicate_unknown_and_ambiguous_rows_are_invalid() {
    let work = Fake::new();
    for rows in [
        vec![row(&[], None)],
        vec![row(&["missing"], None)],
        vec![row(&["a", "a"], None)],
        vec![row(&["a"], None), row(&["b"], None)],
        vec![row(&["a"], None), row(&["b"], Some("model"))],
    ] {
        assert!(Routing::new(rows, work.clone(), Default::default()).is_err());
    }
    let routing = Routing::new(
        vec![row(&["a"], Some("one")), row(&["b"], Some("two"))],
        work,
        Default::default(),
    )
    .unwrap();
    assert_eq!(
        order_of(choose(&routing, Some("two"), None).unwrap()),
        ["b"]
    );
}
#[test]
fn first_session_selection_is_reserved_until_acceptance_and_pins_thereafter() {
    let work = Fake::new();
    let routing = Routing::new(
        vec![row(&["a", "b"], None)],
        work.clone(),
        Default::default(),
    )
    .unwrap();
    let pending = choose(&routing, None, Some("session")).unwrap();
    assert_eq!(
        choose(&routing, None, Some("session"))
            .err()
            .unwrap()
            .status,
        StatusCode::SERVICE_UNAVAILABLE
    );
    drop(pending);
    let mut first = choose(&routing, None, Some("session")).unwrap();
    assert_eq!(first.next().as_deref(), Some("a"));
    assert_eq!(first.next().as_deref(), Some("b"));
    first.accept("b");
    drop(first);
    assert_eq!(
        order_of(choose(&routing, None, Some("session")).unwrap()),
        ["b"]
    );
    work.backends.lock().unwrap()[1].in_flight = 4;
    assert_eq!(
        choose(&routing, None, Some("session"))
            .err()
            .unwrap()
            .status,
        StatusCode::SERVICE_UNAVAILABLE
    );
}
#[test]
fn continuation_keys_and_upstream_cooldown_never_move_a_pinned_request() {
    let routing = Routing::new(
        vec![row(&["a", "b"], None)],
        Fake::new(),
        Default::default(),
    )
    .unwrap();
    let mut first = choose(&routing, None, None).unwrap();
    first.next();
    first.accept("a");
    first
        .response_binding("/v1/responses")
        .unwrap()
        .observe(&serde_json::json!({"object":"response", "id":"resp", "conversation":"conv"}));
    let follow = |id: &str| {
        routing.select(
            "/v1/responses",
            "POST",
            Hints {
                previous: Some(id.into()),
                ..Default::default()
            },
            None,
            crate::test_support::job(),
        )
    };
    assert_eq!(order_of(follow("resp").unwrap().1), ["a"]);
    assert_eq!(
        follow("unknown").err().unwrap().status,
        StatusCode::CONFLICT
    );
    first.observe(
        429,
        &HeaderMap::from_iter([("retry-after".parse().unwrap(), "17".parse().unwrap())]),
    );
    assert_eq!(
        follow("resp").err().unwrap().status,
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(order_of(choose(&routing, None, None).unwrap()), ["b"]);
}
#[tokio::test]
async fn failover_stops_at_the_proposal_boundary() {
    for committed in [false, true] {
        let mut work = Fake::new();
        Arc::get_mut(&mut work).unwrap().committed = committed;
        let route = row(&["a", "b"], None);
        let routing = Routing::new(vec![route.clone()], work.clone(), Default::default()).unwrap();
        let execution = crate::route::RouteExecution::open(&route, work.clone())
            .await
            .unwrap();
        let mut selection = choose(&routing, None, None).unwrap();
        let result = execution
            .fetch(&mut selection, |_| {
                Ok(WorkFetchRequest {
                    service: "test".into(),
                    method: "responses".into(),
                    body: vec![],
                })
            })
            .await;
        assert_eq!(result.is_err(), committed);
        assert_eq!(
            *work.calls.lock().unwrap(),
            if committed { vec!["a"] } else { vec!["a", "b"] }
        );
        if let Ok(mut stream) = result {
            assert!(matches!(
                stream.next().await,
                Some(Ok(WorkEvent::Accepted(_)))
            ));
        }
    }
}

#[tokio::test]
async fn pinned_pre_proposal_failure_is_not_retried_on_another_backend() {
    let work = Fake::new();
    let route = row(&["a", "b"], None);
    let routing = Routing::new(vec![route.clone()], work.clone(), Default::default()).unwrap();
    let mut first = choose(&routing, None, Some("session")).unwrap();
    first.next();
    first.accept("a");
    let execution = crate::route::RouteExecution::open(&route, work.clone())
        .await
        .unwrap();
    let mut pinned = choose(&routing, None, Some("session")).unwrap();
    assert!(
        execution
            .fetch(&mut pinned, |_| Ok(WorkFetchRequest {
                service: "test".into(),
                method: "responses".into(),
                body: vec![],
            }))
            .await
            .is_err()
    );
    assert_eq!(*work.calls.lock().unwrap(), ["a"]);
}

#[tokio::test]
async fn compute_is_rendered_for_each_selected_evaluator() {
    use hellas_client::model::{ComputeJob, GpuDialect, ModelPackage, ModelRequest, evaluator};
    struct Renderers {
        calls: Mutex<Vec<(String, ComputeJob)>>,
    }
    impl WorkExecutionBackend for Renderers {
        fn backends(&self) -> Vec<BackendInfo> {
            [("hip", GpuDialect::Hip), ("cuda", GpuDialect::Cuda)]
                .map(|(id, dialect)| BackendInfo {
                    id: id.into(),
                    evaluator: Some(evaluator(dialect)),
                    max_in_flight: 2,
                    in_flight: 0,
                    down: false,
                })
                .into()
        }
        fn run(
            &self,
            backend: &str,
            _request_job: Arc<crate::jobs::Job>,
            job: ComputeJob,
        ) -> Result<crate::WorkOutputStream<crate::ComputeEvent>, WorkGatewayError> {
            self.calls.lock().unwrap().push((backend.into(), job));
            if backend == "hip" {
                return Err(WorkGatewayError::PreProposal(Box::new(
                    WorkGatewayError::Busy(crate::WorkGatewayBusy),
                )));
            }
            Ok(Box::pin(futures::stream::iter([Ok(WorkEvent::Accepted(
                hellas_rpc::provenance::ExecutionProvenance {
                    commitment_id: [1; 32],
                    provider: hellas_auth::PublicKey::Secp256k1([2; 33]),
                },
            ))])))
        }
        fn drain(&self) -> BoxFuture<'_, Result<(), WorkShutdownError>> {
            Box::pin(async { Ok(()) })
        }
    }
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../client/src/model/package/mini-qwen3.gguf");
    let route = Route {
        backends: vec!["hip".into(), "cuda".into()],
        presentation: Presentation::Model {
            model: "tiny".into(),
            package: path.clone(),
            max_tokens: 1,
        },
    };
    let work = Arc::new(Renderers {
        calls: Default::default(),
    });
    let routing = Routing::new(vec![route.clone()], work.clone(), Default::default()).unwrap();
    let execution = crate::route::RouteExecution::open(&route, work.clone())
        .await
        .unwrap();
    let request = ModelRequest::Text {
        prompt_ids: &[0],
        max_new: 1,
        stops: &[],
    };
    let (_, mut stream) = execution
        .compute(&mut choose(&routing, Some("tiny"), None).unwrap(), &request)
        .await
        .unwrap();
    assert!(matches!(
        stream.next().await,
        Some(Ok(WorkEvent::Accepted(_)))
    ));
    let calls = std::mem::take(&mut *work.calls.lock().unwrap());
    assert_eq!(
        calls.iter().map(|(id, _)| id.as_str()).collect::<Vec<_>>(),
        ["hip", "cuda"]
    );
    for ((_, actual), dialect) in calls.into_iter().zip([GpuDialect::Hip, GpuDialect::Cuda]) {
        let package = ModelPackage::open(&path, &evaluator(dialect))
            .await
            .unwrap();
        let expected = package.render_job(&request).await.unwrap();
        assert_eq!(actual.environment, expected.environment);
        assert_eq!(actual.plan, expected.plan);
        assert_eq!(actual.inputs, expected.inputs);
    }
}

#[test]
fn throttling_without_retry_after_does_not_invent_a_cooldown() {
    let routing = Routing::new(vec![row(&["a"], None)], Fake::new(), Default::default()).unwrap();
    let mut selection = choose(&routing, None, None).unwrap();
    selection.next();
    for headers in [
        HeaderMap::new(),
        HeaderMap::from_iter([("retry-after".parse().unwrap(), "invalid".parse().unwrap())]),
    ] {
        selection.observe(429, &headers);
        assert_eq!(order_of(choose(&routing, None, None).unwrap()), ["a"]);
    }
}

#[test]
fn retry_after_uses_only_valid_upstream_durations_and_dates() {
    assert_eq!(retry_delay(&HeaderMap::new()), None);
    for (value, expected) in [
        ("invalid", None),
        ("-2", None),
        ("0", Some(Duration::ZERO)),
        ("3", Some(Duration::from_secs(3))),
    ] {
        let headers =
            HeaderMap::from_iter([("retry-after".parse().unwrap(), value.parse().unwrap())]);
        assert_eq!(retry_delay(&headers), expected);
    }
    let date = httpdate::fmt_http_date(std::time::SystemTime::now() + Duration::from_secs(60));
    let headers = HeaderMap::from_iter([("retry-after".parse().unwrap(), date.parse().unwrap())]);
    assert!((59..=60).contains(&retry_delay(&headers).unwrap().as_secs()));
}

#[test]
fn snapshot_replacement_retains_pending_sessions_and_continuations() {
    let memory = Arc::new(RoutingState::default());
    let work = Fake::new();
    let old = Routing::new(vec![row(&["a", "b"], None)], work.clone(), memory.clone()).unwrap();
    let mut pending = choose(&old, None, Some("session")).unwrap();
    let next = Routing::new(vec![row(&["b", "a"], None)], work.clone(), memory.clone()).unwrap();
    assert_eq!(
        choose(&next, None, Some("session")).err().unwrap().status,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(pending.next().as_deref(), Some("a"));
    pending.accept("a");
    pending
        .response_binding("/v1/responses")
        .unwrap()
        .observe(&serde_json::json!({"object":"response", "id":"retained"}));
    drop(pending);
    assert_eq!(
        order_of(choose(&next, None, Some("session")).unwrap()),
        ["a"]
    );
    let continuation = |routing: &Arc<Routing>| {
        routing.select(
            "/v1/responses",
            "POST",
            Hints {
                previous: Some("retained".into()),
                ..Default::default()
            },
            None,
            crate::test_support::job(),
        )
    };
    assert_eq!(order_of(continuation(&next).unwrap().1), ["a"]);
    let removed = Routing::new(vec![row(&["b"], None)], work, memory).unwrap();
    assert_eq!(
        choose(&removed, None, Some("session"))
            .err()
            .unwrap()
            .status,
        StatusCode::CONFLICT
    );
    assert_eq!(
        continuation(&removed).err().unwrap().status,
        StatusCode::CONFLICT
    );
}
