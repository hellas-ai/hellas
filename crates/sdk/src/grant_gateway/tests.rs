use super::*;
use crate::grant_client::tests::{definition, network, pinned_offer, principal};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use futures::StreamExt;
use hellas_rpc::{
    OutputEventEnvelope,
    output::{AdaptorEvent, HttpResponseEvent},
    protocol::work_grant::{GrantId, UnixMillis, budget::*, resource::*},
};
use hellas_work::{
    grant_service::GrantService,
    work::{
        BackendFault, PaidProgress, PreparedFetchInput, WorkBackend,
        admission::{CapacityDomain, WorkPermit},
    },
    work_store::grant::GrantStore,
};
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Clone)]
struct Backend {
    slots: Arc<Semaphore>,
    finish: Arc<Semaphore>,
    calls: Arc<AtomicUsize>,
    usage: bool,
}
impl WorkBackend for Backend {
    fn try_admit(&self, domain: CapacityDomain) -> Result<WorkPermit, BackendFault> {
        Ok(WorkPermit::new(
            domain,
            self.slots
                .clone()
                .try_acquire_owned()
                .map_err(|_| BackendFault::new("full"))?,
        ))
    }
    async fn fetch_stream(
        &self,
        input: PreparedFetchInput,
        progress: PaidProgress,
    ) -> Result<Vec<OutputEventEnvelope>, BackendFault> {
        let (parts, admission) = input.into_parts_and_admission();
        let _running = admission.dispatch()?;
        let request =
            hellas_rpc::fetch::verify_input_events(&parts.fetch_input_transcript).unwrap();
        let http =
            hellas_rpc::http_fetch::HttpFetchRequest::decode(request.body.as_bytes()).unwrap();
        let body: serde_json::Value = serde_json::from_slice(&http.body().unwrap()).unwrap();
        assert_eq!(body["max_tokens"], 6);
        assert_eq!(body["stream_options"]["include_usage"], true);
        self.calls.fetch_add(1, Ordering::SeqCst);
        let key = principal(2).1;
        let mut output = hellas_rpc::fetch::FetchOutputTranscriptBuilder::new(
            request.input_commitment,
            request.assurance,
            &key,
        );
        let body = if self.usage {
            "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":3,\"completion_tokens\":2,\"total_tokens\":5}}\n\ndata: [DONE]\n\n"
        } else {
            "data: [DONE]\n\n"
        };
        for event in [
            HttpResponseEvent::Head {
                status: 200,
                headers: vec![("content-type".into(), "text/event-stream".into())],
            },
            HttpResponseEvent::Body {
                base64: STANDARD.encode(body),
            },
        ] {
            progress(
                output
                    .push_event(
                        hellas_rpc::fetch::encode_fetch_event_payload(&OutputEvent::Adaptor(
                            AdaptorEvent::Http(event),
                        ))
                        .unwrap(),
                    )
                    .unwrap(),
            )?;
        }
        self.finish.acquire().await.unwrap().forget();
        Ok(output
            .finish(
                hellas_rpc::fetch::encode_fetch_terminal_payload(&OutputEvent::Finished {
                    stop_reason: hellas_rpc::output::StopReason::EndOfText,
                    usage: None,
                })
                .unwrap(),
            )
            .unwrap())
    }
}
struct Fixture {
    _root: tempfile::TempDir,
    gateway: Arc<GrantGateway>,
    service: GrantService,
    backend: Backend,
    template: HttpsResource,
}
impl Fixture {
    async fn new(usage: bool, budget: u64, held: bool) -> Self {
        let root = tempfile::tempdir().unwrap();
        let mut grant = definition(GrantId([1; 16]), principal(1).0);
        grant.limits = vec![Limit {
            meter: Meter::OutputTokens,
            window: Window::Total,
            amount: budget,
        }];
        let template = HttpsResource {
            origin: "https://private.fixture".into(),
            paths: vec!["/v1/chat/completions".into()],
            methods: vec!["POST".into()],
            credential: None,
            tls: hellas_rpc::http_fetch::HttpTls {
                roots: hellas_rpc::http_fetch::HttpTrustRoots::WebPki,
                spki_sha256: vec![],
            },
            accounting: AccountingProfile::OpenaiChat,
            max_output_tokens: 6,
            max_response_bytes: 4096,
        };
        let resource = &mut grant.policies[0];
        resource.name = "chat".into();
        resource.https = Some(template.clone());
        if let WorkPolicy::Fetch { policy, .. } = &mut resource.work {
            policy.allowed_environment = hellas_rpc::FetchEnvironment::Http.manifest_id();
        }
        let mut store = GrantStore::open(
            &root.path().join("provider"),
            network(),
            principal(2).0.bundle().clone(),
            UnixMillis(1000),
        )
        .unwrap();
        store
            .configure_machine(vec![], 2, UnixMillis(1000))
            .unwrap();
        store.define(grant, UnixMillis(1000)).unwrap();
        let backend = Backend {
            slots: Arc::new(Semaphore::new(2)),
            finish: Arc::new(Semaphore::new(if held { 0 } else { 16 })),
            calls: Arc::new(AtomicUsize::new(0)),
            usage,
        };
        let service = GrantService::new(
            store,
            Arc::new(principal(2).1),
            backend.clone(),
            vec![],
            Arc::new(|| UnixMillis(1000)),
        )
        .unwrap();
        let gateway = GrantGateway::open(
            GrantSessionOptions {
                target: pinned_offer(definition(GrantId([1; 16]), principal(1).0), vec![]),
                client: principal(1).0,
                signer: Arc::new(principal(1).1),
                journal_root: root.path().join("client"),
                timeout: Duration::from_secs(5),
            },
            GrantTransport::Local(service.clone()),
            None,
        )
        .await
        .unwrap();
        Self {
            _root: root,
            gateway,
            service,
            backend,
            template,
        }
    }
    fn request(&self, cap: Option<u64>) -> WorkFetchRequest {
        let mut body = serde_json::json!({"messages":[],"stream":true});
        if let Some(cap) = cap {
            body["max_tokens"] = cap.into();
        }
        let template = &self.template;
        let http = hellas_rpc::http_fetch::HttpFetchRequest {
            url: format!("{}{}", template.origin, template.paths[0]),
            method: "POST".into(),
            headers: vec![],
            body_base64: STANDARD.encode(serde_json::to_vec(&body).unwrap()),
            tls: template.tls.clone(),
            credential: None,
            max_response_bytes: template.max_response_bytes,
        };
        WorkFetchRequest {
            provider: self.gateway.provider,
            service: "openai".into(),
            method: "responses".into(),
            body: serde_json::to_vec(&http).unwrap(),
        }
    }
    fn used(&self) -> u64 {
        self.service
            .administer(|store, _| {
                Ok(store
                    .state()
                    .ledger()
                    .node(BudgetNode::Grant(GrantId([1; 16])))
                    .unwrap()
                    .counter(Meter::OutputTokens, Window::Total)
                    .used)
            })
            .unwrap()
    }
    async fn result(&self, cap: Option<u64>) -> Result<(), WorkGatewayError> {
        let mut stream = self.gateway.fetch(self.request(cap))?;
        let mut terminal = false;
        while let Some(event) = stream.next().await {
            terminal |= event?.terminal().is_some();
        }
        assert!(terminal);
        Ok(())
    }
}

#[tokio::test]
async fn grant_stream_repairs_before_signing_and_drains_after_disconnect() {
    let fixture = Fixture::new(true, 10, true).await;
    let config = fixture.gateway.http_config().unwrap();
    assert_eq!(config.routes[0].max_response_bytes, 4096);
    assert_eq!(config.routes[0].tls, fixture.template.tls);
    let mut stream = fixture.gateway.fetch(fixture.request(None)).unwrap();
    let first = tokio::time::timeout(Duration::from_secs(2), stream.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(matches!(
        first,
        OutputEvent::Adaptor(AdaptorEvent::Http(HttpResponseEvent::Head { .. }))
    ));
    assert_eq!(fixture.backend.calls.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.used(), 0);
    drop(stream);
    fixture.backend.finish.add_permits(1);
    fixture.gateway.drain().await;
    assert_eq!(fixture.used(), 2);
    assert!(matches!(
        fixture.gateway.fetch(fixture.request(None)),
        Err(WorkGatewayError::Busy(_))
    ));
}

#[tokio::test]
async fn over_cap_and_exhausted_allowance_do_not_execute() {
    let fixture = Fixture::new(true, 10, false).await;
    assert!(matches!(
        fixture.result(Some(7)).await,
        Err(WorkGatewayError::Rejected(_))
    ));
    assert_eq!(fixture.backend.calls.load(Ordering::SeqCst), 0);
    for _ in 0..3 {
        fixture.result(None).await.unwrap();
    }
    assert_eq!(fixture.used(), 6);
    assert!(matches!(
        fixture.result(None).await,
        Err(WorkGatewayError::Quota(_))
    ));
    assert_eq!(fixture.backend.calls.load(Ordering::SeqCst), 3);
    fixture.gateway.drain().await;
}

#[tokio::test]
async fn absent_usage_charges_reserve_and_quarantines() {
    let fixture = Fixture::new(false, 100, false).await;
    for _ in 0..3 {
        fixture.result(None).await.unwrap();
    }
    assert_eq!(fixture.used(), 18);
    assert!(matches!(
        fixture.result(None).await,
        Err(WorkGatewayError::Denied(_))
    ));
    assert_eq!(fixture.backend.calls.load(Ordering::SeqCst), 3);
    fixture.gateway.drain().await;
}

#[tokio::test]
async fn pause_revoke_and_expiry_refuse_without_execution() {
    use hellas_rpc::protocol::work_grant::records::GrantState;
    for (state, expires) in [
        (GrantState::Paused, None),
        (GrantState::Revoked, None),
        (GrantState::Active, Some(UnixMillis(1000))),
    ] {
        let fixture = Fixture::new(true, 10, false).await;
        fixture
            .service
            .administer(|store, now| {
                let mut grant = store.state().grant(GrantId([1; 16])).unwrap().clone();
                grant.revision.0 += 1;
                grant.state = state;
                grant.expires = expires;
                store.define(grant, now)
            })
            .unwrap();
        let result = fixture.result(None).await;
        assert!(
            matches!(result, Err(WorkGatewayError::Denied(_))),
            "{result:?}"
        );
        assert_eq!(fixture.backend.calls.load(Ordering::SeqCst), 0);
        assert_eq!(fixture.used(), 0);
        fixture.gateway.drain().await;
    }
}
