use super::*;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use futures::StreamExt;
use hellas_auth::{ProducerSigningKey, PublicKey};
use hellas_authority::model::grant::admin::{WorkControlCommand, WorkControlReply};
use hellas_authority::model::grant::{budget::*, resource::*};
use hellas_gateway::{WorkEvent, WorkExecutionBackend, WorkFetchRequest};
use hellas_rpc::output::OutputEvent;
use hellas_rpc::output::{AdaptorEvent, HttpResponseEvent};
use std::sync::atomic::Ordering;
use tokio::sync::Semaphore;
use {
    hellas_authority::test_support::Allowance, hellas_authority::test_support::Capacity,
    hellas_authority::test_support::chat_resource, hellas_authority::test_support::ids,
    hellas_authority::test_support::use_https, hellas_authority::test_support::within,
    hellas_channel::test_support::actors::FRIEND, hellas_channel::test_support::actors::ROOT,
    hellas_channel::test_support::assert_err,
};

use hellas_channel::test_support::backend::{Backend, Completion, Reply};
fn inspect_chat(request: &hellas_rpc::fetch::FetchInput) {
    let http = hellas_rpc::http_fetch::HttpFetchRequest::decode(request.body.as_bytes()).unwrap();
    let body: serde_json::Value = serde_json::from_slice(&http.body().unwrap()).unwrap();
    assert_eq!(body["max_tokens"], 6);
    assert_eq!(body["stream_options"]["include_usage"], true);
}

#[tokio::test]
async fn explicit_pool_shares_one_channel_and_selects_least_pending_resource() {
    let template = chat_resource("https://private.fixture", 6);
    let mut allowance = Allowance::responses(ids::ALLOWANCE, FRIEND).with_limits(vec![Limit {
        meter: Meter::OutputTokens,
        window: Window::Total,
        amount: 20,
    }]);
    use_https(&mut allowance.definition.policies[0], template.clone());
    let first = allowance.definition.policies[0].resource;
    let mut second_policy = allowance.definition.policies[0].clone();
    second_policy.resource =
        hellas_auth::authority::ResourceId(hellas_auth::Digest::hash(b"second resource"));
    second_policy.name = "second".into();
    let second = second_policy.resource;
    allowance.definition.policies.push(second_policy);
    let backend = Backend {
        finish: Completion::Immediate,
        reply: Reply::events(Reply::http(
            200,
            "application/json",
            r#"{"usage":{"prompt_tokens":1,"completion_tokens":1}}"#,
        )),
        ..Backend::default()
    };
    let host = crate::test_support::Host::builder()
        .with_allowance(allowance)
        .with_backend(backend)
        .build()
        .await;
    let options = host.options(vec![]);
    let duplicate = GrantPoolOptions {
        channels: vec![GrantPoolChannel {
            session: options.clone(),
            resources: vec![first, first],
        }],
    };
    assert!(
        GrantPool::open_pool(
            duplicate,
            vec![GrantTransport::Local(host.world.service.clone())]
        )
        .await
        .is_err()
    );
    let duplicate_channel = GrantPoolOptions {
        channels: vec![
            GrantPoolChannel {
                session: options.clone(),
                resources: vec![first],
            },
            GrantPoolChannel {
                session: options.clone(),
                resources: vec![second],
            },
        ],
    };
    assert!(
        GrantPool::open_pool(
            duplicate_channel,
            vec![
                GrantTransport::Local(host.world.service.clone()),
                GrantTransport::Local(host.world.service.clone())
            ]
        )
        .await
        .is_err()
    );
    assert_eq!(host.backend.calls.load(Ordering::SeqCst), 0);
    let pool = GrantPool::open_pool(
        GrantPoolOptions {
            channels: vec![GrantPoolChannel {
                session: options,
                resources: vec![first, second],
            }],
        },
        vec![GrantTransport::Local(host.world.service.clone())],
    )
    .await
    .unwrap();
    assert_eq!(pool.source.channels.len(), 1);
    assert_eq!(pool.fetch_routes().len(), 2);
    let http = hellas_rpc::http_fetch::HttpFetchRequest {
        url: format!("{}{}", template.origin, template.paths[0]),
        method: "POST".into(),
        headers: vec![],
        body_base64: STANDARD.encode(br#"{"messages":[],"max_tokens":6}"#),
        tls: template.tls,
        credential: None,
        max_response_bytes: template.max_response_bytes,
    };
    let make_request = || WorkFetchRequest {
        provider: pool.source.channels[0].provider,
        resource: None,
        channel: None,
        service: "openai".into(),
        method: "responses".into(),
        body: serde_json::to_vec(&http).unwrap(),
    };
    let legacy = GrantPoolSource {
        channels: pool.source.channels.clone(),
        selections: pool
            .source
            .selections
            .iter()
            .map(|selection| GrantSelection {
                channel: selection.channel,
                resource: selection.resource,
                pending: Arc::new(AtomicUsize::new(0)),
            })
            .collect(),
        explicit: false,
        choose: std::sync::Mutex::new(()),
    };
    assert!(matches!(
        legacy.request(WorkRequest::Fetch(make_request())),
        Err(WorkGatewayError::Rejected(_))
    ));
    let first_pending = pool
        .source
        .request(WorkRequest::Fetch(make_request()))
        .unwrap();
    let second_pending = pool
        .source
        .request(WorkRequest::Fetch(make_request()))
        .unwrap();
    assert_eq!(first_pending.resource, first);
    assert_eq!(second_pending.resource, second);
    drop((first_pending, second_pending));
    let config = pool.http_config().unwrap().unwrap();
    assert_eq!(config.backends.len(), 2);
    for resource in [first, second] {
        let mut request = make_request();
        request.resource = Some(resource);
        request.channel = Some(pool.source.channels[0].channel);
        let mut stream = pool.fetch(request).unwrap();
        while let Some(event) = within(stream.next()).await {
            event.unwrap();
        }
    }
    assert_eq!(host.backend.calls.load(Ordering::SeqCst), 2);
    pool.drain().await.unwrap();
}
struct Fixture {
    host: crate::test_support::Host,
    gateway: Arc<GrantGateway>,
    template: HttpsResource,
    remote: Option<crate::test_support::RemoteHost>,
}
#[derive(Clone, Copy)]
enum UsageReport {
    Reported,
    Missing,
}
#[derive(Clone, Copy)]
enum TransportMode {
    Local,
    Remote,
}
struct FixtureBuilder {
    usage: UsageReport,
    budget: u64,
    completion: Completion,
    transport: TransportMode,
    inspect: Option<fn(&hellas_rpc::fetch::FetchInput)>,
    paced_chunks: usize,
    hold_first: bool,
    max_job_millis: Option<u64>,
}
impl FixtureBuilder {
    /// Body chunks, and the usage chunk after them, each wait for `backend.pace`.
    fn hold_first(mut self) -> Self {
        self.hold_first = true;
        self
    }
    fn paced(mut self, chunks: usize) -> Self {
        self.paced_chunks = chunks;
        self
    }
    fn with_max_job_millis(mut self, millis: u64) -> Self {
        self.max_job_millis = Some(millis);
        self
    }
    fn inspect_request(mut self, inspect: fn(&hellas_rpc::fetch::FetchInput)) -> Self {
        self.inspect = Some(inspect);
        self
    }
    fn without_usage(mut self) -> Self {
        self.usage = UsageReport::Missing;
        self
    }
    fn with_budget(mut self, budget: u64) -> Self {
        self.budget = budget;
        self
    }
    fn hold_completion(mut self) -> Self {
        self.completion = Completion::Permits(Arc::new(Semaphore::new(0)));
        self
    }
    fn remote(mut self) -> Self {
        self.transport = TransportMode::Remote;
        self
    }
    async fn build(self) -> Fixture {
        let mut allowance = Allowance::responses(ids::ALLOWANCE, FRIEND).with_limits(vec![Limit {
            meter: Meter::OutputTokens,
            window: Window::Total,
            amount: self.budget,
        }]);
        let template = chat_resource("https://private.fixture", 6);
        let resource = &mut allowance.definition.policies[0];
        resource.name = "chat".into();
        use_https(resource, template.clone());
        let mut events = Reply::http(
            200,
            "text/event-stream",
            match self.usage {
                UsageReport::Reported => {
                    "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":3,\"completion_tokens\":2,\"total_tokens\":5}}\n\ndata: [DONE]\n\n"
                }
                UsageReport::Missing => "data: [DONE]\n\n",
            },
        );
        if let Some(millis) = self.max_job_millis {
            allowance.definition.max_job_millis = std::num::NonZeroU64::new(millis).unwrap();
        }
        let pace = (self.paced_chunks > 0).then(|| {
            let chunk = Reply::http(200, "text/event-stream", "\n").remove(1);
            let tail = events.split_off(1);
            events.extend(std::iter::repeat_n(chunk, self.paced_chunks).chain(tail));
            Completion::Permits(Arc::new(Semaphore::new(0)))
        });
        let backend = Backend {
            slots: Arc::new(Semaphore::new(2)),
            finish: self.completion,
            pace,
            first: self
                .hold_first
                .then(|| Completion::Permits(Arc::new(Semaphore::new(0)))),
            reply: Reply::events(events),
            inspect: self.inspect,
            ..Backend::default()
        };
        let host = crate::test_support::Host::builder()
            .with_allowance(allowance)
            .with_capacity(Capacity::new(2))
            .with_backend(backend)
            .build()
            .await;
        let remote = match self.transport {
            TransportMode::Local => None,
            TransportMode::Remote => Some(host.remote().await),
        };
        let addresses = remote.as_ref().map_or_else(Vec::new, |r| r.addresses());
        let transport = match self.transport {
            TransportMode::Local => GrantTransport::Local(host.world.service.clone()),
            TransportMode::Remote => GrantTransport::Remote(
                iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
                    .bind_addr("127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap())
                    .unwrap()
                    .bind()
                    .await
                    .unwrap(),
            ),
        };
        let gateway = GrantGateway::open(host.options(addresses), transport, None)
            .await
            .unwrap();
        Fixture {
            host,
            gateway,
            template,
            remote,
        }
    }
}
impl Fixture {
    fn builder() -> FixtureBuilder {
        FixtureBuilder {
            usage: UsageReport::Reported,
            budget: 10,
            completion: Completion::Immediate,
            transport: TransportMode::Local,
            inspect: None,
            paced_chunks: 0,
            hold_first: false,
            max_job_millis: None,
        }
    }
    async fn command(&self, command: WorkControlCommand) -> WorkControlReply {
        hellas_authority::grant_service::WorkAdministration::new(
            self.host.world.service.clone(),
            self.host.allowance.policies.clone(),
            self.host.allowance.max_job_millis,
        )
        .unwrap()
        .execute(
            &self.host.world.administrator(ROOT).await,
            ids::ROOT_GRANT,
            command,
        )
        .await
        .unwrap()
    }
    async fn http(&self) -> Http {
        let access = self.host.gateway_access().await;
        let bearer = access.bearer();
        let server = hellas_gateway::start(hellas_gateway::GatewayOptions {
            server: hellas_gateway::ServerOptions {
                archive: hellas_gateway::ArchiveOptions {
                    directory: self.host.root.path().join("archive"),
                    zdr: true,
                },
                host: "127.0.0.1".into(),
                port: Some(0),
                access,
                allow_remote: false,
                wrap: None,
                wrap_args: vec![],
            },
            work: self.gateway.clone(),
            presentations: hellas_gateway::Presentations {
                http: self.gateway.http_config().unwrap(),
                ..Default::default()
            },
        })
        .await
        .unwrap();
        Http {
            server,
            bearer,
            client: reqwest::Client::new(),
        }
    }
    async fn shutdown(self) {
        self.gateway.drain().await.unwrap();
        if let Some(remote) = self.remote {
            remote.shutdown().await;
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
            resource: None,
            channel: None,
            provider: self.gateway.source.channels[0].provider,
            service: "openai".into(),
            method: "responses".into(),
            body: serde_json::to_vec(&http).unwrap(),
        }
    }
    async fn result(&self, cap: Option<u64>) -> Result<(), WorkGatewayError> {
        let mut stream = self.gateway.fetch(self.request(cap))?;
        let mut terminal = false;
        while let Some(event) = stream.next().await {
            terminal |= matches!(event?, WorkEvent::Output(event) if event.terminal().is_some());
        }
        assert!(terminal);
        Ok(())
    }
}

/// The gateway names the accepted work and its provider before any output,
/// and hands over the transcript that provider signed: every envelope
/// verifies under the announced key, and the bytes are exactly those the
/// provider's signed result for that work id names.
#[tokio::test]
async fn delivered_transcripts_verify_against_the_accepting_provider() {
    let fixture = Fixture::builder().build().await;
    let mut stream = fixture.gateway.fetch(fixture.request(None)).unwrap();
    let mut events = Vec::new();
    while let Some(event) = within(stream.next()).await {
        events.push(event.unwrap());
    }
    let WorkEvent::Accepted(accepted) = &events[0] else {
        panic!("acceptance must precede output")
    };
    assert!(matches!(
        &events[1],
        WorkEvent::Output(OutputEvent::Adaptor(AdaptorEvent::Http(
            HttpResponseEvent::Head { .. }
        )))
    ));
    let [
        ..,
        WorkEvent::Transcript(transcript),
        WorkEvent::Output(terminal),
    ] = events.as_slice()
    else {
        panic!("the transcript must precede the terminal")
    };
    assert!(terminal.terminal().is_some());
    let provider = PublicKey::Secp256k1(
        hellas_authority::model::grant::records::grant_producer(
            &fixture.gateway.source.channels[0].offer.offer().provider,
        )
        .unwrap()
        .to_bytes(),
    );
    assert_eq!(accepted.provider, provider);

    let envelopes = hellas_channel::model::work::decode_transcript(
        transcript,
        hellas_channel::work_store::journal::MAX_RECORD_BYTES,
    )
    .unwrap();
    assert!(!envelopes.is_empty());
    for envelope in &envelopes {
        envelope.verify(&provider).unwrap();
    }
    let stranger = ProducerSigningKey::from_secret_bytes([9; 32])
        .unwrap()
        .public_key();
    assert!(envelopes[0].verify(&stranger).is_err());

    let session = fixture.gateway.source.channels[0].session.lock().await;
    let job = session
        .store()
        .book()
        .job_by_id(hellas_auth::Digest::from_bytes(accepted.commitment_id))
        .expect("the commitment names the accepted job");
    let (result, _) = job.result().expect("the provider signed a result");
    assert_eq!(result.work_id.as_bytes(), &accepted.commitment_id);
    assert_eq!(
        hellas_rpc::ContentRef::for_bytes(transcript),
        result.transcript_content
    );
    drop(session);
    fixture.shutdown().await;
}

#[tokio::test]
async fn resource_repair_precedes_client_signing() {
    let fixture = Fixture::builder()
        .inspect_request(inspect_chat)
        .build()
        .await;
    let config = fixture.gateway.http_config().unwrap().unwrap();
    assert_eq!(config.routes[0].max_response_bytes, 4096);
    assert_eq!(config.routes[0].tls, fixture.template.tls);
    fixture.result(None).await.unwrap();
    assert_eq!(fixture.host.backend.calls.load(Ordering::SeqCst), 1);
    fixture.shutdown().await;
}

#[tokio::test]
async fn disconnected_consumers_do_not_abandon_accepted_work() {
    let fixture = Fixture::builder().hold_completion().build().await;
    let mut stream = fixture.gateway.fetch(fixture.request(None)).unwrap();
    assert!(matches!(
        within(stream.next()).await.unwrap().unwrap(),
        WorkEvent::Accepted(_)
    ));
    // Admission includes durable writes. Wait for the producer's progress before
    // testing its delivery; the finish gate remains closed throughout this check.
    let first = tokio::select! {
        event = stream.next() => event,
        _ = fixture.host.backend.started.notified() => {
            within(stream.next()).await
        }
    }
    .unwrap()
    .unwrap();
    assert!(matches!(
        first,
        WorkEvent::Output(OutputEvent::Adaptor(AdaptorEvent::Http(
            HttpResponseEvent::Head { .. }
        )))
    ));
    assert_eq!(fixture.host.backend.calls.load(Ordering::SeqCst), 1);
    drop(stream);
    fixture.host.backend.finish.release();
    fixture.gateway.drain().await.unwrap();
    assert_eq!(fixture.host.backend.slots.available_permits(), 2);
    assert_err!(
        fixture.gateway.fetch(fixture.request(None)),
        WorkGatewayError::Busy(_)
    );
}

#[tokio::test]
async fn requests_above_the_resource_cap_do_not_execute() {
    let fixture = Fixture::builder().build().await;
    assert_err!(fixture.result(Some(7)).await, WorkGatewayError::Rejected(_));
    assert_eq!(fixture.host.backend.calls.load(Ordering::SeqCst), 0);
    fixture.shutdown().await;
}

#[tokio::test]
async fn paused_terms_are_denied_at_the_gateway() {
    let fixture = Fixture::builder().build().await;
    let WorkControlReply::Status { allowance, .. } = fixture
        .command(WorkControlCommand::Inspect { id: ids::ALLOWANCE })
        .await
    else {
        panic!("allowance status")
    };
    let grant = &fixture.host.allowance;
    let terms = hellas_authority::model::grant::admin::AllowanceTerms {
        policies: grant.policies.iter().map(|p| p.name.clone()).collect(),
        budget: grant.budget,
        max_job_millis: grant.max_job_millis,
        enabled: false,
        allow_account_backed: grant.allow_account_backed,
    };
    fixture
        .command(WorkControlCommand::Revise {
            id: ids::ALLOWANCE,
            expected_revision: allowance.revision,
            terms,
        })
        .await;
    assert_err!(fixture.result(None).await, WorkGatewayError::Denied(_));
    assert_eq!(fixture.host.backend.calls.load(Ordering::SeqCst), 0);
    fixture.shutdown().await;
}

#[tokio::test]
async fn refreshed_https_bounds_are_checked_before_proposal() {
    for change in 0..5 {
        let fixture = Fixture::builder().build().await;
        let mut policy = fixture.host.allowance.policies[0].clone();
        policy.revision.0 += 1;
        let https = policy.https.as_mut().unwrap();
        match change {
            0 => https.origin = "https://changed.fixture".into(),
            1 => https.credential = Some("changed".into()),
            2 => https.max_output_tokens = 3,
            3 => https.paths = vec!["/changed".into()],
            _ => https.max_response_bytes = 128,
        }
        let guard = fixture.gateway.source.channels[0].session.lock().await;
        let mut stream = fixture.gateway.fetch(fixture.request(Some(6))).unwrap();
        let admin = hellas_authority::test_support::common_node::WorkAdmin::new(
            fixture.host.world.service.clone(),
            fixture.host.world.secret(ROOT),
            vec![policy.clone()],
        )
        .await;
        admin
            .command(WorkControlCommand::ConfigureResource {
                policy: policy.name,
            })
            .await
            .unwrap();
        let grant = &fixture.host.allowance;
        admin
            .command(WorkControlCommand::Revise {
                id: ids::ALLOWANCE,
                expected_revision: grant.revision,
                terms: hellas_authority::model::grant::admin::AllowanceTerms {
                    policies: grant.policies.iter().map(|p| p.name.clone()).collect(),
                    budget: grant.budget,
                    max_job_millis: grant.max_job_millis,
                    enabled: true,
                    allow_account_backed: grant.allow_account_backed,
                },
            })
            .await
            .unwrap();
        drop(guard);
        assert!(within(stream.next()).await.unwrap().is_err());
        assert_eq!(fixture.host.backend.calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            fixture.gateway.source.channels[0]
                .session
                .lock()
                .await
                .store()
                .next_nonce()
                .unwrap(),
            1
        );
        fixture.shutdown().await;
    }
}

#[tokio::test]
async fn renamed_policy_keeps_the_selected_resource() {
    let fixture = Fixture::builder().build().await;
    let journal = tempfile::tempdir().unwrap();
    let mut options = fixture.host.options(vec![]);
    options.journal_root = journal.path().to_owned();
    let source = GrantSource::open(
        options,
        GrantTransport::Local(fixture.host.world.service.clone()),
        Some("chat".into()),
    )
    .await
    .unwrap();
    let gateway = Arc::new(WorkGateway::new(GrantPoolSource::single(source), 32));
    let mut policy = fixture.host.allowance.policies[0].clone();
    policy.revision.0 += 1;
    policy.name = "renamed".into();
    let guard = gateway.source.channels[0].session.lock().await;
    let mut stream = gateway.fetch(fixture.request(None)).unwrap();
    let admin = hellas_authority::test_support::common_node::WorkAdmin::new(
        fixture.host.world.service.clone(),
        fixture.host.world.secret(ROOT),
        vec![policy.clone()],
    )
    .await;
    admin
        .command(WorkControlCommand::ConfigureResource {
            policy: policy.name.clone(),
        })
        .await
        .unwrap();
    let grant = &fixture.host.allowance;
    admin
        .command(WorkControlCommand::Revise {
            id: ids::ALLOWANCE,
            expected_revision: grant.revision,
            terms: hellas_authority::model::grant::admin::AllowanceTerms {
                policies: vec![policy.name],
                budget: grant.budget,
                max_job_millis: grant.max_job_millis,
                enabled: true,
                allow_account_backed: grant.allow_account_backed,
            },
        })
        .await
        .unwrap();
    drop(guard);
    while let Some(event) = within(stream.next()).await {
        event.unwrap();
    }
    assert_eq!(fixture.host.backend.calls.load(Ordering::SeqCst), 1);
    gateway.drain().await.unwrap();
    fixture.shutdown().await;
}

#[tokio::test]
async fn wrong_resource_or_channel_never_reaches_a_proposal() {
    let fixture = Fixture::builder().build().await;
    let resource = fixture.host.allowance.policies[0].resource;
    let channel = fixture.gateway.source.channels[0].channel;
    for (selected_resource, selected_channel) in [
        (
            Some(hellas_auth::authority::ResourceId(
                hellas_auth::Digest::hash(b"other"),
            )),
            Some(channel),
        ),
        (
            Some(resource),
            Some(hellas_channel::model::grant::ChannelId(
                hellas_auth::Digest::hash(b"other"),
            )),
        ),
        (Some(resource), None),
    ] {
        let mut request = fixture.request(None);
        request.resource = selected_resource;
        request.channel = selected_channel;
        assert!(fixture.gateway.fetch(request).is_err());
    }
    assert_eq!(fixture.host.backend.calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        fixture.gateway.source.channels[0]
            .session
            .lock()
            .await
            .store()
            .next_nonce()
            .unwrap(),
        1
    );
    fixture.shutdown().await;
}

#[tokio::test]
async fn https_policy_conversion_rejects_a_non_http_schema() {
    let fixture = Fixture::builder().build().await;
    let mut policy = fixture.host.allowance.policies[0].clone();
    for admission in &mut policy.invocation_policy.admissions {
        if let Admission::Fetch { admission } = admission {
            admission.contract = hellas_channel::test_support::test_responses_contract();
        }
    }
    assert!(policy_http_routes(&policy).is_err());
    fixture.shutdown().await;
}

#[tokio::test]
async fn https_policy_conversion_keeps_models_on_their_signed_paths() {
    let fixture = Fixture::builder().build().await;
    let mut policy = fixture.host.allowance.policies[0].clone();
    let template = policy.https.as_mut().unwrap();
    template.paths.push("/health".into());
    template.model_policy = Some(vec![
        hellas_authority::model::grant::resource::PathModelPolicy {
            path: template.paths[0].clone(),
            models: vec!["model-a".into()],
        },
    ]);
    let (_, _, routes) = policy_http_routes(&policy).unwrap();
    let restricted = routes
        .iter()
        .find(|route| route.path == "/v1/chat/completions")
        .unwrap();
    assert_eq!(
        restricted.models.as_deref(),
        Some(["model-a".to_string()].as_slice())
    );
    assert!(
        routes
            .iter()
            .find(|route| route.path == "/health")
            .unwrap()
            .models
            .is_none()
    );
    fixture.shutdown().await;
}

#[tokio::test]
async fn reused_policy_name_cannot_retarget_an_in_flight_request() {
    let fixture = Fixture::builder().build().await;
    let old = fixture.host.allowance.policies[0].clone();
    let mut renamed = old.clone();
    renamed.revision.0 += 1;
    renamed.name = "old-resource".into();
    let mut replacement = old.clone();
    replacement.resource =
        hellas_auth::authority::ResourceId(hellas_auth::Digest::hash(b"replacement"));
    let guard = fixture.gateway.source.channels[0].session.lock().await;
    let mut stream = fixture.gateway.fetch(fixture.request(None)).unwrap();
    let admin = hellas_authority::test_support::common_node::WorkAdmin::new(
        fixture.host.world.service.clone(),
        fixture.host.world.secret(ROOT),
        vec![renamed.clone(), replacement.clone()],
    )
    .await;
    for policy in [renamed.name, replacement.name.clone()] {
        admin
            .command(WorkControlCommand::ConfigureResource { policy })
            .await
            .unwrap();
    }
    let grant = &fixture.host.allowance;
    admin
        .command(WorkControlCommand::Revise {
            id: ids::ALLOWANCE,
            expected_revision: grant.revision,
            terms: hellas_authority::model::grant::admin::AllowanceTerms {
                policies: vec![replacement.name],
                budget: grant.budget,
                max_job_millis: grant.max_job_millis,
                enabled: true,
                allow_account_backed: grant.allow_account_backed,
            },
        })
        .await
        .unwrap();
    drop(guard);
    assert!(within(stream.next()).await.unwrap().is_err());
    assert_eq!(fixture.host.backend.calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        fixture.gateway.source.channels[0]
            .session
            .lock()
            .await
            .store()
            .next_nonce()
            .unwrap(),
        1
    );
    fixture.shutdown().await;
}

#[tokio::test]
async fn source_start_failure_does_not_close_shared_endpoint() {
    let fixture = Fixture::builder().remote().build().await;
    let endpoint = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
        .bind_addr("127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap())
        .unwrap()
        .bind()
        .await
        .unwrap();
    let mut options = fixture
        .host
        .options(fixture.remote.as_ref().unwrap().addresses());
    let journal = tempfile::tempdir().unwrap();
    options.journal_root = journal.path().to_owned();
    assert!(
        GrantSource::open(
            options.clone(),
            GrantTransport::Remote(endpoint.clone()),
            Some("missing".into())
        )
        .await
        .is_err()
    );
    assert!(!endpoint.is_closed());
    let source = GrantSource::open(options, GrantTransport::Remote(endpoint.clone()), None)
        .await
        .unwrap();
    source.session.lock().await.shutdown().await.unwrap();
    assert!(!endpoint.is_closed());
    endpoint.close().await;
    fixture.shutdown().await;
}

#[tokio::test]
async fn gateway_closes_remote_endpoint_after_drain() {
    let fixture = Fixture::builder().remote().build().await;
    let endpoint = fixture
        .gateway
        .endpoints
        .lock()
        .await
        .first()
        .unwrap()
        .clone();
    assert!(!endpoint.is_closed());
    fixture.gateway.drain().await.unwrap();
    assert!(endpoint.is_closed());
    assert!(fixture.gateway.endpoints.lock().await.is_empty());
    if let Some(remote) = fixture.remote {
        remote.shutdown().await;
    }
}

struct Http {
    server: hellas_gateway::GatewayHandle,
    bearer: String,
    client: reqwest::Client,
}
impl Http {
    async fn status(&self) -> reqwest::StatusCode {
        let response = self
            .client
            .post(format!(
                "http://{}/v1/chat/completions",
                self.server.address()
            ))
            .bearer_auth(&self.bearer)
            .json(&serde_json::json!({"messages":[],"stream":true}))
            .send()
            .await
            .unwrap();
        let status = response.status();
        response.bytes().await.unwrap();
        status
    }
}

#[tokio::test]
async fn budget_refusals_map_to_http_too_many_requests() {
    let fixture = Fixture::builder().with_budget(0).build().await;
    let http = fixture.http().await;
    assert_eq!(http.status().await, reqwest::StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(fixture.host.backend.calls.load(Ordering::SeqCst), 0);
    http.server.shutdown().await.unwrap();
    fixture.shutdown().await;
}

#[tokio::test]
async fn repaired_resources_are_usable_through_the_gateway() {
    let fixture = Fixture::builder()
        .without_usage()
        .with_budget(100)
        .build()
        .await;
    // L2 owns the quarantine threshold and counters; arrange that state through Work.
    for _ in 0..3 {
        fixture.result(None).await.unwrap();
    }
    let http = fixture.http().await;
    assert_eq!(http.status().await, reqwest::StatusCode::FORBIDDEN);
    let WorkControlReply::Resource {
        revision,
        quarantined,
        ..
    } = fixture
        .command(WorkControlCommand::InspectResource {
            policy: "chat".into(),
        })
        .await
    else {
        panic!("resource health")
    };
    assert!(quarantined);
    let calls = fixture.host.backend.calls.load(Ordering::SeqCst);
    fixture
        .command(WorkControlCommand::RepairResource {
            policy: "chat".into(),
            expected_revision: revision,
        })
        .await;
    assert_eq!(http.status().await, reqwest::StatusCode::OK);
    assert_eq!(fixture.host.backend.calls.load(Ordering::SeqCst) - calls, 1);
    http.server.shutdown().await.unwrap();
    fixture.shutdown().await;
}

#[tokio::test]
async fn revoked_credentials_close_cached_sessions_before_refusing_reconnection() {
    let fixture = Fixture::builder().remote().build().await;
    let http = fixture.http().await;
    // Opening the grant gateway already authenticated and cached its Work session.
    let node = fixture.host.world.service.node();
    node.revoke_credential(
        &fixture.host.world.administrator(ROOT).await,
        ids::ROOT_GRANT,
        fixture.host.application.credential.id(),
        hellas_auth::authority::Revision(1),
    )
    .await
    .unwrap();
    assert_eq!(http.status().await, reqwest::StatusCode::BAD_GATEWAY);
    assert_eq!(http.status().await, reqwest::StatusCode::FORBIDDEN);
    assert_eq!(fixture.host.backend.calls.load(Ordering::SeqCst), 0);
    http.server.shutdown().await.unwrap();
    fixture.shutdown().await;
}

/// Control timeouts do not bound a stream within its signed job terms.
#[tokio::test]
async fn streams_outlast_the_control_timeout_while_they_progress() {
    let chunks = 5;
    let fixture = Fixture::builder()
        .paced(chunks)
        .with_max_job_millis(60_000)
        .hold_completion()
        .build()
        .await;
    let pace = fixture.host.backend.pace.clone().unwrap();
    let mut stream = fixture.gateway.fetch(fixture.request(None)).unwrap();
    assert!(matches!(
        within(stream.next()).await.unwrap().unwrap(),
        WorkEvent::Accepted(_)
    ));
    assert!(matches!(
        within(stream.next()).await.unwrap().unwrap(),
        WorkEvent::Output(OutputEvent::Adaptor(AdaptorEvent::Http(
            HttpResponseEvent::Head { .. }
        )))
    ));
    tokio::time::pause();
    for _ in 0..chunks {
        tokio::time::advance(std::time::Duration::from_secs(4)).await;
        pace.release();
        assert!(matches!(
            stream.next().await.unwrap().unwrap(),
            WorkEvent::Output(OutputEvent::Adaptor(AdaptorEvent::Http(
                HttpResponseEvent::Body { .. }
            )))
        ));
    }
    tokio::time::resume();
    pace.release(); // The usage chunk.
    fixture.host.backend.finish.release();
    let mut terminal = false;
    while let Some(event) = within(stream.next()).await {
        terminal |=
            matches!(event.unwrap(), WorkEvent::Output(event) if event.terminal().is_some());
    }
    assert!(terminal);
    fixture.shutdown().await;
}

#[tokio::test]
async fn silent_first_result_outlasts_the_control_timeout() {
    let fixture = Fixture::builder()
        .hold_first()
        .with_max_job_millis(60_000)
        .build()
        .await;
    let mut stream = fixture.gateway.fetch(fixture.request(None)).unwrap();
    within(fixture.host.backend.started.notified()).await;
    assert!(matches!(
        within(stream.next()).await.unwrap().unwrap(),
        WorkEvent::Accepted(_)
    ));
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(6)).await;
    assert!(
        futures::poll!(stream.next()).is_pending(),
        "silent accepted work must keep waiting"
    );
    tokio::time::resume();
    fixture.host.backend.first.as_ref().unwrap().release();
    let mut terminal = false;
    while let Some(event) = within(stream.next()).await {
        terminal |=
            matches!(event.unwrap(), WorkEvent::Output(event) if event.terminal().is_some());
    }
    assert!(terminal);
    fixture.shutdown().await;
}

#[tokio::test]
async fn silent_later_result_outlasts_the_control_timeout() {
    let fixture = Fixture::builder()
        .paced(1)
        .with_max_job_millis(60_000)
        .build()
        .await;
    let mut stream = fixture.gateway.fetch(fixture.request(None)).unwrap();
    // The acceptance, then the response head.
    for _ in 0..2 {
        within(stream.next()).await.unwrap().unwrap();
    }
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(6)).await;
    assert!(
        futures::poll!(stream.next()).is_pending(),
        "result gaps are not control RPCs"
    );
    tokio::time::resume();
    let pace = fixture.host.backend.pace.as_ref().unwrap();
    pace.release();
    pace.release();
    let mut terminal = false;
    while let Some(event) = within(stream.next()).await {
        terminal |=
            matches!(event.unwrap(), WorkEvent::Output(event) if event.terminal().is_some());
    }
    assert!(terminal);
    fixture.shutdown().await;
}

#[tokio::test]
async fn silent_work_still_ends_at_the_signed_deadline() {
    let fixture = Fixture::builder()
        .hold_first()
        .with_max_job_millis(20_000)
        .build()
        .await;
    let mut stream = fixture.gateway.fetch(fixture.request(None)).unwrap();
    within(fixture.host.backend.started.notified()).await;
    assert!(matches!(
        within(stream.next()).await.unwrap().unwrap(),
        WorkEvent::Accepted(_)
    ));
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(6)).await;
    assert!(
        futures::poll!(stream.next()).is_pending(),
        "must not expire at the control timeout"
    );
    fixture
        .host
        .world
        .clock
        .set(hellas_auth::authority::UnixMillis(21_001));
    // Keep execution blocked: only the provider's signed expiry may end delivery.
    tokio::time::advance(Duration::from_secs(15)).await;
    tokio::time::resume();
    let error = within(stream.next()).await.unwrap().unwrap_err();
    assert!(
        matches!(
            error,
            WorkGatewayError::Denied(_) | WorkGatewayError::Execution(_)
        ),
        "{error:?}"
    );
    fixture.host.backend.first.as_ref().unwrap().release();
    fixture.shutdown().await;
}

#[tokio::test]
async fn queued_requests_wait_without_a_deadline_and_cancel_on_disconnect() {
    let fixture = Fixture::builder().build().await;
    for disconnect in [false, true] {
        let held = fixture.gateway.source.channels[0].session.lock().await;
        let request = fixture
            .gateway
            .source
            .request(WorkRequest::Fetch(fixture.request(None)))
            .unwrap();
        let (requester, stream) = Requester::<OutputEvent, WorkGatewayError>::new();
        let run = fixture.gateway.source.clone().run(request, requester);
        tokio::pin!(run);
        assert!(futures::poll!(run.as_mut()).is_pending());
        tokio::time::pause();
        tokio::time::advance(Duration::from_secs(6)).await;
        assert!(futures::poll!(run.as_mut()).is_pending());
        tokio::time::resume();
        if disconnect {
            drop(stream);
            // Finish while the other request still owns the mutex.
            assert!(within(run).await.unwrap().is_none());
            assert_eq!(held.store().next_nonce().unwrap(), 2);
            drop(held);
        } else {
            drop(held);
            assert!(within(run).await.unwrap().is_some());
            drop(stream);
        }
    }
    assert_eq!(fixture.host.backend.calls.load(Ordering::SeqCst), 1);
    fixture.shutdown().await;
}

/// The host cancels work, and closes its connection, when the session that
/// delivers it expires. A longer allowance is cut to what the session carries.
#[tokio::test]
async fn remote_jobs_end_before_the_session_that_delivers_them() {
    let fixture = Fixture::builder()
        .remote()
        .with_max_job_millis(20 * 60_000)
        .build()
        .await;
    fixture.result(None).await.unwrap();
    let channel = fixture.gateway.source.channels[0]
        .session
        .lock()
        .await
        .store()
        .channel()
        .id;
    let state = fixture.host.world.snapshot().await;
    let terminals: Vec<_> = state
        .channel(channel)
        .unwrap()
        .job_book()
        .terminals()
        .collect();
    let [terminal] = terminals[..] else {
        panic!("one finished job")
    };
    let a = terminal.outcome.authorization;
    // Signed 30 s before its acceptance deadline; one 5 s idle period is kept
    // for the terminal state before the 15 min session ends.
    let span = a.terminal_deadline_ms.0 - (a.acceptance_deadline_ms.0 - 30_000);
    let carried = hellas_auth::authority::MAX_SESSION_LIFETIME_MS - 5_000;
    assert!(
        span <= carried && span > carried - 1_000,
        "signed {span} ms"
    );
    fixture.shutdown().await;
}

#[tokio::test]
async fn disconnect_during_control_does_not_propose() {
    let fixture = Fixture::builder().build().await;
    let node = fixture.host.world.service.node();
    let held = hellas_authority::test_support::hold_writer(&node).await;
    let request = fixture
        .gateway
        .source
        .request(WorkRequest::Fetch(fixture.request(None)))
        .unwrap();
    let (requester, stream) = Requester::<OutputEvent, WorkGatewayError>::new();
    let run = fixture.gateway.source.clone().run(request, requester);
    tokio::pin!(run);
    assert!(futures::poll!(run.as_mut()).is_pending());
    drop(stream);
    assert!(within(run).await.unwrap().is_none());
    assert_eq!(
        fixture.gateway.source.channels[0]
            .session
            .lock()
            .await
            .store()
            .next_nonce()
            .unwrap(),
        1
    );
    assert_eq!(fixture.host.backend.calls.load(Ordering::SeqCst), 0);
    drop(held);
    fixture.shutdown().await;
}
