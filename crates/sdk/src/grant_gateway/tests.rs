use super::*;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use futures::StreamExt;
use hellas_rpc::output::{AdaptorEvent, HttpResponseEvent};
use hellas_work::model::grant::admin::{WorkControlCommand, WorkControlReply};
use hellas_work::model::grant::{budget::*, resource::*};
use hellas_work::test_support::{
    Allowance, Capacity,
    actors::{FRIEND, ROOT},
    assert_err, chat_resource, ids, use_https, within,
};
use std::sync::atomic::Ordering;

use hellas_work::test_support::backend::{Backend, Completion, Reply};
fn inspect_chat(request: &hellas_rpc::fetch::FetchInput) {
    let http = hellas_rpc::http_fetch::HttpFetchRequest::decode(request.body.as_bytes()).unwrap();
    let body: serde_json::Value = serde_json::from_slice(&http.body().unwrap()).unwrap();
    assert_eq!(body["max_tokens"], 6);
    assert_eq!(body["stream_options"]["include_usage"], true);
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
}
impl FixtureBuilder {
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
        let backend = Backend {
            slots: Arc::new(Semaphore::new(2)),
            finish: self.completion,
            reply: Reply::events(Reply::http(
                200,
                "text/event-stream",
                match self.usage {
                    UsageReport::Reported => {
                        "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":3,\"completion_tokens\":2,\"total_tokens\":5}}\n\ndata: [DONE]\n\n"
                    }
                    UsageReport::Missing => "data: [DONE]\n\n",
                },
            )),
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
        }
    }
    async fn command(&self, command: WorkControlCommand) -> WorkControlReply {
        hellas_work::grant_service::WorkAdministration::new(
            self.host.world.service.clone(),
            self.host.allowance.policies.clone(),
            self.host.allowance.max_job_millis,
        )
        .unwrap()
        .execute(
            &self.host.world.caller(ROOT).await,
            ids::ROOT_GRANT,
            command,
        )
        .await
        .unwrap()
    }
    async fn http(&self) -> Http {
        let access = self.host.gateway_access().await;
        let bearer = access.bearer();
        let server = hellas_gateway::start_http(hellas_gateway::HttpGatewayOptions {
            config: self.gateway.http_config().unwrap(),
            paid: self.gateway.clone(),
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
            provider: self.gateway.provider,
            service: "openai".into(),
            method: "responses".into(),
            body: serde_json::to_vec(&http).unwrap(),
        }
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
async fn resource_repair_precedes_client_signing() {
    let fixture = Fixture::builder()
        .inspect_request(inspect_chat)
        .build()
        .await;
    let config = fixture.gateway.http_config().unwrap();
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
        OutputEvent::Adaptor(AdaptorEvent::Http(HttpResponseEvent::Head { .. }))
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
    let terms = hellas_work::model::grant::admin::AllowanceTerms {
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
        &fixture.host.world.caller(ROOT).await,
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
