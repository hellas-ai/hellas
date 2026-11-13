use super::*;
use hellas_authority::model::grant::budget::*;
use hellas_executor::{FetchProvider, FetchProviderFuture, PreparedFetchRequest};
use hellas_private::StoreLocation;
use hellas_rpc::Assurance;
use hellas_rpc::ProviderEnrollmentBundle;
use hellas_sdk::daemon::{Core, testing::Daemon};
use hellas_sdk::daemon_config::{BackendKind, Document, Listener};
use hellas_sdk::{
    FetchRoute, FetchRouteEntry, FetchRoutePolicy, FetchRouteRegistry, NodeIdentity, RootProver,
    grant_client::UnpinnedOffer,
};
use std::sync::Arc;
use std::{
    num::NonZeroU64,
    sync::atomic::{AtomicUsize, Ordering},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct UnusedRoot;
impl RootProver for UnusedRoot {
    fn prove_statement<'a>(&'a self, _: &'a [u8]) -> hellas_attestation::RootProofFuture<'a> {
        Box::pin(async move { panic!("software enrollment was already signed") })
    }
    fn prove_open_binding<'a>(
        &'a self,
        _: hellas_auth::Digest,
    ) -> hellas_attestation::RootProofFuture<'a> {
        Box::pin(async move { panic!("software Open must sign with the producer, not the root") })
    }
}

struct TlsResponses {
    client: reqwest::Client,
    url: reqwest::Url,
}
impl FetchProvider for TlsResponses {
    fn execution_environment(&self) -> hellas_rpc::ContentId {
        hellas_adaptors::openai::responses::fetch::responses_contract()
            .unwrap()
            .manifest_id()
    }
    fn run(&self, request: PreparedFetchRequest) -> FetchProviderFuture<'_> {
        Box::pin(async move {
            hellas_providers::execute_responses_request(
                &self.client,
                self.url.clone(),
                "fixture-secret",
                request.body.as_bytes().to_vec(),
                &request.idempotency_key(),
                "TLS fixture",
            )
            .await
        })
    }
}

fn response_events(output_tokens: u64) -> String {
    use serde_json::json;
    let part = json!({"type":"output_text","text":"hello","annotations":[]});
    let message = json!({"type":"message","id":"msg_1","status":"completed","role":"assistant","content":[part.clone()]});
    [
        json!({"type":"response.created","response":{"id":"resp_1","object":"response","status":"in_progress","model":"fixture","output":[]}}),
        json!({"type":"response.output_item.added","output_index":0,"item":{"type":"message","id":"msg_1","status":"in_progress","role":"assistant","content":[]}}),
        json!({"type":"response.content_part.added","item_id":"msg_1","output_index":0,"content_index":0,"part":{"type":"output_text","text":"","annotations":[]}}),
        json!({"type":"response.output_text.delta","item_id":"msg_1","output_index":0,"content_index":0,"delta":"hello"}),
        json!({"type":"response.output_text.done","item_id":"msg_1","output_index":0,"content_index":0,"text":"hello"}),
        json!({"type":"response.content_part.done","item_id":"msg_1","output_index":0,"content_index":0,"part":part}),
        json!({"type":"response.output_item.done","output_index":0,"item":message.clone()}),
        json!({"type":"response.completed","response":{"id":"resp_1","object":"response","status":"completed","model":"fixture","output":[message],"usage":{"input_tokens":3,"output_tokens":output_tokens,"total_tokens":3 + output_tokens}}}),
    ].into_iter().enumerate().map(|(i, mut event)| { event["sequence_number"] = i.into(); format!("event: {}\ndata: {event}\n\n", event["type"].as_str().unwrap()) }).collect()
}

#[derive(Clone, Default)]
struct HeldUpstream {
    started: Arc<tokio::sync::Notify>,
    dropped: Arc<tokio::sync::Notify>,
}
#[derive(Default)]
enum UpstreamMode {
    #[default]
    Complete,
    Held(HeldUpstream),
}
struct TlsFixture {
    provider: Arc<TlsResponses>,
    calls: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for TlsFixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}
async fn tls_fixture(mode: UpstreamMode) -> TlsFixture {
    let (ca, acceptor) = hellas_providers::test_support::private_ca_acceptor();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!(
        "https://localhost:{}/v1/responses",
        listener.local_addr().unwrap().port()
    )
    .parse()
    .unwrap();
    let client = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_der(ca.as_ref().der()).unwrap())
        .redirect(reqwest::redirect::Policy::none())
        .timeout(HANG_GUARD)
        .build()
        .unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let count = calls.clone();
    let task = tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            let mut socket = acceptor.accept(socket).await.unwrap();
            let mut headers = vec![];
            while !headers.ends_with(b"\r\n\r\n") {
                assert!(headers.len() < 16384);
                headers.push(socket.read_u8().await.unwrap());
            }
            let headers = String::from_utf8(headers).unwrap().to_lowercase();
            assert!(headers.starts_with("post /v1/responses "));
            assert!(headers.contains("authorization: bearer fixture-secret\r\n"));
            assert!(headers.contains("idempotency-key:"));
            let length: usize = headers
                .lines()
                .find_map(|h| h.strip_prefix("content-length: "))
                .unwrap()
                .parse()
                .unwrap();
            assert!(length < 16384);
            let mut body = vec![0; length];
            socket.read_exact(&mut body).await.unwrap();
            let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(body["store"], false);
            assert_eq!(body["stream"], true);
            assert_eq!(body["max_output_tokens"], 8);
            count.fetch_add(1, Ordering::SeqCst);
            if let UpstreamMode::Held(held) = &mode {
                socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n").await.unwrap();
                held.started.notify_one();
                assert!(
                    matches!(
                        socket.read_u8().await.unwrap_err().kind(),
                        std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::ConnectionReset
                    ),
                    "cancelled upstream must close the TLS body"
                );
                held.dropped.notify_one();
                continue;
            }
            let body = response_events(2);
            socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).await.unwrap();
            socket.shutdown().await.unwrap();
        }
    });
    TlsFixture {
        provider: Arc::new(TlsResponses { client, url }),
        calls,
        task,
    }
}

use hellas_auth::authority::{CredentialSecret, GrantId, Revision};
use hellas_authority::model::grant::admin::{WorkControlCommand, WorkControlReply};
use {
    hellas_authority::test_support::Allowance, hellas_authority::test_support::Capacity,
    hellas_authority::test_support::HANG_GUARD, hellas_authority::test_support::Node,
    hellas_authority::test_support::TestClock, hellas_authority::test_support::authority,
    hellas_authority::test_support::ids, hellas_channel::test_support::Rights,
    hellas_channel::test_support::actors::FRIEND, hellas_channel::test_support::actors::PROVIDER,
    hellas_channel::test_support::actors::ROOT,
};
const ROOT_GRANT: GrantId = ids::ROOT_GRANT;
const ALLOWANCE: GrantId = GrantId([7; 16]);

#[derive(Default)]
struct ShareFixtureBuilder {
    upstream: UpstreamMode,
}
struct ShareFixture {
    _root: tempfile::TempDir,
    upstream: TlsFixture,
    provider: Daemon,
    gateway: ControlledGateway,
    administrator: CredentialSecret,
    application: Arc<hellas_sdk::node_control::profile::ClientProfile>,
}
impl ShareFixtureBuilder {
    fn with_held_upstream(mut self, held: HeldUpstream) -> Self {
        self.upstream = UpstreamMode::Held(held);
        self
    }
    async fn start(self) -> ShareFixture {
        let root = tempfile::tempdir().unwrap();
        let provider_identity =
            NodeIdentity::from_secret_bytes([5; 32], PROVIDER.node_key().to_secret_bytes())
                .unwrap();
        let provider_bundle = software_enrollment(&provider_identity);
        let client_identity =
            NodeIdentity::from_secret_bytes([3; 32], FRIEND.node_key().to_secret_bytes()).unwrap();
        let upstream = tls_fixture(self.upstream).await;
        let content = hellas_channel::test_support::channel::content_store(root.path()).await;
        content.finish_recovery().await.unwrap();
        let document = openai_document(share_options()).unwrap();
        let configuration = hellas_sdk::daemon::testing::configuration(&document).await;
        let mut routes = FetchRouteRegistry::new();
        routes.register(FetchRoute::new("openai", "responses"), FetchRouteEntry::new(
            upstream.provider.clone(),
            Arc::new(hellas_adaptors::openai::responses::fetch::OpenAiResponsesAdaptorFactory::new().unwrap()),
            FetchRoutePolicy::default(),
        ).unwrap()).unwrap();
        let clock = TestClock::new(hellas_auth::authority::UnixMillis::now().unwrap_or_default());
        let mut allowance = Allowance::responses(ALLOWANCE, FRIEND);
        allowance.definition.policies = configuration.resources().to_vec();
        allowance.definition.max_job_millis = NonZeroU64::new(60_000).unwrap();
        let location = StoreLocation::for_test(root.path());
        let world = Node::bootstrap(&location.child("provider").child("authority"))
            .with_network(hellas_authority::model::grant::grant_network())
            .with_provider(provider_bundle.clone())
            .with_clock(clock.clone())
            .with_capacity(Capacity::new(1))
            .with_allowance(allowance)
            .with_grant(
                ids::FRIEND_GRANT,
                Rights::new(authority(), FRIEND)
                    .allow(
                        hellas_authority::grant_service::WORK_EXECUTE,
                        hellas_authority::grant_service::allowance_resource(authority(), ALLOWANCE),
                    )
                    .valid_from(clock.now())
                    .valid_until(hellas_auth::authority::UnixMillis(u64::MAX))
                    .build(),
            )
            .build()
            .await;
        let root_secret = world.secret(ROOT);
        let secret = CredentialSecret::from_parts(root_secret.id(), *root_secret.expose_secret());
        let app_secret = world.secret(FRIEND);
        let application = Arc::new(hellas_sdk::node_control::profile::ClientProfile {
            authority: authority(),
            authorization: ids::FRIEND_GRANT,
            credential: CredentialSecret::from_parts(app_secret.id(), *app_secret.expose_secret()),
            local: None,
        });
        let node = hellas_authority::node::NodeCoordinator::new(
            world.store,
            Arc::new(|| hellas_auth::authority::UnixMillis::now().unwrap()),
        );
        hellas_authority::test_support::common_node::apply_configuration(&node, &configuration)
            .await;
        let mut executor = hellas_executor::ExecutorSpawnConfig::new(
            Arc::new(provider_identity.node_key().clone()),
            routes,
        );
        executor.fetch_max_in_flight = 2;
        executor.fetch_queue_capacity = 0;
        let backend = hellas_sdk::BackendEntry {
            backend: hellas_sdk::Backend::fetch(
                hellas_executor::Executor::spawn_configured(executor)
                    .await
                    .unwrap(),
                configuration.resources()[0].invocation_policy.clone(),
            ),
            evaluator: None,
            max_in_flight: std::num::NonZeroUsize::new(2).unwrap(),
        };
        let provider = Daemon::open(
            runtime(
                root.path(),
                &provider_identity,
                node,
                content,
                Some(Arc::new(UnusedRoot)),
            ),
            document,
            [("openai".into(), backend)].into(),
        )
        .await;
        let caller = hellas_authority::test_support::session(
            &provider.administration().unwrap().node(),
            &secret,
        )
        .await;
        let authorization = ROOT_GRANT;
        let admin = provider.administration().unwrap();
        let WorkControlReply::Offers(mut offers) = provider
            .administration()
            .unwrap()
            .execute(
                &caller,
                authorization,
                WorkControlCommand::Offers { id: None },
            )
            .await
            .unwrap()
        else {
            panic!("offers reply")
        };
        let offer = offers.remove(0);
        let pinned = UnpinnedOffer::decode(
            &offer.encode().unwrap(),
            hellas_auth::authority::UnixMillis::now().unwrap_or_default(),
        )
        .unwrap()
        .pin(&hellas_sdk::client::ProviderTrustAnchor {
            expected_genesis: provider_bundle.content_id(),
            required_assurance: Assurance::ProducerSigned,
            apple_app_attest: None,
        })
        .unwrap();
        let access = {
            use hellas_auth::authority::{GrantSpec, UnixMillis};
            let node = admin.node();
            let scope = GrantSpec {
                authority: caller.authority(),
                subject: caller.subject(),
                permissions: [hellas_authority::operations::Operation::named(
                    hellas_authority::node::GATEWAY_INVOKE,
                )
                .unwrap()
                .permission(caller.authority(), None)
                .unwrap()]
                .into(),
                issuance: None,
                delegation_depth: 0,
                not_before: UnixMillis::now().unwrap_or_default(),
                expires: UnixMillis(UnixMillis::now().unwrap_or_default().0 + 60_000),
            };
            let grant = hellas_auth::authority::GrantId([0xa7; 16]);
            node.grant(
                &caller,
                hellas_auth::authority::GrantCommand::Issue {
                    authorization,
                    id: grant,
                    spec: scope.clone(),
                },
            )
            .await
            .unwrap();
            let (_, credential) = hellas_authority::test_support::credentials::issue_one(
                &node,
                &caller,
                authorization,
                scope,
                hellas_auth::authority::CredentialHolder::Bearer,
            )
            .await
            .unwrap();
            hellas_sdk::gateway::GatewayAccess::new(node, grant, credential)
                .await
                .unwrap()
        };
        let other_location = StoreLocation::for_test(&root.path().join("client"));
        let gateway = controlled_gateway(
            access,
            hellas_sdk::grant_client::GrantSessionOptions {
                control_timeout: std::time::Duration::from_millis(
                    pinned.offer().grant.max_job_millis.get(),
                ),
                target: pinned,
                principal: hellas_channel::test_support::subject_of(client_identity.node_key()),
                signer: Arc::new(client_identity.node_key().clone()),
                application: application.clone(),
                journal_root: other_location,
            },
            &client_identity,
            root.path(),
            admin.node(),
        )
        .await;
        ShareFixture {
            _root: root,
            upstream,
            provider,
            gateway,
            administrator: secret,
            application,
        }
    }
}
impl ShareFixture {
    fn request(&self) -> reqwest::RequestBuilder {
        reqwest::Client::new().post(format!("http://{}/v1/responses", self.gateway.address()))
            .bearer_auth(self.gateway.bearer())
            .json(&serde_json::json!({"model":"fixture","input":"private-gate-input","max_output_tokens":8}))
    }
    async fn revoke_application(&self) {
        let node = self.provider.administration().unwrap().node();
        let caller = hellas_authority::test_support::session(&node, &self.administrator).await;
        node.revoke_credential(
            &caller,
            ROOT_GRANT,
            self.application.credential.id(),
            Revision(1),
        )
        .await
        .unwrap();
    }
    async fn shutdown(self) {
        self.gateway.shutdown().await.unwrap();
        self.provider.shutdown().await.unwrap();
    }
}

#[tokio::test]
async fn controlled_gateway_projects_the_shared_tls_response() {
    let fixture = ShareFixtureBuilder::default().start().await;
    let before = fixture.upstream.calls.load(Ordering::SeqCst);
    let response = tokio::time::timeout(HANG_GUARD, fixture.request().send())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let value: serde_json::Value = response.json().await.unwrap();
    assert_eq!(value["output"][0]["content"][0]["text"], "hello");
    assert_eq!(value["status"], "completed");
    assert_eq!(fixture.upstream.calls.load(Ordering::SeqCst) - before, 1);
    fixture.shutdown().await;
}

#[tokio::test]
async fn credential_revocation_closes_the_real_upstream_tls_body() {
    let held = HeldUpstream::default();
    let fixture = ShareFixtureBuilder::default()
        .with_held_upstream(held.clone())
        .start()
        .await;
    let pending = tokio::spawn(fixture.request().send());
    tokio::time::timeout(HANG_GUARD, held.started.notified())
        .await
        .unwrap();
    fixture.revoke_application().await;
    tokio::time::timeout(HANG_GUARD, held.dropped.notified())
        .await
        .expect("revocation closes the upstream body");
    let response = tokio::time::timeout(HANG_GUARD, pending)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    // The provider ended the job: a failure upstream of the gateway.
    assert_eq!(response.status(), reqwest::StatusCode::BAD_GATEWAY);
    fixture.shutdown().await;
}

/// The provider's self-attested enrollment: a software root, distinct from
/// its node and transport keys, endorses both.
fn software_enrollment(identity: &NodeIdentity) -> ProviderEnrollmentBundle {
    hellas_channel::test_support::enrollment(
        &hellas_auth::ProducerSigningKey::from_secret_bytes([0x55; 32]).unwrap(),
        identity.node_key(),
        *identity.node_id().as_bytes(),
        [0x56; 32],
    )
}

fn share_options() -> OpenAiShareOptions {
    use hellas_auth::authority::ResourceId;
    OpenAiShareOptions {
        port: 0,
        service: "openai".into(),
        method: "responses".into(),
        bearer_token: "fixture".into(),
        resource: ResourceId(hellas_auth::Digest::hash(b"test resource")),
        account: ResourceId(hellas_auth::Digest::hash(b"test account")),
        machine: unlimited(),
        account_budget: unlimited(),
        responses: responses_resource(),
        pricing: pricing(),
        max_job_millis: NonZeroU64::new(60_000).unwrap(),
        max_in_flight: std::num::NonZeroUsize::new(2).unwrap(),
    }
}
#[test]
fn openai_document_requires_a_key_and_redacts_it_from_the_echo() {
    let mut options = share_options();
    options.bearer_token.clear();
    assert!(openai_document(options).is_err());
    let document = openai_document(share_options()).unwrap();
    let (echo, secrets) = document.redacted();
    assert_eq!(secrets.0["openai"]["bearer"], "fixture");
    assert_eq!(document.resources.len(), 1);
    let BackendKind::Fetch {
        upstream: hellas_sdk::daemon_config::Upstream::OpenaiResponses { secret },
        ..
    } = &echo.backends["openai"].kind
    else {
        panic!("OpenAI fetch backend")
    };
    assert!(secret.is_none());
    echo.validate().unwrap();
}

fn responses_resource() -> hellas_authority::model::grant::responses::ResponsesResource {
    hellas_authority::model::grant::responses::ResponsesResource {
        model: "fixture".into(),
        max_output_tokens: 8,
        settings: Default::default(),
    }
}

fn pricing() -> hellas_authority::model::grant::pricing::Pricing {
    use hellas_auth::authority::Revision;
    use hellas_authority::model::grant::pricing::{Pricing, UnitPrice};
    Pricing {
        revision: Revision(1),
        rates: Some(vec![
            UnitPrice {
                meter: Meter::Requests,
                usd_micros: 2,
                units: NonZeroU64::new(1).unwrap(),
            },
            UnitPrice {
                meter: Meter::OutputTokens,
                usd_micros: 3,
                units: NonZeroU64::new(4).unwrap(),
            },
        ]),
    }
}

struct ControlledGateway {
    core: Arc<Core>,
    endpoint: iroh::Endpoint,
    address: String,
    bearer: String,
}
async fn controlled_gateway(
    access: hellas_sdk::gateway::GatewayAccess,
    session: hellas_sdk::grant_client::GrantSessionOptions,
    identity: &NodeIdentity,
    root: &std::path::Path,
    node: hellas_authority::node::NodeCoordinator,
) -> ControlledGateway {
    let content = hellas_channel::test_support::channel::content_store(&root.join("gateway")).await;
    let endpoint = hellas_sdk::grant_client::bind_endpoint(identity.transport_key())
        .await
        .unwrap();
    let target = hellas_sdk::Backend::grant(
        session.target.offer().grant.policies[0].clone(),
        session,
        hellas_sdk::grant_client::GrantTransport::Remote(endpoint.clone()),
    );
    let document = Document {
        listeners: [(
            "api".into(),
            Listener::Http {
                bind: "127.0.0.1:0".parse().unwrap(),
                zdr: true,
            },
        )]
        .into(),
        routes: target.routes("friend").unwrap(),
        backends: [(
            "friend".into(),
            hellas_sdk::daemon_config::Backend {
                max_in_flight: std::num::NonZeroUsize::new(2).unwrap(),
                kind: BackendKind::Grant {
                    access: None,
                    resource: None,
                    evaluator: None,
                    trust: None,
                },
            },
        )]
        .into(),
        ..Default::default()
    };
    let core = Core::open_with_backends(
        runtime(&root.join("gateway"), identity, node, content, None),
        document,
        [(
            "friend".into(),
            hellas_sdk::BackendEntry {
                backend: target,
                evaluator: None,
                max_in_flight: std::num::NonZeroUsize::new(2).unwrap(),
            },
        )]
        .into(),
    )
    .await
    .unwrap();
    ControlledGateway {
        address: core.http_addresses()["api"].to_string(),
        bearer: access.bearer(),
        core,
        endpoint,
    }
}
impl ControlledGateway {
    fn address(&self) -> &str {
        &self.address
    }
    fn bearer(&self) -> &str {
        &self.bearer
    }
    async fn shutdown(self) -> Result<(), hellas_sdk::daemon::Error> {
        let result = self.core.shutdown().await;
        self.endpoint.close().await;
        result
    }
}
fn runtime(
    root: &std::path::Path,
    identity: &NodeIdentity,
    node: hellas_authority::node::NodeCoordinator,
    content: hellas_store::content::DiskStore,
    prover: Option<Arc<dyn hellas_attestation::RootProver>>,
) -> hellas_sdk::daemon::Options {
    let home = StoreLocation::for_test(root);
    hellas_sdk::daemon::Options {
        discovery: false,
        endpoint: None,
        remote_control: Default::default(),
        prover,
        chain: hellas_chain::chain_dir::ChainDir::open(
            &home,
            &hellas_chain::genesis::ChainProfile::known(hellas_chain::genesis::Chain::Devnet),
        )
        .unwrap(),
        home,
        signer: Arc::new(identity.node_key().clone()),
        transport: identity.transport_key(),
        settlement: hellas_kernel::Secp256k1Signer::from_secret_scalar(
            identity.node_secret_bytes(),
        )
        .unwrap(),
        owner: None,
        node,
        content,
    }
}

fn unlimited() -> hellas_authority::model::grant::configuration::ConfiguredBudget {
    hellas_authority::model::grant::configuration::ConfiguredBudget {
        max_in_flight: std::num::NonZeroU16::new(256).unwrap(),
        limits: vec![],
    }
}
