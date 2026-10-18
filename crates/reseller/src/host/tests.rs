use super::*;
use hellas_executor::{FetchProvider, FetchProviderFuture, PreparedFetchRequest};
use hellas_rpc::{Assurance, RootProof};
use hellas_sdk::{
    GrantProviderOptions, grant_client::UnpinnedOffer,
    grant_gateway::responses::FetchGatewayOptions,
};
use hellas_work::model::grant::budget::*;
use std::{
    num::NonZeroU64,
    sync::atomic::{AtomicUsize, Ordering},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct UnusedRoot;
impl RootProver for UnusedRoot {
    async fn prove_statement(
        &self,
        _: &[u8],
    ) -> Result<RootProof, hellas_attestation::AttestationError> {
        panic!("software enrollment was already signed")
    }
    async fn prove_open_binding(
        &self,
        _: hellas_auth::Digest,
    ) -> Result<RootProof, hellas_attestation::AttestationError> {
        panic!("software Open must sign with the producer, not the root")
    }
}

struct TlsResponses {
    client: reqwest::Client,
    url: reqwest::Url,
}
impl FetchProvider for TlsResponses {
    fn execution_environment(&self) -> hellas_rpc::ContentId {
        crate::responses_contract().unwrap().manifest_id()
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
        .timeout(WAIT * 6)
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
use hellas_work::model::grant::admin::{WorkControlCommand, WorkControlReply};
use hellas_work::test_support::{
    Allowance, Capacity, Node, Rights, TestClock, WAIT,
    actors::{FRIEND, PROVIDER, ROOT},
    authority, ids,
};
const ROOT_GRANT: GrantId = ids::ROOT_GRANT;
const ALLOWANCE: GrantId = GrantId([7; 16]);

#[derive(Default)]
struct ResellerBuilder {
    upstream: UpstreamMode,
}
struct Reseller {
    _root: tempfile::TempDir,
    upstream: TlsFixture,
    provider: ProviderHandle,
    gateway: ControlledGateway,
    administrator: CredentialSecret,
    application: Arc<hellas_sdk::node_control::profile::ClientProfile>,
}
impl ResellerBuilder {
    fn with_held_upstream(mut self, held: HeldUpstream) -> Self {
        self.upstream = UpstreamMode::Held(held);
        self
    }
    async fn start(self) -> Reseller {
        let root = tempfile::tempdir().unwrap();
        let provider_identity =
            ClientIdentity::from_secret_bytes(PROVIDER.key().to_secret_bytes(), [5; 32]).unwrap();
        let provider_bundle = provider_identity.contact_enrollment(&ROOT.key()).unwrap();
        let client_identity =
            ClientIdentity::from_secret_bytes(FRIEND.key().to_secret_bytes(), [3; 32]).unwrap();
        let upstream = tls_fixture(self.upstream).await;
        let options = || {
            let mut routes = FetchRouteRegistry::new();
            routes
                .register(
                    FetchRoute::new("openai", "responses"),
                    FetchRouteEntry::new(
                        upstream.provider.clone(),
                        Arc::new(crate::OpenAiResponsesAdaptorFactory::new().unwrap()),
                        FetchRoutePolicy::default(),
                    )
                    .unwrap(),
                )
                .unwrap();
            FetchProviderOptions {
                port: Some(0),
                identity: provider_identity.clone(),
                enrollment: provider_bundle.clone(),
                root: Arc::new(UnusedRoot),
                state_directory: root.path().join("provider"),
                routes,
                fetch_max_in_flight: 2,
                fetch_queue_capacity: 2,
                paid_work: None,
                grants: Some(GrantProviderOptions {
                    policies: vec![
                        crate::responses_policy(
                            hellas_auth::authority::ResourceId(hellas_auth::Digest::hash(
                                b"test resource",
                            )),
                            hellas_auth::authority::ResourceId(hellas_auth::Digest::hash(
                                b"test account",
                            )),
                            hellas_auth::authority::Revision(1),
                            "openai",
                            "responses",
                            responses_resource(),
                            pricing(),
                        )
                        .unwrap(),
                    ],
                    max_job_millis: NonZeroU64::new(60_000).unwrap(),
                }),
            }
        };
        let clock = TestClock::new(hellas_auth::authority::UnixMillis::now().unwrap_or_default());
        let mut allowance = Allowance::responses(ALLOWANCE, FRIEND);
        allowance.definition.policies = options().grants.unwrap().policies;
        allowance.definition.max_job_millis = NonZeroU64::new(60_000).unwrap();
        let world = Node::bootstrap(&root.path().join("provider/grants"))
            .with_network(hellas_work::model::grant::grant_network())
            .with_provider(provider_bundle.clone())
            .with_clock(clock.clone())
            .with_capacity(Capacity::new(1))
            .with_allowance(allowance)
            .with_grant(
                ids::FRIEND_GRANT,
                Rights::new(authority(), FRIEND)
                    .allow(
                        hellas_work::grant_service::WORK_EXECUTE,
                        hellas_work::grant_service::allowance_resource(authority(), ALLOWANCE),
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
        drop(world);
        let provider = start_fetch_provider(options().prepare().await.unwrap())
            .await
            .unwrap();
        let caller = provider
            .administration()
            .unwrap()
            .node()
            .authenticate(&secret)
            .await
            .unwrap();
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
            allowed_environments: offer
                .offer()
                .grant
                .policies
                .iter()
                .map(|p| p.work.allowed_environment())
                .collect(),
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
                permissions: [hellas_work::operations::Operation::named(
                    hellas_work::node::GATEWAY_INVOKE,
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
            let (_, credential) = node
                .issue_credential(&caller, authorization, scope)
                .await
                .unwrap();
            hellas_sdk::gateway::GatewayAccess::new(node, authorization, credential)
                .await
                .unwrap()
        };
        let gateway = controlled_gateway(
            FetchGatewayOptions {
                access,
                host: "127.0.0.1".into(),
                port: Some(0),
                archive: hellas_sdk::gateway::ArchiveOptions {
                    directory: root.path().join("archive"),
                    zdr: true,
                },
                allow_remote: false,
                wrap: None,
                wrap_args: Vec::new(),
                policy: None,
                session: hellas_sdk::grant_client::GrantSessionOptions {
                    timeout: std::time::Duration::from_millis(
                        pinned.offer().grant.max_job_millis.get(),
                    ),
                    target: pinned,
                    signer: Arc::new(client_identity.caller_key().clone()),
                    application: application.clone(),
                    journal_root: root.path().join("client"),
                },
                request_overrides: Default::default(),
            },
            client_identity.transport_key(),
            root.path(),
            admin.node(),
            &provider_bundle,
            &secret,
        )
        .await;
        Reseller {
            _root: root,
            upstream,
            provider,
            gateway,
            administrator: secret,
            application,
        }
    }
}
impl Reseller {
    fn request(&self) -> reqwest::RequestBuilder {
        reqwest::Client::new().post(format!("http://{}/v1/responses", self.gateway.address()))
            .bearer_auth(self.gateway.bearer())
            .json(&serde_json::json!({"model":"fixture","input":"private-gate-input","max_output_tokens":8}))
    }
    async fn revoke_application(&self) {
        let node = self.provider.administration().unwrap().node();
        let caller = node.authenticate(&self.administrator).await.unwrap();
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
async fn controlled_gateway_projects_the_reseller_tls_response() {
    let fixture = ResellerBuilder::default().start().await;
    let before = fixture.upstream.calls.load(Ordering::SeqCst);
    let response = tokio::time::timeout(WAIT, fixture.request().send())
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
    let fixture = ResellerBuilder::default()
        .with_held_upstream(held.clone())
        .start()
        .await;
    let pending = tokio::spawn(fixture.request().send());
    tokio::time::timeout(WAIT, held.started.notified())
        .await
        .unwrap();
    fixture.revoke_application().await;
    tokio::time::timeout(WAIT, held.dropped.notified())
        .await
        .expect("revocation closes the upstream body");
    let response = tokio::time::timeout(WAIT, pending)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(
        response.status(),
        reqwest::StatusCode::INTERNAL_SERVER_ERROR
    );
    fixture.shutdown().await;
}

struct OpenAiFixture {
    root: tempfile::TempDir,
    identity: ClientIdentity,
    enrollment: ProviderEnrollmentBundle,
}
impl OpenAiFixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let identity =
            ClientIdentity::from_secret_bytes(PROVIDER.key().to_secret_bytes(), [5; 32]).unwrap();
        let enrollment = identity.contact_enrollment(&ROOT.key()).unwrap();
        Self {
            root,
            identity,
            enrollment,
        }
    }
    fn options(&self) -> OpenAiProviderOptions<UnusedRoot> {
        use hellas_auth::authority::ResourceId;
        let root = self.root.path();
        let identity = &self.identity;
        let enrollment = &self.enrollment;
        OpenAiProviderOptions {
            port: Some(0),
            identity: identity.clone(),
            enrollment: enrollment.clone(),
            root: Arc::new(UnusedRoot),
            state_directory: root.join("provider"),
            service: "openai".into(),
            method: "responses".into(),
            bearer_token: "fixture".into(),
            resource: ResourceId(hellas_auth::Digest::hash(b"test resource")),
            account: ResourceId(hellas_auth::Digest::hash(b"test account")),
            policy_revision: Revision(1),
            pricing: hellas_work::model::grant::pricing::Pricing {
                revision: hellas_auth::authority::Revision(1),
                rates: None,
            },
            responses: responses_resource(),
            max_job_millis: NonZeroU64::new(60_000).unwrap(),
            fetch_max_in_flight: 1,
            fetch_queue_capacity: 1,
        }
    }
}
#[tokio::test]
async fn openai_host_refuses_an_empty_upstream_key() {
    let fixture = OpenAiFixture::new();
    let mut options = fixture.options();
    options.bearer_token.clear();
    hellas_auth::assert_err!(
        start_openai_provider(&options, None).await,
        OpenAiProviderError::Config(crate::OpenAiConfigError::EmptyKey)
    );
}
#[tokio::test]
async fn host_control_starts_the_openai_reseller_factory() {
    let fixture = OpenAiFixture::new();
    let world = Node::bootstrap(&fixture.root.path().join("provider/grants"))
        .with_provider(fixture.enrollment.clone())
        .with_clock(TestClock::new(
            hellas_auth::authority::UnixMillis::now().unwrap_or_default(),
        ))
        .build()
        .await;
    let secret = world.secret(ROOT);
    let secret = CredentialSecret::from_parts(secret.id(), *secret.expose_secret());
    let node = hellas_work::node::NodeCoordinator::new(
        world.store,
        Arc::new(|| hellas_auth::authority::UnixMillis::now().unwrap_or_default()),
    );
    let (host, control) = controlled_host(
        fixture.root.path(),
        node,
        &fixture.enrollment,
        &secret,
        Some(fixture.options().into_factory()),
        None,
    )
    .await;
    let reply = control
        .set_provider_state(hellas_rpc::pb::host::SetProviderStateRequest {
            enabled: true,
            authorization: ROOT_GRANT.0.to_vec(),
        })
        .await
        .unwrap();
    assert_eq!(
        reply.provider.unwrap().state,
        hellas_rpc::pb::host::RuntimeState::Running as i32
    );
    drop(control);
    host.shutdown().await.unwrap();
}

fn responses_resource() -> hellas_work::model::grant::responses::ResponsesResource {
    hellas_work::model::grant::responses::ResponsesResource {
        model: "fixture".into(),
        max_output_tokens: 8,
        settings: Default::default(),
    }
}

fn pricing() -> hellas_work::model::grant::pricing::Pricing {
    use hellas_auth::authority::Revision;
    use hellas_work::model::grant::pricing::{Pricing, UnitPrice};
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

type TestControl =
    hellas_rpc::services::host_control::HostControlClientImpl<hellas_sdk::wire::mux::MuxTransport>;
async fn controlled_host(
    root: &std::path::Path,
    node: hellas_work::node::NodeCoordinator,
    enrollment: &ProviderEnrollmentBundle,
    secret: &hellas_auth::authority::CredentialSecret,
    provider: Option<hellas_sdk::node_control::host::ProviderFactory>,
    gateway: Option<(FetchGatewayOptions, iroh::SecretKey)>,
) -> (hellas_sdk::node_control::host::HostHandle, TestControl) {
    use hellas_sdk::wire::ServiceMarker;
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let crypto = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls = rustls::ServerConfig::builder_with_provider(crypto.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()).into(),
        )
        .unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.cert.der().clone()).unwrap();
    let mut trust = rustls::ClientConfig::builder_with_provider(crypto)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![
        hellas_rpc::services::host_control::HostControl::ALPN
            .as_bytes()
            .to_vec(),
    ];
    trust.alpn_protocols = tls.alpn_protocols.clone();
    let authority = node.authenticate(secret).await.unwrap().authority();
    let socket = root.join("control/host.socket");
    let host = hellas_sdk::node_control::host::HostHandle::start(
        hellas_sdk::node_control::host::HostOptions {
            identity: Some(enrollment.clone()),
            provider,
            gateway,
            control: Some((
                node,
                hellas_sdk::ProviderControl {
                    socket: socket.clone(),
                    tls: Arc::new(tls),
                    remote: Default::default(),
                },
            )),
        },
    )
    .await
    .unwrap();
    let control = hellas_sdk::node_control::connect_local(
        socket,
        Arc::new(trust),
        "localhost".try_into().unwrap(),
        authority,
        secret,
        &ROOT.key(),
    )
    .await
    .unwrap();
    (host, control)
}
struct ControlledGateway {
    host: hellas_sdk::node_control::host::HostHandle,
    control: TestControl,
    access: hellas_rpc::pb::host::GatewayAccess,
}
async fn controlled_gateway(
    gateway: FetchGatewayOptions,
    key: iroh::SecretKey,
    root: &std::path::Path,
    node: hellas_work::node::NodeCoordinator,
    enrollment: &ProviderEnrollmentBundle,
    secret: &hellas_auth::authority::CredentialSecret,
) -> ControlledGateway {
    let (host, control) =
        controlled_host(root, node, enrollment, secret, None, Some((gateway, key))).await;
    let status = control
        .set_gateway_state(hellas_rpc::pb::host::SetGatewayStateRequest {
            enabled: true,
            authorization: ROOT_GRANT.0.to_vec(),
        })
        .await
        .unwrap();
    assert_eq!(
        status.gateway.unwrap().state,
        hellas_rpc::pb::host::RuntimeState::Running as i32
    );
    let access = control
        .get_gateway_access(hellas_rpc::pb::host::GetGatewayAccessRequest {
            authorization: ROOT_GRANT.0.to_vec(),
        })
        .await
        .unwrap();
    ControlledGateway {
        host,
        control,
        access,
    }
}
impl ControlledGateway {
    fn address(&self) -> &str {
        self.access.address.strip_prefix("http://").unwrap()
    }
    fn bearer(&self) -> &str {
        &self.access.bearer
    }
    async fn shutdown(self) -> Result<(), hellas_sdk::node_control::host::HostError> {
        let status = self
            .control
            .set_gateway_state(hellas_rpc::pb::host::SetGatewayStateRequest {
                enabled: false,
                authorization: ROOT_GRANT.0.to_vec(),
            })
            .await
            .unwrap();
        assert_eq!(
            status.gateway.unwrap().state,
            hellas_rpc::pb::host::RuntimeState::Stopped as i32
        );
        drop(self.control);
        self.host.shutdown().await
    }
}
