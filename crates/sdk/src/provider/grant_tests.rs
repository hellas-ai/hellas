use super::*;
use crate::{
    GrantProviderOptions,
    gateway::{FetchGatewayOptions, start_fetch},
    grant_client::UnpinnedOffer,
};
use hellas_executor::{FetchProvider, FetchProviderFuture, PreparedFetchRequest};
use hellas_rpc::{
    FetchEnvironment, ProducerSigningKey,
    protocol::work_grant::{budget::*, records::*},
};
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
        _: hellas_rpc::Digest,
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
        FetchEnvironment::OpenAiResponses.manifest_id()
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

fn response_events() -> String {
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
        json!({"type":"response.completed","response":{"id":"resp_1","object":"response","status":"completed","model":"fixture","output":[message],"usage":{"input_tokens":3,"output_tokens":2,"total_tokens":5}}}),
    ].into_iter().enumerate().map(|(i, mut event)| { event["sequence_number"] = i.into(); format!("event: {}\ndata: {event}\n\n", event["type"].as_str().unwrap()) }).collect()
}

async fn tls_fixture() -> (
    Arc<TlsResponses>,
    Arc<AtomicUsize>,
    tokio::task::JoinHandle<()>,
) {
    use rcgen::*;
    let mut params = CertificateParams::default();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    let ca = CertifiedIssuer::self_signed(params, KeyPair::generate().unwrap()).unwrap();
    let key = KeyPair::generate().unwrap();
    let leaf = CertificateParams::new(vec!["localhost".into()])
        .unwrap()
        .signed_by(&key, &ca)
        .unwrap();
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![leaf.der().clone()],
        rustls::pki_types::PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
    )
    .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
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
        .timeout(std::time::Duration::from_secs(10))
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
            count.fetch_add(1, Ordering::SeqCst);
            let body = response_events();
            socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).await.unwrap();
            socket.shutdown().await.unwrap();
        }
    });
    (Arc::new(TlsResponses { client, url }), calls, task)
}

#[tokio::test]
async fn contact_offer_open_tls_responses_gateway_and_revocation_preserve_quota() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::WARN)
        .with_test_writer()
        .try_init();
    tokio::time::timeout(std::time::Duration::from_secs(45), async {
        let root = tempfile::tempdir().unwrap();
        let provider_identity = ClientIdentity::from_secret_bytes([2; 32], [2; 32]).unwrap();
        let provider_bundle = provider_identity
            .contact_enrollment(&ProducerSigningKey::from_secret_bytes([3; 32]).unwrap())
            .unwrap();
        let client_identity = ClientIdentity::from_secret_bytes([1; 32], [1; 32]).unwrap();
        let client = Principal::verify(
            client_identity
                .contact_enrollment(&ProducerSigningKey::from_secret_bytes([4; 32]).unwrap())
                .unwrap(),
        )
        .unwrap();
        let (upstream, calls, tls) = tls_fixture().await;
        let options = |contacts: Vec<Principal>| {
            let mut routes = FetchRouteRegistry::new();
            routes
                .register(
                    FetchRoute::new("openai", "responses"),
                    FetchRouteEntry::new(
                        upstream.clone(),
                        Arc::new(hellas_providers::ResponsesFetchAdaptorFactory::new(
                            FetchEnvironment::OpenAiResponses,
                        )),
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
                #[cfg(feature = "paid-provider")]
                paid_work: None,
                grants: Some(GrantProviderOptions {
                    grantees: contacts,
                    policies: vec![
                        crate::grant_provider::responses_policy("openai", "responses").unwrap(),
                    ],
                    limits: vec![Limit {
                        meter: Meter::Requests,
                        window: Window::Total,
                        amount: 2,
                    }],
                    max_job_millis: NonZeroU64::new(10000).unwrap(),
                }),
            }
        };
        let provider = start_fetch_provider(options(vec![client.clone()]))
            .await
            .unwrap();
        let offer = provider.offers().unwrap().remove(0);
        let grant = offer.offer().grant.id;
        let pinned = UnpinnedOffer::decode(
            &offer.encode().unwrap(),
            client.id(),
            hellas_work::grant_service::wall_clock(),
        )
        .unwrap()
        .pin(&hellas_client::ProviderTrustAnchor {
            expected_genesis: provider_bundle.content_id(),
            required_assurance: Assurance::ProducerSigned,
            apple_app_attest: None,
        })
        .unwrap();
        let gateway = start_fetch(FetchGatewayOptions {
            host: "127.0.0.1".into(),
            port: Some(0),
            offer: pinned,
            identity: client_identity,
            journal_root: root.path().join("client"),
            request_overrides: Default::default(),
        })
        .await
        .unwrap();
        let http = reqwest::Client::new();
        let url = format!("http://{}/v1/responses", gateway.address());
        let body = serde_json::json!({"model":"fixture","input":"private-gate-input"});
        assert_eq!(
            http.post(&url).json(&body).send().await.unwrap().status(),
            401
        );
        let refused = http
            .post(&url)
            .bearer_auth(gateway.bearer())
            .json(&serde_json::json!({"model":"fixture","input":"private-gate-input","store":true}))
            .send()
            .await
            .unwrap();
        assert_eq!(refused.status(), 400);
        for streaming in [false, true] {
            let mut body = body.clone();
            body["stream"] = streaming.into();
            let response = http
                .post(&url)
                .bearer_auth(gateway.bearer())
                .json(&body)
                .send()
                .await
                .unwrap();
            let status = response.status();
            let text = response.text().await.unwrap();
            assert!(status.is_success(), "{status}: {text}");
            assert!(text.contains("hello"), "{text}");
            assert!(
                text.contains(if streaming {
                    "response.completed"
                } else {
                    "completed"
                }),
                "{text}"
            );
        }
        assert_eq!(
            http.post(&url)
                .bearer_auth(gateway.bearer())
                .json(&body)
                .send()
                .await
                .unwrap()
                .status(),
            429
        );
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        gateway.shutdown().await.unwrap();
        provider.shutdown().await;
        let revoked = start_fetch_provider(options(vec![])).await.unwrap();
        assert!(revoked.offers().unwrap().is_empty());
        revoked
            .grants
            .as_ref()
            .unwrap()
            .administer(|store, _| {
                assert_eq!(
                    store.state().grant(grant).unwrap().state,
                    GrantState::Revoked
                );
                assert_eq!(
                    store
                        .state()
                        .ledger()
                        .node(BudgetNode::Grant(grant))
                        .unwrap()
                        .counter(Meter::Requests, Window::Total)
                        .used,
                    2
                );
                Ok(())
            })
            .unwrap();
        revoked.shutdown().await;
        assert!(matches!(
            start_fetch_provider(options(vec![client])).await,
            Err(ProviderError::RevokedContact)
        ));
        tls.abort();
    })
    .await
    .unwrap();
}
