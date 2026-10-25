mod handshakes;
pub(crate) mod host;
mod node;
use super::*;
use bytes::Bytes;
use futures::StreamExt as _;
use hellas_executor::{FetchRouteEntry, FetchRoutePolicy};
use hellas_rpc::pb::work::{DeliverResultRequest, WorkStreamEvent};
use hellas_rpc::services::work::StreamResult;
use hellas_wire::mux::{MessagePipe, MuxConfig, MuxTransport, Role};
use hellas_wire::{DefaultClock, Metadata};
use tokio::sync::mpsc;
use tokio::time::{Duration, Instant};

struct UnusedRoot;

impl RootProver for UnusedRoot {
    async fn prove_statement(
        &self,
        _: &[u8],
    ) -> Result<RootProof, hellas_attestation::AttestationError> {
        panic!("ALPN negotiation must not invoke attestation")
    }

    async fn prove_open_binding(
        &self,
        _: hellas_auth::Digest,
    ) -> Result<RootProof, hellas_attestation::AttestationError> {
        panic!("ALPN negotiation must not invoke attestation")
    }
}

#[tokio::test]
async fn paid_provider_advertises_work_and_chain_services() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let mut fixture = crate::test_support::PaidFixture::new();
        let node = fixture.node().await;
        let identity = NodeIdentity::from_secret_bytes([4; 32], [2; 32]).unwrap();
        let (enrollment, _) = crate::test_support::enrollment(identity.transport_key().public());
        let mut routes = FetchRouteRegistry::new();
        routes
            .register(
                FetchRoute::new("openai", "responses"),
                FetchRouteEntry::new(
                    Arc::new(ProbeRoute),
                    Arc::new(ProbeRoute),
                    FetchRoutePolicy::default(),
                )
                .unwrap(),
            )
            .unwrap();
        let root = Arc::new(UnusedRoot);
        let provider = start_fetch_provider(
            FetchProviderOptions {
                port: Some(0),
                identity,
                enrollment,
                root: root.clone(),
                state_directory: fixture.root.path().join("state"),
                routes,
                fetch_max_in_flight: 1,
                fetch_queue_capacity: 1,
                paid_work: Some(
                    crate::PaidProviderOptions::new(fixture.config, node.clone()).unwrap(),
                ),
                grants: None,
            }
            .prepare()
            .await
            .unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(
            Arc::strong_count(&root),
            1,
            "software root must not stay online"
        );
        let client = Endpoint::builder(presets::Minimal)
            .bind_addr("127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap())
            .unwrap()
            .bind()
            .await
            .unwrap();
        let addr = iroh::EndpointAddr::new(provider.node_id()).with_addrs(
            provider
                .bound_sockets()
                .into_iter()
                .filter(|addr| addr.is_ipv4())
                .map(|mut addr| {
                    addr.set_ip(std::net::Ipv4Addr::LOCALHOST.into());
                    iroh::TransportAddr::Ip(addr)
                }),
        );
        assert!(
            client
                .connect(addr.clone(), b"unregistered-service")
                .await
                .is_err()
        );
        for alpn in [
            hellas_rpc::services::chain_sync::ChainSync::ALPN,
            hellas_rpc::services::node::Node::ALPN,
            hellas_rpc::services::work::Work::ALPN,
            hellas_rpc::services::work_setup::WorkSetup::ALPN,
        ] {
            let connection = client.connect(addr.clone(), alpn.as_bytes()).await.unwrap();
            connection.close(0u32.into(), b"tested");
        }
        client.close().await;
        provider.shutdown().await.unwrap();
        node.shutdown().await.unwrap();
    })
    .await
    .expect("paid provider protocol negotiation completes");
}

struct Pipe(mpsc::UnboundedSender<Bytes>, mpsc::UnboundedReceiver<Bytes>);

impl MessagePipe for Pipe {
    type SendError = std::io::Error;
    type RecvError = std::io::Error;

    async fn send_message(&mut self, bytes: Bytes) -> Result<(), Self::SendError> {
        self.0
            .send(bytes)
            .map_err(|_| std::io::ErrorKind::BrokenPipe.into())
    }

    async fn recv_message(&mut self) -> Result<Option<Bytes>, Self::RecvError> {
        Ok(self.1.recv().await)
    }
}

struct SlowStream;

impl Dispatcher<MuxTransport> for SlowStream {
    type Error = hellas_wire::TransportError;

    async fn dispatch(
        &self,
        inbound: hellas_wire::Inbound<hellas_wire::mux::MuxStream>,
    ) -> Result<(), Self::Error> {
        hellas_rpc::call::dispatch_server_streaming::<MuxTransport, StreamResult, _, _, _>(
            inbound,
            |_: DeliverResultRequest| async {
                Ok(hellas_rpc::call::ResponseStream::new(
                    async_stream::stream! {
                        yield Ok(WorkStreamEvent::default());
                        tokio::time::sleep(Duration::from_secs(121)).await;
                        yield Ok(WorkStreamEvent::default());
                    },
                ))
            },
        )
        .await
    }
}

fn mux_pair() -> (MuxTransport, MuxTransport) {
    let (to_server, server_inbox) = mpsc::unbounded_channel();
    let (to_client, client_inbox) = mpsc::unbounded_channel();
    let client = MuxTransport::spawn::<8, _, _>(
        Role::Client,
        DefaultClock,
        MuxConfig::default(),
        Pipe(to_server, client_inbox),
        TransportContext::default(),
    );
    let server = MuxTransport::spawn::<8, _, _>(
        Role::Server,
        DefaultClock,
        MuxConfig::default(),
        Pipe(to_client, server_inbox),
        TransportContext::default(),
    );
    (client, server)
}

#[tokio::test(start_paused = true)]
async fn quiescing_finishes_an_active_response_before_closing_the_session() {
    let (client, server) = mux_pair();
    let (stop, stopping) = tokio::sync::watch::channel(false);
    let serving = tokio::spawn(serve_loop(Arc::new(server), SlowStream, stopping));
    let mut response = hellas_rpc::call::server_streaming::<_, StreamResult>(
        &client,
        DeliverResultRequest::default(),
        Metadata::new(),
    )
    .await
    .unwrap();
    assert!(response.next().await.unwrap().is_ok());
    stop.send_replace(true);
    tokio::task::yield_now().await;
    assert!(!serving.is_finished(), "active delivery survives quiesce");
    assert!(response.next().await.unwrap().is_ok());
    assert!(response.next().await.is_none());
    response.finish().unwrap();
    serving.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn paid_stream_outlives_the_idle_limit_but_idle_connections_close() {
    let (client, server) = mux_pair();
    let serving = tokio::spawn(serve_loop(
        Arc::new(server),
        SlowStream,
        tokio::sync::watch::channel(false).1,
    ));
    for _ in 0..2 {
        let started = Instant::now();
        let mut response = hellas_rpc::call::server_streaming::<_, StreamResult>(
            &client,
            DeliverResultRequest::default(),
            Metadata::new(),
        )
        .await
        .unwrap();
        assert!(response.next().await.unwrap().is_ok());
        assert!(response.next().await.unwrap().is_ok());
        assert!(response.next().await.is_none());
        response.finish().unwrap();
        assert!(started.elapsed() >= Duration::from_secs(121));
        tokio::time::sleep(Duration::from_secs(119)).await;
        assert!(!serving.is_finished());
    }
    tokio::time::sleep(Duration::from_secs(2)).await;
    serving.await.unwrap();
}

// This test only negotiates ALPNs; no upstream implementation is needed.
struct ProbeRoute;
impl hellas_executor::FetchProvider for ProbeRoute {
    fn execution_environment(&self) -> hellas_rpc::ContentId {
        test_responses_contract().manifest_id()
    }
    fn run(
        &self,
        _: hellas_executor::PreparedFetchRequest,
    ) -> hellas_executor::FetchProviderFuture<'_> {
        Box::pin(async { panic!("ALPN probe must not execute upstream work") })
    }
}
impl hellas_executor::FetchAdaptorFactory for ProbeRoute {
    fn execution_environment(&self) -> hellas_rpc::ContentId {
        test_responses_contract().manifest_id()
    }
    fn create(
        &self,
        _: &hellas_executor::FetchCall,
    ) -> Result<hellas_executor::FetchAdaptorSession, hellas_executor::FetchAdaptorError> {
        panic!("ALPN probe must not prepare upstream work")
    }
}

use hellas_work::test_support::test_responses_contract;

#[test]
fn work_is_the_only_execution_protocol_advertised() {
    assert_eq!(served_alpns(false, false, false), [Node::ALPN.as_bytes()]);
    assert_eq!(
        served_alpns(false, true, false),
        [Node::ALPN.as_bytes(), Work::ALPN.as_bytes()]
    );
    assert_eq!(
        served_alpns(false, true, true),
        [
            Node::ALPN.as_bytes(),
            Work::ALPN.as_bytes(),
            hellas_rpc::services::host_control::HostControl::ALPN.as_bytes()
        ]
    );
    assert_eq!(
        served_alpns(true, true, true).len(),
        served_alpns(true, false, false).len() + 1
    );
    assert_eq!(
        served_alpns(true, false, false),
        [
            Node::ALPN.as_bytes(),
            hellas_rpc::services::chain_sync::ChainSync::ALPN.as_bytes(),
            WorkSetup::ALPN.as_bytes(),
            Work::ALPN.as_bytes()
        ]
    );
}

#[tokio::test]
async fn invalid_resources_are_rejected_before_opening_a_journal() {
    use crate::grant_provider::{GrantProviderError, ProviderResources};
    use hellas_work::work_store::grant::NodeStoreError;
    let root = tempfile::tempdir().unwrap();
    let provider =
        crate::test_identity::enrollment(iroh::SecretKey::from_bytes(&[3; 32]).public()).0;
    let mut options = ProviderGrants {
        config: crate::GrantProviderOptions {
            policies: vec![hellas_work::test_support::policy()],
            max_job_millis: std::num::NonZeroU64::MIN,
        },
        authority: ProviderAuthority::Journal {
            root: root.path().join("provider"),
        },
    };
    let routes = FetchRouteRegistry::default();
    assert!(matches!(
        options
            .open(ProviderResources::Fetch(&routes), &provider)
            .await,
        Err(ProviderError::GrantConfig(
            GrantProviderError::MissingRoute(_)
        ))
    ));
    assert!(!root.path().join("provider").exists());
    options.config.policies.clear();
    assert!(matches!(
        options
            .open(ProviderResources::Fetch(&routes), &provider)
            .await,
        Err(ProviderError::NodeStore(NodeStoreError::Uninitialized))
    ));
    assert!(!root.path().join("provider").exists());
}

#[tokio::test(start_paused = true)]
async fn cheap_streams_cannot_extend_the_connection_lifetime() {
    let (client, server) = mux_pair();
    let serving = tokio::spawn(serve_loop(
        Arc::new(server),
        SlowStream,
        tokio::sync::watch::channel(false).1,
    ));
    let started = Instant::now();
    let max_lifetime = Duration::from_secs(15 * 60);
    loop {
        let mut response = match hellas_rpc::call::server_streaming::<_, StreamResult>(
            &client,
            DeliverResultRequest::default(),
            Metadata::new(),
        )
        .await
        {
            Ok(response) => response,
            Err(_) => break,
        };
        while response.next().await.is_some() {}
        if serving.is_finished() {
            break;
        }
        tokio::time::sleep(Duration::from_secs(60)).await;
        assert!(
            started.elapsed() <= max_lifetime + Duration::from_secs(121),
            "repeated streams must not renew a connection forever"
        );
    }
    serving.await.unwrap();
    assert!(started.elapsed() >= max_lifetime);
}

#[tokio::test(start_paused = true)]
async fn a_connection_without_a_first_stream_is_reaped() {
    let (_client, server) = mux_pair();
    let serving = tokio::spawn(serve_loop(
        Arc::new(server),
        SlowStream,
        tokio::sync::watch::channel(false).1,
    ));
    tokio::task::yield_now().await;
    tokio::time::advance(RPC_CONNECTION_IDLE_TIMEOUT - Duration::from_secs(1)).await;
    assert!(!serving.is_finished());
    tokio::time::advance(Duration::from_secs(2)).await;
    tokio::task::yield_now().await;
    assert!(
        serving.is_finished(),
        "no-stream connections release their slot on idle timeout"
    );
    serving.await.unwrap();
}
