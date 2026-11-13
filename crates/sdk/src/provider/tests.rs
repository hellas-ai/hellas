use crate::NodeIdentity;
use crate::daemon::testing::Daemon;
use hellas_private::StoreLocation;
use iroh::{Endpoint, endpoint::presets};
mod handshakes;
pub(crate) mod host;
mod node;
use super::*;
use bytes::Bytes;
use futures::StreamExt as _;
use hellas_rpc::pb::work::{StreamResultRequest, WorkStreamEvent};
use hellas_rpc::services::work::StreamResult;
use hellas_wire::mux::{MessagePipe, MuxConfig, MuxTransport, Role};
use hellas_wire::{DefaultClock, Metadata};
use tokio::sync::mpsc;
use tokio::time::{Duration, Instant};

struct UnusedRoot;

impl RootProver for UnusedRoot {
    fn prove_statement<'a>(&'a self, _: &'a [u8]) -> hellas_attestation::RootProofFuture<'a> {
        Box::pin(async move { panic!("ALPN negotiation must not invoke attestation") })
    }

    fn prove_open_binding<'a>(
        &'a self,
        _: hellas_auth::Digest,
    ) -> hellas_attestation::RootProofFuture<'a> {
        Box::pin(async move { panic!("ALPN negotiation must not invoke attestation") })
    }
}

#[tokio::test]
async fn paid_provider_advertises_work_services_and_serves_no_chain_sync() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let fixture = crate::test_support::PaidFixture::new();
        let identity = NodeIdentity::from_secret_bytes([4; 32], [2; 32]).unwrap();
        let root = Arc::new(UnusedRoot);
        let provider = daemon(
            fixture.root.path(),
            0,
            identity.transport_key(),
            Some(root.clone()),
            Some(fixture.config.chain),
        )
        .await;
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
        // A paid provider is no chain peer: it reads its channels by proof.
        assert!(
            client
                .connect(
                    addr.clone(),
                    hellas_rpc::services::chain_sync::ChainSync::ALPN.as_bytes()
                )
                .await
                .is_err()
        );
        for alpn in [
            hellas_rpc::services::node::Node::ALPN,
            hellas_rpc::services::work::Work::ALPN,
            hellas_rpc::services::work_setup::WorkSetup::ALPN,
        ] {
            let connection = client.connect(addr.clone(), alpn.as_bytes()).await.unwrap();
            connection.close(0u32.into(), b"tested");
        }
        client.close().await;
        provider.shutdown().await.unwrap();
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
            |_: StreamResultRequest| async {
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
    let serving = tokio::spawn(serve_loop(
        Arc::new(server),
        SlowStream,
        stopping,
        RPC_CONNECTION_IDLE_TIMEOUT,
        Instant::now() + MAX_LIFETIME,
    ));
    let mut response = hellas_rpc::call::server_streaming::<_, StreamResult>(
        &client,
        StreamResultRequest::default(),
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
    serving.await.unwrap().unwrap();
}

#[tokio::test(start_paused = true)]
async fn paid_stream_outlives_the_idle_limit_but_idle_connections_close() {
    let (client, server) = mux_pair();
    let serving = tokio::spawn(serve_loop(
        Arc::new(server),
        SlowStream,
        tokio::sync::watch::channel(false).1,
        crate::provider::RPC_CONNECTION_IDLE_TIMEOUT,
        tokio::time::Instant::now() + crate::provider::MAX_LIFETIME,
    ));
    for _ in 0..2 {
        let started = Instant::now();
        let mut response = hellas_rpc::call::server_streaming::<_, StreamResult>(
            &client,
            StreamResultRequest::default(),
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
    serving.await.unwrap().unwrap_err();
}

#[test]
fn work_and_content_are_advertised_with_the_configured_control_services() {
    use hellas_rpc::services::content::Content;
    assert_eq!(
        served_alpns(false, false, false),
        [Node::ALPN.as_bytes(), Content::ALPN.as_bytes()]
    );
    assert_eq!(
        served_alpns(false, true, false),
        [
            Node::ALPN.as_bytes(),
            Content::ALPN.as_bytes(),
            Work::ALPN.as_bytes()
        ]
    );
    assert_eq!(
        served_alpns(false, true, true),
        [
            Node::ALPN.as_bytes(),
            Content::ALPN.as_bytes(),
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
            Content::ALPN.as_bytes(),
            WorkSetup::ALPN.as_bytes(),
            Work::ALPN.as_bytes()
        ]
    );
}

#[tokio::test(start_paused = true)]
async fn cheap_streams_cannot_extend_the_connection_lifetime() {
    let (client, server) = mux_pair();
    let serving = tokio::spawn(serve_loop(
        Arc::new(server),
        SlowStream,
        tokio::sync::watch::channel(false).1,
        crate::provider::RPC_CONNECTION_IDLE_TIMEOUT,
        tokio::time::Instant::now() + crate::provider::MAX_LIFETIME,
    ));
    let started = Instant::now();
    let max_lifetime = Duration::from_secs(15 * 60);
    loop {
        let mut response = match hellas_rpc::call::server_streaming::<_, StreamResult>(
            &client,
            StreamResultRequest::default(),
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
    serving.await.unwrap().unwrap_err();
    assert!(started.elapsed() >= max_lifetime);
}

#[tokio::test(start_paused = true)]
async fn a_connection_without_a_first_stream_is_reaped() {
    let (_client, server) = mux_pair();
    let serving = tokio::spawn(serve_loop(
        Arc::new(server),
        SlowStream,
        tokio::sync::watch::channel(false).1,
        crate::provider::RPC_CONNECTION_IDLE_TIMEOUT,
        tokio::time::Instant::now() + crate::provider::MAX_LIFETIME,
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
    serving.await.unwrap().unwrap_err();
}

async fn daemon(
    root: &std::path::Path,
    port: u16,
    transport: iroh::SecretKey,
    prover: Option<Arc<dyn RootProver>>,
    chain: Option<hellas_chain::chain_dir::ChainDir>,
) -> Daemon {
    use crate::daemon_config::{Document, Listener};
    use hellas_authority::work_store::grant::{NodeStore, NodeStoreError};
    let home = StoreLocation::for_test(root);
    let journal = home.child("authority");
    let (enrollment, signer) = crate::test_identity::enrollment(transport.public());
    let now = hellas_auth::authority::UnixMillis::now().unwrap();
    let store = match NodeStore::open(
        &journal,
        hellas_authority::model::grant::grant_network(),
        Some(enrollment.clone()),
        now,
    )
    .await
    {
        Ok(store) => store,
        Err(NodeStoreError::Uninitialized) => crate::test_node::bootstrap_node(
            &journal,
            hellas_authority::model::grant::grant_network(),
            Some(enrollment.clone()),
            now,
        )
        .await
        .unwrap(),
        Err(error) => panic!("{error}"),
    };
    let node = hellas_authority::node::NodeCoordinator::new(
        store,
        Arc::new(|| hellas_auth::authority::UnixMillis::now().unwrap()),
    );
    let signer = Arc::new(signer);
    Daemon::open(
        crate::daemon::Options {
            discovery: false,
            endpoint: None,
            remote_control: Default::default(),
            prover: Some(Arc::new(
                ProviderOpen::new(signer.clone(), enrollment, prover).unwrap(),
            )),
            chain: chain.unwrap_or_else(|| {
                crate::test_support::chain_dir(root, hellas_channel::test_support::network())
            }),
            home,
            transport,
            settlement: hellas_kernel::Secp256k1Signer::from_secret_scalar(
                signer.to_secret_bytes(),
            )
            .unwrap(),
            signer,
            owner: None,
            node,
            content: hellas_authority::test_support::content_store(&root.join("content")).await,
        },
        Document {
            listeners: [(
                "work".into(),
                Listener::Iroh {
                    port,
                    backends: vec![],
                },
            )]
            .into(),
            ..Default::default()
        },
        Default::default(),
    )
    .await
}
