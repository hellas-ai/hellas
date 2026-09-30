use super::*;
use bytes::Bytes;
use futures::StreamExt as _;
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
        _: hellas_rpc::Digest,
    ) -> Result<RootProof, hellas_attestation::AttestationError> {
        panic!("ALPN negotiation must not invoke attestation")
    }
}

#[tokio::test]
async fn provider_advertises_only_work_protocols() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let fixture = crate::test_support::PaidFixture::new();
        let identity = ClientIdentity::from_secret_bytes([4; 32], [2; 32]).unwrap();
        let (enrollment, _) = crate::test_support::enrollment(identity.transport_key().public());
        let mut routes = FetchRouteRegistry::new();
        routes
            .register(
                FetchRoute::new("openai", "responses"),
                FetchRouteEntry::new(
                    Arc::new(
                        hellas_providers::OpenAiResponsesFetchProvider::with_bearer("fixture")
                            .unwrap(),
                    ),
                    Arc::new(hellas_providers::ResponsesFetchAdaptorFactory::new(
                        hellas_rpc::FetchEnvironment::OpenAiResponses,
                    )),
                    FetchRoutePolicy::default(),
                )
                .unwrap(),
            )
            .unwrap();
        let provider = start_fetch_provider(FetchProviderOptions {
            port: Some(0),
            identity,
            enrollment,
            root: Arc::new(UnusedRoot),
            state_directory: fixture.root.path().join("state"),
            routes,
            fetch_max_in_flight: 1,
            fetch_queue_capacity: 1,
            paid_work: Some(fixture.config),
            #[cfg(feature = "grant-provider")]
            grants: None,
        })
        .await
        .unwrap();
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
                .connect(addr.clone(), b"retired-execution-service")
                .await
                .is_err()
        );
        for alpn in [
            hellas_rpc::services::work::Work::ALPN,
            hellas_rpc::services::work_setup::WorkSetup::ALPN,
        ] {
            let connection = client.connect(addr.clone(), alpn.as_bytes()).await.unwrap();
            connection.close(0u32.into(), b"tested");
        }
        client.close().await;
        provider.shutdown().await;
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
                Ok(Box::pin(async_stream::stream! {
                    yield Ok(WorkStreamEvent::default());
                    tokio::time::sleep(Duration::from_secs(61)).await;
                    yield Ok(WorkStreamEvent::default());
                }))
            },
        )
        .await
    }
}

#[tokio::test(start_paused = true)]
async fn paid_stream_survives_a_slow_upstream_and_an_idle_connection() {
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
    let serving = tokio::spawn(serve(Arc::new(server), SlowStream));
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
        assert!(started.elapsed() >= Duration::from_secs(61));
        tokio::time::sleep(Duration::from_secs(121)).await;
        assert!(!serving.is_finished());
    }
    serving.abort();
    let _ = serving.await;
}
