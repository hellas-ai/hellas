//! Real QUIC handshakes through a pausable UDP relay, using the production
//! standalone provider accept loop and Node RPC dispatch.
use super::super::*;
use super::UnusedRoot;
use hellas_rpc::pb::swarm::GetNodeInfoRequest;
use hellas_rpc::services::node::NodeClientImpl;
use iroh::EndpointAddr;
use std::net::{Ipv4Addr, SocketAddr};
use tokio::net::UdpSocket;

const PROGRESS: Duration = Duration::from_secs(5);

async fn provider() -> ProviderHandle {
    let secret_key = iroh::SecretKey::from_bytes(&[49; 32]);
    let (enrollment, signer) = crate::test_identity::enrollment(secret_key.public());
    let signer = Arc::new(signer);
    start_fetch_provider(ProviderOptions {
        executor: ExecutorSpawnConfig::fetch_only(
            signer.clone(),
            Assurance::ProducerSigned,
            FetchRouteRegistry::new(),
        ),
        grants: None,
        port: Some(0),
        build: String::new(),
        graffiti: Vec::new(),
        discovery: false,
        work: None,
        secret_key,
        open_identity: Arc::new(ProviderOpen::<UnusedRoot>::new(signer, enrollment, None).unwrap()),
    })
    .await
    .unwrap()
}

fn socket(provider: &ProviderHandle) -> SocketAddr {
    let mut socket = provider
        .bound_sockets()
        .into_iter()
        .find(SocketAddr::is_ipv4)
        .unwrap();
    socket.set_ip(Ipv4Addr::LOCALHOST.into());
    socket
}

async fn endpoint() -> Endpoint {
    Endpoint::builder(presets::Minimal)
        .bind_addr("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .unwrap()
        .bind()
        .await
        .unwrap()
}

async fn info(connection: &Connection, expected: EndpointId) {
    let client = NodeClientImpl::new(IrohTransport::new(connection.clone()));
    let response = tokio::time::timeout(PROGRESS, client.get_node_info(GetNodeInfoRequest {}))
        .await
        .expect("an independent Node RPC progresses")
        .unwrap();
    assert_eq!(response.node_id, expected.to_string());
}

struct PausedHandshake {
    target: EndpointAddr,
    received: oneshot::Receiver<()>,
    release: Option<oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for PausedHandshake {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl PausedHandshake {
    async fn new(provider: &ProviderHandle, source: Ipv4Addr) -> Self {
        let socket = UdpSocket::bind(SocketAddr::from((source, 0)))
            .await
            .unwrap();
        let target =
            EndpointAddr::new(provider.node_id()).with_ip_addr(socket.local_addr().unwrap());
        let server = super::handshakes::socket(provider);
        let (sent, received) = oneshot::channel();
        let (release, mut released) = oneshot::channel();
        let task = tokio::spawn(async move {
            let mut sent = Some(sent);
            let mut client = None;
            let mut holding = true;
            let mut pending: Vec<Vec<u8>> = Vec::new();
            let mut packet = [0u8; 65536];
            loop {
                tokio::select! {
                    _ = &mut released, if holding => {
                        holding = false;
                        for packet in pending.drain(..) {
                            socket.send_to(&packet, client.unwrap()).await.unwrap();
                        }
                    }
                    received = socket.recv_from(&mut packet) => {
                        let (size, from) = received.unwrap();
                        if from == server {
                            if holding {
                                // A QUIC long-header response proves the server is
                                // processing this handshake, not merely discovering a peer.
                                if packet[0] & 0x80 != 0 && let Some(sent) = sent.take() {
                                    let _ = sent.send(());
                                }
                                pending.push(packet[..size].to_vec());
                                assert!(pending.len() < 128);
                            } else {
                                socket.send_to(&packet[..size], client.unwrap()).await.unwrap();
                            }
                        } else {
                            client = Some(from);
                            socket.send_to(&packet[..size], server).await.unwrap();
                        }
                    }
                }
            }
        });
        Self {
            target,
            received,
            release: Some(release),
            task,
        }
    }
    async fn stalled(&mut self) {
        tokio::time::timeout(PROGRESS, &mut self.received)
            .await
            .expect("the server begins the held handshake")
            .unwrap();
    }
    fn resume(&mut self) {
        self.release.take().unwrap().send(()).unwrap();
    }
}

#[tokio::test]
async fn stalled_handshake_does_not_block_another_client() {
    let provider = provider().await;
    let client = endpoint().await;
    let mut paused = PausedHandshake::new(&provider, Ipv4Addr::LOCALHOST).await;
    let slow = {
        let endpoint = client.clone();
        let target = paused.target.clone();
        tokio::spawn(async move { endpoint.connect(target, Node::ALPN.as_bytes()).await })
    };
    paused.stalled().await;
    assert!(!slow.is_finished());
    let other = endpoint().await;
    let connection = tokio::time::timeout(
        PROGRESS,
        other.connect(
            EndpointAddr::new(provider.node_id()).with_ip_addr(socket(&provider)),
            Node::ALPN.as_bytes(),
        ),
    )
    .await
    .expect("a stalled peer cannot block accepting another client")
    .unwrap();
    info(&connection, provider.node_id()).await;
    assert!(
        !slow.is_finished(),
        "the delayed handshake is still pending"
    );
    paused.resume();
    let resumed = tokio::time::timeout(PROGRESS, slow)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    info(&resumed, provider.node_id()).await;
    client.close().await;
    other.close().await;
    provider.shutdown().await.unwrap();
}

#[tokio::test]
async fn completed_session_does_not_cancel_another_handshake() {
    let provider = provider().await;
    let client = endpoint().await;
    let target = EndpointAddr::new(provider.node_id()).with_ip_addr(socket(&provider));
    let first = client
        .connect(target.clone(), Node::ALPN.as_bytes())
        .await
        .unwrap();
    info(&first, provider.node_id()).await;
    let mut paused = PausedHandshake::new(&provider, Ipv4Addr::LOCALHOST).await;
    let slow_client = endpoint().await;
    let slow = {
        let endpoint = slow_client.clone();
        let target = paused.target.clone();
        tokio::spawn(async move { endpoint.connect(target, Node::ALPN.as_bytes()).await })
    };
    paused.stalled().await;
    first.close(0u32.into(), b"finish the earlier session");
    let other = endpoint().await;
    let probe = tokio::time::timeout(PROGRESS, other.connect(target, Node::ALPN.as_bytes()))
        .await
        .expect("accept loop handles other work during the paused handshake")
        .unwrap();
    info(&probe, provider.node_id()).await;
    paused.resume();
    let resumed = tokio::time::timeout(PROGRESS, slow)
        .await
        .expect("joining another session must not abandon this handshake")
        .unwrap()
        .unwrap();
    info(&resumed, provider.node_id()).await;
    slow_client.close().await;
    client.close().await;
    other.close().await;
    provider.shutdown().await.unwrap();
}
