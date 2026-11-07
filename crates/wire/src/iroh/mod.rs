//! Iroh transport: one StreamTransport per iroh `Connection`.
//! Iroh substreams ARE the streams; no mux involved.

mod stream;
mod transport;

pub mod pool;
pub mod swarm;

pub use pool::{Pool, PoolError, PoolOptions};
pub use stream::{IrohRecvHalf, IrohSendHalf, IrohStream};
pub use swarm::{
    DiscoveredPeer, Discovery, Peer, PeerExchangeBackend, ServiceRegistry, StaticBackend,
};
pub use transport::{IrohTransport, IrohTransportError, OPEN_EXPORTER_LABEL, OPEN_EXPORTER_LEN};

/// How long [`close`] waits for peers to acknowledge an endpoint's close.
pub const CLOSE_GRACE: std::time::Duration = std::time::Duration::from_millis(250);

/// Close `endpoint`, waiting at most [`CLOSE_GRACE`] for peers to answer.
///
/// `Endpoint::close` sends every connection an application close (code 0)
/// and returns once each has drained. A live peer answers within one round
/// trip. A dial still in its handshake, or one abandoned in the last three
/// probe timeouts, has nobody to answer: it waits the full 3 x PTO, 3 s
/// before any RTT sample. Shutdown should not wait on peers that cannot
/// reply. The close runs to completion detached, never cancelled: a
/// cancelled `Endpoint::close` leaves iroh closing forever, so dropping the
/// endpoint would skip the abort that stops its tasks.
pub async fn close(endpoint: &::iroh::Endpoint) {
    let endpoint = endpoint.clone();
    let closing = n0_future::task::spawn(async move { endpoint.close().await });
    let _ = n0_future::time::timeout(CLOSE_GRACE, closing).await;
}

#[cfg(test)]
mod tests {
    use ::iroh::{Endpoint, EndpointAddr, SecretKey, TransportAddr, endpoint::presets};
    use std::time::{Duration, Instant};

    /// An abandoned dial has no peer to acknowledge its close; iroh would
    /// wait 3 x PTO (about 3 s) for it.
    #[tokio::test]
    async fn close_does_not_wait_for_a_peer_that_cannot_answer() {
        let endpoint = Endpoint::builder(presets::Minimal)
            .bind_addr("127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap())
            .unwrap()
            .bind()
            .await
            .unwrap();
        let nobody = EndpointAddr::from_parts(
            SecretKey::from_bytes(&[7; 32]).public(),
            [TransportAddr::Ip("127.0.0.1:9".parse().unwrap())],
        );
        let dial = endpoint.connect(nobody, b"nobody");
        assert!(
            tokio::time::timeout(Duration::from_millis(50), dial)
                .await
                .is_err()
        );
        let started = Instant::now();
        super::close(&endpoint).await;
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "{:?}",
            started.elapsed()
        );
    }
}
