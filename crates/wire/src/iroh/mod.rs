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

/// Run fallible setup on an endpoint the caller bound. On error the caller
/// still owns the endpoint, so it is closed before the error returns; on
/// success the endpoint passes to whatever the setup built.
pub async fn close_on_error<T, E>(
    endpoint: &::iroh::Endpoint,
    setup: impl Future<Output = Result<T, E>>,
) -> Result<T, E> {
    let result = setup.await;
    if result.is_err() {
        endpoint.close().await;
    }
    result
}
