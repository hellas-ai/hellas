//! One admission path for standalone providers and host-owned iroh endpoints.
use hellas_wire::admission::{ConnectionPermit, ConnectionSlots, Handshakes, KeyedSlots};
use iroh::endpoint::{Connection, Incoming, IncomingAddr};
use std::{net::IpAddr, sync::Arc, time::Duration};
use tokio::{sync::OwnedSemaphorePermit, time::Instant};

pub(crate) const MAX_CONNECTIONS: usize = 128;
pub(crate) const PER_IP: usize = 4;
pub(crate) const PER_SUBNET: usize = 16;
pub(crate) const PER_IDENTITY: usize = 4;
pub(crate) const IDLE_TIMEOUT: Duration = Duration::from_secs(120);
// Even continuous cheap requests release their occupancy budgets within 15 minutes.
pub(crate) const MAX_LIFETIME: Duration = Duration::from_secs(15 * 60);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

pub(crate) fn source_ip(address: IncomingAddr) -> Option<IpAddr> {
    match address {
        IncomingAddr::Ip(address) => Some(address.ip()),
        _ => None,
    }
}

pub(crate) struct Admission {
    slots: ConnectionSlots,
    handshakes: ConnectionSlots,
    rates: Handshakes,
    identities: Arc<KeyedSlots<[u8; 32]>>,
    epoch: Instant,
}
impl Admission {
    pub(crate) fn new() -> Self {
        Self {
            slots: ConnectionSlots::new(MAX_CONNECTIONS, PER_IP, PER_SUBNET),
            handshakes: ConnectionSlots::new(16, 2, 8),
            rates: Handshakes::default(),
            identities: Arc::new(KeyedSlots::new(PER_IDENTITY)),
            epoch: Instant::now(),
        }
    }

    /// Refuse before spawning or awaiting a handshake when any budget is full.
    pub(crate) fn accept(&mut self, incoming: Incoming) -> Option<PendingConnection> {
        let ip = source_ip(incoming.remote_addr());
        let permits = (|| {
            let slot = self.slots.try_acquire(ip)?;
            let handshake = self.handshakes.try_acquire(ip)?;
            self.rates
                .admit(ip, self.epoch.elapsed().as_millis() as u64)
                .then_some((slot, handshake))
        })();
        let Some((slot, handshake)) = permits else {
            incoming.refuse();
            return None;
        };
        Some(PendingConnection {
            incoming,
            slot,
            _handshake: handshake,
            identities: self.identities.clone(),
        })
    }
}

pub(crate) struct PendingConnection {
    incoming: Incoming,
    slot: ConnectionPermit,
    _handshake: ConnectionPermit,
    identities: Arc<KeyedSlots<[u8; 32]>>,
}
impl PendingConnection {
    pub(crate) async fn finish(self) -> Option<AdmittedConnection> {
        let connection = tokio::time::timeout(HANDSHAKE_TIMEOUT, self.incoming.accept().ok()?)
            .await
            .ok()?
            .ok()?;
        let Some(identity) = self
            .identities
            .try_acquire(*connection.remote_id().as_bytes())
        else {
            connection.close(503u32.into(), b"peer at capacity");
            return None;
        };
        Some(AdmittedConnection {
            connection,
            _slot: self.slot,
            _identity: identity,
            deadline: Instant::now() + MAX_LIFETIME,
        })
    }
}

/// Admission follows the connection when a host forwards it to a provider.
pub(crate) struct AdmittedConnection {
    pub(crate) connection: Connection,
    _slot: ConnectionPermit,
    _identity: OwnedSemaphorePermit,
    deadline: Instant,
}
impl AdmittedConnection {
    pub(crate) async fn run<F: Future>(&self, serve: F) -> Option<F::Output> {
        tokio::time::timeout_at(self.deadline, serve).await.ok()
    }
}
impl Drop for AdmittedConnection {
    fn drop(&mut self) {
        self.connection.close(0u32.into(), b"connection finished");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh::{Endpoint, EndpointAddr, endpoint::presets};

    #[tokio::test]
    async fn a_full_pool_refuses_new_handshakes_without_stopping_accept() {
        let server = Endpoint::builder(presets::Minimal)
            .bind_addr("127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap())
            .unwrap()
            .alpns(vec![b"admission-test".to_vec()])
            .bind()
            .await
            .unwrap();
        let target = EndpointAddr::new(server.id()).with_ip_addr(server.bound_sockets()[0]);
        let endpoint = server.clone();
        let (admitted_tx, mut admitted_rx) = tokio::sync::mpsc::channel(2);
        let serving = tokio::spawn(async move {
            let mut admission = Admission::new();
            admission.slots = ConnectionSlots::new(2, 2, 2);
            let mut tasks = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    _ = tasks.join_next(), if !tasks.is_empty() => {},
                    incoming = endpoint.accept() => {
                        let Some(incoming) = incoming else { break; };
                        let Some(pending) = admission.accept(incoming) else { continue; };
                        let admitted_tx = admitted_tx.clone();
                        tasks.spawn(async move {
                            let Some(connection) = pending.finish().await else { return; };
                            let _ = admitted_tx.send(()).await;
                            connection.run(connection.connection.closed()).await;
                        });
                    }
                }
            }
        });
        let mut held = Vec::new();
        for _ in 0..2 {
            let client = Endpoint::builder(presets::Minimal).bind().await.unwrap();
            let connection = client
                .connect(target.clone(), b"admission-test")
                .await
                .unwrap();
            admitted_rx.recv().await.unwrap();
            held.push((client, connection));
        }
        for _ in 0..2 {
            let client = Endpoint::builder(presets::Minimal).bind().await.unwrap();
            let refused = tokio::time::timeout(
                Duration::from_secs(3),
                client.connect(target.clone(), b"admission-test"),
            )
            .await
            .expect("full admission returns a refusal rather than leaving TLS pending");
            assert!(refused.is_err());
            client.close().await;
        }
        for (client, _) in held {
            client.close().await;
        }
        serving.abort();
        server.close().await;
    }
}
