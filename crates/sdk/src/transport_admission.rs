//! Bounded pre-authentication handshakes on node transports.
use iroh::endpoint::IncomingAddr;
use std::sync::{Arc, Weak};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

pub(crate) struct HandshakeSlots {
    slots: Arc<Semaphore>,
    peers: Vec<(IncomingAddr, Weak<Semaphore>)>,
    per_peer: usize,
}
impl HandshakeSlots {
    pub(crate) fn new(global: usize, per_peer: usize) -> Self {
        Self {
            slots: Arc::new(Semaphore::new(global)),
            peers: Vec::new(),
            per_peer,
        }
    }

    /// Before authentication, source ports share their IP's budget. Relay
    /// addresses retain the relay's endpoint identity. Entries live only while
    /// their handshakes hold permits; the global quota also bounds this table.
    pub(crate) fn try_acquire(
        &mut self,
        address: &IncomingAddr,
    ) -> Option<(OwnedSemaphorePermit, OwnedSemaphorePermit)> {
        let slot = self.slots.clone().try_acquire_owned().ok()?;
        let mut address = address.clone();
        if let IncomingAddr::Ip(address) = &mut address {
            address.set_port(0);
        }
        self.peers.retain(|(_, slots)| slots.strong_count() > 0);
        let peer = self
            .peers
            .iter()
            .find(|(peer, _)| *peer == address)
            .and_then(|(_, slots)| slots.upgrade())
            .unwrap_or_else(|| {
                let slots = Arc::new(Semaphore::new(self.per_peer));
                self.peers.push((address, Arc::downgrade(&slots)));
                slots
            });
        Some((slot, peer.try_acquire_owned().ok()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(ip: u8, port: u16) -> IncomingAddr {
        IncomingAddr::Ip(std::net::SocketAddr::from(([127, 0, 0, ip], port)))
    }

    #[test]
    fn ports_share_a_source_budget_and_permits_release_both_limits() {
        let mut slots = HandshakeSlots::new(3, 2);
        let first = slots.try_acquire(&peer(1, 1000)).unwrap();
        let second = slots.try_acquire(&peer(1, 2000)).unwrap();
        assert!(slots.try_acquire(&peer(1, 3000)).is_none());
        let other = slots.try_acquire(&peer(2, 1000)).unwrap();
        assert!(slots.try_acquire(&peer(3, 1000)).is_none());
        drop(first);
        let replacement = slots.try_acquire(&peer(1, 4000)).unwrap();
        drop((second, other, replacement));
        // Expired per-source state does not accumulate or retain exhausted quotas.
        for ip in 1..100 {
            drop(slots.try_acquire(&peer(ip, 1000)).unwrap());
            assert_eq!(slots.peers.len(), 1);
        }
    }
}
