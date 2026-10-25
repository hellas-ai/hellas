//! Shared source rate limits and connection occupancy. Permits live until close.
use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::{Arc, Mutex, Weak},
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

fn subnet(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V4(ip) => Ipv4Addr::from(u32::from(ip) & 0xffffff00).into(),
        IpAddr::V6(ip) => Ipv6Addr::from(u128::from(ip) & (u128::MAX << 64)).into(),
    }
}

/// The source address that per-IP and per-subnet limits apply to. Loopback
/// peers are local processes on the same host, so only global caps bound them.
fn remote_source(ip: Option<IpAddr>) -> Option<IpAddr> {
    ip.map(|ip| ip.to_canonical())
        .filter(|ip| !ip.is_loopback())
}

/// Concurrent permits keyed by an authenticated identity or canonical source.
pub struct KeyedSlots<K> {
    entries: Mutex<BTreeMap<K, Weak<Semaphore>>>,
    limit: usize,
}
impl<K: Ord> KeyedSlots<K> {
    pub fn new(limit: usize) -> Self {
        Self {
            entries: Mutex::new(BTreeMap::new()),
            limit,
        }
    }

    pub fn try_acquire(&self, key: K) -> Option<OwnedSemaphorePermit> {
        let mut entries = self
            .entries
            .lock()
            .expect("connection admission lock poisoned");
        entries.retain(|_, slots| slots.strong_count() > 0);
        let slots = entries
            .get(&key)
            .and_then(Weak::upgrade)
            .unwrap_or_else(|| {
                let slots = Arc::new(Semaphore::new(self.limit));
                entries.insert(key, Arc::downgrade(&slots));
                slots
            });
        slots.try_acquire_owned().ok()
    }
}

pub struct ConnectionSlots {
    global: Arc<Semaphore>,
    ips: KeyedSlots<IpAddr>,
    subnets: KeyedSlots<IpAddr>,
}
/// Dropping a connection returns all of its occupancy budgets together.
pub struct ConnectionPermit {
    _global: OwnedSemaphorePermit,
    _source: Option<(OwnedSemaphorePermit, OwnedSemaphorePermit)>,
}
impl ConnectionSlots {
    pub fn new(global: usize, per_ip: usize, per_subnet: usize) -> Self {
        Self {
            global: Arc::new(Semaphore::new(global)),
            ips: KeyedSlots::new(per_ip),
            subnets: KeyedSlots::new(per_subnet),
        }
    }

    /// Acquire without waiting, so a full pool never blocks the accept loop.
    pub fn try_acquire(&self, ip: Option<IpAddr>) -> Option<ConnectionPermit> {
        let global = self.global.clone().try_acquire_owned().ok()?;
        let source = if let Some(ip) = remote_source(ip) {
            Some((
                self.ips.try_acquire(ip)?,
                self.subnets.try_acquire(subnet(ip))?,
            ))
        } else {
            None
        };
        Some(ConnectionPermit {
            _global: global,
            _source: source,
        })
    }
}

/// Per-IP and per-/24 (IPv6 /64) handshake token buckets.
#[derive(Default)]
pub struct Handshakes(
    std::collections::BTreeMap<(std::net::IpAddr, bool), (u64, crate::peers::TokenBucket)>,
);
impl Handshakes {
    pub fn admit(&mut self, address: Option<std::net::IpAddr>, now: u64) -> bool {
        let Some(ip) = remote_source(address) else {
            // Relays expose an authenticated endpoint identity, not its IP.
            return true;
        };
        self.0
            .retain(|_, (seen, _)| now.saturating_sub(*seen) < 60_000);
        let subnet = subnet(ip);
        for (key, capacity, rate) in [((ip, false), 8.0, 2.0), ((subnet, true), 32.0, 8.0)] {
            if self.0.len() >= 1024 && !self.0.contains_key(&key) {
                return false;
            }
            let (seen, bucket) = self
                .0
                .entry(key)
                .or_insert_with(|| (now, crate::peers::TokenBucket::new(now, capacity)));
            *seen = now;
            if bucket.try_take(now, capacity, rate).is_err() {
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn connection_slots_bound_ip_subnet_and_global_occupancy_until_drop() {
        let slots = ConnectionSlots::new(5, 2, 3);
        let ip = |last| Some(IpAddr::from([192, 0, 2, last]));
        let one = slots.try_acquire(ip(1)).unwrap();
        let two = slots.try_acquire(ip(1)).unwrap();
        assert!(slots.try_acquire(ip(1)).is_none());
        // IPv4-mapped IPv6 addresses consume the same source's budget.
        assert!(
            slots
                .try_acquire(Some(Ipv4Addr::new(192, 0, 2, 1).to_ipv6_mapped().into()))
                .is_none()
        );
        let three = slots.try_acquire(ip(2)).unwrap();
        assert!(slots.try_acquire(ip(3)).is_none());
        let four = slots.try_acquire(Some([198, 51, 100, 1].into())).unwrap();
        let five = slots.try_acquire(Some([198, 51, 100, 2].into())).unwrap();
        assert!(slots.try_acquire(Some([203, 0, 113, 1].into())).is_none());
        drop(one);
        let replacement = slots.try_acquire(ip(1)).unwrap();
        drop((two, three, four, five, replacement));
        for host in 1..100 {
            drop(slots.try_acquire(ip(host)).unwrap());
            assert_eq!(slots.ips.entries.lock().unwrap().len(), 1);
        }
    }

    #[test]
    fn loopback_peers_skip_source_limits_but_not_the_global_cap() {
        let slots = ConnectionSlots::new(6, 1, 1);
        let loopback = Some(std::net::IpAddr::from([127, 0, 0, 1]));
        let held: Vec<_> = (0..6)
            .map(|_| {
                slots
                    .try_acquire(loopback)
                    .expect("loopback is not source limited")
            })
            .collect();
        assert!(
            slots.try_acquire(loopback).is_none(),
            "global cap still applies"
        );
        drop(held);
        let mut gate = Handshakes::default();
        for _ in 0..100 {
            assert!(gate.admit(loopback, 0));
        }
        assert!(gate.0.is_empty());
    }

    #[test]
    fn handshakes_bound_each_ip_subnet_and_idle_lifetime() {
        let mut gate = Handshakes::default();
        let ip = |last| Some(std::net::IpAddr::from([192, 0, 2, last]));
        for _ in 0..8 {
            assert!(gate.admit(ip(1), 0));
        }
        assert!(!gate.admit(ip(1), 0));
        for host in 2..5 {
            for _ in 0..8 {
                assert!(gate.admit(ip(host), 0));
            }
        }
        assert!(!gate.admit(ip(5), 0));
        assert!(gate.admit(ip(1), 1_000));
        assert!(gate.admit(ip(1), 61_000));
        assert_eq!(gate.0.len(), 2);
    }
}
