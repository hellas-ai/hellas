//! Bounded admission for endpoints that have not proved an application credential.
//! Transport keys identify buckets; they never establish service authority.
use hellas_wire::{WireCode, WireStatus};
use iroh::EndpointId;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::time::Instant;

const BURST: u32 = 8;
const REFILL: Duration = Duration::from_secs(2);
const MAX_PEERS: usize = 512;

struct Bucket {
    tokens: u32,
    active: u32,
    refilled: Instant,
}
impl Bucket {
    fn refill(&mut self, now: Instant) {
        let count = now.saturating_duration_since(self.refilled).as_nanos() / REFILL.as_nanos();
        if count >= u128::from(BURST) {
            self.tokens = BURST;
            self.refilled = now;
        } else {
            let count = count as u32; // Strictly below BURST.
            self.tokens = (self.tokens + count).min(BURST);
            self.refilled += REFILL * count;
        }
    }
}

#[derive(Clone, Default)]
pub(super) struct UnverifiedAdmission(Arc<Mutex<HashMap<EndpointId, Bucket>>>);

impl UnverifiedAdmission {
    pub(super) fn admit(
        &self,
        peer: EndpointId,
        now: Instant,
    ) -> Result<UnverifiedConnection, WireStatus> {
        let mut buckets = self
            .0
            .lock()
            .map_err(|_| WireStatus::new(WireCode::Unavailable, "Work admission is unavailable"))?;
        if !buckets.contains_key(&peer) && buckets.len() >= MAX_PEERS {
            buckets.retain(|_, bucket| {
                bucket.refill(now);
                bucket.active != 0 || bucket.tokens < BURST
            });
            if buckets.len() >= MAX_PEERS {
                return Err(capacity());
            }
        }
        let bucket = buckets.entry(peer).or_insert(Bucket {
            tokens: BURST,
            active: 0,
            refilled: now,
        });
        bucket.refill(now);
        if bucket.tokens == 0 || bucket.active >= BURST {
            return Err(capacity());
        }
        bucket.tokens -= 1;
        bucket.active += 1;
        Ok(UnverifiedConnection {
            admission: self.clone(),
            peer,
            authenticated: false,
        })
    }
}

/// Pending and public payment connections retain this lease. Successful grant
/// authentication releases it and returns the token; failed attempts consume it.
pub(super) struct UnverifiedConnection {
    admission: UnverifiedAdmission,
    peer: EndpointId,
    authenticated: bool,
}
impl UnverifiedConnection {
    pub(super) fn authenticated(mut self) {
        self.authenticated = true;
    }
}
impl Drop for UnverifiedConnection {
    fn drop(&mut self) {
        if let Ok(mut buckets) = self.admission.0.lock()
            && let Some(bucket) = buckets.get_mut(&self.peer)
        {
            bucket.active = bucket.active.saturating_sub(1);
            if self.authenticated {
                bucket.tokens = (bucket.tokens + 1).min(BURST);
            }
        }
    }
}

pub(super) fn capacity() -> WireStatus {
    WireStatus::new(
        WireCode::ResourceExhausted,
        "Work connection admission is at capacity",
    )
}
