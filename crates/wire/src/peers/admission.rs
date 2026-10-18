use std::fmt;

use super::{PeerId, RpcMethod, RpcService};

/// Transport-independent RPC identity used for accounting and admission.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RequestKind {
    pub service: &'static str,
    pub method: &'static str,
}

impl RequestKind {
    pub const fn new(service: &'static str, method: &'static str) -> Self {
        Self { service, method }
    }

    pub const fn for_method<M: RpcMethod>() -> Self {
        Self {
            service: <M::Service as RpcService>::NAME,
            method: M::NAME,
        }
    }
}

/// Admission token returned before a request starts.
///
/// The caller must pass this value to `PeerRegistry::release` when the request
/// completes so in-flight counters and latency stats stay accurate. The
/// registry disarms the permit inside `release`; if a debug build drops an
/// armed permit (i.e. neither released nor disarmed), it panics — that
/// indicates a leaked in-flight slot, which the registry has no way to clean
/// up on its own from sans-io state alone.
///
/// Higher-level managers wrap this in an RAII guard so dropping the guard
/// records [`Outcome::Cancelled`] and consumes the permit before its `Drop`
/// fires; successful or failed RPC completion consumes the guard and records
/// the final [`Outcome`].
#[must_use = "permits must be released through PeerRegistry::release"]
#[derive(Debug)]
pub struct Permit {
    peer: PeerId,
    kind: RequestKind,
    armed: bool,
}

impl Permit {
    pub(super) const fn new(peer: PeerId, kind: RequestKind) -> Self {
        Self {
            peer,
            kind,
            armed: true,
        }
    }

    pub const fn peer(&self) -> PeerId {
        self.peer
    }

    pub const fn kind(&self) -> RequestKind {
        self.kind
    }

    /// Internal disarm called by `PeerRegistry::release` before dropping the
    /// permit. Application code should not call this directly.
    pub(super) const fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for Permit {
    fn drop(&mut self) {
        if self.armed {
            #[cfg(debug_assertions)]
            panic!(
                "Permit for peer {} method {}::{} dropped without being released. \
                 Did you forget to call `PeerRegistry::release` (or use an RAII guard)?",
                self.peer, self.kind.service, self.kind.method
            );
            // In release builds we eat the leak silently — the alternative
            // is panicking servers in production over a missing release call.
        }
    }
}

/// Result reported when a previously admitted request completes.
#[derive(Clone, Debug, PartialEq)]
pub enum Outcome {
    Ok { rtt_ms: f64 },
    Err { rtt_ms: Option<f64>, error: String },
    Cancelled,
}

impl Outcome {
    pub const fn ok(rtt_ms: f64) -> Self {
        Self::Ok { rtt_ms }
    }
}

/// Why a request was denied before any I/O should be attempted.
#[derive(Clone, Debug, PartialEq)]
pub enum AcquireDenied {
    PeerLimit {
        peer: PeerId,
        max_peers: usize,
    },
    InFlightPeer {
        peer: PeerId,
        limit: usize,
    },
    InFlightTotal {
        limit: usize,
    },
    RateLimited {
        peer: PeerId,
        retry_after_ms: Option<u64>,
    },
}

impl fmt::Display for AcquireDenied {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PeerLimit { peer, max_peers } => {
                write!(
                    f,
                    "peer registry is full while admitting {peer} (max {max_peers})"
                )
            }
            Self::InFlightPeer { peer, limit } => {
                write!(f, "peer {peer} has reached its in-flight limit ({limit})")
            }
            Self::InFlightTotal { limit } => {
                write!(
                    f,
                    "registry has reached its total in-flight limit ({limit})"
                )
            }
            Self::RateLimited {
                peer,
                retry_after_ms: Some(ms),
            } => {
                write!(f, "peer {peer} is rate limited, retry after {ms} ms")
            }
            Self::RateLimited {
                peer,
                retry_after_ms: None,
            } => {
                write!(f, "peer {peer} is rate limited")
            }
        }
    }
}

impl std::error::Error for AcquireDenied {}

#[derive(Clone, Debug, PartialEq)]
pub struct TokenBucket {
    tokens: f64,
    last_refill_ms: u64,
}

impl TokenBucket {
    pub fn new(now_ms: u64, capacity: f64) -> Self {
        Self {
            tokens: capacity,
            last_refill_ms: now_ms,
        }
    }

    /// Try to consume one token. Returns `Err(retry_after_ms)` when empty —
    /// `None` retry-after means "never" (either refill rate is zero, or the
    /// bucket's capacity is below one token so it can never admit at all).
    pub fn try_take(
        &mut self,
        now_ms: u64,
        capacity: f64,
        refill_per_sec: f64,
    ) -> Result<(), Option<u64>> {
        // A bucket whose capacity is below one token can never hold enough to
        // admit a request, no matter how long the caller waits. Refilling
        // would just clamp back to the sub-token capacity. Return `Err(None)`
        // so callers don't advertise a misleading retry-after.
        if capacity < 1.0 {
            return Err(None);
        }

        self.refill(now_ms, capacity, refill_per_sec);

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            return Ok(());
        }

        let missing = 1.0 - self.tokens;
        let retry_after_ms = if refill_per_sec > 0.0 {
            Some(((missing / refill_per_sec) * 1000.0).ceil() as u64)
        } else {
            None
        };
        Err(retry_after_ms)
    }

    fn refill(&mut self, now_ms: u64, capacity: f64, refill_per_sec: f64) {
        if now_ms <= self.last_refill_ms {
            return;
        }

        if refill_per_sec > 0.0 {
            let elapsed_ms = now_ms - self.last_refill_ms;
            self.tokens =
                (self.tokens + (elapsed_ms as f64 / 1000.0) * refill_per_sec).min(capacity);
        }
        self.last_refill_ms = now_ms;
    }
}
