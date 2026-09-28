//! Connection pool for reusing iroh connections per service ALPN.
//!
//! * Returns either a raw `iroh::endpoint::Connection` or a per-conn
//!   `IrohTransport` — no tonic `Channel` / HTTP/2 layer involved.
//! * Uses a simple cache + background sweeper instead of a per-conn
//!   actor; iroh `Connection` is cheap to clone and is already an
//!   `Arc`-backed handle.
//! * Is keyed by `(EndpointId, ALPN)`, but exposes the ALPN
//!   via `ServiceMarker` rather than a tonic `NamedService`.
//!
//! # Example
//!
//! ```rust,no_run
//! use hellas_wire::iroh::{Pool, PoolOptions};
//! use hellas_wire::ServiceMarker;
//! # use iroh::{Endpoint, EndpointId};
//!
//! # async fn example(endpoint: Endpoint, peer: EndpointId) -> Result<(), Box<dyn std::error::Error>> {
//! struct MyService;
//! impl ServiceMarker for MyService {
//!     const NAME: &'static str = "my.Service";
//!     const ALPN: &'static str = "/my.Service/2.0";
//!     const SERVICE_ID: u32 = 0;
//! }
//!
//! let pool = Pool::for_service::<MyService>(endpoint, PoolOptions::default());
//! let transport = pool.transport(peer).await?;
//! # let _ = transport;
//! # Ok(())
//! # }
//! ```

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ::iroh::endpoint::Connection;
use ::iroh::{Endpoint, EndpointId};
// Xtensa (esp32-s3) lacks native 64-bit atomics; portable-atomic provides a
// mutex-fallback so embedded targets still compile.
use portable_atomic::{AtomicU64, Ordering};
use tracing::Instrument;
use web_time::Instant;

use crate::iroh::transport::IrohTransport;
use crate::transport::ServiceMarker;

/// Configuration for the connection pool.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PoolOptions {
    /// Duration to keep idle connections alive. Default: 10s.
    pub idle_timeout: Duration,
    /// Timeout for connection establishment. Default: 5s.
    pub connect_timeout: Duration,
    /// Maximum cached connections (LRU-evicted when full). Default: 1024.
    pub max_connections: usize,
}

impl Default for PoolOptions {
    fn default() -> Self {
        Self {
            idle_timeout: Duration::from_secs(10),
            connect_timeout: Duration::from_secs(5),
            max_connections: 1024,
        }
    }
}

/// Error from pool operations.
#[derive(Debug, Clone, thiserror::Error)]
pub enum PoolError {
    /// The connection pool has been shut down.
    #[error("connection pool is shut down")]
    Shutdown,
    /// Connection timed out.
    #[error("connection timed out")]
    Timeout,
    /// Too many active connections.
    #[error("too many connections")]
    TooManyConnections,
    /// Iroh connection error.
    #[error("connect error: {0}")]
    Connect(Arc<::iroh::endpoint::ConnectError>),
}

impl From<::iroh::endpoint::ConnectError> for PoolError {
    fn from(e: ::iroh::endpoint::ConnectError) -> Self {
        Self::Connect(Arc::new(e))
    }
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct CachedConn {
    connection: Connection,
    /// Monotonic on native and browsers.
    last_used: Instant,
}

struct Inner {
    endpoint: Endpoint,
    alpn: Vec<u8>,
    options: PoolOptions,
    cache: Mutex<HashMap<EndpointId, CachedConn>>,
    next_generation: AtomicU64,
    closed: AtomicBoolFlag,
}

/// Lightweight cross-thread atomic-bool wrapper (avoids pulling in another
/// dep for a one-liner).
#[derive(Default)]
struct AtomicBoolFlag(std::sync::atomic::AtomicBool);

impl AtomicBoolFlag {
    fn is_set(&self) -> bool {
        self.0.load(std::sync::atomic::Ordering::SeqCst)
    }
    fn set(&self) {
        self.0.store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// A connection pool for a single ALPN protocol.
///
/// Connections are stored by `EndpointId`; on cache hit the cached
/// `Connection` is returned (after a liveness check), on miss a new
/// connection is established under `connect_timeout`. A background task
/// sweeps idle entries past `idle_timeout`.
#[derive(Clone)]
pub struct Pool {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for Pool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pool")
            .field("alpn", &String::from_utf8_lossy(&self.inner.alpn))
            .finish_non_exhaustive()
    }
}

impl Pool {
    /// Create a new connection pool for the given ALPN.
    #[must_use]
    pub fn new(endpoint: Endpoint, alpn: &[u8], options: PoolOptions) -> Self {
        let inner = Arc::new(Inner {
            endpoint,
            alpn: alpn.to_vec(),
            options,
            cache: Mutex::new(HashMap::new()),
            next_generation: AtomicU64::new(1),
            closed: AtomicBoolFlag::default(),
        });

        // Spawn the idle sweeper. It holds a Weak<Inner> so the pool is
        // dropped when the last `Pool` handle goes away.
        let weak = Arc::downgrade(&inner);
        n0_future::task::spawn(async move {
            loop {
                let Some(inner) = weak.upgrade() else {
                    return;
                };
                if inner.closed.is_set() {
                    return;
                }
                let idle_timeout = inner.options.idle_timeout;
                drop(inner);
                n0_future::time::sleep(idle_timeout).await;
                let Some(inner) = weak.upgrade() else {
                    return;
                };
                inner.sweep_idle();
            }
        });

        Self { inner }
    }

    /// Create a pool for a specific service marker. The ALPN is derived
    /// from `ServiceMarker::ALPN`.
    #[must_use]
    pub fn for_service<S: ServiceMarker>(endpoint: Endpoint, options: PoolOptions) -> Self {
        Self::new(endpoint, S::ALPN.as_bytes(), options)
    }

    /// Return the ALPN this pool is scoped to.
    #[must_use]
    pub fn alpn(&self) -> &[u8] {
        &self.inner.alpn
    }

    /// Return the underlying iroh endpoint.
    #[must_use]
    pub fn endpoint(&self) -> &Endpoint {
        &self.inner.endpoint
    }

    /// Get or establish a connection to the given peer. Returns the
    /// cached `iroh::endpoint::Connection` if one is live; otherwise
    /// opens a new one under `connect_timeout`.
    ///
    /// Callers that want a `StreamTransport` directly should use
    /// [`Pool::transport`] instead.
    ///
    /// # Errors
    ///
    /// Returns [`PoolError`] if the pool is shut down, the dial times
    /// out, the connection limit is reached, or iroh refuses the dial.
    pub async fn connection(
        &self,
        target: impl Into<iroh::EndpointAddr>,
    ) -> Result<Connection, PoolError> {
        let target: iroh::EndpointAddr = target.into();
        let peer_id = target.id;
        if self.inner.closed.is_set() {
            return Err(PoolError::Shutdown);
        }

        // Fast path: liveness-checked cache hit. Cache is keyed on
        // EndpointId because that's the stable identity — any hints
        // in the EndpointAddr are dial-time only and don't affect
        // whether a live connection can be reused.
        if let Some(conn) = self.inner.cached_live(peer_id) {
            return Ok(conn);
        }

        // Slow path: dial a fresh one. We don't lock the cache across the
        // dial — concurrent racers might each open a connection; the
        // loser's connection is dropped immediately when we re-insert.
        // Pass the full EndpointAddr to iroh::Endpoint::connect so any
        // CLI-supplied direct addresses become dial hints.
        // The QUIC driver retains the current span for the connection's entire
        // lifetime. Give it a root span so it cannot keep the dialing request
        // and its ancestors open while subsequent requests reuse the connection.
        let span = tracing::info_span!(target: "hellas_request", parent: None, "quic.connection");
        let connect = self
            .inner
            .endpoint
            .connect(target, self.inner.alpn.as_slice())
            .instrument(span);
        let conn = n0_future::time::timeout(self.inner.options.connect_timeout, connect)
            .await
            .map_err(|_| PoolError::Timeout)?
            .map_err(PoolError::from)?;

        // Bump the generation counter so that future debug/introspection
        // hooks can distinguish reinserts; the value itself isn't read by
        // the cache fast path yet.
        let _ = self.inner.next_generation.fetch_add(1, Ordering::SeqCst);
        let mut cache = self
            .inner
            .cache
            .lock()
            .expect("pool cache mutex should not be poisoned");

        // If a racer already inserted a live connection while we were
        // dialing, prefer the cached one and drop ours (the iroh
        // connection close will happen when `conn` is dropped).
        if let Some(existing) = cache.get(&peer_id)
            && existing.connection.close_reason().is_none()
        {
            return Ok(existing.connection.clone());
        }

        // Enforce max_connections via simple eviction: remove the
        // least-recently-used entry until we fit.
        while cache.len() >= self.inner.options.max_connections && !cache.is_empty() {
            if let Some(lru_id) = cache
                .iter()
                .min_by_key(|(_, c)| c.last_used)
                .map(|(id, _)| *id)
            {
                cache.remove(&lru_id);
            } else {
                break;
            }
        }

        if cache.len() >= self.inner.options.max_connections {
            return Err(PoolError::TooManyConnections);
        }

        cache.insert(
            peer_id,
            CachedConn {
                connection: conn.clone(),
                last_used: Instant::now(),
            },
        );
        Ok(conn)
    }

    /// Convenience: get a connection and wrap it in `IrohTransport`.
    ///
    /// Note: cloning `IrohTransport` is intentionally not supported, so
    /// each call hands the caller a fresh transport over a (possibly
    /// reused) underlying iroh connection.
    ///
    /// # Errors
    ///
    /// Forwards [`PoolError`] from [`Pool::connection`].
    pub async fn transport(
        &self,
        target: impl Into<iroh::EndpointAddr>,
    ) -> Result<IrohTransport, PoolError> {
        let conn = self.connection(target).await?;
        Ok(IrohTransport::new(conn))
    }

    /// Force-remove the cached connection for a peer (if any). The
    /// caller can immediately re-dial via [`Pool::connection`].
    pub fn invalidate(&self, peer_id: EndpointId) {
        if let Ok(mut cache) = self.inner.cache.lock() {
            cache.remove(&peer_id);
        }
    }

    /// Mark the pool as closed; cached connections are dropped and no
    /// new dials are accepted.
    pub fn shutdown(&self) {
        self.inner.closed.set();
        if let Ok(mut cache) = self.inner.cache.lock() {
            cache.clear();
        }
    }
}

impl Inner {
    fn cached_live(&self, peer_id: EndpointId) -> Option<Connection> {
        let mut cache = self.cache.lock().ok()?;
        let entry = cache.get_mut(&peer_id)?;
        if entry.connection.close_reason().is_some() {
            cache.remove(&peer_id);
            return None;
        }
        entry.last_used = Instant::now();
        Some(entry.connection.clone())
    }

    fn sweep_idle(&self) {
        let Ok(mut cache) = self.cache.lock() else {
            return;
        };
        let now = Instant::now();
        let idle_timeout = self.options.idle_timeout;
        cache.retain(|_, c| {
            if c.connection.close_reason().is_some() {
                return false;
            }
            now.duration_since(c.last_used) < idle_timeout
        });
    }
}

impl Drop for Pool {
    fn drop(&mut self) {
        // If this is the last handle, mark closed so the sweeper exits
        // promptly on its next wake.
        if Arc::strong_count(&self.inner) == 1 {
            self.inner.closed.set();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing::instrument::{Instrument, WithSubscriber};
    use tracing_subscriber::{Layer, layer::Context, prelude::*, registry::LookupSpan};

    #[derive(Clone, Default)]
    struct ClosedSpans(Arc<Mutex<Vec<&'static str>>>);

    impl<S: tracing::Subscriber + for<'a> LookupSpan<'a>> Layer<S> for ClosedSpans {
        fn on_close(&self, id: tracing::span::Id, ctx: Context<'_, S>) {
            self.0.lock().unwrap().push(ctx.span(&id).unwrap().name());
        }
    }

    #[tokio::test]
    async fn pooled_connection_does_not_hold_request_span_open() {
        let closed = ClosedSpans::default();
        let dispatch = tracing::Dispatch::new(
            tracing_subscriber::registry()
                .with(tracing_subscriber::filter::LevelFilter::INFO)
                .with(closed.clone()),
        );
        async {
            let alpn = b"/hellas-test/pool/1";
            let server = Endpoint::builder(::iroh::endpoint::presets::Minimal)
                .alpns(vec![alpn.to_vec()])
                .bind()
                .await
                .unwrap();
            let client = Endpoint::builder(::iroh::endpoint::presets::Minimal)
                .bind()
                .await
                .unwrap();
            let pool = Pool::new(client.clone(), alpn, PoolOptions::default());
            let request = tracing::info_span!("request");
            let (connected, accepted) =
                tokio::join!(pool.connection(server.addr()).instrument(request), async {
                    server.accept().await.unwrap().await.unwrap()
                },);
            let connected = connected.unwrap();
            assert!(connected.close_reason().is_none());
            assert!(accepted.close_reason().is_none());
            assert!(
                closed.0.lock().unwrap().contains(&"request"),
                "request span must close while the pooled connection is still live"
            );
            pool.shutdown();
            client.close().await;
            server.close().await;
        }
        .with_subscriber(dispatch)
        .await;
    }
}
