//! mDNS-based local network peer discovery backend.
//!
//! Uses `iroh-mdns-address-lookup`, which exposes a clonable handle with a
//! `subscribe()` stream of `DiscoveryEvent`s.
//!
//! ALPN scoping is honoured: discovered peers whose published user-data does
//! NOT advertise our target ALPN are skipped. The encoding follows the
//! service-advertisement scheme (postcard `Vec<Vec<u8>>` then
//! base64url-no-pad).

use std::pin::Pin;
use std::sync::Arc;

use data_encoding::BASE64URL_NOPAD;
use futures::stream::{Stream, StreamExt};
use iroh_mdns_address_lookup::{DiscoveryEvent, MdnsAddressLookup};
use tracing::debug;

use super::discovery::{DiscoveredPeer, Discovery};
use super::peers::{FeedResult, PeerFeedSpec, Scope};

// ---------------------------------------------------------------------------
// User-data ALPN encoding helpers (parity with tonic-iroh-transport).
// ---------------------------------------------------------------------------

/// Classification for service-scoped discovery against published user-data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UserDataAlpnMatch {
    /// The published metadata contains the required ALPN.
    Match,
    /// The published metadata is present but does not contain the ALPN.
    Mismatch,
    /// No service metadata was published.
    Missing,
}

fn decode_alpns(user_data: &str) -> Vec<Vec<u8>> {
    BASE64URL_NOPAD
        .decode(user_data.as_bytes())
        .ok()
        .and_then(|bytes| postcard::from_bytes::<Vec<Vec<u8>>>(&bytes).ok())
        .unwrap_or_default()
}

fn classify_user_data_alpn(user_data: Option<&str>, alpn: &[u8]) -> UserDataAlpnMatch {
    match user_data {
        Some(user_data) if decode_alpns(user_data).iter().any(|a| a == alpn) => {
            UserDataAlpnMatch::Match
        }
        Some(_) => UserDataAlpnMatch::Mismatch,
        None => UserDataAlpnMatch::Missing,
    }
}

// ---------------------------------------------------------------------------
// Feed builder.
// ---------------------------------------------------------------------------

async fn subscribe_ready<S>(
    subscribe: impl std::future::Future<Output = S>,
    ready: Option<tokio::sync::watch::Sender<bool>>,
) -> S {
    let subscription = subscribe.await;
    if let Some(ready) = ready {
        ready.send_replace(true);
    }
    subscription
}

fn mdns_feed(
    mdns: Arc<MdnsAddressLookup>,
    alpn: Vec<u8>,
    priority: u8,
    trust: u8,
    ready: Option<tokio::sync::watch::Sender<bool>>,
) -> PeerFeedSpec {
    let scope_alpn = alpn.clone();
    let peer_trust = trust;
    let stream = async_stream::try_stream! {
        // subscribe() enqueues registration on the actor's FIFO mailbox.
        // Advertisements sent after readiness cannot overtake that registration.
        let mut sub = subscribe_ready(mdns.subscribe(), ready).await;
        while let Some(event) = sub.next().await {
            if let DiscoveryEvent::Discovered { endpoint_info, .. } = event {
                let endpoint_id = endpoint_info.endpoint_id;
                let user_data_str = endpoint_info.data.user_data().map(|u| u.to_string());
                match classify_user_data_alpn(user_data_str.as_deref(), &alpn) {
                    UserDataAlpnMatch::Match => {}
                    UserDataAlpnMatch::Mismatch => {
                        debug!(%endpoint_id, alpn = %String::from_utf8_lossy(&alpn), "mdns: ALPN mismatch, skipping");
                        continue;
                    }
                    UserDataAlpnMatch::Missing => {
                        debug!(%endpoint_id, alpn = %String::from_utf8_lossy(&alpn), "mdns: missing service metadata, skipping");
                        continue;
                    }
                }
                debug!(%endpoint_id, source = "mdns", "discovered peer");
                yield DiscoveredPeer { id: endpoint_id, trust: peer_trust };
            }
        }
    };
    let stream: Pin<Box<dyn Stream<Item = FeedResult<DiscoveredPeer>> + Send>> = Box::pin(stream);
    PeerFeedSpec {
        name: "mdns",
        priority,
        trust,
        scope: Scope::Service(scope_alpn),
        stream,
    }
}

// ---------------------------------------------------------------------------
// Backend.
// ---------------------------------------------------------------------------

/// mDNS-based local network peer discovery backend.
#[derive(Clone)]
pub struct MdnsBackend {
    mdns: Arc<MdnsAddressLookup>,
    priority: u8,
    trust: u8,
    ready: Option<tokio::sync::watch::Sender<bool>>,
}

impl MdnsBackend {
    /// Create an mDNS backend wrapping the given discovery instance.
    #[must_use]
    pub fn new(mdns: MdnsAddressLookup) -> Self {
        Self {
            mdns: Arc::new(mdns),
            priority: 50,
            trust: 200,
            ready: None,
        }
    }

    /// Create an mDNS backend from an `Arc`-shared discovery instance.
    #[must_use]
    pub fn with_arc(mdns: Arc<MdnsAddressLookup>) -> Self {
        Self {
            mdns,
            priority: 50,
            trust: 200,
            ready: None,
        }
    }

    /// Notify when the first discovery feed has subscribed to mDNS events.
    #[must_use]
    pub fn notify_subscribed(mut self, ready: tokio::sync::watch::Sender<bool>) -> Self {
        self.ready = Some(ready);
        self
    }

    /// Set the feed priority (lower = polled first). Default: 50.
    #[must_use]
    pub fn priority(mut self, p: u8) -> Self {
        self.priority = p;
        self
    }

    /// Set the source trust level (0-255). Default: 200.
    #[must_use]
    pub fn trust(mut self, t: u8) -> Self {
        self.trust = t;
        self
    }
}

impl Discovery for MdnsBackend {
    fn name(&self) -> &'static str {
        "mdns"
    }

    fn feeds(&self, alpn: &[u8]) -> Vec<PeerFeedSpec> {
        vec![mdns_feed(
            Arc::clone(&self.mdns),
            alpn.to_vec(),
            self.priority,
            self.trust,
            self.ready.clone(),
        )]
    }
}

// ---------------------------------------------------------------------------
// User-data encoding — public helper so node servers can publish ALPNs.
// ---------------------------------------------------------------------------

/// Encode service ALPNs into the base64-postcard form that the mDNS feed
/// expects in `EndpointData::user_data`. Returns `None` if the encoded form
/// would exceed iroh's user-data length limit (the caller must shorten the
/// ALPN list or omit publishing).
#[must_use]
pub fn encode_alpns(alpns: &[Vec<u8>]) -> Option<String> {
    let bytes = postcard::to_allocvec(alpns).ok()?;
    Some(BASE64URL_NOPAD.encode(&bytes))
}

// ---------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn readiness_requires_polling_the_lazy_subscription_not_a_discovered_peer() {
        use futures::FutureExt as _;
        let (registered, registration) = tokio::sync::oneshot::channel();
        let (ready, subscribed) = tokio::sync::watch::channel(false);
        let subscription = subscribe_ready(
            async move {
                registration.await.unwrap();
                futures::stream::pending::<DiscoveryEvent>()
            },
            Some(ready),
        );
        futures::pin_mut!(subscription);
        assert!(!*subscribed.borrow());
        assert!(subscription.as_mut().now_or_never().is_none());
        assert!(!*subscribed.borrow(), "subscription is still registering");
        registered.send(()).unwrap();
        let mut feed = subscription.now_or_never().expect("subscription completed");
        assert!(*subscribed.borrow());
        assert!(
            feed.next().now_or_never().is_none(),
            "no peer was discovered"
        );
    }

    #[test]
    fn classify_user_data_alpn_distinguishes_missing_match_and_mismatch() {
        let encoded = encode_alpns(&[b"/svc.A/2.0".to_vec(), b"/svc.B/2.0".to_vec()])
            .expect("valid user-data");

        assert_eq!(
            classify_user_data_alpn(Some(&encoded), b"/svc.A/2.0"),
            UserDataAlpnMatch::Match
        );
        assert_eq!(
            classify_user_data_alpn(Some(&encoded), b"/svc.C/2.0"),
            UserDataAlpnMatch::Mismatch
        );
        assert_eq!(
            classify_user_data_alpn(None, b"/svc.A/2.0"),
            UserDataAlpnMatch::Missing
        );
    }

    #[test]
    fn encode_decode_round_trips_alpns() {
        let encoded = encode_alpns(&[b"/svc.a/2.0".to_vec(), b"/svc.b/2.0".to_vec()])
            .expect("encoding should succeed");
        let decoded = decode_alpns(&encoded);
        assert_eq!(
            decoded,
            vec![b"/svc.a/2.0".to_vec(), b"/svc.b/2.0".to_vec()]
        );
    }

    #[test]
    fn malformed_user_data_decodes_to_empty_set() {
        assert!(decode_alpns("%%%not-base64%%%").is_empty());
    }
}
