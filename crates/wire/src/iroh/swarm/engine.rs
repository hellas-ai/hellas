//! Swarm engine: merges peer feeds with priority and deduplication.

use std::pin::Pin;
use std::task::{Context, Poll};

use crate::peers::{DiscoverySource, PeerEvent, PeerId, PeerRegistry, TransportSecurity};
use ::iroh::EndpointId;
use futures::stream::{SelectAll, Stream};
use web_time::Instant;

use super::discovery::Peer;
use super::peers::{FeedError, FeedResult, PeerFeed, PeerFeedSpec, scope_matches};

/// A tagged feed: wraps a `PeerFeed` to attach source metadata to each item.
struct TaggedFeed {
    name: &'static str,
    trust: u8,
    inner: PeerFeed,
}

impl Stream for TaggedFeed {
    type Item = FeedResult<Peer>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_next(cx) {
            Poll::Ready(Some(Ok(discovered))) => {
                let peer = Peer::new(&discovered, this.name, this.trust);
                Poll::Ready(Some(Ok(peer)))
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(e))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
type TaggedPeerFeed = Pin<Box<dyn Stream<Item = FeedResult<Peer>> + Send>>;

#[cfg(target_arch = "wasm32")]
type TaggedPeerFeed = Pin<Box<dyn Stream<Item = FeedResult<Peer>>>>;

/// Merges multiple peer feeds into a single deduped stream.
pub struct SwarmEngine {
    inner: SelectAll<TaggedPeerFeed>,
    seen: PeerRegistry,
    started: Instant,
    local_id: EndpointId,
}

impl SwarmEngine {
    /// Build an engine for a specific ALPN using the provided feed specs.
    ///
    /// Feeds whose scope doesn't match `alpn` are dropped; the rest are
    /// sorted by priority (ascending = polled first) and merged with
    /// per-peer dedup that also skips the local endpoint. Deduplication
    /// lasts only while the bounded peer registry retains the identity.
    #[must_use]
    pub fn new(local_id: EndpointId, alpn: &[u8], mut feeds: Vec<PeerFeedSpec>) -> Self {
        let mut inner = SelectAll::new();
        feeds.sort_by_key(|f| f.priority);
        for spec in feeds {
            if !scope_matches(&spec.scope, alpn) {
                continue;
            }
            let tagged: TaggedPeerFeed = Box::pin(TaggedFeed {
                name: spec.name,
                trust: spec.trust,
                inner: spec.stream,
            });
            inner.push(tagged);
        }
        Self {
            inner,
            seen: PeerRegistry::default(),
            started: Instant::now(),
            local_id,
        }
    }
}

impl Stream for SwarmEngine {
    type Item = Result<Peer, FeedError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        loop {
            match Pin::new(&mut this.inner).poll_next(cx) {
                Poll::Ready(Some(res)) => match res {
                    Ok(peer) => {
                        if peer.id() == this.local_id {
                            continue;
                        }
                        let change = this.seen.apply(
                            u64::try_from(this.started.elapsed().as_millis()).unwrap_or(u64::MAX),
                            PeerId::from(*peer.id().as_bytes()),
                            PeerEvent::Discovered {
                                source: DiscoverySource::Transport("discovery"),
                                transport_security: TransportSecurity::Untrusted,
                            },
                        );
                        if change.inserted && !change.dropped {
                            return Poll::Ready(Some(Ok(peer)));
                        }
                    }
                    Err(e) => return Poll::Ready(Some(Err(e))),
                },
                Poll::Ready(None) => return Poll::Ready(None),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use ::iroh::{EndpointId, SecretKey};
    use futures::stream::StreamExt;

    use super::super::peers::{Scope, static_feed};
    use super::SwarmEngine;

    fn endpoint_id(byte: u8) -> EndpointId {
        SecretKey::from([byte; 32]).public()
    }

    #[tokio::test]
    async fn discovery_retention_is_bounded_across_identity_churn() {
        let bound = crate::peers::PeerRegistryConfig::default().max_peers;
        let peers = (0..bound + 16)
            .map(|number| {
                let mut secret = [0; 32];
                secret[..8].copy_from_slice(&u64::try_from(number).unwrap().to_le_bytes());
                SecretKey::from(secret).public()
            })
            .collect();
        let mut engine = SwarmEngine::new(
            endpoint_id(255),
            b"/svc.Test/2.0",
            vec![static_feed(peers, 0, 0, Scope::Any)],
        );
        let mut emitted = 0;
        while let Some(peer) = engine.next().await {
            peer.expect("valid discovery");
            emitted += 1;
            assert!(
                engine.seen.len() <= bound,
                "discovery retained too many identities"
            );
        }
        assert_eq!(
            emitted,
            bound + 16,
            "new identities still flow after eviction"
        );
    }

    #[tokio::test]
    async fn skips_local_peer_and_dedupes() {
        let local = endpoint_id(1);
        let remote = endpoint_id(2);

        let feeds = vec![
            static_feed(vec![local, remote], 10, 100, Scope::Any),
            static_feed(vec![remote], 20, 100, Scope::Any),
        ];
        let mut engine = SwarmEngine::new(local, b"/svc.Test/2.0", feeds);

        let first = engine
            .next()
            .await
            .expect("one remote peer expected")
            .expect("peer should be ok");
        assert_eq!(first.id(), remote);

        assert!(
            engine.next().await.is_none(),
            "duplicate peer should be deduped"
        );
    }
}
