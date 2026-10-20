//! DHT-based peer discovery backend.
//!
//! Threat model:
//! - DHT service advertisements are signed by the advertising iroh endpoint
//!   identity, so a peer cannot forge another endpoint's ad.
//! - The shared shard buckets themselves remain globally writable rendezvous
//!   points. Attackers can still spam or overwrite shard contents.
//! - This backend is intended for bootstrap only. Once an honest peer is
//!   found, direct iroh communication becomes the trusted path.
//!
//! The bucket publisher, resolver, record validation, and tests live together
//! because they share the same signed-advertisement invariants.

use std::cmp::Reverse;
use std::collections::{BTreeMap, btree_map::Entry};
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ::iroh::{Endpoint, EndpointId, SecretKey, Signature};
use futures::stream::{Stream, StreamExt};
use mainline::{Dht, MutableItem, errors::PutMutableError};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::broadcast;
use tokio_stream::wrappers::IntervalStream;
use tracing::{debug, info, trace, warn};

use super::discovery::{DiscoveredPeer, Discovery};
use super::peers::{FeedError, FeedResult, PeerFeedSpec, Scope};

// ---------------------------------------------------------------------------
// Constants — namespace + bucket sizing for DHT shard records.
// ---------------------------------------------------------------------------

const DHT_SHARD_COUNT: u8 = 16;
const DHT_REPLICA_COUNT: usize = 2;
const DHT_PUBLISH_RETRIES: usize = 4;
const DHT_AD_TTL_SECS: u64 = 120;
const DHT_QUERY_CONCURRENCY: usize = 4;

pub(crate) const DHT_BUCKET_VERSION: u8 = 2;
pub(crate) const DHT_MAX_BUCKET_BYTES: usize = 1000;
const MAX_FUTURE_SKEW_SECS: u64 = 300;

// ---------------------------------------------------------------------------
// Key/salt derivation helpers — deterministic from (alpn, minute, shard).
// ---------------------------------------------------------------------------

/// Derive the shared shard signing key from service ALPN, unix minute, and
/// shard index.
fn derive_signing_key(alpn: &[u8], unix_minute: u64, shard: u8) -> mainline::SigningKey {
    let mut hasher = Sha256::new();
    hasher.update(b"hellas-wire:dht:key:v2:");
    hasher.update(alpn);
    hasher.update(unix_minute.to_le_bytes());
    hasher.update([shard]);
    let hash = hasher.finalize();
    mainline::SigningKey::from_bytes(&hash.into())
}

/// Derive salt for a service shard bucket.
fn derive_salt(alpn: &[u8], unix_minute: u64, shard: u8) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(b"hellas-wire:dht:salt:v2:");
    hasher.update(alpn);
    hasher.update(unix_minute.to_le_bytes());
    hasher.update([shard]);
    hasher.finalize().to_vec()
}

/// Deterministically choose the shards this endpoint should publish into for
/// a service.
fn replica_shards(node_id: &[u8; 32], alpn: &[u8]) -> Vec<u8> {
    replica_shards_with_limits(node_id, alpn, DHT_SHARD_COUNT, DHT_REPLICA_COUNT)
}

fn replica_shards_with_limits(
    node_id: &[u8; 32],
    alpn: &[u8],
    shard_count: u8,
    replica_count: usize,
) -> Vec<u8> {
    let replica_count = replica_count.min(shard_count as usize);
    let mut ranked_shards = (0..shard_count)
        .map(|shard| {
            let mut hasher = Sha256::new();
            hasher.update(b"hellas-wire:dht:shards:v3:");
            hasher.update(node_id);
            hasher.update(alpn);
            hasher.update([shard]);
            (hasher.finalize(), shard)
        })
        .collect::<Vec<_>>();

    ranked_shards.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));
    ranked_shards
        .into_iter()
        .take(replica_count)
        .map(|(_, shard)| shard)
        .collect()
}

/// Get current unix minute with optional offset.
///
/// Times before the Unix epoch use its first minute.
fn unix_minute(offset: i64) -> u64 {
    let now = unix_timestamp_secs().unwrap_or_default();
    apply_minute_offset(now / 60, offset)
}

fn apply_minute_offset(minute: u64, offset: i64) -> u64 {
    if offset >= 0 {
        minute.saturating_add(offset.unsigned_abs())
    } else {
        minute.saturating_sub(offset.unsigned_abs())
    }
}

fn unix_timestamp_secs() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|e| format!("system clock before unix epoch: {e}"))
}

// ---------------------------------------------------------------------------
// Record types — signed service ads inside shard buckets.
// ---------------------------------------------------------------------------

/// A single signed service advertisement stored inside a DHT shard bucket.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedServiceAd {
    ad: ServiceAd,
    signature: Signature,
}

/// The unsigned service advertisement payload.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct ServiceAd {
    /// The advertising iroh endpoint id bytes.
    node_id: [u8; 32],
    /// Optional coarse tags for filtering.
    tags: Vec<String>,
    /// Unix timestamp when published.
    published_at: u64,
    /// Unix timestamp after which the ad should be discarded.
    expires_at: u64,
}

/// A bounded, shared mutable bucket of signed service advertisements.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct ServiceBucket {
    /// Bucket format version.
    version: u8,
    /// Signed ads currently held in this shard.
    ads: Vec<SignedServiceAd>,
}

#[derive(Debug, Serialize)]
struct ServiceAdEnvelope<'a> {
    version: u8,
    alpn: &'a [u8],
    minute: u64,
    shard: u8,
    node_id: [u8; 32],
    tags: &'a [String],
    published_at: u64,
    expires_at: u64,
}

impl SignedServiceAd {
    /// Create and sign a service advertisement for a specific shard bucket.
    fn sign(
        secret_key: &SecretKey,
        alpn: &[u8],
        minute: u64,
        shard: u8,
        tags: &[String],
        published_at: u64,
        expires_at: u64,
    ) -> postcard::Result<Self> {
        let ad = ServiceAd {
            node_id: *secret_key.public().as_bytes(),
            tags: tags.to_vec(),
            published_at,
            expires_at,
        };
        let message = signing_message(alpn, minute, shard, &ad)?;
        Ok(Self {
            signature: secret_key.sign(&message),
            ad,
        })
    }

    /// Return the advertised endpoint id if the bytes decode to a valid iroh id.
    fn endpoint_id(&self) -> Option<EndpointId> {
        EndpointId::from_bytes(&self.ad.node_id).ok()
    }

    /// Return the advertised endpoint id bytes.
    fn node_id(&self) -> [u8; 32] {
        self.ad.node_id
    }

    /// Check whether the ad contains all required tags.
    fn has_tags(&self, required_tags: &[String]) -> bool {
        required_tags.iter().all(|tag| self.ad.tags.contains(tag))
    }

    fn published_at(&self) -> u64 {
        self.ad.published_at
    }

    fn expires_at(&self) -> u64 {
        self.ad.expires_at
    }

    /// Validate the ad against the bucket namespace and current time.
    fn verify(&self, alpn: &[u8], minute: u64, shard: u8, now: u64) -> bool {
        if self.ad.expires_at <= now
            || self.ad.published_at > self.ad.expires_at
            || self.ad.published_at > now.saturating_add(MAX_FUTURE_SKEW_SECS)
        {
            return false;
        }

        let Some(endpoint_id) = self.endpoint_id() else {
            return false;
        };

        match signing_message(alpn, minute, shard, &self.ad) {
            Ok(message) => endpoint_id.verify(&message, &self.signature).is_ok(),
            Err(_) => false,
        }
    }
}

impl ServiceBucket {
    fn new(ads: Vec<SignedServiceAd>) -> Self {
        Self {
            version: DHT_BUCKET_VERSION,
            ads,
        }
    }

    fn merge_valid(
        buckets: impl IntoIterator<Item = ServiceBucket>,
        alpn: &[u8],
        minute: u64,
        shard: u8,
        now: u64,
    ) -> Vec<SignedServiceAd> {
        let mut merged = BTreeMap::<[u8; 32], SignedServiceAd>::new();

        for bucket in buckets {
            if bucket.version != DHT_BUCKET_VERSION {
                continue;
            }

            for ad in bucket.ads {
                if !ad.verify(alpn, minute, shard, now) {
                    continue;
                }

                match merged.entry(ad.node_id()) {
                    Entry::Vacant(entry) => {
                        entry.insert(ad);
                    }
                    Entry::Occupied(mut entry) if ad_precedes(&ad, entry.get()) => {
                        entry.insert(ad);
                    }
                    Entry::Occupied(_) => {}
                }
            }
        }

        let mut ads: Vec<_> = merged.into_values().collect();
        ads.sort_by_key(ad_sort_key);
        ads
    }

    fn upsert(&mut self, ad: SignedServiceAd) {
        if let Some(existing) = self
            .ads
            .iter_mut()
            .find(|existing| existing.node_id() == ad.node_id())
        {
            if ad_precedes(&ad, existing) {
                *existing = ad;
            }
            return;
        }
        self.ads.push(ad);
    }

    fn trim_to_size(&mut self, preferred_node: Option<[u8; 32]>) -> postcard::Result<bool> {
        self.ads
            .sort_by_key(|ad| preferred_ad_sort_key(ad, preferred_node));

        loop {
            if self.encoded_len()? <= DHT_MAX_BUCKET_BYTES {
                return Ok(true);
            }

            let removal_idx = self
                .ads
                .iter()
                .rposition(|ad| Some(ad.node_id()) != preferred_node);

            match removal_idx {
                Some(idx) => {
                    self.ads.remove(idx);
                }
                None => break,
            }
        }

        Ok(self.encoded_len()? <= DHT_MAX_BUCKET_BYTES)
    }

    fn encoded_len(&self) -> postcard::Result<usize> {
        postcard::to_allocvec(self).map(|bytes| bytes.len())
    }
}

fn signing_message(
    alpn: &[u8],
    minute: u64,
    shard: u8,
    ad: &ServiceAd,
) -> postcard::Result<Vec<u8>> {
    postcard::to_allocvec(&ServiceAdEnvelope {
        version: DHT_BUCKET_VERSION,
        alpn,
        minute,
        shard,
        node_id: ad.node_id,
        tags: &ad.tags,
        published_at: ad.published_at,
        expires_at: ad.expires_at,
    })
}

fn ad_precedes(candidate: &SignedServiceAd, existing: &SignedServiceAd) -> bool {
    ad_sort_key(candidate) < ad_sort_key(existing)
}

fn ad_sort_key(ad: &SignedServiceAd) -> (Reverse<u64>, Reverse<u64>, [u8; 32]) {
    (
        Reverse(ad.published_at()),
        Reverse(ad.expires_at()),
        ad.node_id(),
    )
}

fn preferred_ad_sort_key(
    ad: &SignedServiceAd,
    preferred_node: Option<[u8; 32]>,
) -> (bool, Reverse<u64>, Reverse<u64>, [u8; 32]) {
    let deprioritized = matches!(preferred_node, Some(node_id) if ad.node_id() != node_id);
    (
        deprioritized,
        Reverse(ad.published_at()),
        Reverse(ad.expires_at()),
        ad.node_id(),
    )
}

// ---------------------------------------------------------------------------
// Resolver — client-side DHT shard query.
// ---------------------------------------------------------------------------

/// Resolver for querying service records from mainline DHT.
#[derive(Clone)]
struct DhtResolver {
    dht: Arc<Dht>,
}

impl DhtResolver {
    fn new(dht: Arc<Dht>) -> Self {
        Self { dht }
    }

    /// Query a specific shard bucket for a service ALPN and minute.
    async fn query_shard(
        &self,
        alpn: &[u8],
        minute: u64,
        shard: u8,
    ) -> Result<Vec<SignedServiceAd>, FeedError> {
        let signing_key = derive_signing_key(alpn, minute, shard);
        let public_key = signing_key.verifying_key();
        let pk_bytes = *public_key.as_bytes();
        let salt = derive_salt(alpn, minute, shard);
        let alpn_owned = alpn.to_vec();

        trace!(
            alpn = %String::from_utf8_lossy(&alpn_owned),
            minute,
            shard,
            "Querying DHT shard"
        );

        // Use mainline's async stream directly so dropping discovery cancels
        // in-flight shard queries instead of waiting for spawn_blocking work
        // to finish.
        let dht = self.dht.as_ref().clone().as_async();
        let mut stream = dht.get_mutable(&pk_bytes, Some(salt.as_slice()), None);
        let mut result = Vec::new();
        while let Some(item) = stream.next().await {
            result.push(item);
        }

        let now = unix_timestamp_secs().unwrap_or_default();

        let buckets = result
            .into_iter()
            .filter_map(
                |item| match postcard::from_bytes::<ServiceBucket>(item.value()) {
                    Ok(bucket) => Some(bucket),
                    Err(e) => {
                        warn!(
                            alpn = %String::from_utf8_lossy(&alpn_owned),
                            minute,
                            shard,
                            error = %e,
                            "Failed to deserialize DHT shard bucket"
                        );
                        None
                    }
                },
            )
            .collect::<Vec<_>>();

        let ads = ServiceBucket::merge_valid(buckets, &alpn_owned, minute, shard, now);
        debug!(
            alpn = %String::from_utf8_lossy(&alpn_owned),
            minute,
            shard,
            ads = ads.len(),
            "Resolved DHT shard"
        );
        Ok(ads)
    }
}

// ---------------------------------------------------------------------------
// Publisher — server-side DHT shard upsert loop.
// ---------------------------------------------------------------------------

/// Configuration for DHT publishing.
#[derive(Debug, Clone)]
pub struct DhtPublisherConfig {
    /// Tags to include in published records (e.g., region/tier).
    pub tags: Vec<String>,
    /// How often to republish records.
    pub publish_interval: Duration,
}

impl Default for DhtPublisherConfig {
    fn default() -> Self {
        Self {
            tags: Vec::new(),
            publish_interval: Duration::from_secs(30),
        }
    }
}

/// Publishes service records to the DHT on a fixed interval.
pub struct DhtPublisher {
    dht: Arc<Dht>,
    secret_key: SecretKey,
    services: Vec<Vec<u8>>,
    config: DhtPublisherConfig,
}

impl DhtPublisher {
    /// Create a publisher for a given DHT client and endpoint identity.
    #[must_use]
    pub fn new(dht: Arc<Dht>, secret_key: SecretKey, config: DhtPublisherConfig) -> Self {
        Self {
            dht,
            secret_key,
            services: Vec::new(),
            config,
        }
    }

    /// Register a service ALPN to publish.
    pub fn add_service(&mut self, alpn: Vec<u8>) {
        self.services.push(alpn);
    }

    /// Run the background publishing loop until shutdown is signalled.
    pub async fn run(self, mut shutdown_rx: broadcast::Receiver<()>) {
        let Self {
            dht,
            secret_key,
            services,
            config,
        } = self;

        info!(services = services.len(), "Starting DHT publisher");
        publish_all(&dht, &services, &secret_key, &config.tags).await;

        let mut interval = tokio::time::interval(config.publish_interval);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let _ = interval.tick().await;

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    publish_all(&dht, &services, &secret_key, &config.tags).await;
                }
                _ = shutdown_rx.recv() => {
                    info!("DHT publisher shutting down");
                    break;
                }
            }
        }
    }
}

async fn publish_all(
    dht: &Arc<Dht>,
    services: &[Vec<u8>],
    secret_key: &SecretKey,
    tags: &[String],
) {
    let node_id = secret_key.public();
    for alpn in services {
        let alpn_display = String::from_utf8_lossy(alpn).to_string();

        for shard in replica_shards(node_id.as_bytes(), alpn) {
            match publish_shard(dht, secret_key, alpn, shard, tags).await {
                Ok(()) => debug!(alpn = %alpn_display, shard, "Published DHT shard"),
                Err(e) => {
                    warn!(alpn = %alpn_display, shard, error = %e, "Failed to publish DHT shard");
                }
            }
        }
    }
}

async fn publish_shard(
    dht: &Arc<Dht>,
    secret_key: &SecretKey,
    alpn: &[u8],
    shard: u8,
    tags: &[String],
) -> Result<(), String> {
    let published_at = unix_timestamp_secs()?;
    let minute = published_at / 60;
    let expires_at = published_at.saturating_add(DHT_AD_TTL_SECS);
    let local_ad = SignedServiceAd::sign(
        secret_key,
        alpn,
        minute,
        shard,
        tags,
        published_at,
        expires_at,
    )
    .map_err(|e| format!("sign service ad: {e}"))?;
    let preferred_node = local_ad.node_id();

    for attempt in 0..DHT_PUBLISH_RETRIES {
        let (ads, latest_seq) = read_shard_state(dht, alpn, minute, shard, published_at).await;
        let mut bucket = ServiceBucket::new(ads);
        bucket.upsert(local_ad.clone());

        let fits = bucket
            .trim_to_size(Some(preferred_node))
            .map_err(|e| format!("serialize service bucket: {e}"))?;
        if !fits {
            return Err("local service advertisement exceeds shard bucket size".to_string());
        }

        let value = postcard::to_allocvec(&bucket)
            .map_err(|e| format!("serialize trimmed service bucket: {e}"))?;
        let signing_key = derive_signing_key(alpn, minute, shard);
        let salt = derive_salt(alpn, minute, shard);
        let item = MutableItem::new(
            signing_key,
            &value,
            latest_seq.map_or(1, |seq| seq + 1),
            Some(&salt),
        );

        let dht = dht.as_ref().clone().as_async();
        let put_result = dht.put_mutable(item, latest_seq).await;

        match put_result {
            Ok(_) => return Ok(()),
            Err(PutMutableError::Concurrency(err)) => {
                debug!(attempt, shard, error = %err, "Retrying DHT shard publish after contention");
            }
            Err(PutMutableError::Query(err)) => {
                return Err(format!("put mutable shard: {err}"));
            }
        }
    }

    Err("DHT shard remained contended after retries".to_string())
}

async fn read_shard_state(
    dht: &Arc<Dht>,
    alpn: &[u8],
    minute: u64,
    shard: u8,
    now: u64,
) -> (Vec<SignedServiceAd>, Option<i64>) {
    let signing_key = derive_signing_key(alpn, minute, shard);
    let public_key = *signing_key.verifying_key().as_bytes();
    let salt = derive_salt(alpn, minute, shard);
    let dht = dht.as_ref().clone().as_async();
    let alpn_display = String::from_utf8_lossy(alpn).to_string();

    let items = dht
        .get_mutable(&public_key, Some(salt.as_slice()), None)
        .collect::<Vec<_>>()
        .await;

    let latest_seq = items.iter().map(mainline::MutableItem::seq).max();
    let buckets = items
        .into_iter()
        .filter_map(|item| match postcard::from_bytes::<ServiceBucket>(item.value()) {
            Ok(bucket) => Some(bucket),
            Err(e) => {
                warn!(alpn = %alpn_display, shard, error = %e, "Failed to decode DHT shard bucket");
                None
            }
        })
        .collect::<Vec<_>>();

    (
        ServiceBucket::merge_valid(buckets, alpn, minute, shard, now),
        latest_seq,
    )
}

// ---------------------------------------------------------------------------
// Feed builder — initial burst over previous+current minute, then poll.
// ---------------------------------------------------------------------------

/// Build a DHT feed (initial burst + periodic poll) for a service ALPN.
#[must_use]
fn dht_feed(
    dht: Arc<Dht>,
    alpn: Vec<u8>,
    poll_interval: Duration,
    required_tags: &[String],
    priority: u8,
    trust: u8,
) -> PeerFeedSpec {
    let resolver = DhtResolver::new(dht);
    let burst_alpn = alpn.clone();
    let burst_resolver = resolver.clone();
    let required = required_tags.to_vec();
    let peer_trust = trust;

    let burst = async_stream::try_stream! {
        for offset in [0i64, -1] {
            let minute = unix_minute(offset);
            let queries = futures::stream::iter(0..DHT_SHARD_COUNT)
                .map({
                    let resolver = burst_resolver.clone();
                    let alpn = burst_alpn.clone();
                    move |shard| {
                        let resolver = resolver.clone();
                        let alpn = alpn.clone();
                        async move { resolver.query_shard(&alpn, minute, shard).await }
                    }
                })
                .buffer_unordered(DHT_QUERY_CONCURRENCY);

            futures::pin_mut!(queries);
            while let Some(ads) = queries.next().await {
                let ads = ads?;
                for ad in ads {
                    if !required.is_empty() && !ad.has_tags(&required) {
                        trace!("Skipping DHT record (tags mismatch)");
                        continue;
                    }
                    let Some(id) = ad.endpoint_id() else {
                        continue;
                    };
                    debug!(%id, source = "dht", "discovered peer");
                    yield DiscoveredPeer { id, trust: peer_trust };
                }
            }
        }
    };

    let poll_alpn = alpn.clone();
    let poll_resolver = resolver.clone();
    let required_poll = required_tags.to_vec();
    let mut interval = IntervalStream::new(tokio::time::interval(poll_interval));
    let dht_stream = async_stream::try_stream! {
        // skip first tick, burst already queried
        let _ = interval.next().await;
        while interval.next().await.is_some() {
            let minute = unix_minute(0);
            let queries = futures::stream::iter(0..DHT_SHARD_COUNT)
                .map({
                    let resolver = poll_resolver.clone();
                    let alpn = poll_alpn.clone();
                    move |shard| {
                        let resolver = resolver.clone();
                        let alpn = alpn.clone();
                        async move { resolver.query_shard(&alpn, minute, shard).await }
                    }
                })
                .buffer_unordered(DHT_QUERY_CONCURRENCY);

            futures::pin_mut!(queries);
            while let Some(ads) = queries.next().await {
                let ads = ads?;
                for ad in ads {
                    if !required_poll.is_empty() && !ad.has_tags(&required_poll) {
                        continue;
                    }
                    if let Some(id) = ad.endpoint_id() {
                        yield DiscoveredPeer { id, trust: peer_trust };
                    }
                }
            }
        }
    };

    let combined: Pin<Box<dyn Stream<Item = FeedResult<DiscoveredPeer>> + Send>> = Box::pin(
        burst
            .chain(dht_stream)
            .map(|r: Result<DiscoveredPeer, FeedError>| r),
    );
    let scope = Scope::Service(alpn);
    PeerFeedSpec {
        name: "dht",
        priority,
        trust,
        scope,
        stream: combined,
    }
}

// ---------------------------------------------------------------------------
// Backend — public surface plugged into `ServiceRegistry`.
// ---------------------------------------------------------------------------

/// DHT-based peer discovery backend.
#[derive(Clone)]
pub struct DhtBackend {
    endpoint: Endpoint,
    dht: Arc<Dht>,
    priority: u8,
    trust: u8,
    poll_interval: Duration,
    required_tags: Vec<String>,
}

impl DhtBackend {
    /// Create a new DHT backend, starting a fresh DHT client.
    ///
    /// # Errors
    ///
    /// Returns an error if the DHT client fails to bind.
    pub fn new(endpoint: &Endpoint) -> std::io::Result<Self> {
        let dht =
            Arc::new(Dht::client().map_err(|e| std::io::Error::other(format!("DHT client: {e}")))?);
        Ok(Self {
            endpoint: endpoint.clone(),
            dht,
            priority: 100,
            trust: 50,
            poll_interval: Duration::from_secs(60),
            required_tags: Vec::new(),
        })
    }

    /// Create a DHT backend reusing an existing DHT client.
    #[must_use]
    pub fn with_dht(endpoint: &Endpoint, dht: Arc<Dht>) -> Self {
        Self {
            endpoint: endpoint.clone(),
            dht,
            priority: 100,
            trust: 50,
            poll_interval: Duration::from_secs(60),
            required_tags: Vec::new(),
        }
    }

    /// Set the feed priority (lower = polled first). Default: 100.
    #[must_use]
    pub fn priority(mut self, p: u8) -> Self {
        self.priority = p;
        self
    }

    /// Set the source trust level (0-255). Default: 50.
    #[must_use]
    pub fn trust(mut self, t: u8) -> Self {
        self.trust = t;
        self
    }

    /// Set the DHT poll interval. Default: 60s.
    #[must_use]
    pub fn poll_interval(mut self, d: Duration) -> Self {
        self.poll_interval = d;
        self
    }

    /// Set required tags for filtering DHT records.
    #[must_use]
    pub fn required_tags(mut self, tags: Vec<String>) -> Self {
        self.required_tags = tags;
        self
    }

    /// Access the underlying DHT client.
    #[must_use]
    pub fn dht(&self) -> &Arc<Dht> {
        &self.dht
    }

    /// Create a DHT publisher for server-side announcements.
    #[must_use]
    pub fn create_publisher(&self, config: DhtPublisherConfig) -> DhtPublisher {
        DhtPublisher::new(
            Arc::clone(&self.dht),
            self.endpoint.secret_key().clone(),
            config,
        )
    }
}

impl Discovery for DhtBackend {
    fn name(&self) -> &'static str {
        "dht"
    }

    fn feeds(&self, alpn: &[u8]) -> Vec<PeerFeedSpec> {
        vec![dht_feed(
            Arc::clone(&self.dht),
            alpn.to_vec(),
            self.poll_interval,
            &self.required_tags,
            self.priority,
            self.trust,
        )]
    }
}

// ---------------------------------------------------------------------------
// Tests — ported from tonic-iroh-transport's dht::tests and record::tests.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ::iroh::SecretKey;

    #[test]
    fn signing_key_derivation_is_deterministic() {
        let alpn = b"/test.Service/2.0";
        let minute = 12345u64;

        let key1 = derive_signing_key(alpn, minute, 3);
        let key2 = derive_signing_key(alpn, minute, 3);
        assert_eq!(key1.to_bytes(), key2.to_bytes());
    }

    #[test]
    fn signing_key_changes_with_minute() {
        let alpn = b"/test.Service/2.0";
        let key1 = derive_signing_key(alpn, 12345, 3);
        let key2 = derive_signing_key(alpn, 12346, 3);
        assert_ne!(key1.to_bytes(), key2.to_bytes());
    }

    #[test]
    fn salt_derivation_is_deterministic() {
        let alpn = b"/test.Service/2.0";
        let minute = 12345u64;

        let salt1 = derive_salt(alpn, minute, 3);
        let salt2 = derive_salt(alpn, minute, 3);
        assert_eq!(salt1, salt2);
        assert_eq!(salt1.len(), 32);
    }

    #[test]
    fn shard_selection_is_stable_and_distinct() {
        let node_id = [42u8; 32];
        let shards = replica_shards(&node_id, b"/test.Service/2.0");

        assert_eq!(shards.len(), DHT_REPLICA_COUNT);
        assert_eq!(shards, replica_shards(&node_id, b"/test.Service/2.0"));
        assert_ne!(shards[0], shards[1]);
        assert!(shards.iter().all(|shard| *shard < DHT_SHARD_COUNT));
    }

    #[test]
    fn unix_minute_applies_offset() {
        let current = unix_minute(0);
        let previous = unix_minute(-1);
        let next = unix_minute(1);
        assert_eq!(previous + 1, current);
        assert_eq!(current + 1, next);
    }

    #[test]
    fn negative_minute_offset_saturates_at_zero() {
        assert_eq!(apply_minute_offset(0, -1), 0);
        assert_eq!(apply_minute_offset(0, i64::MIN), 0);
        assert_eq!(apply_minute_offset(3, -10), 0);
    }

    #[test]
    fn signed_ad_round_trips() {
        let key = SecretKey::from_bytes(&[7u8; 32]);
        let ad = SignedServiceAd::sign(
            &key,
            b"/svc.Test/2.0",
            123,
            4,
            &["prod".to_string()],
            1_000,
            1_120,
        )
        .expect("ad should serialize");

        assert!(ad.verify(b"/svc.Test/2.0", 123, 4, 1_060));
        assert!(!ad.verify(b"/svc.Test/2.0", 123, 5, 1_060));
        assert!(!ad.verify(b"/svc.Other/2.0", 123, 4, 1_060));
    }

    #[test]
    fn merge_valid_dedupes_and_prefers_newer_ads() {
        let key = SecretKey::from_bytes(&[9u8; 32]);
        let newer = SignedServiceAd::sign(&key, b"/svc.Test/2.0", 55, 2, &[], 200, 320)
            .expect("newer ad should serialize");
        let older = SignedServiceAd::sign(
            &key,
            b"/svc.Test/2.0",
            55,
            2,
            &["old".to_string()],
            100,
            220,
        )
        .expect("older ad should serialize");

        let merged = ServiceBucket::merge_valid(
            [
                ServiceBucket::new(vec![older]),
                ServiceBucket::new(vec![newer.clone()]),
            ],
            b"/svc.Test/2.0",
            55,
            2,
            210,
        );

        assert_eq!(merged, vec![newer]);
    }
}
