#![allow(clippy::alloc_instead_of_core)]
#![allow(clippy::disallowed_types)]
#![allow(clippy::redundant_pub_crate)]
#![allow(clippy::std_instead_of_alloc)]
#![allow(clippy::std_instead_of_core)]
#![allow(dead_code)]

pub(crate) mod itf;
pub(crate) mod itf_l1_fees;
pub(crate) mod l1;
pub(crate) mod l1_fees;
pub(crate) mod map_store;

use hellas_kernel::{
    Auth, Batch, BlockHeight, CloseKind, Coin, CoinId, Edge, EdgeId, Funding, Genesis, InsertError,
    KernelResult, Key, List, MAX_EDGE_OUTPUTS, NetworkId, Parties, PartyAuth, PayloadHash, Payout,
    Proof, RegistryChunk, RegistryChunkId, RegistryNamespace, Sig, SigVerifier, Snapshot, State,
    Store, Terms, TermsHash, Tx, View,
};

/// The network every fixture in this crate's tests is bound to.
///
/// One definition on purpose: authorizations built by these helpers are
/// checked against contexts built by these helpers, so a second network
/// id anywhere would break that pairing silently rather than loudly.
pub(crate) const NETWORK: NetworkId = match NetworkId::new("hellas-kernel-test") {
    Some(network) => network,
    None => panic!("literal is a legal network id"),
};

/// Forgeable verifier used by every test in this crate. Accepts the
/// deterministic shapes produced by [`Sig::placeholder`] in place of
/// real cryptography. Production callers must wire verifiers backed by
/// real crypto or a preverified-cache lookup.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub(crate) struct FakeVerifier;

pub(crate) const FAKE_VERIFIER: FakeVerifier = FakeVerifier;

impl SigVerifier for FakeVerifier {
    fn verify_sig(&self, sig: Sig, party_key: Key, hash: hellas_kernel::PayloadHash) -> bool {
        sig == Sig::placeholder(party_key, hash)
    }
}

/// Production-shaped verifier stub: rejects every signature. Tests that
/// exercise "what happens without an accepting verifier" use this to
/// stand in for the unconfigured production case.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub(crate) struct RejectVerifier;

pub(crate) const REJECT_VERIFIER: RejectVerifier = RejectVerifier;

impl SigVerifier for RejectVerifier {
    fn verify_sig(&self, _sig: Sig, _party_key: Key, _hash: hellas_kernel::PayloadHash) -> bool {
        false
    }
}

#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
struct CoinSlot {
    id: CoinId,
    coin: Option<Coin>,
}

#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
struct EdgeSlot {
    id: EdgeId,
    edge: Option<Edge>,
}

/// A registry slot the store will accept writes to.
///
/// `FixedStore` pre-declares every slot, so a registry-aware test names
/// the chunk ids it intends to touch the same way it names coin and edge
/// ids. `R` defaults to zero so the many tests that touch no registry
/// state keep their two-parameter `FixedStore<C, E>` spelling.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
struct RegistrySlot {
    id: RegistryChunkId,
    chunk: Option<RegistryChunk>,
}

#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub(crate) struct FixedStore<const C: usize, const E: usize, const R: usize = 0> {
    coins: [CoinSlot; C],
    edges: [EdgeSlot; E],
    registry: [RegistrySlot; R],
}

impl<const C: usize, const E: usize, const R: usize> FixedStore<C, E, R> {
    pub(crate) const fn empty_with_registry(
        coins: [CoinId; C],
        edges: [EdgeId; E],
        registry: [RegistryChunkId; R],
    ) -> Self {
        let mut coin_slots = [CoinSlot::EMPTY; C];
        let mut edge_slots = [EdgeSlot::EMPTY; E];
        let mut registry_slots = [RegistrySlot::EMPTY; R];
        let mut index = 0;

        while index < C {
            coin_slots[index] = CoinSlot::empty(coins[index]);
            index += 1;
        }

        index = 0;
        while index < E {
            edge_slots[index] = EdgeSlot::empty(edges[index]);
            index += 1;
        }

        index = 0;
        while index < R {
            registry_slots[index] = RegistrySlot::empty(registry[index]);
            index += 1;
        }

        Self {
            coins: coin_slots,
            edges: edge_slots,
            registry: registry_slots,
        }
    }

    pub(crate) fn coin(&self, id: CoinId) -> Option<Coin> {
        self.find_coin(id).and_then(|index| self.coins[index].coin)
    }

    pub(crate) fn edge(&self, id: EdgeId) -> Option<Edge> {
        self.find_edge(id).and_then(|index| self.edges[index].edge)
    }

    pub(crate) fn registry_chunk(&self, id: RegistryChunkId) -> Option<RegistryChunk> {
        self.find_registry(id)
            .and_then(|index| self.registry[index].chunk)
    }

    fn find_coin(&self, id: CoinId) -> Option<usize> {
        self.coins.iter().position(|slot| slot.id == id)
    }

    fn find_edge(&self, id: EdgeId) -> Option<usize> {
        self.edges.iter().position(|slot| slot.id == id)
    }

    fn find_registry(&self, id: RegistryChunkId) -> Option<usize> {
        self.registry.iter().position(|slot| slot.id == id)
    }
}

impl<const C: usize, const E: usize> FixedStore<C, E> {
    pub(crate) const fn empty(coins: [CoinId; C], edges: [EdgeId; E]) -> Self {
        Self::empty_with_registry(coins, edges, [])
    }
}

impl<const C: usize, const E: usize, const R: usize> Store for FixedStore<C, E, R> {
    type Batch<'a>
        = FixedTx<'a, C, E, R>
    where
        Self: 'a;

    fn begin(&mut self) -> Self::Batch<'_> {
        FixedTx {
            working: *self,
            parent: self,
        }
    }
}

pub(crate) struct FixedTx<'a, const C: usize, const E: usize, const R: usize = 0> {
    working: FixedStore<C, E, R>,
    parent: &'a mut FixedStore<C, E, R>,
}

impl<const C: usize, const E: usize, const R: usize> Batch for FixedTx<'_, C, E, R> {
    fn coin(&self, id: CoinId) -> Option<Coin> {
        self.working.coin(id)
    }

    fn insert_coin(&mut self, id: CoinId, coin: Coin) -> KernelResult<(), InsertError> {
        let Some(index) = self.working.find_coin(id) else {
            return Err(InsertError::Unavailable);
        };
        if self.working.coins[index].coin.is_some() {
            return Err(InsertError::Exists);
        }
        self.working.coins[index].coin = Some(coin);
        Ok(())
    }

    fn remove_coin(&mut self, id: CoinId) -> Option<Coin> {
        let index = self.working.find_coin(id)?;
        self.working.coins[index].coin.take()
    }

    fn edge(&self, id: EdgeId) -> Option<Edge> {
        self.working.edge(id)
    }

    fn insert_edge(&mut self, id: EdgeId, edge: Edge) -> KernelResult<(), InsertError> {
        let Some(index) = self.working.find_edge(id) else {
            return Err(InsertError::Unavailable);
        };
        if self.working.edges[index].edge.is_some() {
            return Err(InsertError::Exists);
        }
        self.working.edges[index].edge = Some(edge);
        Ok(())
    }

    fn remove_edge(&mut self, id: EdgeId) -> Option<Edge> {
        let index = self.working.find_edge(id)?;
        self.working.edges[index].edge.take()
    }

    fn registry_chunk(&self, id: RegistryChunkId) -> Option<RegistryChunk> {
        self.working.registry_chunk(id)
    }

    fn insert_registry_chunk(
        &mut self,
        id: RegistryChunkId,
        chunk: RegistryChunk,
    ) -> KernelResult<(), InsertError> {
        let Some(index) = self.working.find_registry(id) else {
            return Err(InsertError::Unavailable);
        };
        if self.working.registry[index].chunk.is_some() {
            return Err(InsertError::Exists);
        }
        self.working.registry[index].chunk = Some(chunk);
        Ok(())
    }

    fn remove_registry_chunk(&mut self, id: RegistryChunkId) -> Option<RegistryChunk> {
        let index = self.working.find_registry(id)?;
        self.working.registry[index].chunk.take()
    }

    fn commit(self) {
        *self.parent = self.working;
    }
}

impl<const C: usize, const E: usize, const R: usize> Snapshot for FixedStore<C, E, R> {
    type View = View<C, E, R>;

    fn view(&self) -> Self::View {
        View::with_registry(
            self.coins.map(|slot| slot.coin.map(|coin| (slot.id, coin))),
            self.edges.map(|slot| slot.edge.map(|edge| (slot.id, edge))),
            self.registry
                .map(|slot| slot.chunk.map(|chunk| (slot.id, chunk))),
        )
    }
}

/// Registry slots every trace, property, and model-checking harness
/// declares, and that no currently-landed transition may write.
///
/// Declared rather than omitted on purpose. With no slot at all a stray
/// registry write fails as [`InsertError::Unavailable`] and surfaces as
/// "the kernel rejected a valid operation", which names the wrong bug.
/// With these declared, the write succeeds against the store and is
/// caught by the invariant that says the transition should not have
/// made it — which names the right one. A write to a slot outside this
/// pair still fails, just less legibly.
pub(crate) const CANARY_REGISTRY_SLOTS: usize = 2;

pub(crate) fn canary_registry_slots() -> [RegistryChunkId; CANARY_REGISTRY_SLOTS] {
    [
        RegistryChunkId::derive(NETWORK, RegistryNamespace::PaymentClose, [0xc0; 32], 0),
        RegistryChunkId::derive(NETWORK, RegistryNamespace::BondLease, [0xc1; 32], 0),
    ]
}

impl CoinSlot {
    const EMPTY: Self = Self {
        id: CoinId::from_bytes([0; CoinId::LENGTH]),
        coin: None,
    };

    const fn empty(id: CoinId) -> Self {
        Self { id, coin: None }
    }
}

impl EdgeSlot {
    const EMPTY: Self = Self {
        id: EdgeId::from_bytes([0; EdgeId::LENGTH]),
        edge: None,
    };

    const fn empty(id: EdgeId) -> Self {
        Self { id, edge: None }
    }
}

impl RegistrySlot {
    const EMPTY: Self = Self {
        id: RegistryChunkId::from_bytes([0; RegistryChunkId::LENGTH]),
        chunk: None,
    };

    const fn empty(id: RegistryChunkId) -> Self {
        Self { id, chunk: None }
    }
}

pub(crate) fn state<const C: usize, const E: usize, const R: usize, const G: usize>(
    store: FixedStore<C, E, R>,
    seeds: [Genesis; G],
) -> State<FixedStore<C, E, R>> {
    let Ok(state) = State::genesis(store, &seeds) else {
        panic!("genesis rejected test seed");
    };
    state
}

pub(crate) const fn coin_id(byte: u8) -> CoinId {
    CoinId::from_bytes([byte; CoinId::LENGTH])
}

pub(crate) const fn edge_id(byte: u8) -> EdgeId {
    EdgeId::from_bytes([byte; EdgeId::LENGTH])
}

pub(crate) const fn key(byte: u8) -> Key {
    Key::from_bytes([byte; Key::LENGTH])
}

pub(crate) const fn coin_view(coin: Coin) -> (Key, u64) {
    (coin.owner(), coin.value())
}

pub(crate) const fn edge_view(edge: &Edge) -> (u64, u64, BlockHeight, Parties, TermsHash) {
    (
        edge.value(),
        edge.reserve(),
        edge.timeout(),
        edge.parties(),
        edge.terms(),
    )
}

/// Bounded list literal: the given items live, remaining slots defaulted.
/// The capacity `N` is inferred from the call site.
pub(crate) fn list<T: Copy + Default, const N: usize>(items: &[T]) -> List<T, N> {
    let mut buf = [T::default(); N];
    buf[..items.len()].copy_from_slice(items);
    let Some(list) = List::new(buf, items.len()) else {
        panic!("test list exceeds capacity");
    };
    list
}

/// Payout list literal from `(owner, value)` pairs.
pub(crate) fn payouts(entries: &[(Key, u64)]) -> List<Payout, MAX_EDGE_OUTPUTS> {
    let mut buf = [Payout::default(); MAX_EDGE_OUTPUTS];
    for (slot, (owner, value)) in buf.iter_mut().zip(entries) {
        *slot = Payout::new(*owner, *value);
    }
    let Some(list) = List::new(buf, entries.len()) else {
        panic!("test payouts exceed capacity");
    };
    list
}

/// `Tx::Open` authorized with the placeholder sigs `FAKE_VERIFIER`
/// accepts, keyed to `maker`/`taker`. Adversarial tests pass mismatching
/// keys.
pub(crate) fn open_tx(funding: Funding, terms: Terms, maker: Key, taker: Key) -> Tx {
    let hash = Tx::open_hash(NETWORK, &funding, &terms);
    Tx::open(
        funding,
        terms,
        PartyAuth::owner(Auth::native(Sig::placeholder(maker, hash))),
        PartyAuth::owner(Auth::native(Sig::placeholder(taker, hash))),
    )
}

/// Placeholder-signed mutual close proof over the canonical close payload.
pub(crate) fn placeholder_mutual(
    input: EdgeId,
    terms: TermsHash,
    outputs: &List<Payout, MAX_EDGE_OUTPUTS>,
    maker: Key,
    taker: Key,
) -> Proof {
    let hash = mutual_hash(input, terms, outputs);
    Proof::mutual(
        PartyAuth::owner(Auth::native(Sig::placeholder(maker, hash))),
        PartyAuth::owner(Auth::native(Sig::placeholder(taker, hash))),
    )
}

/// Canonical payload hash a mutual close witness signs.
pub(crate) fn mutual_hash(
    input: EdgeId,
    terms: TermsHash,
    outputs: &List<Payout, MAX_EDGE_OUTPUTS>,
) -> PayloadHash {
    Tx::payload_hash(NETWORK, input, CloseKind::Mutual, terms, outputs)
}
