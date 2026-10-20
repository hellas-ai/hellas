//! Smoke tests for the growing-backend `MapStore`.
//!
//! Drives the kernel against a `BTreeMap`-backed store. Confirms the `Store`
//! trait composes with non-bounded backends, and runs a sequence longer than
//! `FixedStore`'s compile-time slot count to validate the map's grow path.

#![allow(clippy::alloc_instead_of_core)]
#![allow(clippy::disallowed_types)]
#![allow(clippy::expect_used)]
#![allow(clippy::std_instead_of_alloc)]
#![allow(clippy::std_instead_of_core)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::indexing_slicing)] // tests may index; the panic-freedom lock targets src

mod support;

use hellas_kernel::{
    ApplyError, Batch, BlockHash, BlockHeight, Coin, CoinId, Context, Edge, EdgeId, Funding,
    Genesis, InsertError, KernelResult, Key, List, MAX_EDGE_OUTPUTS, Parties, PartyKeys, Payout,
    Proof, ProtocolCode, RegistryChunk, RegistryChunkId, State, Store, Terms, Tx,
};
use support::{
    FAKE_VERIFIER, coin_id, key, list,
    map_store::{MapStore, MapTx, map_state},
    open_tx,
};

const TIMEOUT: BlockHeight = BlockHeight::new(2);
const TIMEOUT_CONTEXT: Context = Context::new(
    support::NETWORK,
    TIMEOUT,
    BlockHash::from_bytes([0; BlockHash::LENGTH]),
);
const CONTEXT: Context = Context::new(
    support::NETWORK,
    BlockHeight::new(1),
    BlockHash::from_bytes([0; BlockHash::LENGTH]),
);

fn payouts(
    maker: Key,
    taker: Key,
    maker_value: u64,
    taker_value: u64,
) -> List<Payout, MAX_EDGE_OUTPUTS> {
    support::payouts(&[(maker, maker_value), (taker, taker_value)])
}

#[test]
fn map_store_round_trip() {
    let maker = key(7);
    let taker = key(8);
    let parties = Parties::new(PartyKeys::sole(maker), PartyKeys::sole(taker));
    let maker_coin = coin_id(1);
    let taker_coin = coin_id(2);
    let outputs = payouts(maker, taker, 7, 8);
    let terms = Terms::basic(ProtocolCode::new(1), parties, TIMEOUT, outputs.clone());
    let funding_value = Funding::new(list(&[maker_coin]), list(&[taker_coin]));
    let edge = Tx::edge_id_of(&funding_value, &terms);
    let open = open_tx(funding_value, terms.clone(), maker, taker);
    let resolve = Tx::close(edge, Proof::timeout(terms), outputs);

    let mut state = map_state([
        Genesis::coin(maker_coin, maker, 10),
        Genesis::coin(taker_coin, taker, 5),
    ]);
    assert_eq!(state.store().coin_count(), 2);
    assert_eq!(state.store().edge_count(), 0);

    state
        .apply(CONTEXT, &FAKE_VERIFIER, &open)
        .expect("open accepted");
    assert_eq!(state.store().coin_count(), 0);
    assert_eq!(state.store().edge_count(), 1);
    assert!(state.store().edge(edge).is_some());

    state
        .apply(TIMEOUT_CONTEXT, &FAKE_VERIFIER, &resolve)
        .expect("resolve accepted");
    assert_eq!(state.store().coin_count(), 2);
    assert_eq!(state.store().edge_count(), 0);

    let payout_owners: Vec<Key> = state.store().coins().map(|(_, c)| c.owner()).collect();
    assert!(payout_owners.contains(&maker));
    assert!(payout_owners.contains(&taker));
}

/// Open and resolve N successive edges, each funded by the previous resolve's
/// payout coins. `FixedStore` can't hold this many slots without
/// over-allocation; `MapStore` grows naturally.
#[test]
fn map_store_handles_long_chain() {
    const N: usize = 32;
    let maker = key(7);
    let taker = key(8);
    let parties = Parties::new(PartyKeys::sole(maker), PartyKeys::sole(taker));
    let payout_outputs = payouts(maker, taker, 7, 8);
    let terms = Terms::basic(ProtocolCode::new(1), parties, TIMEOUT, payout_outputs);

    // Fund with a single big maker coin and a single big taker coin; each
    // resolve splits 15 → (7, 8) which the next open consumes whole.
    let mut maker_coin = coin_id(1);
    let mut taker_coin = coin_id(2);

    let mut state = map_state([
        Genesis::coin(maker_coin, maker, 7),
        Genesis::coin(taker_coin, taker, 8),
    ]);

    for _ in 0..N {
        let funding_value = Funding::new(list(&[maker_coin]), list(&[taker_coin]));
        let edge = Tx::edge_id_of(&funding_value, &terms);
        let open = open_tx(funding_value, terms.clone(), maker, taker);
        let outputs = payouts(maker, taker, 7, 8);
        let resolve = Tx::close(edge, Proof::timeout(terms.clone()), outputs.clone());
        // The two payout coins from this resolve become the next open's
        // funding. Compute them before consuming `resolve`.
        let resolved_outputs = Tx::close_output_ids(edge, &outputs);

        state
            .apply(CONTEXT, &FAKE_VERIFIER, &open)
            .expect("open accepted in chain");
        state
            .apply(TIMEOUT_CONTEXT, &FAKE_VERIFIER, &resolve)
            .expect("resolve accepted in chain");

        maker_coin = resolved_outputs.as_slice()[0];
        taker_coin = resolved_outputs.as_slice()[1];
    }

    assert_eq!(state.store().edge_count(), 0, "all edges resolved");
    // Each iteration's payouts feed the next open's funding, so at the end
    // only the final iteration's two payout coins remain live.
    assert_eq!(state.store().coin_count(), 2);
}

// ---------------------------------------------------------------------
// Store-contract violations
//
// `error.rs` documents that `CoinChanged` / `EdgeChanged` and the
// fold-phase `MissingCoin` / `MissingEdge` / insert-rejection errors
// signal a broken `Batch` implementation, and that the kernel surfaces
// them as recoverable errors instead of committing a half-applied
// operation. `SabotageStore` breaks the contract in one chosen way per
// test; the kernel must return exactly the documented error and leave
// the backing store byte-identical.
// ---------------------------------------------------------------------

/// One specific way a batch can violate the [`Batch`] contract.
#[allow(
    clippy::large_enum_variant,
    reason = "one fixture value per test; an edge is the thing being swapped"
)]
#[derive(Debug, Clone, Copy)]
enum Sabotage {
    /// `remove_coin` claims every slot is empty.
    LoseCoinOnRemove,
    /// `remove_coin` returns this coin instead of the stored one.
    SwapCoinOnRemove(Coin),
    /// `insert_coin` rejects every id as occupied.
    RejectCoinInsert,
    /// `remove_edge` claims every slot is empty.
    LoseEdgeOnRemove,
    /// `remove_edge` returns this edge instead of the stored one.
    SwapEdgeOnRemove(Edge),
}

#[derive(Debug)]
struct SabotageStore {
    inner: MapStore,
    mode: Sabotage,
}

struct SabotageTx<'a> {
    inner: MapTx<'a>,
    mode: Sabotage,
}

impl Store for SabotageStore {
    type Batch<'a>
        = SabotageTx<'a>
    where
        Self: 'a;

    fn begin(&mut self) -> Self::Batch<'_> {
        SabotageTx {
            inner: self.inner.begin(),
            mode: self.mode,
        }
    }
}

impl Batch for SabotageTx<'_> {
    fn coin(&self, id: CoinId) -> Option<Coin> {
        self.inner.coin(id)
    }

    fn insert_coin(&mut self, id: CoinId, coin: Coin) -> KernelResult<(), InsertError> {
        if matches!(self.mode, Sabotage::RejectCoinInsert) {
            return Err(InsertError::Exists);
        }
        self.inner.insert_coin(id, coin)
    }

    fn remove_coin(&mut self, id: CoinId) -> Option<Coin> {
        match self.mode {
            Sabotage::LoseCoinOnRemove => None,
            Sabotage::SwapCoinOnRemove(decoy) => {
                self.inner.remove_coin(id);
                Some(decoy)
            }
            _ => self.inner.remove_coin(id),
        }
    }

    fn edge(&self, id: EdgeId) -> Option<Edge> {
        self.inner.edge(id)
    }

    fn insert_edge(&mut self, id: EdgeId, edge: Edge) -> KernelResult<(), InsertError> {
        self.inner.insert_edge(id, edge)
    }

    fn remove_edge(&mut self, id: EdgeId) -> Option<Edge> {
        match self.mode {
            Sabotage::LoseEdgeOnRemove => None,
            Sabotage::SwapEdgeOnRemove(decoy) => {
                self.inner.remove_edge(id);
                Some(decoy)
            }
            _ => self.inner.remove_edge(id),
        }
    }

    // No registry sabotage mode: the sabotage tests drive the coin/edge
    // effects `State::apply` folds today. A mode here would name a fold
    // that does not exist yet.
    fn registry_chunk(&self, id: RegistryChunkId) -> Option<RegistryChunk> {
        self.inner.registry_chunk(id)
    }

    fn insert_registry_chunk(
        &mut self,
        id: RegistryChunkId,
        chunk: RegistryChunk,
    ) -> KernelResult<(), InsertError> {
        self.inner.insert_registry_chunk(id, chunk)
    }

    fn remove_registry_chunk(&mut self, id: RegistryChunkId) -> Option<RegistryChunk> {
        self.inner.remove_registry_chunk(id)
    }

    fn commit(self) {
        self.inner.commit();
    }
}

/// Canonical single-edge scenario over an honest `MapStore`: two seeded
/// coins, the open that locks them, and the timeout close that resolves
/// the edge. Returns the pre-open state plus both operations.
fn scenario() -> (State<MapStore>, Tx, Tx, EdgeId) {
    let maker = key(7);
    let taker = key(8);
    let maker_coin = coin_id(1);
    let taker_coin = coin_id(2);
    let outputs = payouts(maker, taker, 7, 8);
    let terms = Terms::basic(
        ProtocolCode::new(1),
        Parties::new(PartyKeys::sole(maker), PartyKeys::sole(taker)),
        TIMEOUT,
        outputs.clone(),
    );
    let funding = Funding::new(list(&[maker_coin]), list(&[taker_coin]));
    let edge = Tx::edge_id_of(&funding, &terms);
    let open = open_tx(funding, terms.clone(), maker, taker);
    let close = Tx::close(edge, Proof::timeout(terms), outputs);
    let state = map_state([
        Genesis::coin(maker_coin, maker, 10),
        Genesis::coin(taker_coin, taker, 5),
    ]);
    (state, open, close, edge)
}

type Snapshot = (
    Vec<(CoinId, Coin)>,
    Vec<(EdgeId, Edge)>,
    Vec<(RegistryChunkId, RegistryChunk)>,
);

/// Every object kind the store holds. Registry chunks are included for
/// the same reason coins and edges are: a rolled-back apply that left a
/// chunk behind would otherwise compare equal to one that did not.
fn snapshot(store: &MapStore) -> Snapshot {
    (
        store.coins().collect(),
        store.edges().collect(),
        store.registry_chunks().collect(),
    )
}

/// Applies `op` over a sabotaged wrap of `inner`, asserting the expected
/// contract-violation error and that the backing store is untouched.
fn assert_sabotaged_apply(
    inner: MapStore,
    mode: &Sabotage,
    context: Context,
    op: &Tx,
    expected: &ApplyError,
) {
    let before = snapshot(&inner);
    let mut state = State::new(SabotageStore { inner, mode: *mode });

    assert_eq!(state.apply(context, &FAKE_VERIFIER, op), Err(*expected));
    assert_eq!(snapshot(&state.into_store().inner), before);
}

#[test]
fn fold_surfaces_coin_contract_violations_without_committing() {
    let maker_coin = coin_id(1);
    let (state, open, _, _) = scenario();
    let store = state.into_store();
    let decoy = store.coin(coin_id(2)).expect("taker coin seeded");

    assert_sabotaged_apply(
        store,
        &Sabotage::LoseCoinOnRemove,
        CONTEXT,
        &open,
        &ApplyError::MissingCoin { id: maker_coin },
    );

    let (state, open, _, _) = scenario();
    assert_sabotaged_apply(
        state.into_store(),
        &Sabotage::SwapCoinOnRemove(decoy),
        CONTEXT,
        &open,
        &ApplyError::CoinChanged { id: maker_coin },
    );
}

#[test]
fn fold_surfaces_edge_contract_violations_without_committing() {
    // An honest open produces the live edge the sabotaged closes target.
    let opened = || {
        let (mut state, open, close, edge) = scenario();
        state
            .apply(CONTEXT, &FAKE_VERIFIER, &open)
            .expect("honest open accepted");
        (state.into_store(), close, edge)
    };

    let (store, close, edge) = opened();
    let output = Tx::close_output_ids(edge, &payouts(key(7), key(8), 7, 8)).as_slice()[0];
    assert_sabotaged_apply(
        store,
        &Sabotage::RejectCoinInsert,
        TIMEOUT_CONTEXT,
        &close,
        &ApplyError::CoinInsertRejected {
            id: output,
            reason: InsertError::Exists,
        },
    );

    let (store, close, edge) = opened();
    assert_sabotaged_apply(
        store,
        &Sabotage::LoseEdgeOnRemove,
        TIMEOUT_CONTEXT,
        &close,
        &ApplyError::MissingEdge { id: edge },
    );

    // Decoy edge with a different locked value, from an unrelated store.
    let (mut other, _, _, _) = scenario();
    let other_terms = Terms::basic(
        ProtocolCode::new(2),
        Parties::new(PartyKeys::sole(key(7)), PartyKeys::sole(key(8))),
        TIMEOUT,
        payouts(key(7), key(8), 10, 5),
    );
    let other_funding = Funding::new(list(&[coin_id(1)]), list(&[coin_id(2)]));
    let other_edge = Tx::edge_id_of(&other_funding, &other_terms);
    other
        .apply(
            CONTEXT,
            &FAKE_VERIFIER,
            &open_tx(other_funding, other_terms, key(7), key(8)),
        )
        .expect("decoy open accepted");
    let decoy = other.store().edge(other_edge).expect("decoy edge live");

    let (store, close, edge) = opened();
    assert_sabotaged_apply(
        store,
        &Sabotage::SwapEdgeOnRemove(decoy),
        TIMEOUT_CONTEXT,
        &close,
        &ApplyError::EdgeChanged { id: edge },
    );
}
