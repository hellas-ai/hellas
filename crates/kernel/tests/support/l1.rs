#![allow(dead_code)]

//! Canonical fixed scenario shared by the trace-replay, property, and
//! model-checking tests: two genesis coins (maker 10, taker 5), one
//! bilateral terms shape, and up to two chained edges.

use super::{
    CANARY_REGISTRY_SLOTS, FixedStore, canary_registry_slots, coin_id, list, open_tx,
    placeholder_mutual, state,
};

use hellas_kernel::{
    BlockHash, BlockHeight, CoinId, Context, Edge, EdgeId, Funding, Genesis, Key, List,
    MAX_EDGE_INPUTS, MAX_EDGE_OUTPUTS, Parties, PartyKeys, Payout, Proof, ProtocolCode, State,
    Terms, Tx, View,
};

pub(crate) const CONTEXT: Context = Context::new(
    super::NETWORK,
    BlockHeight::new(1),
    BlockHash::from_bytes([0; BlockHash::LENGTH]),
);
pub(crate) const TIMEOUT: BlockHeight = BlockHeight::new(2);
pub(crate) const TIMEOUT_CONTEXT: Context = Context::new(
    super::NETWORK,
    TIMEOUT,
    BlockHash::from_bytes([0; BlockHash::LENGTH]),
);
pub(crate) const MAKER: Key = Key::from_bytes([7; Key::LENGTH]);
pub(crate) const TAKER: Key = Key::from_bytes([8; Key::LENGTH]);
/// Third party owning nothing; the concrete realization of the model's
/// `Adversary` party in rejected-open replay.
pub(crate) const ADVERSARY: Key = Key::from_bytes([0xee; Key::LENGTH]);
pub(crate) const PARTIES: Parties = Parties::new(PartyKeys::sole(MAKER), PartyKeys::sole(TAKER));
pub(crate) const PROTOCOL: ProtocolCode = ProtocolCode::new(1);
pub(crate) const OTHER_PROTOCOL: ProtocolCode = ProtocolCode::new(2);
pub(crate) const MAKER_ID: CoinId = coin_id(1);
pub(crate) const TAKER_ID: CoinId = coin_id(2);
pub(crate) const MAKER_VALUE: u64 = 10;
pub(crate) const TAKER_VALUE: u64 = 5;
pub(crate) const EDGE_VALUE: u64 = MAKER_VALUE + TAKER_VALUE;
pub(crate) const MAKER_PAYOUT: u64 = 7;
pub(crate) const TAKER_PAYOUT: u64 = 8;
pub(crate) const BAD_PAYOUT: u64 = TAKER_PAYOUT + 1;

pub(crate) fn terms() -> Terms {
    Terms::basic(PROTOCOL, PARTIES, TIMEOUT, payouts())
}

pub(crate) fn other_terms() -> Terms {
    Terms::basic(OTHER_PROTOCOL, PARTIES, TIMEOUT, payouts())
}

pub(crate) type TraceState = State<FixedStore<6, 2, CANARY_REGISTRY_SLOTS>>;
pub(crate) type TraceView = View<6, 2, CANARY_REGISTRY_SLOTS>;

#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub(crate) enum EdgeKey {
    First,
    Second,
}

#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub(crate) enum OpenKey {
    Full,
    MakerOnly,
    TakerOnly,
    Empty,
}

#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub(crate) enum ProofKey {
    Mutual,
    Timeout,
    EarlyTimeout,
    WrongTerms,
}

pub(crate) fn initial_state() -> TraceState {
    state(
        FixedStore::empty_with_registry(
            [
                MAKER_ID,
                TAKER_ID,
                maker_out(EdgeKey::First),
                taker_out(EdgeKey::First),
                maker_out(EdgeKey::Second),
                taker_out(EdgeKey::Second),
            ],
            [edge_id(EdgeKey::First), edge_id(EdgeKey::Second)],
            canary_registry_slots(),
        ),
        [
            Genesis::coin(MAKER_ID, MAKER, MAKER_VALUE),
            Genesis::coin(TAKER_ID, TAKER, TAKER_VALUE),
        ],
    )
}

pub(crate) fn genesis<const C: usize, const E: usize, const R: usize>(
    store: FixedStore<C, E, R>,
) -> State<FixedStore<C, E, R>> {
    state(
        store,
        [
            Genesis::coin(MAKER_ID, MAKER, MAKER_VALUE),
            Genesis::coin(TAKER_ID, TAKER, TAKER_VALUE),
        ],
    )
}

pub(crate) fn open(edge: EdgeKey) -> Tx {
    match edge {
        EdgeKey::First => open_case(OpenKey::Full),
        EdgeKey::Second => open_tx(second_funding(), terms(), MAKER, TAKER),
    }
}

pub(crate) fn open_case(key: OpenKey) -> Tx {
    open_tx(open_funding(key), open_terms(key), MAKER, TAKER)
}

pub(crate) fn open_case_op(key: OpenKey) -> Tx {
    open_case(key)
}

pub(crate) fn open_case_id(key: OpenKey) -> EdgeId {
    Tx::edge_id_of(&open_funding(key), &open_terms(key))
}

pub(crate) fn open_case_inputs(key: OpenKey) -> List<CoinId, MAX_EDGE_INPUTS> {
    match key {
        OpenKey::Full => list(&[MAKER_ID, TAKER_ID]),
        OpenKey::MakerOnly => list(&[MAKER_ID]),
        OpenKey::TakerOnly => list(&[TAKER_ID]),
        OpenKey::Empty => list(&[]),
    }
}

pub(crate) fn close(edge: EdgeKey, proof: ProofKey) -> Tx {
    close_with(edge, proof, payouts())
}

pub(crate) fn close_with(
    edge: EdgeKey,
    proof: ProofKey,
    outputs: List<Payout, MAX_EDGE_OUTPUTS>,
) -> Tx {
    Tx::close(edge_id(edge), proof_for(edge, proof, &outputs), outputs)
}

pub(crate) fn edge_id(edge: EdgeKey) -> EdgeId {
    match edge {
        EdgeKey::First => open_case_id(OpenKey::Full),
        EdgeKey::Second => Tx::edge_id_of(&second_funding(), &terms()),
    }
}

pub(crate) fn maker_out(edge: EdgeKey) -> CoinId {
    output_ids(edge).as_slice()[0]
}

pub(crate) fn taker_out(edge: EdgeKey) -> CoinId {
    output_ids(edge).as_slice()[1]
}

pub(crate) fn output_ids(edge: EdgeKey) -> List<CoinId, MAX_EDGE_OUTPUTS> {
    Tx::close_output_ids(edge_id(edge), &payouts())
}

pub(crate) const fn edge_value(edge: &Edge) -> u64 {
    edge.value()
}

pub(crate) fn live_value<const C: usize, const E: usize, const R: usize>(
    view: &View<C, E, R>,
) -> u64 {
    let mut total = 0_u64;
    for (_, coin) in view.coins() {
        total = total.saturating_add(coin.value());
    }
    for (_, edge) in view.edges() {
        total = total.saturating_add(edge.value());
    }
    total
}

pub(crate) fn payouts() -> List<Payout, MAX_EDGE_OUTPUTS> {
    payouts_with(MAKER_PAYOUT, TAKER_PAYOUT)
}

pub(crate) fn bad_payouts() -> List<Payout, MAX_EDGE_OUTPUTS> {
    payouts_with(MAKER_PAYOUT, BAD_PAYOUT)
}

/// Value-conserving payouts that drain the entire edge to the maker. Used to
/// expose proof-binding holes: any kind that does not bind payouts will accept
/// these instead of the canonical (`MAKER_PAYOUT`, `TAKER_PAYOUT`) split.
pub(crate) fn maker_grab_payouts() -> List<Payout, MAX_EDGE_OUTPUTS> {
    payouts_with(EDGE_VALUE, 0)
}

pub(crate) fn payouts_with(maker: u64, taker: u64) -> List<Payout, MAX_EDGE_OUTPUTS> {
    super::payouts(&[(MAKER, maker), (TAKER, taker)])
}

/// The second edge is funded by the first edge's payout coins.
fn second_funding() -> Funding {
    Funding::new(
        list(&[maker_out(EdgeKey::First)]),
        list(&[taker_out(EdgeKey::First)]),
    )
}

/// Canonical funding for either edge, mirroring the model's positional
/// `makerInput` / `takerInput` wiring.
pub(crate) fn funding_for(edge: EdgeKey) -> Funding {
    match edge {
        EdgeKey::First => Funding::new(list(&[MAKER_ID]), list(&[TAKER_ID])),
        EdgeKey::Second => second_funding(),
    }
}

/// Canonical payout values addressed to explicit owner keys. Used to
/// build terms for opens claimed by non-canonical parties.
pub(crate) fn payouts_owned(maker: Key, taker: Key) -> List<Payout, MAX_EDGE_OUTPUTS> {
    super::payouts(&[(maker, MAKER_PAYOUT), (taker, TAKER_PAYOUT)])
}

fn proof_for(edge: EdgeKey, proof: ProofKey, outputs: &List<Payout, MAX_EDGE_OUTPUTS>) -> Proof {
    let terms = terms();
    match proof {
        ProofKey::Mutual => placeholder_mutual(edge_id(edge), terms.hash(), outputs, MAKER, TAKER),
        ProofKey::Timeout | ProofKey::EarlyTimeout => Proof::timeout(terms),
        // Submitting a Timeout proof whose terms don't match the edge's terms
        // commitment triggers `TermsMismatch` in the verifier.
        ProofKey::WrongTerms => Proof::timeout(other_terms()),
    }
}

fn open_funding(key: OpenKey) -> Funding {
    match key {
        OpenKey::Full => Funding::new(list(&[MAKER_ID]), list(&[TAKER_ID])),
        OpenKey::MakerOnly => Funding::new(list(&[MAKER_ID]), list(&[])),
        OpenKey::TakerOnly => Funding::new(list(&[]), list(&[TAKER_ID])),
        OpenKey::Empty => Funding::new(list(&[]), list(&[])),
    }
}

fn open_terms(key: OpenKey) -> Terms {
    let (maker, taker) = match key {
        OpenKey::Full => (MAKER_PAYOUT, TAKER_PAYOUT),
        OpenKey::MakerOnly => (MAKER_VALUE, 0),
        OpenKey::TakerOnly => (0, TAKER_VALUE),
        OpenKey::Empty => (0, 0),
    };
    Terms::basic(PROTOCOL, PARTIES, TIMEOUT, payouts_with(maker, taker))
}
