use super::{CANARY_REGISTRY_SLOTS, FixedStore, canary_registry_slots, coin_id, state};

use hellas_kernel::{
    BlockHash, BlockHeight, CoinId, Context, EdgeId, Fees, Funding, Genesis, Key, List,
    MAX_EDGE_OUTPUTS, MAX_PARTY_INPUTS, Parties, PartyKeys, Payout, Proof, ProtocolCode, State,
    Terms, Tx, View,
};

pub(crate) const TIMEOUT: BlockHeight = BlockHeight::new(2);
pub(crate) const MAKER: Key = Key::from_bytes([7; Key::LENGTH]);
pub(crate) const TAKER: Key = Key::from_bytes([8; Key::LENGTH]);
pub(crate) const PROTOCOL: ProtocolCode = ProtocolCode::new(1);
pub(crate) const MAKER_ID: CoinId = coin_id(1);
pub(crate) const TAKER_ID: CoinId = coin_id(2);
pub(crate) const MAKER_VALUE: u64 = 40;
pub(crate) const TAKER_VALUE: u64 = 40;
pub(crate) const BASE_CLOSE_FEE: i64 = 10;
pub(crate) const RAISED_CLOSE_FEE: i64 = 18;

pub(crate) const BASE_FEES: Fees = Fees::new(1, 3, 0, 3);
pub(crate) const RAISED_FEES: Fees = Fees::new(18, 0, 0, 0);

pub(crate) type TraceState = State<FixedStore<12, 5, CANARY_REGISTRY_SLOTS>>;
pub(crate) type TraceView = View<12, 5, CANARY_REGISTRY_SLOTS>;

#[derive(Debug, Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) enum FundingShape {
    Full,
    MakerOnly,
    TakerOnly,
    Empty,
    SelfEdge,
}

#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub(crate) enum ProofKey {
    Mutual,
    Timeout,
}

pub(crate) fn initial_state() -> TraceState {
    initial_state_with(MAKER_VALUE, TAKER_VALUE)
}

pub(crate) fn initial_state_underfunded() -> TraceState {
    initial_state_with(20, TAKER_VALUE)
}

fn initial_state_with(maker_value: u64, taker_value: u64) -> TraceState {
    state(
        FixedStore::empty_with_registry(
            [
                MAKER_ID,
                TAKER_ID,
                maker_out(FundingShape::Full),
                taker_out(FundingShape::Full),
                maker_out(FundingShape::MakerOnly),
                taker_out(FundingShape::MakerOnly),
                maker_out(FundingShape::TakerOnly),
                taker_out(FundingShape::TakerOnly),
                maker_out(FundingShape::Empty),
                taker_out(FundingShape::Empty),
                maker_out(FundingShape::SelfEdge),
                taker_out(FundingShape::SelfEdge),
            ],
            [
                edge_id(FundingShape::Full),
                edge_id(FundingShape::MakerOnly),
                edge_id(FundingShape::TakerOnly),
                edge_id(FundingShape::Empty),
                edge_id(FundingShape::SelfEdge),
            ],
            canary_registry_slots(),
        ),
        [
            Genesis::coin(MAKER_ID, MAKER, maker_value),
            Genesis::coin(TAKER_ID, TAKER, taker_value),
        ],
    )
}

pub(crate) const fn fees_for_open(shape: FundingShape) -> Fees {
    match shape {
        FundingShape::Empty => Fees::ZERO,
        FundingShape::Full
        | FundingShape::MakerOnly
        | FundingShape::TakerOnly
        | FundingShape::SelfEdge => BASE_FEES,
    }
}

pub(crate) fn context(height: i64, fees: Fees) -> Context {
    let Ok(height) = u64::try_from(height) else {
        panic!("negative l1_fees height");
    };
    Context::with_fees(
        super::NETWORK,
        BlockHeight::new(height),
        BlockHash::from_bytes([0; BlockHash::LENGTH]),
        fees,
    )
}

pub(crate) fn open(shape: FundingShape) -> Tx {
    let parties = parties(shape);
    super::open(
        open_funding(shape),
        terms(shape),
        (
            hellas_kernel::PartyKeys::sole(parties.maker().owner()),
            hellas_kernel::Authority::Owner,
        ),
        (
            hellas_kernel::PartyKeys::sole(parties.taker().owner()),
            hellas_kernel::Authority::Owner,
        ),
    )
}

pub(crate) fn close(shape: FundingShape, proof: ProofKey) -> Tx {
    let input = edge_id(shape);
    let outputs = payouts(shape);
    let proof = match proof {
        ProofKey::Mutual => {
            let parties = parties(shape);
            super::placeholder_mutual(
                input,
                terms(shape).hash(),
                &outputs,
                parties.maker().owner(),
                parties.taker().owner(),
            )
        }
        ProofKey::Timeout => Proof::timeout(terms(shape), None),
    };
    Tx::close(input, proof, outputs)
}

pub(crate) fn edge_id(shape: FundingShape) -> EdgeId {
    Tx::edge_id_of(&open_funding(shape), &terms(shape))
}

pub(crate) fn maker_out(shape: FundingShape) -> CoinId {
    nth(&output_ids(shape), 0)
}

pub(crate) fn taker_out(shape: FundingShape) -> CoinId {
    nth(&output_ids(shape), 1)
}

pub(crate) fn output_ids(shape: FundingShape) -> List<CoinId, MAX_EDGE_OUTPUTS> {
    Tx::close_output_ids(edge_id(shape), &payouts(shape))
}

pub(crate) fn payouts(shape: FundingShape) -> List<Payout, MAX_EDGE_OUTPUTS> {
    match shape {
        FundingShape::Full => payouts_with(MAKER, 29, TAKER, 28),
        FundingShape::MakerOnly => payouts_with(MAKER, 20, TAKER, 0),
        // Both positions of a self-edge are the maker, so both committed
        // destinations are the maker's: its taker payout lands there too.
        FundingShape::SelfEdge => payouts_with(MAKER, 20, MAKER, 0),
        FundingShape::TakerOnly => payouts_with(MAKER, 0, TAKER, 20),
        FundingShape::Empty => payouts_with(MAKER, 0, TAKER, 0),
    }
}

pub(crate) fn terms(shape: FundingShape) -> Terms {
    Terms::basic(PROTOCOL, parties(shape), TIMEOUT, payouts(shape))
}

pub(crate) const fn parties(shape: FundingShape) -> Parties {
    match shape {
        FundingShape::SelfEdge => Parties::new(PartyKeys::sole(MAKER), PartyKeys::sole(MAKER)),
        FundingShape::Full
        | FundingShape::MakerOnly
        | FundingShape::TakerOnly
        | FundingShape::Empty => Parties::new(PartyKeys::sole(MAKER), PartyKeys::sole(TAKER)),
    }
}

fn open_funding(shape: FundingShape) -> Funding {
    match shape {
        FundingShape::Full => Funding::new(party1(MAKER_ID), party1(TAKER_ID)),
        FundingShape::MakerOnly | FundingShape::SelfEdge => {
            Funding::new(party1(MAKER_ID), empty_party())
        }
        FundingShape::TakerOnly => Funding::new(empty_party(), party1(TAKER_ID)),
        FundingShape::Empty => Funding::new(empty_party(), empty_party()),
    }
}

fn payouts_with(
    maker_owner: Key,
    maker_value: u64,
    taker_owner: Key,
    taker_value: u64,
) -> List<Payout, MAX_EDGE_OUTPUTS> {
    let first = Payout::new(maker_owner, maker_value);
    let second = Payout::new(taker_owner, taker_value);
    let Some(outputs) = List::new([first, second, first, first], 2) else {
        panic!("invalid l1_fees payout list");
    };
    outputs
}

fn party1(id: CoinId) -> List<CoinId, MAX_PARTY_INPUTS> {
    let Some(inputs) = List::new([id; MAX_PARTY_INPUTS], 1) else {
        panic!("invalid l1_fees party list");
    };
    inputs
}

fn empty_party() -> List<CoinId, MAX_PARTY_INPUTS> {
    let Some(inputs) = List::new([MAKER_ID; MAX_PARTY_INPUTS], 0) else {
        panic!("invalid l1_fees party list");
    };
    inputs
}

fn nth<const N: usize>(ids: &List<CoinId, N>, index: usize) -> CoinId {
    ids.as_slice()[index]
}
