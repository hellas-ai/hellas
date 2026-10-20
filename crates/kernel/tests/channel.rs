//! Channel open/close tests.
//!
//! Scenario constants (keys, coin ids, values, timeout, canonical terms)
//! come from `support::l1`; this root adds the fee-bearing contexts,
//! terms variants, and fixed-slot stores the lifecycle tests need.

#![allow(clippy::alloc_instead_of_core)]
#![allow(clippy::disallowed_types)]
#![allow(clippy::std_instead_of_alloc)]
#![allow(clippy::std_instead_of_core)]
#![allow(clippy::indexing_slicing)] // tests may index; the panic-freedom lock targets src

mod support;

#[path = "channel/batch.rs"]
mod batch;
#[path = "channel/close.rs"]
mod close;
#[path = "channel/op.rs"]
mod op;
#[path = "channel/open.rs"]
mod open;
#[path = "channel/work.rs"]
mod work;

use support::l1::{
    self, CONTEXT, EdgeKey, MAKER, MAKER_ID as MAKER_COIN, OpenKey, PARTIES, PROTOCOL, TAKER,
    TAKER_ID as TAKER_COIN, TIMEOUT, TIMEOUT_CONTEXT,
};
use support::{
    FAKE_VERIFIER, FixedStore, REJECT_VERIFIER, coin_id, coin_view, edge_view, list,
    open as open_tx_with, placeholder_mutual, state,
};

use hellas_kernel::{
    ApplyError, Auth, Block, BlockHash, BlockHeight, CloseKind, CoinId, Context, Cost, EdgeId,
    Event, EventKind, Fees, Funding, Genesis, InsertError, InvalidCloseReason, InvalidOpenReason,
    InvalidProofReason, Key, List, MAX_EDGE_INPUTS, MAX_EDGE_OUTPUTS, MAX_PARTY_INPUTS, Parties,
    PayloadHash, Payout, Proof, Sig, State, Terms, TermsHash, Tx, View,
};

const FEE_CONTEXT: Context = Context::with_fees(
    support::NETWORK,
    BlockHeight::new(1),
    BlockHash::from_bytes([0; BlockHash::LENGTH]),
    Fees::new(3, 0, 0, 0),
);
const RESOURCE_CONTEXT: Context = Context::with_fees(
    support::NETWORK,
    BlockHeight::new(1),
    BlockHash::from_bytes([0; BlockHash::LENGTH]),
    Fees::new(1, 3, 0, 3),
);
const RESOURCE_TIMEOUT_CONTEXT: Context = Context::with_fees(
    support::NETWORK,
    TIMEOUT,
    BlockHash::from_bytes([0; BlockHash::LENGTH]),
    Fees::new(1, 3, 0, 3),
);

const EXTRA_COIN: CoinId = coin_id(7);

const MAKER_SEED: Genesis = Genesis::coin(MAKER_COIN, MAKER, 10);
const TAKER_SEED: Genesis = Genesis::coin(TAKER_COIN, TAKER, 5);

fn basic_terms() -> Terms {
    l1::terms()
}

fn other_terms_value() -> Terms {
    l1::other_terms()
}

fn terms() -> TermsHash {
    basic_terms().hash()
}

fn other_terms() -> TermsHash {
    other_terms_value().hash()
}

fn terms_with(outputs: &List<Payout, MAX_EDGE_OUTPUTS>) -> Terms {
    terms_with_timeout(TIMEOUT, outputs)
}

fn terms_with_timeout(timeout: BlockHeight, outputs: &List<Payout, MAX_EDGE_OUTPUTS>) -> Terms {
    Terms::basic(PROTOCOL, PARTIES, timeout, outputs.clone())
}

fn terms_paying(maker: u64, taker: u64) -> Terms {
    terms_with(&payouts(
        Payout::new(MAKER, maker),
        Payout::new(TAKER, taker),
    ))
}

fn proof() -> Proof {
    Proof::timeout(basic_terms(), None)
}

fn other_proof() -> Proof {
    Proof::timeout(other_terms_value(), None)
}

fn mutual_proof(input: EdgeId, outputs: &List<Payout, MAX_EDGE_OUTPUTS>) -> Proof {
    placeholder_mutual(input, terms(), outputs, MAKER, TAKER)
}

fn mutual_hash(input: EdgeId, outputs: &List<Payout, MAX_EDGE_OUTPUTS>) -> PayloadHash {
    support::mutual_hash(input, terms(), outputs)
}

fn edge() -> EdgeId {
    l1::edge_id(EdgeKey::First)
}

fn maker_out() -> CoinId {
    l1::maker_out(EdgeKey::First)
}

fn taker_out() -> CoinId {
    l1::taker_out(EdgeKey::First)
}

fn extra_out() -> CoinId {
    let outputs = payouts3(
        Payout::new(MAKER, 6),
        Payout::new(TAKER, 5),
        Payout::new(MAKER, 4),
    );
    nth(&Tx::close_output_ids(edge(), &outputs), 2)
}

fn funded_state() -> State<FixedStore<6, 1>> {
    state(empty_store(), [MAKER_SEED, TAKER_SEED])
}

fn funded_state_for(open: &Tx) -> State<FixedStore<6, 1>> {
    state(store_for(open), [MAKER_SEED, TAKER_SEED])
}

fn open_state() -> State<FixedStore<6, 1>> {
    let mut state = funded_state();
    let _event = apply(&mut state, &open_op());
    state
}

fn open_op() -> Tx {
    l1::open_case(OpenKey::Full)
}

fn open_edge_id(open: &Tx) -> EdgeId {
    match open {
        Tx::Open { funding, terms, .. } => Tx::edge_id_of(funding, terms),
        Tx::Close { .. } | Tx::Move { .. } | Tx::Owner(_) => panic!("expected Tx::Open"),
    }
}

/// Builds a `Tx::Open` with canonical placeholder open signatures for
/// `(MAKER, TAKER)`. Adversarial tests use `open_tx_with` and pass the
/// keys they claim.
fn open_tx(funding: Funding, terms: Terms) -> Tx {
    open_tx_with(
        funding,
        terms,
        (
            hellas_kernel::PartyKeys::sole(MAKER),
            hellas_kernel::Authority::Owner,
        ),
        (
            hellas_kernel::PartyKeys::sole(TAKER),
            hellas_kernel::Authority::Owner,
        ),
    )
}

fn funding(maker: CoinId, taker: CoinId) -> Funding {
    Funding::new(party1(maker), party1(taker))
}

fn maker2_funding(first: CoinId, second: CoinId, taker: CoinId) -> Funding {
    Funding::new(list(&[first, second]), party1(taker))
}

fn empty_party() -> List<CoinId, MAX_PARTY_INPUTS> {
    list(&[])
}

fn party1(id: CoinId) -> List<CoinId, MAX_PARTY_INPUTS> {
    list(&[id])
}

fn payouts(first: Payout, second: Payout) -> List<Payout, MAX_EDGE_OUTPUTS> {
    list(&[first, second])
}

fn payouts3(first: Payout, second: Payout, third: Payout) -> List<Payout, MAX_EDGE_OUTPUTS> {
    list(&[first, second, third])
}

const fn payouts4() -> List<Payout, MAX_EDGE_OUTPUTS> {
    List::all([
        Payout::new(MAKER, 4),
        Payout::new(TAKER, 4),
        Payout::new(MAKER, 4),
        Payout::new(TAKER, 3),
    ])
}

fn no_payouts() -> List<Payout, MAX_EDGE_OUTPUTS> {
    list(&[])
}

fn input_ids0() -> List<CoinId, MAX_EDGE_INPUTS> {
    list(&[])
}

fn input_ids1(id: CoinId) -> List<CoinId, MAX_EDGE_INPUTS> {
    list(&[id])
}

fn input_ids2(first: CoinId, second: CoinId) -> List<CoinId, MAX_EDGE_INPUTS> {
    list(&[first, second])
}

fn input_ids3(first: CoinId, second: CoinId, third: CoinId) -> List<CoinId, MAX_EDGE_INPUTS> {
    list(&[first, second, third])
}

fn output_ids0() -> List<CoinId, MAX_EDGE_OUTPUTS> {
    list(&[])
}

fn nth<const N: usize>(ids: &List<CoinId, N>, index: usize) -> CoinId {
    ids.as_slice()[index]
}

fn output_ids2(first: CoinId, second: CoinId) -> List<CoinId, MAX_EDGE_OUTPUTS> {
    list(&[first, second])
}

fn output_ids3(first: CoinId, second: CoinId, third: CoinId) -> List<CoinId, MAX_EDGE_OUTPUTS> {
    list(&[first, second, third])
}

fn apply<const C: usize, const E: usize, const R: usize>(
    state: &mut State<FixedStore<C, E, R>>,
    op: &Tx,
) -> hellas_kernel::Event {
    apply_with(state, CONTEXT, op)
}

/// Applies `op` and returns the public event it announces.
///
/// Both halves of the outcome are checked here rather than at the forty
/// call sites below. An ordinary open or close is a public edge
/// mutation, so it always announces itself, and it moves no registry
/// state — a transition that quietly started writing chunks would fail
/// every channel test that routes through this helper.
fn apply_with<const C: usize, const E: usize, const R: usize>(
    state: &mut State<FixedStore<C, E, R>>,
    context: Context,
    op: &Tx,
) -> hellas_kernel::Event {
    let Ok(outcome) = state.apply(context, &FAKE_VERIFIER, op) else {
        panic!("operation rejected");
    };
    assert!(
        outcome.registry().is_empty(),
        "an ordinary edge operation wrote registry state: {:?}",
        outcome.registry(),
    );
    let Some(event) = outcome.public_event() else {
        panic!("an edge operation applied without announcing itself");
    };
    event.clone()
}

fn lifetime_fee_for(context: Context, timeout: BlockHeight) -> Option<u64> {
    let blocks = timeout.get().checked_sub(context.block_height().get())?;
    context.fees().lifetime().checked_mul(blocks)
}

fn empty_store() -> FixedStore<6, 1> {
    store_for(&open_op())
}

fn store_for(open: &Tx) -> FixedStore<6, 1> {
    FixedStore::empty(
        [
            MAKER_COIN,
            TAKER_COIN,
            EXTRA_COIN,
            maker_out(),
            taker_out(),
            extra_out(),
        ],
        [open_edge_id(open)],
    )
}

fn store_for_close(open: &Tx, outputs: &List<Payout, MAX_EDGE_OUTPUTS>) -> FixedStore<6, 1> {
    let edge_id = open_edge_id(open);
    let ids = Tx::close_output_ids(edge_id, outputs);
    let first = ids.as_slice().first().copied().unwrap_or_else(maker_out);
    let second = ids.as_slice().get(1).copied().unwrap_or_else(taker_out);
    let third = ids.as_slice().get(2).copied().unwrap_or_else(extra_out);

    FixedStore::empty(
        [MAKER_COIN, TAKER_COIN, EXTRA_COIN, first, second, third],
        [edge_id],
    )
}

fn coin_store() -> FixedStore<6, 0> {
    FixedStore::empty(
        [
            MAKER_COIN,
            TAKER_COIN,
            EXTRA_COIN,
            maker_out(),
            taker_out(),
            extra_out(),
        ],
        [],
    )
}
