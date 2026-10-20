//! Random operation sequences against a Rust reference model.
//!
//! This test runs `proptest-state-machine` over a closed enum of kernel
//! operations, applies each to both the kernel and a `BTreeMap`-backed
//! reference, and asserts the two agree on the exact live coin/edge sets
//! after every step. The reference encodes the intended semantics in
//! straight Rust — no signatures and no fee math — so divergence from the
//! kernel surfaces as a bug in either side.
//!
//! Unlike the fixed-scenario suites (`tests/channel*`, `tests/itf.rs`,
//! `tests/stateright.rs`), every case here draws fresh scenario
//! parameters: funding values, the committed timeout height and timeout
//! split, and per-close mutual splits. The kernel context tracks the
//! reference height, so timeout gating is exercised at whatever heights
//! the generator lands on rather than at two pinned constants.

#![allow(clippy::alloc_instead_of_core)]
#![allow(clippy::disallowed_types)]
#![allow(clippy::expect_used)]
#![allow(clippy::std_instead_of_alloc)]
#![allow(clippy::std_instead_of_core)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::indexing_slicing)] // tests may index; the panic-freedom lock targets src

mod support;

use std::collections::BTreeMap;

use hellas_kernel::{
    BlockHash, BlockHeight, CoinId, Context, EdgeId, Funding, Genesis, Key, List, MAX_EDGE_OUTPUTS,
    Parties, PartyKeys, Payout, Proof, ProtocolCode, State, Terms, Tx,
};
use proptest::prelude::*;
use proptest::test_runner::Config;
use proptest_state_machine::{ReferenceStateMachine, StateMachineTest, prop_state_machine};
use support::{
    FAKE_VERIFIER, coin_id, list,
    map_store::{MapStore, map_state},
    open_tx, placeholder_mutual,
};

const MAKER: Key = Key::from_bytes([7; Key::LENGTH]);
const TAKER: Key = Key::from_bytes([8; Key::LENGTH]);
const PARTIES: Parties = Parties::new(PartyKeys::sole(MAKER), PartyKeys::sole(TAKER));
const PROTOCOL: ProtocolCode = ProtocolCode::new(1);
const MAKER_COIN: CoinId = coin_id(1);
const TAKER_COIN: CoinId = coin_id(2);

/// Scenario parameters drawn once per proptest case.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Params {
    maker_value: u64,
    taker_value: u64,
    /// Committed timeout height; opens happen strictly below it.
    timeout: u64,
    /// Maker's share of the committed timeout payouts.
    timeout_maker_pay: u64,
}

impl Params {
    const fn total(self) -> u64 {
        self.maker_value + self.taker_value
    }

    fn terms(self) -> Terms {
        Terms::basic(
            PROTOCOL,
            PARTIES,
            BlockHeight::new(self.timeout),
            payouts(
                self.timeout_maker_pay,
                self.total() - self.timeout_maker_pay,
            ),
        )
    }

    fn edge_id(self) -> EdgeId {
        Tx::edge_id_of(&funding(), &self.terms())
    }
}

fn payouts(maker_pay: u64, taker_pay: u64) -> List<Payout, MAX_EDGE_OUTPUTS> {
    list(&[Payout::new(MAKER, maker_pay), Payout::new(TAKER, taker_pay)])
}

fn funding() -> Funding {
    Funding::new(list(&[MAKER_COIN]), list(&[TAKER_COIN]))
}

const fn context_at(height: u64) -> Context {
    Context::new(
        support::NETWORK,
        BlockHeight::new(height),
        BlockHash::from_bytes([0; BlockHash::LENGTH]),
    )
}

fn open_op(params: Params) -> Tx {
    open_tx(funding(), params.terms(), MAKER, TAKER)
}

fn timeout_close(params: Params) -> Tx {
    let outputs = payouts(
        params.timeout_maker_pay,
        params.total() - params.timeout_maker_pay,
    );
    Tx::close(params.edge_id(), Proof::timeout(params.terms()), outputs)
}

fn mutual_close(params: Params, maker_pay: u64) -> Tx {
    let edge = params.edge_id();
    let outputs = payouts(maker_pay, params.total() - maker_pay);
    let proof = placeholder_mutual(edge, params.terms().hash(), &outputs, MAKER, TAKER);
    Tx::close(edge, proof, outputs)
}

// Reference model -----------------------------------------------------------

/// Live state, no fees, no signatures. The reference assumes every operation
/// it accepts the kernel will also accept; the kernel acceptance set is a
/// strict subset (proof verification, fee math, etc.). When the reference
/// applies a transition, the kernel must reach the identical live state.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RefState {
    params: Params,
    coins: BTreeMap<CoinId, (Key, u64)>,
    /// Locked value while the edge is live.
    edge: Option<u64>,
    height: u64,
}

impl RefState {
    fn genesis(params: Params) -> Self {
        let mut coins = BTreeMap::new();
        coins.insert(MAKER_COIN, (MAKER, params.maker_value));
        coins.insert(TAKER_COIN, (TAKER, params.taker_value));
        Self {
            params,
            coins,
            edge: None,
            height: 1,
        }
    }

    fn funding_live(&self) -> bool {
        self.coins.contains_key(&MAKER_COIN) && self.coins.contains_key(&TAKER_COIN)
    }

    fn close_into(&mut self, maker_pay: u64) {
        let edge = self.params.edge_id();
        self.edge = None;
        for (index, payout) in payouts(maker_pay, self.params.total() - maker_pay)
            .iter()
            .enumerate()
        {
            self.coins
                .insert(payout.id(edge, index), (payout.owner(), payout.value()));
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum Transition {
    /// Lock both genesis coins under the drawn terms. Requires the
    /// committed timeout to still be in the future.
    Open,
    /// Resolve at the committed timeout split; height must have reached
    /// the timeout.
    CloseTimeout,
    /// Cooperative close at an arbitrary conserving split, before the
    /// timeout.
    CloseMutual {
        maker_pay: u64,
    },
    Tick,
}

struct L1Reference;

impl ReferenceStateMachine for L1Reference {
    type State = RefState;
    type Transition = Transition;

    fn init_state() -> BoxedStrategy<Self::State> {
        (0..=100_u64, 0..=100_u64, 2..=6_u64, 0..=201_u64)
            .prop_map(|(maker_value, taker_value, timeout, split_seed)| {
                let params = Params {
                    maker_value,
                    taker_value,
                    timeout,
                    timeout_maker_pay: split_seed % (maker_value + taker_value + 1),
                };
                RefState::genesis(params)
            })
            .boxed()
    }

    fn transitions(state: &Self::State) -> BoxedStrategy<Self::Transition> {
        let tick = || Just(Transition::Tick).boxed();
        let open = if state.funding_live() && state.height < state.params.timeout {
            Just(Transition::Open).boxed()
        } else {
            tick()
        };
        let timeout = if state.edge.is_some() && state.height >= state.params.timeout {
            Just(Transition::CloseTimeout).boxed()
        } else {
            tick()
        };
        let mutual = if state.edge.is_some() && state.height < state.params.timeout {
            (0..=state.params.total())
                .prop_map(|maker_pay| Transition::CloseMutual { maker_pay })
                .boxed()
        } else {
            tick()
        };

        prop_oneof![1 => tick(), 2 => open, 2 => timeout, 3 => mutual].boxed()
    }

    fn apply(mut state: Self::State, transition: &Self::Transition) -> Self::State {
        match transition {
            Transition::Open => {
                let maker = state
                    .coins
                    .remove(&MAKER_COIN)
                    .expect("Open precondition: maker coin present");
                let taker = state
                    .coins
                    .remove(&TAKER_COIN)
                    .expect("Open precondition: taker coin present");
                state.edge = Some(maker.1 + taker.1);
            }
            Transition::CloseTimeout => state.close_into(state.params.timeout_maker_pay),
            Transition::CloseMutual { maker_pay } => state.close_into(*maker_pay),
            Transition::Tick => state.height += 1,
        }
        state
    }

    fn preconditions(state: &Self::State, transition: &Self::Transition) -> bool {
        match transition {
            Transition::Open => {
                state.edge.is_none() && state.funding_live() && state.height < state.params.timeout
            }
            Transition::CloseTimeout => {
                state.edge.is_some() && state.height >= state.params.timeout
            }
            Transition::CloseMutual { maker_pay } => {
                state.edge.is_some()
                    && state.height < state.params.timeout
                    && *maker_pay <= state.params.total()
            }
            Transition::Tick => true,
        }
    }
}

// SUT -----------------------------------------------------------------------

struct L1Test;

impl StateMachineTest for L1Test {
    type SystemUnderTest = State<MapStore>;
    type Reference = L1Reference;

    fn init_test(
        ref_state: &<Self::Reference as ReferenceStateMachine>::State,
    ) -> Self::SystemUnderTest {
        map_state([
            Genesis::coin(MAKER_COIN, MAKER, ref_state.params.maker_value),
            Genesis::coin(TAKER_COIN, TAKER, ref_state.params.taker_value),
        ])
    }

    fn apply(
        mut sut: Self::SystemUnderTest,
        ref_state: &<Self::Reference as ReferenceStateMachine>::State,
        transition: <Self::Reference as ReferenceStateMachine>::Transition,
    ) -> Self::SystemUnderTest {
        // `ref_state` is the post-transition state; only `Tick` changes
        // height, so for the kernel-visible transitions the post-height
        // equals the height the operation must apply at.
        let params = ref_state.params;
        let context = context_at(ref_state.height);
        match transition {
            Transition::Open => {
                sut.apply(context, &FAKE_VERIFIER, &open_op(params))
                    .expect("kernel rejected Open that ref accepted");
            }
            Transition::CloseTimeout => {
                sut.apply(context, &FAKE_VERIFIER, &timeout_close(params))
                    .expect("kernel rejected CloseTimeout that ref accepted");
            }
            Transition::CloseMutual { maker_pay } => {
                sut.apply(context, &FAKE_VERIFIER, &mutual_close(params, maker_pay))
                    .expect("kernel rejected CloseMutual that ref accepted");
            }
            Transition::Tick => {}
        }
        sut
    }

    fn check_invariants(
        sut: &Self::SystemUnderTest,
        ref_state: &<Self::Reference as ReferenceStateMachine>::State,
    ) {
        // Exact live coin set: same cardinality, same (owner, value) per id.
        let store = sut.store();
        assert_eq!(store.coin_count(), ref_state.coins.len(), "live coin set");
        for (id, (owner, value)) in &ref_state.coins {
            let coin = store
                .coin(*id)
                .unwrap_or_else(|| panic!("kernel missing coin {id:?}"));
            assert_eq!(coin.owner(), *owner, "coin {id:?} owner");
            assert_eq!(coin.value(), *value, "coin {id:?} value");
        }

        // Exact live edge set (zero or one).
        match ref_state.edge {
            Some(value) => {
                let edge = store
                    .edge(ref_state.params.edge_id())
                    .expect("kernel missing the live edge");
                assert_eq!(edge.value(), value, "edge locked value");
                assert_eq!(store.edge_count(), 1, "live edge set");
            }
            None => assert_eq!(store.edge_count(), 0, "live edge set"),
        }

        // The map-backed store accepts any chunk id, so this catches a
        // registry write to *any* slot, derived or not — the reference
        // machine models coins and edges and has no registry state for
        // a chunk to correspond to.
        assert_eq!(
            store.registry_chunk_count(),
            0,
            "reference machine has no registry state, kernel wrote some",
        );
    }
}

prop_state_machine! {
    #![proptest_config(Config {
        cases: 64,
        max_shrink_iters: 256,
        ..Config::default()
    })]

    #[test]
    fn random_op_sequences_match_reference(sequential 1..32 => L1Test);
}
