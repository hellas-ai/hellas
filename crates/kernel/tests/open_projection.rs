//! What [`open_projection`] says an open will do, against what the open
//! path actually does.
//!
//! Two halves, and both are needed.
//!
//! The **differential** half opens real transactions against a real
//! store and requires the projection to have named, in advance, the
//! exact edge id, the exact locked value, reserve and committed
//! close-fee schedule, the exact timeout payout the terms had to commit,
//! and the exact rejection for every input the chain refuses. That is
//! what catches a projection whose plumbing reaches for the wrong
//! funding count, the wrong cost function, or the wrong half of a party
//! split.
//!
//! The **vector** half pins the same quantities to numbers computed by
//! hand from the fee schedule, and it is not redundant. Projection and
//! consensus deliberately share one implementation of every formula
//! here, so a change to a shared formula moves both answers together and
//! no differential could see it. The vectors are the independent
//! restatement: perturb the open cost, the reserve cost, the lifetime
//! rent, the timeout close price, or the value subtraction, and exactly
//! these assertions fail.
//!
//! Every schedule but one is nonzero. The deployed chain compiles
//! `KERNEL_FEES = Fees::ZERO`, and a suite that exercised only that
//! would pass against an implementation that had quietly dropped a term.
//!
//! On the development filesystem this repo lives on, `cargo` has been
//! seen to reuse a stale prebuilt binary and report failures the current
//! source does not produce; if these fail inexplicably, `touch` a source
//! file and confirm the run says "Compiling" before believing it.

#![allow(clippy::alloc_instead_of_core)]
#![allow(clippy::disallowed_types)]
#![allow(clippy::std_instead_of_alloc)]
#![allow(clippy::std_instead_of_core)]
#![allow(clippy::indexing_slicing)] // tests may index; the panic-freedom lock targets src

mod support;

use hellas_kernel::{
    ApplyError, ApplyOutcome, BOND_LEASE_CHUNKS, BlockHash, BlockHeight, CoinId, Context, EdgeId,
    EventKind, Fees, Genesis, InvalidOpenReason, Key, List, MAX_EDGE_OUTPUTS, MAX_PARTY_INPUTS,
    OpenFunding, OpenProjection, Parties, PartyKeys, Payout, ProtocolCode, RegistryChunkId, State,
    Terms, TermsProfile, Tx, WorkPaymentTerms, WorkStakeBondTerms, bond_lease_slots,
    open_projection, work_payment_settlement,
};
use support::{FAKE_VERIFIER, FixedStore, NETWORK, coin_id, key, open, state};

const CLIENT: Key = key(7);
const PROVIDER: Key = key(8);
const PROTOCOL: ProtocolCode = ProtocolCode::new(1);

/// Funding owned by whichever party the case's terms name as maker, one
/// id per slot the widest case uses.
const MAKER_COINS: [CoinId; 3] = [coin_id(0x11), coin_id(0x12), coin_id(0x13)];
/// Funding owned by the case's taker.
const TAKER_COINS: [CoinId; 2] = [coin_id(0x21), coin_id(0x22)];
/// The provider's stake, spent by the bond a payment channel leases.
const BOND_COIN: CoinId = coin_id(0x31);
const BOND_FUNDING: u64 = 900;

/// Inside `[MIN_OMIT_RESPONSE_BLOCKS, MAX_OMIT_RESPONSE_BLOCKS]` and
/// `(0, MAX_START_VALIDITY_BLOCKS]`: this suite is about arithmetic, and
/// a window rejection would hide it.
const OMIT_RESPONSE_BLOCKS: u64 = 64;
const START_VALIDITY_BLOCKS: u64 = 8;
const OMISSION_BOND: u64 = 2;

/// The fee schedules every shape is opened under.
///
/// `ZERO` because it is what the chain deploys; the rest because it is
/// not what the chain may assume. `(2, 5, 7, 11)` prices all four
/// dimensions distinctly, so a formula that swapped two of them cannot
/// coincide with the right answer; the last two isolate a single
/// dimension each.
const SCHEDULES: [Fees; 5] = [
    Fees::ZERO,
    Fees::new(1, 3, 0, 3),
    Fees::new(2, 5, 7, 11),
    Fees::new(0, 0, 0, 4),
    Fees::new(9, 0, 0, 0),
];

const HEIGHT: BlockHeight = BlockHeight::new(1);
const HORIZON: BlockHeight = BlockHeight::new(6);

/// Funding fanouts across the two party lists, all summing to the same
/// total so the fanout is the only thing that moves.
const FANOUTS: [(&[u64], &[u64]); 5] = [
    (&[900], &[]),
    (&[], &[900]),
    (&[400, 500], &[]),
    (&[400], &[500]),
    (&[100, 200, 300], &[150, 150]),
];

/// The same totals for the shapes that admit maker funding only.
const MAKER_FANOUTS: [&[u64]; 3] = [&[900], &[400, 500], &[100, 200, 300]];

/// Six coin slots, two edges — the open's own and the bond a payment
/// leases — and the bond's two lease chunks.
type CaseStore = FixedStore<6, 2, { BOND_LEASE_CHUNKS as usize }>;

// ── The differential ──────────────────────────────────────────────────

/// Basic terms, every funding fanout the party lists admit, every
/// payout fanout, every schedule.
#[test]
fn projection_matches_apply_for_basic_opens() {
    for fees in SCHEDULES {
        for (maker, taker) in FANOUTS {
            for payouts in 1..=MAX_EDGE_OUTPUTS {
                let terms = basic_terms(fees, &funding_of(maker, taker), payouts);
                assert_projection_matches_apply(fees, maker, taker, &terms);
            }
        }
    }
}

/// A tag-4 bond: provider-funded only, every payout back to the
/// provider, and a timeout that reads both lease chunks and so costs
/// more slots than any other shape's.
#[test]
fn projection_matches_apply_for_work_stake_bonds() {
    for fees in SCHEDULES {
        for maker in MAKER_FANOUTS {
            for payouts in 1..=MAX_EDGE_OUTPUTS {
                let terms = bond_terms(fees, &funding_of(maker, &[]), payouts);
                assert_projection_matches_apply(fees, maker, &[], &terms);
            }
        }
    }
}

/// A tag-2 payment edge, against a bond posted first under the same
/// schedule. No timeout payout to require, four fixed close slots to
/// reserve, and a capacity the projection's values have to reproduce
/// through the landed settlement helper.
#[test]
fn projection_matches_apply_for_work_payments() {
    for fees in SCHEDULES {
        for maker in MAKER_FANOUTS {
            let bond_funding = priced_one(BOND_COIN, BOND_FUNDING);
            let bond = bond_terms(fees, &bond_funding, 1);
            let bond_edge = Tx::edge_id_of(&bond_funding.funding(), &bond);
            let terms = payment_terms(bond_edge, &bond);

            let funding = funding_of(maker, &[]);
            let projection = project(fees, &funding, &terms);
            let mut state = case_state(&terms, projection.edge(), bond_edge, maker, &[]);
            let Ok(_posted) =
                state.apply(context(fees), &FAKE_VERIFIER, &signed(&bond_funding, &bond))
            else {
                panic!("the bond a payment leases opens first");
            };

            let outcome = apply_open(&mut state, fees, &funding, &terms);
            assert_edge_matches(&state, &outcome, &projection);
            assert_debits_account_for(&projection, total(maker, &[]));
            assert_eq!(
                projection.timeout_payout(),
                None,
                "a payment has no timeout"
            );

            // The reason an endpoint asks for a projection at all: it
            // must know the capacity before it signs anything, and
            // capacity is read off exactly these three numbers.
            let Some(settlement) = work_payment_settlement(projection.values(), OMISSION_BOND)
            else {
                panic!("a live payment edge settles");
            };
            assert!(
                settlement.capacity() > 0,
                "an admitted payment channel has capacity",
            );
        }
    }
}

/// The timeout payout is a requirement, not a suggestion: the total the
/// projection names opens, and the two totals either side of it are
/// refused as [`InvalidOpenReason::TermsValueMismatch`].
///
/// This is what makes the number trustworthy to a caller writing terms
/// it has not signed yet.
#[test]
fn projection_names_the_exact_timeout_payout_apply_requires() {
    for fees in SCHEDULES {
        for payouts in 1..=MAX_EDGE_OUTPUTS {
            let maker = MAKER_FANOUTS[0];
            let funding = funding_of(maker, &[]);
            let terms = basic_terms(fees, &funding, payouts);
            let projection = project(fees, &funding, &terms);
            let Some(required) = projection.timeout_payout() else {
                panic!("basic terms commit a timeout payout");
            };
            assert_eq!(committed_payout(&terms), required);

            for wrong in [required - 1, required + 1] {
                let terms = Terms::basic(
                    PROTOCOL,
                    parties(),
                    HORIZON,
                    payouts_summing_to(wrong, payouts, CLIENT),
                );
                let mut state = case_state(
                    &terms,
                    Tx::edge_id_of(&funding.funding(), &terms),
                    unused_edge(),
                    maker,
                    &[],
                );
                assert_eq!(
                    reject(&mut state, fees, &funding, &terms),
                    InvalidOpenReason::TermsValueMismatch,
                );
            }
        }
    }
}

/// Every rejection the projection claims to reproduce, reproduced.
///
/// Each case moves exactly one thing: a funding total one unit below
/// what the debits come to, a sum that wraps, a horizon that is not in
/// the future, and one overflow per fee dimension. The projection's
/// error and the chain's must be the same value, not merely both errors.
#[test]
fn projection_returns_the_rejection_apply_returns() {
    let cases: [(&str, Fees, BlockHeight, &[u64], InvalidOpenReason); 6] = [
        (
            "funding one unit short",
            BOUNDARY_FEES,
            HORIZON,
            &[EXACT_DEBITS - 1],
            InvalidOpenReason::FundingInsufficient,
        ),
        (
            "funding sum wraps u64",
            Fees::ZERO,
            HORIZON,
            &[u64::MAX, u64::MAX],
            InvalidOpenReason::FundingOverflow,
        ),
        (
            "horizon is the open block",
            BOUNDARY_FEES,
            HEIGHT,
            &[900],
            InvalidOpenReason::TimeoutNotFuture,
        ),
        (
            "open fee wraps",
            Fees::new(u64::MAX, u64::MAX, 0, 0),
            HORIZON,
            &[900],
            InvalidOpenReason::FeeOverflow,
        ),
        (
            // A one-coin basic open touches two slots and reserves
            // five, so a slot price that wraps the reserve leaves the
            // open fee finite. Nothing else separates these two
            // overflows: both charge the same two proof units.
            "reserve wraps",
            Fees::new(0, u64::MAX / 4, 0, 0),
            HORIZON,
            &[900],
            InvalidOpenReason::ReserveOverflow,
        ),
        (
            "lifetime rent wraps",
            Fees::new(0, 0, 0, u64::MAX),
            HORIZON,
            &[900],
            InvalidOpenReason::LifetimeFeeOverflow,
        ),
    ];

    for (name, fees, horizon, maker, reason) in cases {
        let funding = funding_of(maker, &[]);
        let terms = Terms::basic(
            PROTOCOL,
            parties(),
            horizon,
            payouts_summing_to(0, 1, CLIENT),
        );
        assert_eq!(
            open_projection(HEIGHT, fees, &funding, &terms),
            Err(reason),
            "{name}: projection",
        );
        let mut state = case_state(
            &terms,
            Tx::edge_id_of(&funding.funding(), &terms),
            unused_edge(),
            maker,
            &[],
        );
        assert_eq!(
            reject(&mut state, fees, &funding, &terms),
            reason,
            "{name}: apply",
        );
    }
}

/// Funding exactly equal to the debits opens a zero-value edge; one unit
/// less does not open at all. Both answers come from the projection
/// before either is submitted.
#[test]
fn projection_matches_apply_at_the_funding_boundary() {
    let funding = funding_of(&[EXACT_DEBITS], &[]);
    let terms = basic_terms(BOUNDARY_FEES, &funding, 1);
    let projection = project(BOUNDARY_FEES, &funding, &terms);
    assert_eq!(projection.values().value(), 0);
    assert_projection_matches_apply(BOUNDARY_FEES, &[EXACT_DEBITS], &[], &terms);
}

/// The open fee, lifetime rent, reserve, principal and timeout payout of
/// three opens, every number computed here from the schedule rather
/// than read back from the kernel.
///
/// This is the half a shared implementation cannot check against itself.
#[test]
fn projected_numbers_match_independently_computed_vectors() {
    // Basic, two coins totalling 114, opened at height 1 with a horizon
    // of 4. Open cost {base 1, slots 2+1, proofs 2} at (2,5,7,11):
    // 2 + 15 + 14 = 31. Rent: 11 a block for 3 blocks = 33. Reserve
    // cost {1, 5, 2}: 2 + 25 + 14 = 41. Principal: 114 - 31 - 33 - 41
    // = 9. A two-payout timeout costs {1, 2+1, 1} = 2 + 15 + 7 = 24, so
    // it distributes 9 + (41 - 24) = 26.
    let funding = funding_of(&[44, 70], &[]);
    let terms = Terms::basic(
        PROTOCOL,
        parties(),
        BlockHeight::new(4),
        payouts_summing_to(26, 2, CLIENT),
    );
    let projection = project(Fees::new(2, 5, 7, 11), &funding, &terms);
    assert_eq!(projection.open_fee(), 31);
    assert_eq!(projection.lifetime_fee(), 33);
    assert_eq!(projection.values().reserve(), 41);
    assert_eq!(projection.values().value(), 9);
    assert_eq!(projection.timeout_payout(), Some(26));

    // The same funding as a tag-4 bond at (1,3,0,3) with a horizon of 5.
    // A bond is charged two proof units, reserves eight slots because
    // its timeout reads both lease chunks and the payment edge a lease
    // names, and here commits one payout: open 1 + 3*3 = 10, rent
    // 3*4 = 12, reserve 1 + 3*8 = 25, principal 114 - 10 - 12 - 25 = 67.
    // Its one-payout timeout costs 1 + 3*(1+4) = 16, so it distributes
    // 67 + (25 - 16) = 76.
    let terms = Terms::work_stake_bond(WorkStakeBondTerms {
        parties: parties(),
        timeout: BlockHeight::new(5),
        timeout_outputs: payouts_summing_to(76, 1, CLIENT),
        max_job_price: 4,
    });
    let projection = project(Fees::new(1, 3, 0, 3), &funding, &terms);
    assert_eq!(projection.open_fee(), 10);
    assert_eq!(projection.lifetime_fee(), 12);
    assert_eq!(projection.values().reserve(), 25);
    assert_eq!(projection.values().value(), 67);
    assert_eq!(projection.timeout_payout(), Some(76));

    // A payment against a bond expiring at 5, at (2,5,7,11): its open
    // touches four more slots than a basic one, 2 + 5*5 + 14 = 41; rent
    // 11*4 = 44; reserve is its dearer exit {1, 4, 2} = 2 + 20 + 14 = 36.
    // Principal 500 - 41 - 44 - 36 = 379. Freeze verifies two signatures
    // and Adjudicated one, so the routes distribute 379 + (36 - 36) and
    // 379 + (36 - 29); capacity is the smaller, less the bond.
    //
    // Projection only: no bond is posted here, because none of this
    // arithmetic reads one. The chain's live-bond and lease rules are
    // exercised by the differential above.
    let terms = payment_terms(
        unused_edge(),
        &Terms::work_stake_bond(WorkStakeBondTerms {
            parties: Parties::new(PartyKeys::sole(PROVIDER), PartyKeys::sole(CLIENT)),
            timeout: BlockHeight::new(5),
            timeout_outputs: payouts_summing_to(1, 1, PROVIDER),
            max_job_price: 4,
        }),
    );
    let projection = project(Fees::new(2, 5, 7, 11), &funding_of(&[500], &[]), &terms);
    assert_eq!(projection.open_fee(), 41);
    assert_eq!(projection.lifetime_fee(), 44);
    assert_eq!(projection.values().reserve(), 36);
    assert_eq!(projection.values().value(), 379);
    assert_eq!(projection.timeout_payout(), None);
    let Some(settlement) = work_payment_settlement(projection.values(), OMISSION_BOND) else {
        panic!("the payment vector settles");
    };
    assert_eq!(settlement.freeze_total(), 379);
    assert_eq!(settlement.adjudicated_total(), 386);
    assert_eq!(settlement.capacity(), 379 - OMISSION_BOND);
}

/// The id an endpoint signs against is the id the chain derives, and it
/// moves with the funding order as well as with the terms.
#[test]
fn projected_edge_id_is_the_derived_edge_id() {
    let fees = Fees::new(2, 5, 7, 11);
    let funding = funding_of(&[400, 500], &[]);
    let terms = basic_terms(fees, &funding, 1);
    let projection = project(fees, &funding, &terms);
    assert_eq!(
        projection.edge(),
        Tx::edge_id_of(&funding.funding(), &terms)
    );

    let swapped = OpenFunding::new(
        priced(&[MAKER_COINS[1], MAKER_COINS[0]], &[500, 400]),
        priced(&[], &[]),
    );
    assert_ne!(project(fees, &swapped, &terms).edge(), projection.edge());
}

// ── Harness ───────────────────────────────────────────────────────────

/// The schedule the funding-boundary cases are priced under.
const BOUNDARY_FEES: Fees = Fees::new(1, 3, 0, 3);

/// Exactly the three debits of a one-coin, one-payout basic open at
/// [`BOUNDARY_FEES`] over the five blocks to [`HORIZON`]: open
/// 1 + 3*2 = 7, rent 3*5 = 15, reserve 1 + 3*5 = 16.
const EXACT_DEBITS: u64 = 7 + 15 + 16;

const fn parties() -> Parties {
    Parties::new(PartyKeys::sole(CLIENT), PartyKeys::sole(PROVIDER))
}

const fn context(fees: Fees) -> Context {
    Context::with_fees(
        NETWORK,
        HEIGHT,
        BlockHash::from_bytes([0; BlockHash::LENGTH]),
        fees,
    )
}

fn total(maker: &[u64], taker: &[u64]) -> u64 {
    maker.iter().chain(taker).sum()
}

fn funding_of(maker: &[u64], taker: &[u64]) -> OpenFunding {
    OpenFunding::new(priced(&MAKER_COINS, maker), priced(&TAKER_COINS, taker))
}

fn priced_one(id: CoinId, value: u64) -> OpenFunding {
    OpenFunding::new(priced(&[id], &[value]), priced(&[], &[]))
}

fn priced(ids: &[CoinId], values: &[u64]) -> List<(CoinId, u64), MAX_PARTY_INPUTS> {
    let mut buf = [(CoinId::from_bytes([0; CoinId::LENGTH]), 0); MAX_PARTY_INPUTS];
    for (slot, (id, value)) in buf.iter_mut().zip(ids.iter().zip(values)) {
        *slot = (*id, *value);
    }
    let Some(coins) = List::new(buf, values.len()) else {
        panic!("case funds more coins than one party may");
    };
    coins
}

/// Basic terms whose committed timeout payouts sum to exactly what an
/// edge funded this way requires.
///
/// The two-pass construction the projection exists to make possible: a
/// draft fixes the horizon, the profile and the payout fanout — the only
/// three things the requirement depends on — and the second pass writes
/// payouts satisfying the number the first pass returned.
fn basic_terms(fees: Fees, funding: &OpenFunding, payouts: usize) -> Terms {
    let body = |outputs| Terms::basic(PROTOCOL, parties(), HORIZON, outputs);
    let draft = body(payouts_summing_to(0, payouts, CLIENT));
    let required = required_payout(fees, funding, &draft);
    body(payouts_summing_to(required, payouts, CLIENT))
}

/// A tag-4 bond, whose payouts must return the whole stake to the
/// provider and to nobody else.
fn bond_terms(fees: Fees, funding: &OpenFunding, payouts: usize) -> Terms {
    let body = |outputs| {
        Terms::work_stake_bond(WorkStakeBondTerms {
            parties: Parties::new(PartyKeys::sole(PROVIDER), PartyKeys::sole(CLIENT)),
            timeout: HORIZON,
            timeout_outputs: outputs,
            max_job_price: 4,
        })
    };
    let draft = body(payouts_summing_to(0, payouts, PROVIDER));
    let required = required_payout(fees, funding, &draft);
    body(payouts_summing_to(required, payouts, PROVIDER))
}

/// The payment edge insured by `bond`, whose complete body it embeds.
fn payment_terms(bond_edge: EdgeId, bond: &Terms) -> Terms {
    let TermsProfile::WorkStakeBond(body) = bond.profile() else {
        panic!("a payment is insured by a bond");
    };
    Terms::work_payment(WorkPaymentTerms {
        bond_edge,
        bond_terms: body.clone(),
        private_policy_commitment: [4; 32],
        omit_response_blocks: OMIT_RESPONSE_BLOCKS,
        start_validity_blocks: START_VALIDITY_BLOCKS,
        omission_bond: OMISSION_BOND,
    })
}

/// The timeout payout a draft's shape requires, read from the projection
/// rather than recomputed here.
fn required_payout(fees: Fees, funding: &OpenFunding, draft: &Terms) -> u64 {
    let Some(required) = project(fees, funding, draft).timeout_payout() else {
        panic!("this shape commits a timeout payout");
    };
    required
}

/// `total` on the first payout and nothing on the rest. The kernel pins
/// the sum, so the split is free; the fanout is not, because it prices
/// the timeout close.
fn payouts_summing_to(total: u64, fanout: usize, owner: Key) -> List<Payout, MAX_EDGE_OUTPUTS> {
    let mut buf = [Payout::new(owner, 0); MAX_EDGE_OUTPUTS];
    buf[0] = Payout::new(owner, total);
    let Some(outputs) = List::new(buf, fanout) else {
        panic!("case commits more payouts than an edge may");
    };
    outputs
}

fn committed_payout(terms: &Terms) -> u64 {
    let Some(outputs) = terms.timeout_outputs() else {
        panic!("this shape commits a timeout payout");
    };
    outputs.iter().map(|payout| payout.value()).sum()
}

fn project(fees: Fees, funding: &OpenFunding, terms: &Terms) -> OpenProjection {
    match open_projection(HEIGHT, fees, funding, terms) {
        Ok(projection) => projection,
        Err(reason) => panic!("the case projects: {reason:?}"),
    }
}

/// An edge id no case opens, for the store slot a shape without a bond
/// leaves unused.
const fn unused_edge() -> EdgeId {
    EdgeId::from_bytes([0xee; EdgeId::LENGTH])
}

fn lease_slots(bond_edge: EdgeId) -> [RegistryChunkId; BOND_LEASE_CHUNKS as usize] {
    bond_lease_slots(NETWORK, bond_edge)
}

/// The store one case runs against: its own edge, the bond it may
/// lease, the six coins any case names, and the bond's two lease chunks.
///
/// Funding ownership follows the terms rather than a fixed table, so
/// every shape's coins belong to the party its own body names.
fn case_state(
    terms: &Terms,
    edge: EdgeId,
    bond_edge: EdgeId,
    maker: &[u64],
    taker: &[u64],
) -> State<CaseStore> {
    let store = FixedStore::empty_with_registry(
        [
            MAKER_COINS[0],
            MAKER_COINS[1],
            MAKER_COINS[2],
            TAKER_COINS[0],
            TAKER_COINS[1],
            BOND_COIN,
        ],
        [edge, bond_edge],
        lease_slots(bond_edge),
    );
    let parties = terms.parties();
    state(
        store,
        [
            Genesis::coin(MAKER_COINS[0], parties.maker().owner(), at(maker, 0)),
            Genesis::coin(MAKER_COINS[1], parties.maker().owner(), at(maker, 1)),
            Genesis::coin(MAKER_COINS[2], parties.maker().owner(), at(maker, 2)),
            Genesis::coin(TAKER_COINS[0], parties.taker().owner(), at(taker, 0)),
            Genesis::coin(TAKER_COINS[1], parties.taker().owner(), at(taker, 1)),
            Genesis::coin(BOND_COIN, PROVIDER, BOND_FUNDING),
        ],
    )
}

fn at(values: &[u64], index: usize) -> u64 {
    values.get(index).copied().unwrap_or_default()
}

/// The transaction a case submits, authorized by whichever keys its own
/// terms name.
fn signed(funding: &OpenFunding, terms: &Terms) -> Tx {
    let parties = terms.parties();
    open(
        funding.funding(),
        terms.clone(),
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

fn apply_open(
    state: &mut State<CaseStore>,
    fees: Fees,
    funding: &OpenFunding,
    terms: &Terms,
) -> ApplyOutcome {
    match state.apply(context(fees), &FAKE_VERIFIER, &signed(funding, terms)) {
        Ok(outcome) => outcome,
        Err(error) => panic!("the projected open was rejected: {error:?}"),
    }
}

fn reject(
    state: &mut State<CaseStore>,
    fees: Fees,
    funding: &OpenFunding,
    terms: &Terms,
) -> InvalidOpenReason {
    match state.apply(context(fees), &FAKE_VERIFIER, &signed(funding, terms)) {
        Err(ApplyError::InvalidOpen { reason, .. }) => reason,
        other => panic!("expected an invalid open, got {other:?}"),
    }
}

/// The whole differential for one case: project it, apply it, and
/// require the chain to have produced exactly what was projected.
fn assert_projection_matches_apply(fees: Fees, maker: &[u64], taker: &[u64], terms: &Terms) {
    let funding = funding_of(maker, taker);
    let projection = project(fees, &funding, terms);
    let mut state = case_state(terms, projection.edge(), unused_edge(), maker, taker);
    let outcome = apply_open(&mut state, fees, &funding, terms);

    assert_edge_matches(&state, &outcome, &projection);
    assert_debits_account_for(&projection, total(maker, taker));
    if let Some(required) = projection.timeout_payout() {
        assert_eq!(
            committed_payout(terms),
            required,
            "the terms committed the projected requirement",
        );
    }
}

/// The edge the chain opened is the edge that was projected: same id,
/// same principal, same reserve, same committed close-fee schedule.
fn assert_edge_matches(
    state: &State<CaseStore>,
    outcome: &ApplyOutcome,
    projection: &OpenProjection,
) {
    let Some(event) = outcome.public_event() else {
        panic!("an open announces the edge it produced");
    };
    let EventKind::EdgeOpened { output, .. } = event.kind() else {
        panic!("an open announces an open");
    };
    assert_eq!(*output, projection.edge(), "derived edge id");
    let Some(edge) = state.store().edge(projection.edge()) else {
        panic!("the projected edge is live");
    };
    assert_eq!(
        edge.values(),
        projection.values(),
        "principal, reserve, close-fee schedule",
    );
}

/// The three debits are the whole difference between what was funded and
/// what the edge locked. Nothing is charged that the projection did not
/// name, and nothing it named goes uncharged.
fn assert_debits_account_for(projection: &OpenProjection, funded: u64) {
    let values = projection.values();
    assert_eq!(
        funded,
        projection.open_fee() + projection.lifetime_fee() + values.reserve() + values.value(),
    );
}
