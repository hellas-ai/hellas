//! Work-channel terms: the tag-4 bond whose only exit is `Timeout`, and
//! the payment edge whose exits are `Freeze` and `Adjudicated`.
//!
//! On the development filesystem this repo lives on, `cargo` has been
//! seen to reuse a stale prebuilt binary for this target and report
//! payment-close failures that the current source does not produce; if
//! these fail inexplicably, `touch` a source file to force a recompile
//! and confirm the run says "Compiling" before believing it.

use super::*;
use hellas_kernel::{
    BOND_LEASE_CHUNKS, BondLease, BondLeaseFault, PartyAuth, PartyKeys, PaymentContestCommitment,
    SigVerifier, WorkPaymentTerms, WorkStakeBondTerms, bond_lease_slot, bond_lease_slots,
    check_response,
};
use std::cell::Cell;

/// A third key, party to nothing here.
const OUTSIDER: Key = Key::from_bytes([9; Key::LENGTH]);
const STAKE: u64 = 10;

/// The provider's stake coin, and the provider of a *payment* channel
/// is its taker: a bond funded from the maker's side would be the
/// client staking its own recourse.
const BOND_COIN: CoinId = coin_id(0x51);
const BOND_SEED: Genesis = Genesis::coin(BOND_COIN, TAKER, STAKE);

/// Provider = maker = `MAKER` (funds the stake), client = taker.
fn bond() -> WorkStakeBondTerms {
    WorkStakeBondTerms {
        parties: PARTIES,
        timeout: TIMEOUT,
        timeout_outputs: list(&[Payout::new(MAKER, STAKE)]),
        max_job_price: 4,
    }
}

fn work_terms_of(bond: WorkStakeBondTerms) -> Terms {
    Terms::work_stake_bond(bond)
}

fn work_terms() -> Terms {
    work_terms_of(bond())
}

fn work_funding() -> Funding {
    Funding::new(list(&[MAKER_COIN]), empty_party())
}

fn work_open() -> Tx {
    open_tx(work_funding(), work_terms())
}

fn work_edge() -> EdgeId {
    Tx::edge_id_of(&work_funding(), &work_terms())
}

/// The bond a payment channel leases: the same policy as
/// [`work_terms`], with the roles mirrored so the provider — the
/// payment's taker — is the one who stakes.
/// A live tag-4 bond, opened into a store sized for its timeout close.
/// The move tests use it as "a live edge that is not a payment
/// channel".
fn open_work_bond_state() -> State<FixedStore<6, 1>> {
    let outputs = list(&[Payout::new(MAKER, STAKE)]);
    let open = work_open();
    let mut state = state(store_for_close(&open, &outputs), [MAKER_SEED, TAKER_SEED]);
    let _event = apply(&mut state, &open);
    state
}

fn payment_bond() -> WorkStakeBondTerms {
    WorkStakeBondTerms {
        parties: Parties::new(PartyKeys::sole(TAKER), PartyKeys::sole(MAKER)),
        timeout_outputs: list(&[Payout::new(TAKER, STAKE)]),
        ..bond()
    }
}

fn payment_bond_terms() -> Terms {
    Terms::work_stake_bond(payment_bond())
}

/// The stake is the provider's alone, so the bond is funded from the
/// provider's own coin and its taker list is empty.
fn payment_bond_funding() -> Funding {
    Funding::new(list(&[BOND_COIN]), empty_party())
}

fn payment_bond_edge() -> EdgeId {
    Tx::edge_id_of(&payment_bond_funding(), &payment_bond_terms())
}

/// Authorized by the mirrored pair: this bond's maker is the payment
/// channel's taker, so the provider signs the maker side of it.
fn payment_bond_open() -> Tx {
    open_tx_with(
        payment_bond_funding(),
        payment_bond_terms(),
        (
            hellas_kernel::PartyKeys::sole(TAKER),
            hellas_kernel::Authority::Owner,
        ),
        (
            hellas_kernel::PartyKeys::sole(MAKER),
            hellas_kernel::Authority::Owner,
        ),
    )
}

/// The one payout an unleased or expired bond returns to its provider.
fn bond_timeout_outputs() -> List<Payout, MAX_EDGE_OUTPUTS> {
    list(&[Payout::new(TAKER, STAKE)])
}

fn bond_timeout_out() -> CoinId {
    nth(
        &Tx::close_output_ids(payment_bond_edge(), &bond_timeout_outputs()),
        0,
    )
}

fn bond_timeout_tx() -> Tx {
    Tx::close(
        payment_bond_edge(),
        Proof::timeout(payment_bond_terms(), None),
        bond_timeout_outputs(),
    )
}

/// Client-funded payment edge naming the provider's bond. Mirrored
/// roles: the payment maker is the bond's taker.
fn payment_of(mutate: impl FnOnce(&mut WorkPaymentTerms)) -> Terms {
    let mut payment = WorkPaymentTerms {
        bond_edge: payment_bond_edge(),
        bond_terms: payment_bond(),
        private_policy_commitment: [4; 32],
        omit_response_blocks: 64,
        start_validity_blocks: 8,
        omission_bond: 2,
    };
    mutate(&mut payment);
    Terms::work_payment(payment)
}

fn payment_terms() -> Terms {
    payment_of(|_| {})
}

fn payment_funding() -> Funding {
    Funding::new(list(&[MAKER_COIN]), empty_party())
}

#[test]
fn work_bond_open_locks_the_stake_under_its_own_close_kinds() {
    let open = work_open();
    let mut state = funded_state_for(&open);
    let _event = apply(&mut state, &open);

    let Some(edge) = state.store().edge(work_edge()) else {
        panic!("work bond edge live");
    };
    assert_eq!(edge.value(), STAKE);
    assert!(edge.allows(CloseKind::Timeout));
    assert!(!edge.allows(CloseKind::Mutual));
    assert!(!edge.allows(CloseKind::Freeze));
    assert!(!edge.allows(CloseKind::Adjudicated));
}

/// The whole of a tag-4 bond's own open policy, one mutation per
/// conjunct. Each case moves exactly one thing about an otherwise legal
/// bond, so no rule here can be satisfied by another.
#[test]
fn work_bond_open_checks_every_conjunct_of_its_policy() {
    let cases = [
        // A bond that can cover no job insures nothing.
        (
            work_terms_of(WorkStakeBondTerms {
                max_job_price: 0,
                ..bond()
            }),
            InvalidOpenReason::JobPriceCapZero,
        ),
        // Sum-preserving, party-changing: the stake would time out to
        // the client, who staked nothing.
        (
            work_terms_of(WorkStakeBondTerms {
                timeout_outputs: list(&[Payout::new(TAKER, STAKE)]),
                ..bond()
            }),
            InvalidOpenReason::WorkStakeReturnRouting,
        ),
    ];

    for (terms, reason) in cases {
        let funding = work_funding();
        let output = Tx::edge_id_of(&funding, &terms);
        let open = open_tx(funding, terms);
        let mut state = funded_state_for(&work_open());
        let store = *state.store();
        assert_eq!(
            state.apply(CONTEXT, &FAKE_VERIFIER, &open),
            Err(ApplyError::InvalidOpen { output, reason }),
        );
        assert_eq!(*state.store(), store);
    }
}

/// The stake is the edge's own value, so a bond funded only with a
/// worthless coin is refused as a zero-value stake rather than accepted
/// as a bond insuring nothing — and a bond funded with nothing at all is
/// refused before that, because its maker's owner is proved by nothing.
#[test]
fn work_bond_open_rejects_a_zero_value_stake() {
    let terms = work_terms_of(WorkStakeBondTerms {
        timeout_outputs: list(&[Payout::new(MAKER, 0)]),
        ..bond()
    });

    let unfunded = Funding::new(empty_party(), empty_party());
    let output = Tx::edge_id_of(&unfunded, &terms);
    let open = open_tx(unfunded, terms.clone());
    let mut empty = funded_state_for(&work_open());
    let store = *empty.store();
    assert_eq!(
        empty.apply(CONTEXT, &FAKE_VERIFIER, &open),
        Err(ApplyError::InvalidOpen {
            output,
            reason: InvalidOpenReason::WorkStakeMakerUnfunded,
        }),
    );
    assert_eq!(*empty.store(), store);

    let funding = Funding::new(list(&[EXTRA_COIN]), empty_party());
    let output = Tx::edge_id_of(&funding, &terms);
    let open = open_tx(funding, terms);
    let mut state = state(
        store_for(&open),
        [MAKER_SEED, TAKER_SEED, Genesis::coin(EXTRA_COIN, MAKER, 0)],
    );
    let store = *state.store();

    assert_eq!(
        state.apply(CONTEXT, &FAKE_VERIFIER, &open),
        Err(ApplyError::InvalidOpen {
            output,
            reason: InvalidOpenReason::WorkStakeValueZero,
        }),
    );
    assert_eq!(*state.store(), store);
}

/// The stake is the provider's alone: an unleased bond times out
/// permissionlessly, so a client contribution would be a gift to the
/// provider.
#[test]
fn work_bond_open_rejects_client_funding() {
    let terms = work_terms_of(WorkStakeBondTerms {
        timeout_outputs: list(&[Payout::new(MAKER, STAKE + 5)]),
        ..bond()
    });
    let funding = Funding::new(list(&[MAKER_COIN]), list(&[TAKER_COIN]));
    let output = Tx::edge_id_of(&funding, &terms);
    let open = open_tx(funding, terms);
    let mut state = funded_state_for(&work_open());
    let store = *state.store();

    assert_eq!(
        state.apply(CONTEXT, &FAKE_VERIFIER, &open),
        Err(ApplyError::InvalidOpen {
            output,
            reason: InvalidOpenReason::WorkStakeTakerFunded,
        }),
    );
    assert_eq!(*state.store(), store);
}

/// The payment edge has no timeout close and no payout fixed at open:
/// its horizon buys admission and rent, nothing else.
#[test]
fn work_payment_open_commits_freeze_and_adjudicated_only() {
    let terms = payment_terms();
    let funding = payment_funding();
    let edge_id = Tx::edge_id_of(&funding, &terms);
    let open = open_tx(funding, terms.clone());
    let mut state = bonded_state_for(edge_id);
    apply_payment_open(&mut state, &open);

    let Some(edge) = state.store().edge(edge_id) else {
        panic!("payment edge live");
    };
    assert_eq!(edge.value(), 10);
    assert!(edge.allows(CloseKind::Freeze));
    assert!(edge.allows(CloseKind::Adjudicated));
    assert!(!edge.allows(CloseKind::Timeout));
    assert!(!edge.allows(CloseKind::Mutual));
    assert_eq!(terms.timeout_outputs(), None);
    assert!(Tx::timeout_close(edge_id, &terms).is_none());
}

/// A payment is only as good as the bond it names. Its parties and its
/// horizon are *derived* from the embedded witness, so the cases here
/// are the bond's own policy plus this body's own windows.
#[test]
fn work_payment_open_rejects_a_bond_it_does_not_match() {
    let cases = [
        (
            payment_of(|payment| payment.bond_terms.max_job_price = 0),
            InvalidOpenReason::JobPriceCapZero,
        ),
        // A bond whose stake returns to a third key is not this
        // provider's stake.
        (
            payment_of(|payment| {
                payment.bond_terms.timeout_outputs = list(&[Payout::new(OUTSIDER, STAKE)]);
            }),
            InvalidOpenReason::WorkStakeReturnRouting,
        ),
        (
            payment_of(|payment| payment.omit_response_blocks = 0),
            InvalidOpenReason::WorkResponseWindowOutOfRange,
        ),
        (
            payment_of(|payment| {
                payment.omit_response_blocks = hellas_kernel::MAX_OMIT_RESPONSE_BLOCKS + 1;
            }),
            InvalidOpenReason::WorkResponseWindowOutOfRange,
        ),
        (
            payment_of(|payment| payment.start_validity_blocks = 0),
            InvalidOpenReason::WorkStartValidityOutOfRange,
        ),
        (
            payment_of(|payment| {
                payment.start_validity_blocks = hellas_kernel::MAX_START_VALIDITY_BLOCKS + 1;
            }),
            InvalidOpenReason::WorkStartValidityOutOfRange,
        ),
    ];

    for (terms, reason) in cases {
        let funding = payment_funding();
        let output = Tx::edge_id_of(&funding, &terms);
        let open = open_tx(funding, terms);
        let mut state = funded_state_for(&work_open());
        let store = *state.store();
        assert_eq!(
            state.apply(CONTEXT, &FAKE_VERIFIER, &open),
            Err(ApplyError::InvalidOpen { output, reason }),
        );
        assert_eq!(*state.store(), store);
    }
}

// ── The payment close ─────────────────────────────────────────────────
//
// One scalar is contested and one scalar is paid. The fixtures below
// build the whole vertical: a funded payment edge worth `PAYMENT_VALUE`,
// certificates the client signs against it, the two moves, and the two
// closes. Every amount here is chosen so the arithmetic is checkable by
// eye — capacity 8, bond 2, and a payout pair that always sums to 10.

use hellas_kernel::{
    Batch as _, Decode, EarnedCertificate, Encode as _, InvalidMoveReason, Move, NetworkId, Party,
    PaymentCloseResponse, PaymentCloseStart, PendingCloseFault, PendingPaymentClose, RegistryChunk,
    RegistryChunkId, RegistryNamespace, RegistryRecordTag, StartId, Store as _, freeze_digest,
    no_earned_digest, pending_payment_close_slot, response_digest, settlement_commitment,
    start_digest, start_id,
};

/// Value the payment edge locks: the client's whole funding coin, since
/// this fixture's fee schedule is zero.
const PAYMENT_VALUE: u64 = 10;
/// Omission bond `payment_of` commits.
const OMISSION_BOND: u64 = 2;
/// Largest certificate this channel may admit.
const PAYMENT_CAPACITY: u64 = PAYMENT_VALUE - OMISSION_BOND;
/// Response window `payment_of` commits.
const RESPONSE_WINDOW: u64 = 64;
/// Height every fixture opens and starts at.
const START_HEIGHT: u64 = 1;
/// Height the response window shuts at.
const RESPONSE_DEADLINE: u64 = START_HEIGHT + RESPONSE_WINDOW;
/// Validity span `payment_of` commits for a start.
const START_VALIDITY: (u64, u64) = (START_HEIGHT, START_HEIGHT);

const fn at(height: u64) -> Context {
    Context::new(
        support::NETWORK,
        BlockHeight::new(height),
        BlockHash::from_bytes([0; BlockHash::LENGTH]),
    )
}

fn payment_edge_id() -> EdgeId {
    Tx::edge_id_of(&payment_funding(), &payment_terms())
}

fn payment_terms_hash() -> TermsHash {
    payment_terms().hash()
}

fn pending_slot() -> RegistryChunkId {
    pending_payment_close_slot(support::NETWORK, payment_edge_id())
}

/// Provider first, client second — the fixed shape every work-payment
/// close pays into.
fn payment_payouts(provider: u64, client: u64) -> List<Payout, MAX_EDGE_OUTPUTS> {
    payouts(Payout::new(TAKER, provider), Payout::new(MAKER, client))
}

fn payment_payout_ids() -> List<CoinId, MAX_EDGE_OUTPUTS> {
    Tx::close_output_ids(payment_edge_id(), &payment_payouts(0, 0))
}

fn lease_slots() -> [RegistryChunkId; BOND_LEASE_CHUNKS as usize] {
    bond_lease_slots(support::NETWORK, payment_bond_edge())
}

/// The whole vertical the payment tests run against: the client's
/// funding coin and the provider's stake coin, the payment edge and the
/// bond it leases, the three payout coins those two edges close into,
/// and the three registry slots — one contest, two lease chunks.
type PaymentStore = FixedStore<6, 2, 3>;

fn payment_store() -> PaymentStore {
    let ids = payment_payout_ids();
    let [first_lease, second_lease] = lease_slots();
    FixedStore::empty_with_registry(
        [
            MAKER_COIN,
            TAKER_COIN,
            BOND_COIN,
            nth(&ids, 0),
            nth(&ids, 1),
            bond_timeout_out(),
        ],
        [payment_edge_id(), payment_bond_edge()],
        [pending_slot(), first_lease, second_lease],
    )
}

/// Seeds the store and posts the bond, leaving the payment unopened.
///
/// The bond comes first because it has to: a payment open leases a live
/// bond, so a channel whose bond has not landed cannot be opened at all.
fn bonded_state() -> State<PaymentStore> {
    let mut state = state(payment_store(), [MAKER_SEED, TAKER_SEED, BOND_SEED]);
    let Ok(outcome) = state.apply(CONTEXT, &FAKE_VERIFIER, &payment_bond_open()) else {
        panic!("bond open rejected");
    };
    assert!(
        outcome.registry().is_empty(),
        "posting a bond takes no lease over it",
    );
    state
}

/// A posted bond and a store sized for one payment edge of the caller's
/// choosing.
///
/// The standard fixture declares [`payment_edge_id`]; a test that varies
/// the terms produces a different edge and needs its own slot for it.
fn bonded_state_for(payment_edge: EdgeId) -> State<FixedStore<2, 2, 2>> {
    let store = FixedStore::empty_with_registry(
        [MAKER_COIN, BOND_COIN],
        [payment_edge, payment_bond_edge()],
        lease_slots(),
    );
    let mut state = state(store, [MAKER_SEED, BOND_SEED]);
    let _event = apply(&mut state, &payment_bond_open());
    state
}

/// Applies a payment open, asserting the two halves of what one is: an
/// announced edge and the lease it takes over its bond.
fn apply_payment_open<const C: usize, const E: usize, const R: usize>(
    state: &mut State<FixedStore<C, E, R>>,
    open: &Tx,
) {
    let Ok(outcome) = state.apply(CONTEXT, &FAKE_VERIFIER, open) else {
        panic!("payment open rejected");
    };
    assert!(
        outcome.public_event().is_some(),
        "an open produces an edge, so it announces itself",
    );
    assert_eq!(
        outcome.registry().len(),
        usize::from(BOND_LEASE_CHUNKS),
        "a payment open leases its bond",
    );
}

fn open_payment_state() -> State<PaymentStore> {
    let open = open_tx(payment_funding(), payment_terms());
    let mut state = bonded_state();
    let Ok(outcome) = state.apply(CONTEXT, &FAKE_VERIFIER, &open) else {
        panic!("payment open rejected");
    };
    assert_eq!(
        outcome.registry().len(),
        usize::from(BOND_LEASE_CHUNKS),
        "an open writes no contest, and exactly the lease it takes",
    );
    state
}

fn certificate(amount: u64) -> EarnedCertificate {
    EarnedCertificate::new(payment_edge_id(), payment_terms_hash(), amount)
}

/// A certificate signed by the client, which is the only party whose
/// signature the kernel accepts on one.
fn signed_certificate(amount: u64) -> (EarnedCertificate, PartyAuth) {
    signed_certificate_by(MAKER, certificate(amount))
}

fn signed_certificate_by(
    key: Key,
    certificate: EarnedCertificate,
) -> (EarnedCertificate, PartyAuth) {
    let sig = Sig::placeholder(key, certificate.digest(support::NETWORK));
    (certificate, PartyAuth::owner(sig))
}

const fn key_of(role: Party) -> Key {
    match role {
        Party::Maker => MAKER,
        Party::Taker => TAKER,
    }
}

fn earned_digest_of(certificate: Option<&(EarnedCertificate, PartyAuth)>) -> PayloadHash {
    certificate.map_or_else(
        || no_earned_digest(payment_edge_id(), payment_terms_hash()),
        |(certificate, _)| certificate.digest(support::NETWORK),
    )
}

fn start_body(
    role: Party,
    validity: (u64, u64),
    certificate: Option<(EarnedCertificate, PartyAuth)>,
    signer: Key,
) -> PaymentCloseStart {
    let digest = start_digest(
        support::NETWORK,
        payment_edge_id(),
        payment_terms_hash(),
        role,
        validity,
        earned_digest_of(certificate.as_ref()),
    );
    PaymentCloseStart::new(
        payment_edge_id(),
        payment_terms(),
        role,
        validity,
        certificate,
        PartyAuth::owner(Sig::placeholder(signer, digest)),
    )
}

fn start_tx(role: Party, amount: Option<u64>) -> Tx {
    Tx::move_action(Move::StartPaymentClose(start_body(
        role,
        START_VALIDITY,
        amount.map(signed_certificate),
        key_of(role),
    )))
}

fn response_body(
    start: StartId,
    role: Party,
    certificate: (EarnedCertificate, PartyAuth),
    signer: Key,
) -> PaymentCloseResponse {
    let digest = response_digest(
        support::NETWORK,
        payment_edge_id(),
        payment_terms_hash(),
        start,
        role,
        certificate.0.digest(support::NETWORK),
    );
    PaymentCloseResponse::new(
        payment_edge_id(),
        start,
        role,
        certificate,
        PartyAuth::owner(Sig::placeholder(signer, digest)),
    )
}

fn response(start: StartId, amount: u64) -> PaymentCloseResponse {
    response_body(start, Party::Taker, signed_certificate(amount), TAKER)
}

fn response_tx(start: StartId, amount: u64) -> Tx {
    Tx::move_action(Move::RespondPaymentClose(response(start, amount)))
}

fn adjudicated_tx(record: &PendingPaymentClose, provider: u64) -> Tx {
    let seal = record.contest_commitment(support::NETWORK, payment_edge_id(), payment_terms_hash());
    Tx::close(
        payment_edge_id(),
        Proof::adjudicated(seal),
        payment_payouts(provider, PAYMENT_VALUE - provider),
    )
}

fn freeze_tx(earned: u64, validity: (u64, u64), provider: u64) -> Tx {
    let digest = freeze_digest(
        support::NETWORK,
        payment_edge_id(),
        payment_terms_hash(),
        earned,
        validity,
    );
    Tx::close(
        payment_edge_id(),
        Proof::freeze(
            earned,
            validity,
            PartyAuth::owner(Sig::placeholder(MAKER, digest)),
            PartyAuth::owner(Sig::placeholder(TAKER, digest)),
        ),
        payment_payouts(provider, PAYMENT_VALUE - provider),
    )
}

fn pending_record<const C: usize, const E: usize, const R: usize>(
    state: &State<FixedStore<C, E, R>>,
) -> Option<PendingPaymentClose> {
    let chunk = state.store().registry_chunk(pending_slot())?;
    let Ok(record) = PendingPaymentClose::decode_exact(chunk.data()) else {
        panic!("a stored contest record decodes");
    };
    Some(record)
}

/// Applies a move and asserts it announces nothing publicly.
fn apply_move<const C: usize, const E: usize, const R: usize>(
    state: &mut State<FixedStore<C, E, R>>,
    context: Context,
    op: &Tx,
) {
    let Ok(outcome) = state.apply(context, &FAKE_VERIFIER, op) else {
        panic!("move rejected");
    };
    assert_eq!(
        outcome.public_event(),
        None,
        "a move settles nothing, so it announces nothing",
    );
    assert_eq!(
        outcome.registry().len(),
        1,
        "a payment-close move writes exactly the one contest slot",
    );
}

/// One side of a work-payment payout: its owner and its value.
type PayoutView = Option<(Key, u64)>;

/// Applies a work-payment close and returns the coins it produced.
fn apply_payment_close<const C: usize, const E: usize, const R: usize>(
    state: &mut State<FixedStore<C, E, R>>,
    context: Context,
    op: &Tx,
) -> (PayoutView, PayoutView) {
    let ids = payment_payout_ids();
    let Ok(outcome) = state.apply(context, &FAKE_VERIFIER, op) else {
        panic!("close rejected");
    };
    assert!(
        outcome.public_event().is_some(),
        "a close consumes an edge, so it announces itself",
    );
    (
        state.store().coin(nth(&ids, 0)).map(coin_view),
        state.store().coin(nth(&ids, 1)).map(coin_view),
    )
}

/// The complete unilateral close: the provider opens with the greatest
/// certificate it holds, the client says nothing, and after the window
/// the contested scalar is what gets paid.
#[test]
fn a_provider_start_settles_its_certificate_once_the_window_closes() {
    let mut state = open_payment_state();
    apply_move(&mut state, CONTEXT, &start_tx(Party::Taker, Some(5)));

    let Some(record) = pending_record(&state) else {
        panic!("the start wrote a contest");
    };
    assert_eq!(record.payment_edge(), payment_edge_id());
    assert_eq!(record.opener_role(), Party::Taker);
    assert_eq!(record.start_cumulative(), 5);
    assert_eq!(record.final_cumulative(), 5);
    assert!(!record.responded());
    assert!(!record.penalty_due());
    assert_eq!(record.penalty_amount(), OMISSION_BOND);
    assert_eq!(record.response_deadline(), RESPONSE_DEADLINE);

    let close = adjudicated_tx(&record, 5);
    let (provider, client) = apply_payment_close(&mut state, at(RESPONSE_DEADLINE), &close);

    assert_eq!(provider, Some((TAKER, 5)));
    assert_eq!(client, Some((MAKER, PAYMENT_VALUE - 5)));
    assert_eq!(state.store().edge(payment_edge_id()), None);
    assert_eq!(
        pending_record(&state),
        None,
        "the close retires the contest it settled",
    );
}

/// The heart of the slice. A client opens low; the provider answers with
/// the client's own higher signature; the contradiction forfeits the
/// funded bond on top of the raised amount.
#[test]
fn a_proved_client_understatement_forfeits_the_omission_bond() {
    let mut state = open_payment_state();
    apply_move(&mut state, CONTEXT, &start_tx(Party::Maker, Some(3)));

    let Some(opened) = pending_record(&state) else {
        panic!("the start wrote a contest");
    };
    apply_move(&mut state, at(2), &response_tx(opened.start_id(), 7));

    let Some(answered) = pending_record(&state) else {
        panic!("the response advanced the contest");
    };
    assert_eq!(answered.start_cumulative(), 3, "the opener's claim is kept");
    assert_eq!(answered.final_cumulative(), 7);
    assert!(answered.responded());
    assert!(
        answered.penalty_due(),
        "the client contradicted its own start",
    );

    // An advancing response ends the window immediately: there is no
    // legal second response, so nothing is gained by waiting.
    let (provider, client) = apply_payment_close(&mut state, at(3), &adjudicated_tx(&answered, 9));

    assert_eq!(provider, Some((TAKER, 7 + OMISSION_BOND)));
    assert_eq!(client, Some((MAKER, PAYMENT_VALUE - 7 - OMISSION_BOND)));
}

/// A provider opener that is merely raised has proved nothing about the
/// client, so the same response shape forfeits nothing.
#[test]
fn a_response_to_a_provider_start_advances_payment_without_a_penalty() {
    let mut state = open_payment_state();
    apply_move(&mut state, CONTEXT, &start_tx(Party::Taker, Some(3)));
    let Some(opened) = pending_record(&state) else {
        panic!("the start wrote a contest");
    };

    apply_move(&mut state, at(2), &response_tx(opened.start_id(), 7));
    let Some(answered) = pending_record(&state) else {
        panic!("the response advanced the contest");
    };
    assert!(!answered.penalty_due());

    let (provider, client) = apply_payment_close(&mut state, at(3), &adjudicated_tx(&answered, 7));
    assert_eq!(provider, Some((TAKER, 7)));
    assert_eq!(client, Some((MAKER, PAYMENT_VALUE - 7)));
}

/// An opener with no certificate claims zero, which is the implicit
/// certificate rather than an absent one.
#[test]
fn a_start_with_no_certificate_claims_zero() {
    let mut state = open_payment_state();
    apply_move(&mut state, CONTEXT, &start_tx(Party::Taker, None));

    let Some(record) = pending_record(&state) else {
        panic!("the start wrote a contest");
    };
    assert_eq!(record.start_cumulative(), 0);
    assert_eq!(record.final_cumulative(), 0);

    let (provider, client) = apply_payment_close(
        &mut state,
        at(RESPONSE_DEADLINE),
        &adjudicated_tx(&record, 0),
    );
    assert_eq!(provider, Some((TAKER, 0)));
    assert_eq!(client, Some((MAKER, PAYMENT_VALUE)));
}

/// The cooperative exit. With no contest live it is a one-transaction
/// close at the amount both parties sign.
#[test]
fn a_cooperative_freeze_pays_the_jointly_signed_amount() {
    let mut state = open_payment_state();
    let (provider, client) = apply_payment_close(&mut state, CONTEXT, &freeze_tx(6, (1, 1), 6));

    assert_eq!(provider, Some((TAKER, 6)));
    assert_eq!(client, Some((MAKER, PAYMENT_VALUE - 6)));
    assert_eq!(state.store().edge(payment_edge_id()), None);
}

/// A freeze may end a contest, but it inherits both of the contest's
/// results: it cannot settle below what the contest reached, and it
/// cannot erase a penalty the contest proved.
#[test]
fn a_freeze_over_a_proved_understatement_still_forfeits_the_bond() {
    let mut state = open_payment_state();
    apply_move(&mut state, CONTEXT, &start_tx(Party::Maker, Some(3)));
    let Some(opened) = pending_record(&state) else {
        panic!("the start wrote a contest");
    };
    apply_move(&mut state, at(2), &response_tx(opened.start_id(), 7));

    let too_low = freeze_tx(6, (3, 3), 6);
    let store = *state.store();
    assert_eq!(
        state.apply(at(3), &FAKE_VERIFIER, &too_low),
        Err(ApplyError::InvalidProof {
            input: payment_edge_id(),
            reason: InvalidProofReason::FreezeBelowSettled,
        }),
    );
    assert_eq!(*state.store(), store);

    let (provider, client) =
        apply_payment_close(&mut state, at(3), &freeze_tx(7, (3, 3), 7 + OMISSION_BOND));
    assert_eq!(provider, Some((TAKER, 7 + OMISSION_BOND)));
    assert_eq!(client, Some((MAKER, PAYMENT_VALUE - 7 - OMISSION_BOND)));
    assert_eq!(pending_record(&state), None);
}

/// A client opener that co-signs a higher freeze has understated just as
/// visibly as one caught by a response, and forfeits the same bond.
#[test]
fn a_freeze_above_a_client_start_proves_the_understatement_itself() {
    let mut state = open_payment_state();
    apply_move(&mut state, CONTEXT, &start_tx(Party::Maker, Some(3)));

    let (provider, client) =
        apply_payment_close(&mut state, at(2), &freeze_tx(5, (2, 2), 5 + OMISSION_BOND));
    assert_eq!(provider, Some((TAKER, 5 + OMISSION_BOND)));
    assert_eq!(client, Some((MAKER, PAYMENT_VALUE - 5 - OMISSION_BOND)));
}

/// Freezing at exactly the client opener's own claim proves nothing
/// beyond it, so no bond moves.
#[test]
fn a_freeze_at_the_client_start_amount_forfeits_nothing() {
    let mut state = open_payment_state();
    apply_move(&mut state, CONTEXT, &start_tx(Party::Maker, Some(3)));

    let (provider, client) = apply_payment_close(&mut state, at(2), &freeze_tx(3, (2, 2), 3));
    assert_eq!(provider, Some((TAKER, 3)));
    assert_eq!(client, Some((MAKER, PAYMENT_VALUE - 3)));
}

// ── Contest rules ─────────────────────────────────────────────────────

/// Every rejection below leaves the store exactly as it found it. A move
/// that mutated on its way to a rejection would be a move that could be
/// spammed for its side effect.
fn assert_start_rejected(
    state: &mut State<PaymentStore>,
    context: Context,
    op: &Tx,
    reason: InvalidMoveReason,
) {
    let store = *state.store();
    assert_eq!(
        state.apply(context, &FAKE_VERIFIER, op),
        Err(ApplyError::InvalidMove {
            input: payment_edge_id(),
            reason,
        }),
    );
    assert_eq!(*state.store(), store);
}

fn assert_close_rejected(
    state: &mut State<PaymentStore>,
    context: Context,
    op: &Tx,
    reason: InvalidProofReason,
) {
    let store = *state.store();
    assert_eq!(
        state.apply(context, &FAKE_VERIFIER, op),
        Err(ApplyError::InvalidProof {
            input: payment_edge_id(),
            reason,
        }),
    );
    assert_eq!(*state.store(), store);
}

/// Runs the public read-only check over a real batch snapshot, then runs
/// the same response through the kernel and compares the exact result.
fn assert_response_corresponds<const C: usize, const E: usize, const R: usize>(
    case: &str,
    expected_result: Option<ApplyError>,
    state: &mut State<FixedStore<C, E, R>>,
    context: Context,
    response: &PaymentCloseResponse,
) {
    let mut validation_store = *state.store();
    let checked = {
        let batch = validation_store.begin();
        check_response(response, context, &FAKE_VERIFIER, &batch)
    };
    let before = *state.store();
    let applied = state.apply(
        context,
        &FAKE_VERIFIER,
        &Tx::move_action(Move::RespondPaymentClose(response.clone())),
    );

    match (checked, applied) {
        (Ok(checked_record), Ok(outcome)) => {
            assert_eq!(expected_result, None, "{case}");
            assert_eq!(outcome.registry().len(), 1, "{case}");
            assert_ne!(
                *state.store(),
                before,
                "{case}: acceptance must commit the response"
            );
            assert_eq!(pending_record(state), Some(checked_record), "{case}");
        }
        (Err(checked), Err(actual)) => {
            assert_eq!(actual, checked, "{case}");
            assert_eq!(Some(actual), expected_result, "{case}");
            assert_eq!(*state.store(), before, "{case}: rejection must not commit");
        }
        (checked, applied) => {
            panic!("{case}: response check and apply disagreed: {checked:?}, {applied:?}")
        }
    }
}

fn pending_response_state() -> (State<PaymentStore>, PendingPaymentClose) {
    let mut state = open_payment_state();
    apply_move(&mut state, CONTEXT, &start_tx(Party::Maker, Some(3)));
    let Some(opened) = pending_record(&state) else {
        panic!("the start wrote a contest");
    };
    (state, opened)
}

const fn invalid_response(input: EdgeId, reason: InvalidMoveReason) -> ApplyError {
    ApplyError::InvalidMove { input, reason }
}

/// A start id no contest here ever had. The cases naming it either have
/// no contest to answer at all, or are answering one that is not theirs.
const fn unknown_start() -> StartId {
    StartId::from_bytes([9; StartId::LENGTH])
}

/// A response on a live work-stake bond: a real edge between the same two
/// roles, committing no adjudicated exit.
fn response_on_work_bond() -> PaymentCloseResponse {
    let earned = EarnedCertificate::new(work_edge(), work_terms().hash(), 5);
    PaymentCloseResponse::new(
        work_edge(),
        unknown_start(),
        Party::Taker,
        signed_certificate_by(MAKER, earned),
        PartyAuth::owner(Sig::from_bytes([0; Sig::LENGTH])),
    )
}

/// A certificate the client really signed, for another edge entirely.
fn certificate_for_another_edge() -> (EarnedCertificate, PartyAuth) {
    let earned = EarnedCertificate::new(
        EdgeId::from_bytes([0x77; EdgeId::LENGTH]),
        payment_terms_hash(),
        5,
    );
    signed_certificate_by(MAKER, earned)
}

/// A certificate the client really signed, on this edge but under terms
/// that are not this channel's.
fn certificate_for_other_terms() -> (EarnedCertificate, PartyAuth) {
    signed_certificate_by(MAKER, EarnedCertificate::new(payment_edge_id(), terms(), 5))
}

/// This channel's own certificate, signed by the provider instead of the
/// client — the only party whose signature the kernel accepts on one.
fn provider_signed_certificate() -> (EarnedCertificate, PartyAuth) {
    signed_certificate_by(TAKER, certificate(5))
}

/// The world one response meets: the store it is checked against, and the
/// height it arrives at. Each case names one, and it is built afresh for
/// that case alone, so no case can see what another wrote.
#[derive(Clone, Copy, Debug)]
enum Subject {
    /// A posted bond, and no payment edge at all.
    Bonded,
    /// A live work-stake bond, which commits no adjudicated exit.
    WorkBond,
    /// A live payment channel carrying no contest.
    Opened,
    /// A contest whose one response has already been spent.
    Answered,
    /// A live contest, unanswered, well inside its window.
    Pending,
    /// That same live contest, met at the height its window shuts.
    Late,
}

/// What the read-only check and the applying path both owe a case.
#[derive(Clone, Copy, Debug)]
enum Verdict {
    /// Neither of them finds the edge the response names.
    NoEdge,
    /// Both refuse the response, on the edge it names, for this reason.
    Bad(InvalidMoveReason),
    /// Both accept it, and commit the same advanced record.
    Good,
}

impl Verdict {
    /// The exact result both paths owe a response naming `input`.
    const fn expected(self, input: EdgeId) -> Option<ApplyError> {
        match self {
            Self::NoEdge => Some(ApplyError::MissingEdge { id: input }),
            Self::Bad(reason) => Some(invalid_response(input, reason)),
            Self::Good => None,
        }
    }
}

/// One predicate of the response check, and the verdict it is owed.
#[derive(Clone, Debug)]
struct Predicate {
    /// What this case is called when it fails.
    case: &'static str,
    /// The world the response meets.
    subject: Subject,
    /// The response itself.
    response: PaymentCloseResponse,
    /// What both paths must say about it.
    verdict: Verdict,
}

/// Every exit [`check_response`] has, in one place.
///
/// One row per predicate, and the array's own length pins how many there
/// are: the four a response meets before there is a live contest to
/// answer, the nine refusals of an answer to one, and the acceptance. A
/// predicate added to the kernel and not to this list leaves the count
/// short; a row that stops mattering leaves it long.
#[allow(
    clippy::large_stack_arrays,
    reason = "fourteen inline responses, each carrying two bounded party witnesses"
)]
fn response_predicates(start: StartId) -> [Predicate; 14] {
    [
        Predicate {
            case: "missing edge",
            subject: Subject::Bonded,
            response: response(unknown_start(), 5),
            verdict: Verdict::NoEdge,
        },
        Predicate {
            case: "not a payment channel",
            subject: Subject::WorkBond,
            response: response_on_work_bond(),
            verdict: Verdict::Bad(InvalidMoveReason::NotAPaymentChannel),
        },
        Predicate {
            case: "pending contest missing",
            subject: Subject::Opened,
            response: response(unknown_start(), 5),
            verdict: Verdict::Bad(InvalidMoveReason::ClosePendingMissing),
        },
        Predicate {
            case: "already responded",
            subject: Subject::Answered,
            response: response(start, 6),
            verdict: Verdict::Bad(InvalidMoveReason::AlreadyResponded),
        },
        Predicate {
            case: "start id mismatch",
            subject: Subject::Pending,
            response: response(unknown_start(), 5),
            verdict: Verdict::Bad(InvalidMoveReason::StartIdMismatch),
        },
        Predicate {
            case: "responder is not beneficiary",
            subject: Subject::Pending,
            response: response_body(start, Party::Maker, signed_certificate(5), MAKER),
            verdict: Verdict::Bad(InvalidMoveReason::ResponderNotBeneficiary),
        },
        Predicate {
            case: "response window closed",
            subject: Subject::Late,
            response: response(start, 5),
            verdict: Verdict::Bad(InvalidMoveReason::ResponseWindowClosed),
        },
        Predicate {
            case: "certificate edge mismatch",
            subject: Subject::Pending,
            response: response_body(start, Party::Taker, certificate_for_another_edge(), TAKER),
            verdict: Verdict::Bad(InvalidMoveReason::CertificateNotBound),
        },
        Predicate {
            case: "certificate terms mismatch",
            subject: Subject::Pending,
            response: response_body(start, Party::Taker, certificate_for_other_terms(), TAKER),
            verdict: Verdict::Bad(InvalidMoveReason::CertificateNotBound),
        },
        Predicate {
            case: "certificate not increasing",
            subject: Subject::Pending,
            response: response(start, 3),
            verdict: Verdict::Bad(InvalidMoveReason::CertificateNotIncreasing),
        },
        Predicate {
            case: "certificate over capacity",
            subject: Subject::Pending,
            response: response(start, PAYMENT_CAPACITY + 1),
            verdict: Verdict::Bad(InvalidMoveReason::CertificateOverCapacity),
        },
        Predicate {
            case: "bad certificate signature",
            subject: Subject::Pending,
            response: response_body(start, Party::Taker, provider_signed_certificate(), TAKER),
            verdict: Verdict::Bad(InvalidMoveReason::BadCertificateSignature),
        },
        Predicate {
            case: "bad action signature",
            subject: Subject::Pending,
            response: response_body(start, Party::Taker, signed_certificate(5), MAKER),
            verdict: Verdict::Bad(InvalidMoveReason::BadSignature),
        },
        Predicate {
            case: "happy path",
            subject: Subject::Pending,
            response: response(start, 5),
            verdict: Verdict::Good,
        },
    ]
}

/// Runs one predicate: the read-only check over a real batch snapshot,
/// then the same response through the kernel, compared exactly.
fn assert_predicate(predicate: &Predicate) {
    let Predicate {
        case,
        subject,
        response,
        verdict,
    } = predicate;
    let expected = verdict.expected(response.payment_edge());
    match subject {
        Subject::Bonded => {
            let mut state = bonded_state();
            assert_response_corresponds(case, expected, &mut state, at(2), response);
        }
        Subject::WorkBond => {
            let mut state = open_work_bond_state();
            assert_response_corresponds(case, expected, &mut state, at(2), response);
        }
        Subject::Opened => {
            let mut state = open_payment_state();
            assert_response_corresponds(case, expected, &mut state, at(2), response);
        }
        Subject::Answered => {
            let (mut state, opened) = pending_response_state();
            apply_move(&mut state, at(2), &response_tx(opened.start_id(), 5));
            assert_response_corresponds(case, expected, &mut state, at(2), response);
        }
        Subject::Pending => {
            let (mut state, _) = pending_response_state();
            assert_response_corresponds(case, expected, &mut state, at(2), response);
        }
        Subject::Late => {
            let (mut state, _) = pending_response_state();
            let shut = at(RESPONSE_DEADLINE);
            assert_response_corresponds(case, expected, &mut state, shut, response);
        }
    }
}

/// The extracted predicate is the apply path's predicate, not a second
/// model of it. Every read-only rejection branch is compared against a
/// real kernel execution, and acceptance is compared against the record
/// that execution actually commits.
///
/// The predicates live in [`response_predicates`] and nowhere else, and
/// this iterates all of them: there is one list, so there is no second
/// list to fall behind it.
#[test]
fn response_check_corresponds_to_apply_for_every_predicate() {
    let (_, opened) = pending_response_state();
    for predicate in response_predicates(opened.start_id()) {
        assert_predicate(&predicate);
    }
}

/// A start binds to the edge's own terms and to a payment channel. The
/// bond case is the one that matters: it is a live work edge with a
/// matching terms hash whose profile still has no close contest.
#[test]
fn a_start_binds_to_the_payment_terms_of_a_payment_edge() {
    let mut state = open_payment_state();
    let mismatched = Tx::move_action(Move::StartPaymentClose(PaymentCloseStart::new(
        payment_edge_id(),
        basic_terms(),
        Party::Taker,
        START_VALIDITY,
        None,
        PartyAuth::owner(Sig::from_bytes([0; 64])),
    )));
    assert_start_rejected(
        &mut state,
        CONTEXT,
        &mismatched,
        InvalidMoveReason::TermsMismatch,
    );

    let mut bond_state = open_work_bond_state();
    let on_a_bond = Tx::move_action(Move::StartPaymentClose(PaymentCloseStart::new(
        work_edge(),
        work_terms(),
        Party::Taker,
        START_VALIDITY,
        None,
        PartyAuth::owner(Sig::from_bytes([0; 64])),
    )));
    let store = *bond_state.store();
    assert_eq!(
        bond_state.apply(CONTEXT, &FAKE_VERIFIER, &on_a_bond),
        Err(ApplyError::InvalidMove {
            input: work_edge(),
            reason: InvalidMoveReason::NotAPaymentChannel,
        }),
    );
    assert_eq!(*bond_state.store(), store);
}

/// A start signature is spendable only inside the interval it names, and
/// that interval may be no wider than the terms allow.
#[test]
fn a_start_is_bounded_by_its_signed_validity_window() {
    let mut state = open_payment_state();

    let early = Tx::move_action(Move::StartPaymentClose(start_body(
        Party::Taker,
        (5, 6),
        None,
        TAKER,
    )));
    assert_start_rejected(
        &mut state,
        CONTEXT,
        &early,
        InvalidMoveReason::OutsideValidityWindow,
    );

    let late = Tx::move_action(Move::StartPaymentClose(start_body(
        Party::Taker,
        (1, 1),
        None,
        TAKER,
    )));
    assert_start_rejected(
        &mut state,
        at(2),
        &late,
        InvalidMoveReason::OutsideValidityWindow,
    );

    // `start_validity_blocks` is 8, so a nine-block interval is one
    // block too wide even though the inclusion height is inside it.
    let too_wide = Tx::move_action(Move::StartPaymentClose(start_body(
        Party::Taker,
        (1, 9),
        None,
        TAKER,
    )));
    assert_start_rejected(
        &mut state,
        CONTEXT,
        &too_wide,
        InvalidMoveReason::ValiditySpanTooWide,
    );

    // The widest interval the terms admit is accepted.
    let widest = Tx::move_action(Move::StartPaymentClose(start_body(
        Party::Taker,
        (1, 8),
        None,
        TAKER,
    )));
    apply_move(&mut state, CONTEXT, &widest);
}

/// One contest per edge, opened by whoever gets there first. A second
/// start by the opener would extend its own deadline; one by the other
/// role would replace the deadline the response is bound to.
#[test]
fn a_live_contest_refuses_a_second_start_from_either_role() {
    let mut state = open_payment_state();
    apply_move(&mut state, CONTEXT, &start_tx(Party::Taker, Some(5)));
    let Some(opened) = pending_record(&state) else {
        panic!("the start wrote a contest");
    };

    for role in [Party::Taker, Party::Maker] {
        assert_start_rejected(
            &mut state,
            at(2),
            &Tx::move_action(Move::StartPaymentClose(start_body(
                role,
                (2, 2),
                Some(signed_certificate(6)),
                key_of(role),
            ))),
            InvalidMoveReason::ClosePending,
        );
    }
    assert_eq!(
        pending_record(&state),
        Some(opened),
        "a refused start extends no deadline and raises no amount",
    );
}

/// A certificate is evidence about one channel at one amount, and the
/// kernel checks all three of those claims before it checks a signature.
#[test]
fn a_start_certificate_must_bind_this_channel_and_fit_its_capacity() {
    let mut state = open_payment_state();

    let elsewhere = signed_certificate_by(
        MAKER,
        EarnedCertificate::new(
            EdgeId::from_bytes([0x77; EdgeId::LENGTH]),
            payment_terms_hash(),
            5,
        ),
    );
    assert_start_rejected(
        &mut state,
        CONTEXT,
        &Tx::move_action(Move::StartPaymentClose(start_body(
            Party::Taker,
            START_VALIDITY,
            Some(elsewhere),
            TAKER,
        ))),
        InvalidMoveReason::CertificateNotBound,
    );

    let other_terms =
        signed_certificate_by(MAKER, EarnedCertificate::new(payment_edge_id(), terms(), 5));
    assert_start_rejected(
        &mut state,
        CONTEXT,
        &Tx::move_action(Move::StartPaymentClose(start_body(
            Party::Taker,
            START_VALIDITY,
            Some(other_terms),
            TAKER,
        ))),
        InvalidMoveReason::CertificateNotBound,
    );

    // Zero has exactly one encoding, and it is the absent one.
    assert_start_rejected(
        &mut state,
        CONTEXT,
        &start_tx(Party::Taker, Some(0)),
        InvalidMoveReason::CertificateNotPositive,
    );

    // Capacity is the value the cheaper close route distributes, less
    // the funded bond: 10 − 2.
    assert_start_rejected(
        &mut state,
        CONTEXT,
        &start_tx(Party::Taker, Some(PAYMENT_CAPACITY + 1)),
        InvalidMoveReason::CertificateOverCapacity,
    );
    apply_move(
        &mut state,
        CONTEXT,
        &start_tx(Party::Taker, Some(PAYMENT_CAPACITY)),
    );
}

/// Only the client signs a certificate, and only the named opener signs
/// a start.
#[test]
fn a_start_needs_the_client_on_the_certificate_and_the_opener_on_the_action() {
    let mut state = open_payment_state();

    let provider_signed = signed_certificate_by(TAKER, certificate(5));
    assert_start_rejected(
        &mut state,
        CONTEXT,
        &Tx::move_action(Move::StartPaymentClose(start_body(
            Party::Taker,
            START_VALIDITY,
            Some(provider_signed),
            TAKER,
        ))),
        InvalidMoveReason::BadCertificateSignature,
    );

    // The role selects the key: a start claiming to be the provider's
    // but carrying the client's signature is not the provider's.
    assert_start_rejected(
        &mut state,
        CONTEXT,
        &Tx::move_action(Move::StartPaymentClose(start_body(
            Party::Taker,
            START_VALIDITY,
            None,
            MAKER,
        ))),
        InvalidMoveReason::BadSignature,
    );
}

/// A second deployment, identical to this one in every respect except
/// its name.
const OTHER_NETWORK: NetworkId = match NetworkId::new("hellas-kernel-other") {
    Some(network) => network,
    None => panic!("literal is a legal network id"),
};

/// Every payload the work vocabulary signs is bound to one network.
///
/// Two deployments with the same genesis allocations derive the same
/// coin ids, hence the same payment edge, hence the same terms hash —
/// so the edge separates nothing, and the network in each preimage is
/// the whole of the separation. `tests/network.rs` states this for a
/// Basic open and a Mutual close only; the staked vocabulary's version
/// of it was deleted with the staked vocabulary, and these are the
/// digests that replaced it.
///
/// The inequalities alone would not settle it — a decoder can hash two
/// networks apart and still accept either witness — so the certificate,
/// the piece with the most to steal, is also carried through `apply`.
#[test]
fn every_work_payload_is_bound_to_one_network() {
    let edge = payment_edge_id();
    let terms = payment_terms_hash();
    let earned = certificate(5);
    let home = earned.digest(support::NETWORK);

    assert_ne!(home, earned.digest(OTHER_NETWORK), "earned certificate");
    assert_ne!(
        settlement_commitment(support::NETWORK, edge, terms, 5),
        settlement_commitment(OTHER_NETWORK, edge, terms, 5),
        "settlement commitment",
    );
    assert_ne!(
        start_digest(
            support::NETWORK,
            edge,
            terms,
            Party::Maker,
            START_VALIDITY,
            home
        ),
        start_digest(
            OTHER_NETWORK,
            edge,
            terms,
            Party::Maker,
            START_VALIDITY,
            home
        ),
        "close start",
    );
    let start = start_id(
        start_digest(
            support::NETWORK,
            edge,
            terms,
            Party::Maker,
            START_VALIDITY,
            home,
        ),
        START_HEIGHT,
    );
    assert_ne!(
        response_digest(support::NETWORK, edge, terms, start, Party::Taker, home),
        response_digest(OTHER_NETWORK, edge, terms, start, Party::Taker, home),
        "close response",
    );
    assert_ne!(
        freeze_digest(support::NETWORK, edge, terms, 5, START_VALIDITY),
        freeze_digest(OTHER_NETWORK, edge, terms, 5, START_VALIDITY),
        "freeze",
    );
    assert_ne!(
        pending_payment_close_slot(support::NETWORK, edge),
        pending_payment_close_slot(OTHER_NETWORK, edge),
        "contest slot",
    );
    assert_ne!(
        bond_lease_slot(support::NETWORK, payment_bond_edge(), 0),
        bond_lease_slot(OTHER_NETWORK, payment_bond_edge(), 0),
        "lease slot",
    );

    let mut state = open_payment_state();
    apply_move(&mut state, CONTEXT, &start_tx(Party::Maker, Some(5)));
    let Some(record) = pending_record(&state) else {
        panic!("a start writes its contest record");
    };
    assert_ne!(
        record.contest_commitment(support::NETWORK, edge, terms),
        record.contest_commitment(OTHER_NETWORK, edge, terms),
        "adjudicated seal",
    );
}

/// And the end-to-end consequence: the same certificate, signed for the
/// other network, does not settle here.
///
/// One certificate is reused verbatim in both places it can be spent —
/// a response's cumulative scalar and a cooperative freeze — because a
/// binding that held on one path and not the other would be no binding
/// at all.
#[test]
fn a_certificate_signed_for_another_network_does_not_settle_here() {
    let mut state = open_payment_state();
    let earned = certificate(5);
    let foreign = (
        earned,
        PartyAuth::owner(Sig::placeholder(MAKER, earned.digest(OTHER_NETWORK))),
    );

    assert_start_rejected(
        &mut state,
        CONTEXT,
        &Tx::move_action(Move::StartPaymentClose(start_body(
            Party::Maker,
            START_VALIDITY,
            Some(foreign),
            MAKER,
        ))),
        InvalidMoveReason::BadCertificateSignature,
    );

    let digest = freeze_digest(
        OTHER_NETWORK,
        payment_edge_id(),
        payment_terms_hash(),
        5,
        START_VALIDITY,
    );
    let store = *state.store();
    assert_eq!(
        state.apply(
            CONTEXT,
            &FAKE_VERIFIER,
            &Tx::close(
                payment_edge_id(),
                Proof::freeze(
                    5,
                    START_VALIDITY,
                    PartyAuth::owner(Sig::placeholder(MAKER, digest)),
                    PartyAuth::owner(Sig::placeholder(TAKER, digest)),
                ),
                payment_payouts(5, PAYMENT_VALUE - 5),
            ),
        ),
        Err(ApplyError::InvalidProof {
            input: payment_edge_id(),
            reason: InvalidProofReason::BadSignature,
        }),
    );
    assert_eq!(*state.store(), store, "a rejected close changes nothing");
}

/// The response is the certificate holder's one chance, bound to the
/// contest that won and shut at the deadline.
#[test]
fn the_response_is_one_bounded_answer_from_the_beneficiary() {
    let mut state = open_payment_state();

    // Nothing to answer yet.
    assert_start_rejected(
        &mut state,
        CONTEXT,
        &response_tx(StartId::from_bytes([0; 32]), 5),
        InvalidMoveReason::ClosePendingMissing,
    );

    apply_move(&mut state, CONTEXT, &start_tx(Party::Maker, Some(3)));
    let Some(opened) = pending_record(&state) else {
        panic!("the start wrote a contest");
    };

    assert_start_rejected(
        &mut state,
        at(2),
        &response_tx(StartId::from_bytes([9; 32]), 5),
        InvalidMoveReason::StartIdMismatch,
    );
    assert_start_rejected(
        &mut state,
        at(2),
        &Tx::move_action(Move::RespondPaymentClose(response_body(
            opened.start_id(),
            Party::Maker,
            signed_certificate(5),
            MAKER,
        ))),
        InvalidMoveReason::ResponderNotBeneficiary,
    );
    // Equal is not an advance: it would consume the one answer and
    // change nothing.
    assert_start_rejected(
        &mut state,
        at(2),
        &response_tx(opened.start_id(), 3),
        InvalidMoveReason::CertificateNotIncreasing,
    );
    assert_start_rejected(
        &mut state,
        at(2),
        &response_tx(opened.start_id(), PAYMENT_CAPACITY + 1),
        InvalidMoveReason::CertificateOverCapacity,
    );
    // Strictly below the deadline. At it, the adjudicated close is
    // already legal, so admitting both would make one height ambiguous.
    assert_start_rejected(
        &mut state,
        at(RESPONSE_DEADLINE),
        &response_tx(opened.start_id(), 5),
        InvalidMoveReason::ResponseWindowClosed,
    );

    // Both bounds are pinned by admitting the answer that sits exactly on
    // each of them: the last block of the window, and the largest
    // certificate the channel can fund. A response one block early or one
    // unit short would leave an off-by-one free to deny the provider the
    // very remedy the window exists to give it — and the height bound in
    // particular has to admit `deadline - 1`, because the adjudicated
    // close is refused there, and a height where neither move is legal
    // would be a gap in a contest that must always be resolvable.
    apply_move(
        &mut state,
        at(RESPONSE_DEADLINE - 1),
        &response_tx(opened.start_id(), PAYMENT_CAPACITY),
    );
    assert_start_rejected(
        &mut state,
        at(RESPONSE_DEADLINE - 1),
        &response_tx(opened.start_id(), PAYMENT_CAPACITY),
        InvalidMoveReason::AlreadyResponded,
    );
}

/// A response certificate is evidence about one channel, and it has to
/// be evidence about *this* one.
///
/// This is the check that has no signature standing behind it. A provider
/// holding a certificate the client signed for another channel between
/// the same two keys carries a digest the client really did sign, under
/// an answer the provider really did sign: both verifications pass, and
/// only the binding refuses it. The start path is guarded the same way
/// and for the same reason.
#[test]
fn a_response_certificate_must_bind_this_channel() {
    let mut state = open_payment_state();
    apply_move(&mut state, CONTEXT, &start_tx(Party::Maker, Some(3)));
    let Some(opened) = pending_record(&state) else {
        panic!("the start wrote a contest");
    };

    let elsewhere = signed_certificate_by(
        MAKER,
        EarnedCertificate::new(
            EdgeId::from_bytes([0x77; EdgeId::LENGTH]),
            payment_terms_hash(),
            5,
        ),
    );
    assert_start_rejected(
        &mut state,
        at(2),
        &Tx::move_action(Move::RespondPaymentClose(response_body(
            opened.start_id(),
            Party::Taker,
            elsewhere,
            TAKER,
        ))),
        InvalidMoveReason::CertificateNotBound,
    );

    let other_terms =
        signed_certificate_by(MAKER, EarnedCertificate::new(payment_edge_id(), terms(), 5));
    assert_start_rejected(
        &mut state,
        at(2),
        &Tx::move_action(Move::RespondPaymentClose(response_body(
            opened.start_id(),
            Party::Taker,
            other_terms,
            TAKER,
        ))),
        InvalidMoveReason::CertificateNotBound,
    );
}

/// A response reveals no terms, so the close-kind set is the only thing
/// that identifies the profile. A work-stake bond is a live edge between
/// two roles that commits no adjudicated exit, and a response on it is
/// refused for that structural reason rather than for a missing contest.
#[test]
fn a_response_is_refused_on_an_edge_that_is_not_a_payment_channel() {
    let mut bond_state = open_work_bond_state();
    let on_a_bond = Tx::move_action(Move::RespondPaymentClose(PaymentCloseResponse::new(
        work_edge(),
        StartId::from_bytes([0; StartId::LENGTH]),
        Party::Taker,
        signed_certificate_by(
            MAKER,
            EarnedCertificate::new(work_edge(), work_terms().hash(), 1),
        ),
        PartyAuth::owner(Sig::from_bytes([0; 64])),
    )));
    let store = *bond_state.store();
    assert_eq!(
        bond_state.apply(CONTEXT, &FAKE_VERIFIER, &on_a_bond),
        Err(ApplyError::InvalidMove {
            input: work_edge(),
            reason: InvalidMoveReason::NotAPaymentChannel,
        }),
    );
    assert_eq!(*bond_state.store(), store);
}

/// A start and the response that answers it, in one block.
///
/// The contest slot has to be read through the staged batch, not through
/// committed state: §4.6 requires the charged lookup to observe earlier
/// same-block mutations, and the kernel gets that by folding each
/// operation into one shared transaction before the next is validated.
/// Every other test here applies its moves in separate committed
/// batches, which cannot tell that apart from a kernel that only ever
/// sees the previous block.
#[test]
fn a_response_answers_a_start_in_the_same_block() {
    let mut state = open_payment_state();
    let claimed = signed_certificate(3);
    // The identifier the start will be given, derived exactly as the
    // kernel derives it, since no committed state exists to read it from.
    let opened = start_id(
        start_digest(
            support::NETWORK,
            payment_edge_id(),
            payment_terms_hash(),
            Party::Maker,
            START_VALIDITY,
            earned_digest_of(Some(&claimed)),
        ),
        START_HEIGHT,
    );
    let ops = List::all([start_tx(Party::Maker, Some(3)), response_tx(opened, 5)]);

    let Ok(diff) = state.apply_all(CONTEXT, &FAKE_VERIFIER, &ops) else {
        panic!("a start and its answer share one block");
    };
    assert_eq!(diff.len(), 2);

    let Some(record) = pending_record(&state) else {
        panic!("the block left one contest");
    };
    assert_eq!(record.start_id(), opened, "the response found this start");
    assert!(record.responded(), "the second move saw the first");
    assert_eq!(record.start_cumulative(), 3);
    assert_eq!(record.final_cumulative(), 5);
    assert!(
        record.penalty_due(),
        "a client opener raised by its own later signature forfeits the bond",
    );
}

/// A response carries two signatures and needs both: the client's on the
/// certificate, the provider's on the answer.
#[test]
fn a_response_needs_both_of_its_signatures() {
    let mut state = open_payment_state();
    apply_move(&mut state, CONTEXT, &start_tx(Party::Maker, Some(3)));
    let Some(opened) = pending_record(&state) else {
        panic!("the start wrote a contest");
    };

    let forged = signed_certificate_by(TAKER, certificate(5));
    let digest = response_digest(
        support::NETWORK,
        payment_edge_id(),
        payment_terms_hash(),
        opened.start_id(),
        Party::Taker,
        forged.0.digest(support::NETWORK),
    );
    assert_start_rejected(
        &mut state,
        at(2),
        &Tx::move_action(Move::RespondPaymentClose(PaymentCloseResponse::new(
            payment_edge_id(),
            opened.start_id(),
            Party::Taker,
            forged,
            PartyAuth::owner(Sig::placeholder(TAKER, digest)),
        ))),
        InvalidMoveReason::BadCertificateSignature,
    );
    assert_start_rejected(
        &mut state,
        at(2),
        &Tx::move_action(Move::RespondPaymentClose(response_body(
            opened.start_id(),
            Party::Taker,
            signed_certificate(5),
            MAKER,
        ))),
        InvalidMoveReason::BadSignature,
    );
}

/// Round 3 authenticated the certificate before the provider's action,
/// letting a hostile client spend two checks on a response it alone made.
/// Admission and execution share this predicate, so pin the short circuit
/// here: a bad action is one verification, never two.
#[test]
fn round3_bad_action_signature_is_checked_first() {
    struct CountingReject<'a>(&'a Cell<usize>);

    impl SigVerifier for CountingReject<'_> {
        fn verify_sig(&self, _sig: Sig, _party_key: Key, _hash: PayloadHash) -> bool {
            self.0.set(self.0.get() + 1);
            false
        }
    }

    let (state, opened) = pending_response_state();
    let mut validation_store = *state.store();
    let batch = validation_store.begin();
    let checks = Cell::new(0);
    let checked = check_response(
        &response(opened.start_id(), 5),
        at(2),
        &CountingReject(&checks),
        &batch,
    );
    assert_eq!(
        checked,
        Err(ApplyError::InvalidMove {
            input: payment_edge_id(),
            reason: InvalidMoveReason::BadSignature,
        }),
    );
    assert_eq!(checks.get(), 1, "certificate verification must not run");
}

/// The adjudicated close is the contest's result and nothing else: no
/// contest, no close; window still open, no close; a seal naming another
/// state, no close.
#[test]
fn an_adjudicated_close_settles_only_a_finished_contest() {
    let mut state = open_payment_state();

    assert_close_rejected(
        &mut state,
        CONTEXT,
        &Tx::close(
            payment_edge_id(),
            Proof::adjudicated(PaymentContestCommitment::from_bytes([0; 32])),
            payment_payouts(0, PAYMENT_VALUE),
        ),
        InvalidProofReason::ClosePendingMissing,
    );

    apply_move(&mut state, CONTEXT, &start_tx(Party::Taker, Some(5)));
    let Some(record) = pending_record(&state) else {
        panic!("the start wrote a contest");
    };

    // One block short of the deadline the provider can still speak, so
    // the contest is not over.
    assert_close_rejected(
        &mut state,
        at(RESPONSE_DEADLINE - 1),
        &adjudicated_tx(&record, 5),
        InvalidProofReason::ResponseWindowOpen,
    );
    assert_close_rejected(
        &mut state,
        at(RESPONSE_DEADLINE),
        &Tx::close(
            payment_edge_id(),
            Proof::adjudicated(PaymentContestCommitment::from_bytes([0xab; 32])),
            payment_payouts(5, PAYMENT_VALUE - 5),
        ),
        InvalidProofReason::ContestMismatch,
    );

    // At the deadline exactly, the window is shut and the close lands.
    let (provider, _client) = apply_payment_close(
        &mut state,
        at(RESPONSE_DEADLINE),
        &adjudicated_tx(&record, 5),
    );
    assert_eq!(provider, Some((TAKER, 5)));
}

/// The payout shape is derived, not chosen. Its owners, its order, its
/// fanout, and the amount the contest ended on are all pinned.
#[test]
fn an_adjudicated_close_pays_only_the_derived_split() {
    let mut state = open_payment_state();
    apply_move(&mut state, CONTEXT, &start_tx(Party::Taker, Some(5)));
    let Some(record) = pending_record(&state) else {
        panic!("the start wrote a contest");
    };
    let seal = record.contest_commitment(support::NETWORK, payment_edge_id(), payment_terms_hash());

    let wrong_shapes = [
        // Provider paid more than the contest reached, client less.
        payment_payouts(6, PAYMENT_VALUE - 6),
        // Right amounts, swapped owners.
        payouts(Payout::new(MAKER, 5), Payout::new(TAKER, PAYMENT_VALUE - 5)),
        // One output instead of two.
        list(&[Payout::new(TAKER, PAYMENT_VALUE)]),
    ];
    for outputs in wrong_shapes {
        assert_close_rejected(
            &mut state,
            at(RESPONSE_DEADLINE),
            &Tx::close(payment_edge_id(), Proof::adjudicated(seal), outputs),
            InvalidProofReason::PayoutMismatch,
        );
    }
}

/// A freeze is bounded by the interval it names, and consensus bounds
/// that interval itself: it reveals no terms to bound it with.
#[test]
fn a_freeze_is_bounded_by_its_signed_window_and_by_consensus() {
    let mut state = open_payment_state();

    assert_close_rejected(
        &mut state,
        CONTEXT,
        &freeze_tx(6, (5, 6), 6),
        InvalidProofReason::FreezeOutsideValidityWindow,
    );
    assert_close_rejected(
        &mut state,
        CONTEXT,
        &freeze_tx(6, (1, hellas_kernel::MAX_FREEZE_AUTH_BLOCKS + 1), 6),
        InvalidProofReason::FreezeOutsideValidityWindow,
    );
    // The widest interval consensus admits is accepted.
    let widest = (1, hellas_kernel::MAX_FREEZE_AUTH_BLOCKS);
    let (provider, _client) = apply_payment_close(&mut state, CONTEXT, &freeze_tx(6, widest, 6));
    assert_eq!(provider, Some((TAKER, 6)));
}

/// A freeze is cooperative, so it needs both parties. One signature is
/// one party's opinion.
#[test]
fn a_freeze_needs_both_parties() {
    let mut state = open_payment_state();
    let validity = (1, 1);
    let digest = freeze_digest(
        support::NETWORK,
        payment_edge_id(),
        payment_terms_hash(),
        6,
        validity,
    );
    for (maker, taker) in [
        (
            Sig::placeholder(MAKER, digest),
            Sig::placeholder(MAKER, digest),
        ),
        (
            Sig::placeholder(TAKER, digest),
            Sig::placeholder(TAKER, digest),
        ),
    ] {
        assert_close_rejected(
            &mut state,
            CONTEXT,
            &Tx::close(
                payment_edge_id(),
                Proof::freeze(
                    6,
                    validity,
                    PartyAuth::owner(maker),
                    PartyAuth::owner(taker),
                ),
                payment_payouts(6, PAYMENT_VALUE - 6),
            ),
            InvalidProofReason::BadSignature,
        );
    }
}

// ── Absence is a permission, so nothing may be mistaken for it ────────

/// Overwrites the pending slot with `chunk`, bypassing the transitions.
///
/// The only way to reach the corrupt-state branches: no move can write
/// one of these, which is exactly why a reader that treated them as
/// absence would never be caught by a test that only submits moves.
fn poison_pending(state: &mut State<PaymentStore>, chunk: RegistryChunk) {
    let mut store = *state.store();
    {
        let mut batch = store.begin();
        let _ = batch.remove_registry_chunk(pending_slot());
        let Ok(()) = batch.insert_registry_chunk(pending_slot(), chunk) else {
            panic!("the fixture declares the pending slot");
        };
        batch.commit();
    }
    *state = State::new(store);
}

/// How to break a live contest's stored bytes.
#[derive(Clone, Copy)]
enum Corruption {
    /// Flip one byte, keeping the record's width.
    Byte(usize),
    /// Make the value one byte longer, so it splits into two chunks.
    Longer,
    /// Make the value one byte shorter than a record.
    Shorter,
}

/// A live contest's bytes, broken as `corruption` says.
fn corrupted_record_bytes(
    state: &State<PaymentStore>,
    corruption: Corruption,
) -> List<u8, { hellas_kernel::REGISTRY_CHUNK_DATA_CAPACITY + 1 }> {
    let Some(chunk) = state.store().registry_chunk(pending_slot()) else {
        panic!("a contest is live");
    };
    let mut bytes = [0_u8; hellas_kernel::REGISTRY_CHUNK_DATA_CAPACITY + 1];
    bytes[..PendingPaymentClose::ENCODED_SIZE].copy_from_slice(chunk.data());
    match corruption {
        Corruption::Byte(offset) => {
            bytes[offset] ^= 0xff;
            list(&bytes[..PendingPaymentClose::ENCODED_SIZE])
        }
        // 121 bytes is one past a chunk's data capacity.
        Corruption::Longer => list(&bytes[..]),
        Corruption::Shorter => list(&bytes[..PendingPaymentClose::ENCODED_SIZE - 1]),
    }
}

/// Every way a present chunk can fail to be this edge's record is a
/// rejection, and never "no contest is live". Absence is what lets a
/// start open a contest and lets a freeze skip the pending rules, so a
/// reader that fell back to it would hand both permissions to whoever
/// corrupted the slot.
#[test]
fn a_present_but_unreadable_contest_is_never_read_as_absence() {
    // Offsets into the record body: the envelope is two bytes, then the
    // version byte, then the payment edge.
    const VERSION_OFFSET: usize = 2;
    const EDGE_OFFSET: usize = 3;

    // One case per conjunct of the reader's shape rule, plus the body
    // and edge rules. A case list that only covered the record tag would
    // leave the count, index, length, and namespace clauses free to be
    // deleted without a test noticing.
    let faults = [
        // Another namespace's value parked in this slot.
        (
            RegistryNamespace::BondLease,
            RegistryRecordTag::PaymentPending,
            Corruption::Byte(EDGE_OFFSET),
            PendingCloseFault::Shape,
        ),
        // Wrong record kind under the right namespace.
        (
            RegistryNamespace::PaymentClose,
            RegistryRecordTag::BondLease,
            Corruption::Byte(EDGE_OFFSET),
            PendingCloseFault::Shape,
        ),
        // The first chunk of a longer value: right kind, wrong count.
        (
            RegistryNamespace::PaymentClose,
            RegistryRecordTag::PaymentPending,
            Corruption::Longer,
            PendingCloseFault::Shape,
        ),
        // A shorter value of the right kind: the record has one width.
        (
            RegistryNamespace::PaymentClose,
            RegistryRecordTag::PaymentPending,
            Corruption::Shorter,
            PendingCloseFault::Shape,
        ),
        // Right kind and width, bytes that are not a canonical record.
        (
            RegistryNamespace::PaymentClose,
            RegistryRecordTag::PaymentPending,
            Corruption::Byte(VERSION_OFFSET),
            PendingCloseFault::Body,
        ),
        // A whole canonical record — for a different edge.
        (
            RegistryNamespace::PaymentClose,
            RegistryRecordTag::PaymentPending,
            Corruption::Byte(EDGE_OFFSET),
            PendingCloseFault::Edge,
        ),
    ];

    for (namespace, record_tag, corruption, fault) in faults {
        let mut state = open_payment_state();
        apply_move(&mut state, CONTEXT, &start_tx(Party::Taker, Some(5)));
        let bytes = corrupted_record_bytes(&state, corruption);
        let Some(chunk) = RegistryChunk::split(namespace, record_tag, bytes.as_slice(), 0) else {
            panic!("the corrupted value splits into a first chunk");
        };
        poison_pending(&mut state, chunk);

        // A start must not read the corruption as a free contest slot.
        assert_start_rejected(
            &mut state,
            at(2),
            &Tx::move_action(Move::StartPaymentClose(start_body(
                Party::Taker,
                (2, 2),
                None,
                TAKER,
            ))),
            InvalidMoveReason::ClosePendingFault { fault },
        );
        // A freeze must not read it as "no contest", which would let it
        // settle below a contest and skip a proved penalty.
        assert_close_rejected(
            &mut state,
            at(2),
            &freeze_tx(6, (2, 2), 6),
            InvalidProofReason::ClosePendingFault { fault },
        );
        // An adjudicated close must not read it as a missing contest
        // either — same rejection, different reason from absence.
        assert_close_rejected(
            &mut state,
            at(RESPONSE_DEADLINE),
            &Tx::close(
                payment_edge_id(),
                Proof::adjudicated(PaymentContestCommitment::from_bytes([0; 32])),
                payment_payouts(5, PAYMENT_VALUE - 5),
            ),
            InvalidProofReason::ClosePendingFault { fault },
        );
    }
}

// ── Prices and windows ────────────────────────────────────────────────

/// The exact cost vectors the design assigns. Slots count every physical
/// store slot a transition touches, including the contest slot a start
/// reads before it writes and a close reads whether or not it is there.
#[test]
fn payment_close_costs_are_the_assigned_vectors() {
    assert_eq!(start_tx(Party::Taker, None).cost(), Cost::new(1, 2, 1));
    assert_eq!(start_tx(Party::Taker, Some(5)).cost(), Cost::new(1, 2, 2));
    assert_eq!(
        response_tx(StartId::from_bytes([0; 32]), 5).cost(),
        Cost::new(1, 2, 2),
    );
    assert_eq!(freeze_tx(6, (1, 1), 6).cost(), Cost::new(1, 4, 2));
    assert_eq!(
        Tx::close(
            payment_edge_id(),
            Proof::adjudicated(PaymentContestCommitment::from_bytes([0; 32])),
            payment_payouts(0, PAYMENT_VALUE),
        )
        .cost(),
        Cost::new(1, 4, 1),
    );
}

/// Fees make the slot count visible in the money, and the tag-4 timeout
/// touches two slots no other timeout does.
///
/// Under the zero schedule every count is free and the whole of this
/// arithmetic collapses to one number, so a timeout priced by the wrong
/// profile would be invisible everywhere else in this file. Here the
/// open commits the payout its own timeout's price leaves, and the
/// timeout then pays exactly that: if the two ever read the price from
/// different places, one of these two operations is refused.
#[test]
fn a_work_bond_prices_its_lease_reading_timeout_under_nonzero_fees() {
    /// The provider's coin: open fee 7, lifetime fee 3, reserve 25.
    const FUNDED: u64 = 43;
    /// What the edge locks once those three are taken.
    const STAKED: u64 = 8;
    /// `STAKED` plus the reserve left after a 16-unit timeout close.
    const RETURNED: u64 = 17;

    const FEE_COIN: CoinId = coin_id(0x53);
    let seed = Genesis::coin(FEE_COIN, TAKER, FUNDED);
    let outputs = list(&[Payout::new(TAKER, RETURNED)]);
    let terms = Terms::work_stake_bond(WorkStakeBondTerms {
        parties: Parties::new(PartyKeys::sole(TAKER), PartyKeys::sole(MAKER)),
        timeout_outputs: outputs.clone(),
        ..bond()
    });
    let funding = Funding::new(list(&[FEE_COIN]), empty_party());
    let edge = Tx::edge_id_of(&funding, &terms);
    let open = open_tx_with(
        funding,
        terms.clone(),
        (
            hellas_kernel::PartyKeys::sole(TAKER),
            hellas_kernel::Authority::Owner,
        ),
        (
            hellas_kernel::PartyKeys::sole(MAKER),
            hellas_kernel::Authority::Owner,
        ),
    );

    let store = FixedStore::empty_with_registry(
        [FEE_COIN, nth(&Tx::close_output_ids(edge, &outputs), 0)],
        [edge],
        bond_lease_slots(support::NETWORK, edge),
    );
    let mut state = state(store, [seed]);
    let _event = apply_with(&mut state, RESOURCE_CONTEXT, &open);
    let Some(live) = state.store().edge(edge) else {
        panic!("bond edge live");
    };
    assert_eq!(live.value(), STAKED);
    assert_eq!(live.reserve(), 25);

    // Unleased, so it closes at once — and for exactly the committed
    // payout, which the open accepted only because both sides priced
    // the close the same way.
    let _event = apply_with(
        &mut state,
        RESOURCE_CONTEXT,
        &Tx::close(edge, Proof::timeout(terms, None), outputs),
    );
    assert_eq!(
        state
            .store()
            .coin(nth(
                &Tx::close_output_ids(edge, &list(&[Payout::new(TAKER, RETURNED)])),
                0
            ))
            .map(coin_view),
        Some((TAKER, RETURNED)),
    );
}

/// The exact cost vectors the design assigns to the work profiles'
/// opens and to a tag-4 timeout.
///
/// Slots count every physical store slot a transition touches: a
/// payment open reaches for its funding coin, the edge it creates, the
/// bond it verifies, and both chunks of the lease it writes, and a
/// tag-4 timeout reads both lease chunks, and the payment edge a present
/// lease names, before it can know which height rule governs it. The
/// generic Basic vectors are pinned beside them.
#[test]
fn work_open_and_bond_timeout_costs_are_the_assigned_vectors() {
    assert_eq!(
        open_tx(payment_funding(), payment_terms()).cost(),
        Cost::new(1, 5, 2),
    );
    assert_eq!(payment_bond_open().cost(), Cost::new(1, 2, 2));
    assert_eq!(bond_timeout_tx().cost(), Cost::new(1, 5, 1));

    // Generic: one funding coin and one edge at open, one edge and one
    // payout at timeout, and one proof unit for each party's witness.
    let generic = basic_terms();
    let funding = Funding::new(list(&[MAKER_COIN]), empty_party());
    let edge = Tx::edge_id_of(&funding, &generic);
    assert_eq!(open_tx(funding, generic.clone()).cost(), Cost::new(1, 2, 2));
    assert_eq!(
        Tx::close(
            edge,
            Proof::timeout(generic, None),
            list(&[Payout::new(MAKER, STAKE)]),
        )
        .cost(),
        Cost::new(1, 2, 1),
    );
}

/// The response window has a derived floor, not a chosen one: below it
/// the provider has no measured opportunity to observe the start and get
/// an answer included, so the omission theorem the channel is priced on
/// does not hold and consensus refuses the open.
#[test]
fn a_payment_open_refuses_a_window_below_the_derived_floor() {
    let floor = hellas_kernel::MIN_OMIT_RESPONSE_BLOCKS;
    let too_short = payment_of(|payment| payment.omit_response_blocks = floor - 1);
    let funding = payment_funding();
    let output = Tx::edge_id_of(&funding, &too_short);
    let mut state = funded_state_for(&work_open());
    let store = *state.store();

    assert_eq!(
        state.apply(CONTEXT, &FAKE_VERIFIER, &open_tx(funding, too_short)),
        Err(ApplyError::InvalidOpen {
            output,
            reason: InvalidOpenReason::WorkResponseWindowOutOfRange,
        }),
    );
    assert_eq!(*state.store(), store);

    // Exactly at the floor is admitted, so the bound is the floor and
    // not something above it.
    let exact = payment_of(|payment| payment.omit_response_blocks = floor);
    let funding = payment_funding();
    let edge = Tx::edge_id_of(&funding, &exact);
    let open = open_tx(funding, exact);
    let mut state = bonded_state_for(edge);
    apply_payment_open(&mut state, &open);
}

/// A channel whose omission bond swallows everything a close
/// distributes can admit no certificate at all, so it is refused at
/// open rather than opened as a channel in name only.
#[test]
fn a_payment_open_refuses_an_unfunded_capacity() {
    // The edge locks 10, so a bond of 10 leaves capacity zero and a
    // bond of 11 leaves none at all.
    for bond in [PAYMENT_VALUE, PAYMENT_VALUE + 1] {
        let terms = payment_of(|payment| payment.omission_bond = bond);
        let funding = payment_funding();
        let output = Tx::edge_id_of(&funding, &terms);
        let mut state = funded_state_for(&work_open());
        let store = *state.store();

        assert_eq!(
            state.apply(CONTEXT, &FAKE_VERIFIER, &open_tx(funding, terms)),
            Err(ApplyError::InvalidOpen {
                output,
                reason: InvalidOpenReason::WorkPaymentCapacityUnfunded,
            }),
        );
        assert_eq!(*state.store(), store);
    }
}

/// Neither work-payment exit expires at the admission horizon. That
/// horizon buys admission and rent; a channel that stopped being
/// settleable once it stopped admitting jobs would strand every amount
/// already earned against it.
#[test]
fn the_payment_exits_stay_open_past_the_admission_horizon() {
    // `TIMEOUT` is the committed horizon, and every height below is
    // well past it.
    let horizon = TIMEOUT.get();

    let mut state = open_payment_state();
    apply_move(&mut state, CONTEXT, &start_tx(Party::Taker, Some(5)));
    let Some(record) = pending_record(&state) else {
        panic!("the start wrote a contest");
    };
    assert!(RESPONSE_DEADLINE > horizon);
    let (provider, _client) = apply_payment_close(
        &mut state,
        at(RESPONSE_DEADLINE),
        &adjudicated_tx(&record, 5),
    );
    assert_eq!(provider, Some((TAKER, 5)));

    let mut state = open_payment_state();
    let past = horizon + 40;
    let (provider, _client) =
        apply_payment_close(&mut state, at(past), &freeze_tx(6, (past, past), 6));
    assert_eq!(provider, Some((TAKER, 6)));
}

/// A start within one committed window of the height ceiling would wrap
/// its own deadline into the past. The work profile is disabled there
/// rather than opening a contest that is already over.
#[test]
fn a_start_too_close_to_the_height_ceiling_is_refused() {
    let mut state = open_payment_state();
    let height = u64::MAX - RESPONSE_WINDOW + 1;
    let start = Tx::move_action(Move::StartPaymentClose(start_body(
        Party::Taker,
        (height, height),
        None,
        TAKER,
    )));

    assert_start_rejected(
        &mut state,
        at(height),
        &start,
        InvalidMoveReason::DeadlineOverflow,
    );
}

/// A move on an edge that is not there is a missing edge, not an
/// invalid move: the distinction is what lets a host retain a
/// transaction whose edge has not been synced yet.
#[test]
fn a_move_on_an_absent_edge_reports_the_missing_edge() {
    let mut state = state(payment_store(), [MAKER_SEED, TAKER_SEED]);
    assert_eq!(
        state.apply(CONTEXT, &FAKE_VERIFIER, &start_tx(Party::Taker, Some(5))),
        Err(ApplyError::MissingEdge {
            id: payment_edge_id(),
        }),
    );
}

// ── The bond lease ────────────────────────────────────────────────────
//
// A payment channel is only worth what its bond can be slashed for, and
// nothing in a signed payment open proves that bond exists. These tests
// are the attack the design names: `C` signs a bond open and a payment
// open for the same block, and `P` submits the payment alone — or
// submits it against a bond it has already committed elsewhere.

/// A second client-funded channel over the *same* bond. Its policy
/// commitment differs, so it is a different edge with different terms
/// and its own funding coin — everything about it is fresh except the
/// bond it tries to lease.
const SECOND_CLIENT_COIN: CoinId = coin_id(0x52);
const SECOND_CLIENT_SEED: Genesis = Genesis::coin(SECOND_CLIENT_COIN, MAKER, PAYMENT_VALUE);

fn second_payment_terms() -> Terms {
    payment_of(|payment| payment.private_policy_commitment = [5; 32])
}

fn second_payment_funding() -> Funding {
    Funding::new(list(&[SECOND_CLIENT_COIN]), empty_party())
}

fn second_payment_edge() -> EdgeId {
    Tx::edge_id_of(&second_payment_funding(), &second_payment_terms())
}

/// A live tag-4 bond the payment did *not* embed: same parties, same
/// stake, one different price cap, so its terms hash is not the one the
/// payment commits to.
fn other_bond_terms() -> Terms {
    Terms::work_stake_bond(WorkStakeBondTerms {
        max_job_price: 6,
        ..payment_bond()
    })
}

fn other_bond_edge() -> EdgeId {
    Tx::edge_id_of(&payment_bond_funding(), &other_bond_terms())
}

/// Reassembles the lease the store holds, exactly as a host would: two
/// chunks, in slot order, decoded as one record.
fn stored_lease<const C: usize, const E: usize, const R: usize>(
    state: &State<FixedStore<C, E, R>>,
) -> BondLease {
    let mut bytes = Vec::new();
    for (index, slot) in lease_slots().into_iter().enumerate() {
        let Some(chunk) = state.store().registry_chunk(slot) else {
            panic!("lease chunk {index} stored");
        };
        assert_eq!(chunk.namespace(), RegistryNamespace::BondLease);
        assert_eq!(chunk.record_tag(), RegistryRecordTag::BondLease);
        assert_eq!(chunk.chunk_count(), BOND_LEASE_CHUNKS);
        assert_eq!(chunk.chunk_index(), u8::try_from(index).unwrap_or(u8::MAX));
        bytes.extend_from_slice(chunk.data());
    }
    let Ok(lease) = BondLease::decode_exact(&bytes) else {
        panic!("the stored lease decodes");
    };
    lease
}

fn lease_is_absent<const C: usize, const E: usize, const R: usize>(
    state: &State<FixedStore<C, E, R>>,
) -> bool {
    lease_slots()
        .into_iter()
        .all(|slot| state.store().registry_chunk(slot).is_none())
}

/// The open half of the bond's exclusivity rule: the edge and the lease
/// land together, and the lease says which channel now holds the bond.
#[test]
fn a_payment_open_leases_the_bond_it_names() {
    let mut state = bonded_state();
    let open = open_tx(payment_funding(), payment_terms());
    let Ok(outcome) = state.apply(CONTEXT, &FAKE_VERIFIER, &open) else {
        panic!("payment open rejected");
    };

    // One change: the public edge event and the private lease writes.
    assert_eq!(
        outcome.public_event().map(hellas_kernel::Event::kind),
        Some(&EventKind::EdgeOpened {
            inputs: list(&[MAKER_COIN]),
            output: payment_edge_id(),
        }),
    );
    let slots: Vec<RegistryChunkId> = outcome
        .registry()
        .iter()
        .map(|mutation| mutation.id())
        .collect();
    assert_eq!(slots, lease_slots().to_vec());

    let lease = stored_lease(&state);
    assert_eq!(lease.bond_edge(), payment_bond_edge());
    assert_eq!(lease.payment_edge(), payment_edge_id());
    assert_eq!(lease.payment_terms_hash(), payment_terms_hash());
    assert_eq!(lease.private_policy_commitment(), [4; 32]);
    assert_eq!(lease.admission_horizon(), TIMEOUT.get());
}

/// The attack, in three shapes: a payment open naming a bond that never
/// landed, one naming a bond already spent, and one naming a bond
/// another channel is already leasing. Each would put a client's funding
/// into a channel with no stake behind it.
#[test]
fn a_payment_open_needs_a_bond_that_is_live_and_unleased() {
    let payment = open_tx(payment_funding(), payment_terms());

    // 1. `P` withholds the bond open and submits the payment open `C`
    //    already signed. The bond edge is simply not there.
    let mut absent = state(payment_store(), [MAKER_SEED, TAKER_SEED, BOND_SEED]);
    let before = *absent.store();
    assert_eq!(
        absent.apply(CONTEXT, &FAKE_VERIFIER, &payment),
        Err(ApplyError::MissingEdge {
            id: payment_bond_edge(),
        }),
    );
    assert_eq!(*absent.store(), before, "a refused open moves nothing");

    // 2. The bond landed and was taken back. An unleased bond times out
    //    at any height, which is exactly what makes a payment open held
    //    back until after that timeout fail here rather than lease a
    //    bond the provider has already recovered.
    let mut closed = bonded_state();
    let _event = apply(&mut closed, &bond_timeout_tx());
    let before = *closed.store();
    assert_eq!(
        closed.apply(CONTEXT, &FAKE_VERIFIER, &payment),
        Err(ApplyError::MissingEdge {
            id: payment_bond_edge(),
        }),
    );
    assert_eq!(*closed.store(), before);

    // 3. One bond, one channel. The second open finds the slots taken.
    let store = FixedStore::empty_with_registry(
        [MAKER_COIN, BOND_COIN, SECOND_CLIENT_COIN],
        [payment_edge_id(), payment_bond_edge()],
        lease_slots(),
    );
    let mut leased = state(store, [MAKER_SEED, BOND_SEED, SECOND_CLIENT_SEED]);
    let _event = apply(&mut leased, &payment_bond_open());
    let Ok(_outcome) = leased.apply(CONTEXT, &FAKE_VERIFIER, &payment) else {
        panic!("the first payment open leases the bond");
    };
    let second = open_tx(second_payment_funding(), second_payment_terms());
    let before = *leased.store();
    assert_eq!(
        leased.apply(CONTEXT, &FAKE_VERIFIER, &second),
        Err(ApplyError::InvalidOpen {
            output: second_payment_edge(),
            reason: InvalidOpenReason::WorkBondAlreadyLeased,
        }),
    );
    assert_eq!(*leased.store(), before);
    // The lease that was already there is the first channel's, unchanged.
    assert_eq!(stored_lease(&leased).payment_edge(), payment_edge_id());
}

/// A live bond is not enough: it has to be *this* bond. The embedded
/// witness is the bond's own canonical bytes, so one comparison decides
/// the stake, the award, the horizon, and the two parties at once.
#[test]
fn a_payment_open_needs_the_bond_whose_terms_it_embeds() {
    let payment = payment_of(|payment| payment.bond_edge = other_bond_edge());
    let funding = payment_funding();
    let output = Tx::edge_id_of(&funding, &payment);
    let open = open_tx(funding, payment);
    // Both bonds' lease slots are declared, so nothing but the check
    // itself stands between this open and a lease over the wrong bond.
    let [first, second] = lease_slots();
    let [other_first, other_second] = bond_lease_slots(support::NETWORK, other_bond_edge());
    let store = FixedStore::empty_with_registry(
        [MAKER_COIN, BOND_COIN],
        [output, other_bond_edge()],
        [first, second, other_first, other_second],
    );
    let mut state = state(store, [MAKER_SEED, BOND_SEED]);
    let _event = apply(
        &mut state,
        &open_tx_with(
            payment_bond_funding(),
            other_bond_terms(),
            (
                hellas_kernel::PartyKeys::sole(TAKER),
                hellas_kernel::Authority::Owner,
            ),
            (
                hellas_kernel::PartyKeys::sole(MAKER),
                hellas_kernel::Authority::Owner,
            ),
        ),
    );
    let before = *state.store();

    assert_eq!(
        state.apply(CONTEXT, &FAKE_VERIFIER, &open),
        Err(ApplyError::InvalidOpen {
            output,
            reason: InvalidOpenReason::WorkBondTermsMismatch,
        }),
    );
    assert_eq!(*state.store(), before);
}

/// Writes `chunk` into lease slot `index`, leaving the other empty.
///
/// Nothing in the kernel can produce this state — a lease is created
/// whole in one registry diff — so it is written directly, which is the
/// only way to test that a reader refuses it rather than rounding it to
/// "no lease".
fn poison_lease<const C: usize, const E: usize, const R: usize>(
    state: &mut State<FixedStore<C, E, R>>,
    index: u8,
    chunk: RegistryChunk,
) {
    let slot = bond_lease_slot(support::NETWORK, payment_bond_edge(), index);
    let mut store = *state.store();
    {
        let mut batch = store.begin();
        let _ = batch.remove_registry_chunk(slot);
        let Ok(()) = batch.insert_registry_chunk(slot, chunk) else {
            panic!("the fixture declares both lease slots");
        };
        batch.commit();
    }
    *state = State::new(store);
}

/// One well-formed chunk of a lease-shaped value, with its partner
/// missing.
fn half_lease_chunk(index: u8) -> RegistryChunk {
    let value = [0x5a_u8; BondLease::ENCODED_SIZE];
    let Some(chunk) = RegistryChunk::split(
        RegistryNamespace::BondLease,
        RegistryRecordTag::BondLease,
        &value,
        index,
    ) else {
        panic!("a lease-width value splits at both indices");
    };
    chunk
}

/// The lease is two chunks, so "unleased" is a statement about both
/// slots. Half of one is not the absence of one.
#[test]
fn a_half_written_lease_is_never_read_as_an_unleased_bond() {
    let payment = open_tx(payment_funding(), payment_terms());

    for occupied in 0..BOND_LEASE_CHUNKS {
        let mut state = bonded_state();
        poison_lease(&mut state, occupied, half_lease_chunk(occupied));
        let before = *state.store();

        // The open cannot take a lease over slots it cannot read...
        assert_eq!(
            state.apply(CONTEXT, &FAKE_VERIFIER, &payment),
            Err(ApplyError::InvalidOpen {
                output: payment_edge_id(),
                reason: InvalidOpenReason::WorkBondLeaseFault {
                    fault: BondLeaseFault::Partial,
                },
            }),
        );
        // ...and the bond cannot take the exit that only an unleased
        // bond has.
        assert_eq!(
            state.apply(CONTEXT, &FAKE_VERIFIER, &bond_timeout_tx()),
            Err(ApplyError::InvalidProof {
                input: payment_bond_edge(),
                reason: InvalidProofReason::BondLeaseFault {
                    fault: BondLeaseFault::Partial,
                },
            }),
        );
        assert_eq!(*state.store(), before, "neither refusal moved anything");
    }
}

/// Writes a whole two-chunk value into the lease slots.
fn poison_whole_lease<const C: usize, const E: usize, const R: usize>(
    state: &mut State<FixedStore<C, E, R>>,
    record_tag: RegistryRecordTag,
    value: &[u8],
) {
    for index in 0..BOND_LEASE_CHUNKS {
        let Some(chunk) =
            RegistryChunk::split(RegistryNamespace::BondLease, record_tag, value, index)
        else {
            panic!("a lease-width value splits at both indices");
        };
        poison_lease(state, index, chunk);
    }
}

/// Absence is a permission — it is what opens the immediate exit — so
/// every present-but-unreadable shape is refused instead of rounded to
/// it. A bond whose lease slots hold something nobody can read is not a
/// bond nobody has recourse against.
#[test]
fn a_present_but_unreadable_lease_is_never_read_as_absence() {
    let readable = {
        let mut state = open_payment_state();
        let mut bytes = [0_u8; BondLease::ENCODED_SIZE];
        let written = stored_lease(&state).write_to(&mut bytes);
        assert_eq!(written, BondLease::ENCODED_SIZE);
        let _ = &mut state;
        bytes
    };
    // The bond edge is the 32 bytes after the envelope and version.
    let mut other_bond = readable;
    other_bond[3..35].copy_from_slice(&[0x2c; 32]);

    let cases = [
        // A whole, well-formed value of another record kind.
        (
            RegistryRecordTag::PaymentPending,
            readable,
            BondLeaseFault::Shape,
            "another record kind",
        ),
        // Lease-shaped chunks whose reassembled bytes are not a lease.
        (
            RegistryRecordTag::BondLease,
            [0x5a; BondLease::ENCODED_SIZE],
            BondLeaseFault::Body,
            "noncanonical body",
        ),
        // A readable lease over some other bond, in this bond's slots.
        (
            RegistryRecordTag::BondLease,
            other_bond,
            BondLeaseFault::Edge,
            "another bond's lease",
        ),
    ];

    for (record_tag, value, fault, case) in cases {
        let mut state = open_payment_state();
        poison_whole_lease(&mut state, record_tag, &value);
        assert_eq!(
            state.apply(CONTEXT, &FAKE_VERIFIER, &bond_timeout_tx()),
            Err(ApplyError::InvalidProof {
                input: payment_bond_edge(),
                reason: InvalidProofReason::BondLeaseFault { fault },
            }),
            "{case}",
        );
    }
}

/// The close half of the rule, and the fix for the other side of the
/// same setup race: a client that co-signs a bond open and then never
/// sends the payment open must not be able to lock the provider's stake
/// for the whole horizon at no cost to itself.
#[test]
fn an_unleased_work_bond_times_out_at_once() {
    let mut state = bonded_state();
    assert!(lease_is_absent(&state), "nothing leased this bond");

    // Strictly before the committed timeout — the height rule every
    // other profile is governed by would refuse this exact close.
    assert!(CONTEXT.block_height() < TIMEOUT);
    let _event = apply(&mut state, &bond_timeout_tx());

    assert_eq!(state.store().edge(payment_bond_edge()), None);
    assert_eq!(
        state.store().coin(bond_timeout_out()).map(coin_view),
        Some((TAKER, STAKE)),
        "the stake returns to the provider that posted it",
    );
}

/// Once a channel is leasing the bond, the provider's stake stays where
/// the client's recourse can reach it until the horizon both sides
/// committed to — and the lease leaves with it.
#[test]
fn a_leased_work_bond_waits_for_its_horizon_and_takes_the_lease_with_it() {
    let mut state = open_payment_state();
    let timeout = bond_timeout_tx();

    let before = *state.store();
    assert_eq!(
        state.apply(CONTEXT, &FAKE_VERIFIER, &timeout),
        Err(ApplyError::InvalidProof {
            input: payment_bond_edge(),
            reason: InvalidProofReason::TimeoutNotReached,
        }),
    );
    assert_eq!(*state.store(), before, "a refused close moves nothing");

    // At the horizon it goes, and the lease goes with it: a record
    // about an edge that no longer exists is unreachable state.
    let Ok(outcome) = state.apply(at(TIMEOUT.get()), &FAKE_VERIFIER, &timeout) else {
        panic!("the horizon close is admitted");
    };
    let slots: Vec<RegistryChunkId> = outcome
        .registry()
        .iter()
        .map(|mutation| mutation.id())
        .collect();
    assert_eq!(slots, lease_slots().to_vec());
    assert!(
        outcome
            .registry()
            .iter()
            .all(|mutation| mutation.chunk().is_none()),
        "the close deletes both chunks rather than rewriting them",
    );
    assert_eq!(state.store().edge(payment_bond_edge()), None);
    assert!(lease_is_absent(&state));
    assert_eq!(
        state.store().coin(bond_timeout_out()).map(coin_view),
        Some((TAKER, STAKE)),
    );

    // The payment channel it insured is untouched: its own exits stay
    // open past the admission horizon.
    assert!(state.store().edge(payment_edge_id()).is_some());
}

/// A payment channel cannot open at or after its own admission horizon:
/// there would be no block left in which to admit a job. The rule is
/// enforced by the generic lifetime check — a payment's committed
/// horizon *is* its `Terms::timeout()` — and is pinned here because it
/// is the horizon rule the bond lease depends on, not because of where
/// it happens to live.
#[test]
fn a_payment_open_at_its_admission_horizon_is_refused() {
    let mut state = bonded_state();
    let open = open_tx(payment_funding(), payment_terms());

    assert_eq!(
        state.apply(at(TIMEOUT.get()), &FAKE_VERIFIER, &open),
        Err(ApplyError::InvalidOpen {
            output: payment_edge_id(),
            reason: InvalidOpenReason::TimeoutNotFuture,
        }),
    );
    assert!(lease_is_absent(&state), "a refused open takes no lease");
}

// ── The public settlement arithmetic ──────────────────────────────────
//
// The endpoints have to know what a close will pay before they sign the
// certificate it pays from, and they cannot read an `Edge`: they read a
// finalized edge's values from a light client. The tests below are the
// binding between that public arithmetic and the arithmetic consensus
// actually applies — not a second opinion about it.

use hellas_kernel::{EdgeValues, WorkPaymentSettlement, adjudicated_payouts, freeze_payouts};

/// Returns the settlement projection of the live payment edge.
fn settlement_of<const C: usize, const E: usize, const R: usize>(
    state: &State<FixedStore<C, E, R>>,
    omission_bond: u64,
) -> WorkPaymentSettlement {
    let Some(edge) = state.store().edge(payment_edge_id()) else {
        panic!("the payment edge is live");
    };
    let Some(settlement) = hellas_kernel::work_payment_settlement(edge.values(), omission_bond)
    else {
        panic!("a live payment edge prices both of its exits");
    };
    settlement
}

/// The payouts the public helper builds are the payouts consensus
/// accepts, and one unit either way is refused.
#[test]
fn the_public_payout_helper_builds_the_close_consensus_accepts() {
    let mut state = open_payment_state();
    apply_move(&mut state, CONTEXT, &start_tx(Party::Taker, Some(5)));
    let Some(record) = pending_record(&state) else {
        panic!("the start wrote a contest");
    };

    let settlement = settlement_of(&state, OMISSION_BOND);
    assert_eq!(settlement.adjudicated_total(), PAYMENT_VALUE);
    assert_eq!(settlement.capacity(), PAYMENT_CAPACITY);
    assert_eq!(settlement.omission_bond(), OMISSION_BOND);

    let Ok(outputs) = adjudicated_payouts(
        settlement,
        PARTIES,
        record.final_cumulative(),
        false,
        [false; 2],
    ) else {
        panic!("a contest inside capacity has payouts");
    };
    let seal = record.contest_commitment(support::NETWORK, payment_edge_id(), payment_terms_hash());

    // MUTATION: one unit of omission bond the edge did not commit. The
    // endpoint's payout is then a unit over what the contest proved, and
    // consensus refuses it.
    let Some(inflated) = hellas_kernel::work_payment_settlement(
        EdgeValues::new(PAYMENT_VALUE, 0, Fees::ZERO),
        OMISSION_BOND + 1,
    ) else {
        panic!("the inflated settlement is representable");
    };
    let Ok(over) = adjudicated_payouts(
        inflated,
        PARTIES,
        record.final_cumulative(),
        true,
        [false; 2],
    ) else {
        panic!("the inflated payout is representable");
    };
    assert_close_rejected(
        &mut state,
        at(RESPONSE_DEADLINE),
        &Tx::close(payment_edge_id(), Proof::adjudicated(seal), list(&over)),
        InvalidProofReason::PayoutMismatch,
    );

    let (provider, client) = apply_payment_close(
        &mut state,
        at(RESPONSE_DEADLINE),
        &Tx::close(payment_edge_id(), Proof::adjudicated(seal), list(&outputs)),
    );
    assert_eq!(provider, Some((TAKER, 5)));
    assert_eq!(client, Some((MAKER, PAYMENT_VALUE - 5)));
}

/// The penalty branch: a proved understatement pays the forfeited bond
/// on top, and the helper's `penalty_due` is that same branch.
#[test]
fn the_public_payout_helper_covers_both_penalty_values() {
    let mut state = open_payment_state();
    apply_move(&mut state, CONTEXT, &start_tx(Party::Maker, Some(3)));
    let Some(opened) = pending_record(&state) else {
        panic!("the start wrote a contest");
    };
    apply_move(&mut state, at(2), &response_tx(opened.start_id(), 7));
    let Some(answered) = pending_record(&state) else {
        panic!("the response advanced the contest");
    };
    assert!(answered.penalty_due());

    let settlement = settlement_of(&state, OMISSION_BOND);
    let Ok(outputs) = adjudicated_payouts(
        settlement,
        PARTIES,
        answered.final_cumulative(),
        answered.penalty_due(),
        [false; 2],
    ) else {
        panic!("the proved understatement has payouts");
    };

    // MUTATION: the same contest settled as though nothing were proved.
    let Ok(unpenalised) = adjudicated_payouts(
        settlement,
        PARTIES,
        answered.final_cumulative(),
        false,
        [false; 2],
    ) else {
        panic!("the unpenalised payout is representable");
    };
    let seal =
        answered.contest_commitment(support::NETWORK, payment_edge_id(), payment_terms_hash());
    assert_close_rejected(
        &mut state,
        at(3),
        &Tx::close(
            payment_edge_id(),
            Proof::adjudicated(seal),
            list(&unpenalised),
        ),
        InvalidProofReason::PayoutMismatch,
    );

    let (provider, client) = apply_payment_close(
        &mut state,
        at(3),
        &Tx::close(payment_edge_id(), Proof::adjudicated(seal), list(&outputs)),
    );
    assert_eq!(provider, Some((TAKER, 7 + OMISSION_BOND)));
    assert_eq!(client, Some((MAKER, PAYMENT_VALUE - 7 - OMISSION_BOND)));
}

/// The cooperative route has its own total, and the helper knows which.
#[test]
fn the_public_freeze_payout_matches_the_cooperative_close() {
    let mut state = open_payment_state();
    let settlement = settlement_of(&state, OMISSION_BOND);
    assert_eq!(settlement.freeze_total(), PAYMENT_VALUE);

    let Ok(outputs) = freeze_payouts(settlement, PARTIES, 6, 0, [false; 2]) else {
        panic!("a freeze inside capacity has payouts");
    };
    let validity = (1, 1);
    let digest = freeze_digest(
        support::NETWORK,
        payment_edge_id(),
        payment_terms_hash(),
        6,
        validity,
    );
    let (provider, client) = apply_payment_close(
        &mut state,
        CONTEXT,
        &Tx::close(
            payment_edge_id(),
            Proof::freeze(
                6,
                validity,
                PartyAuth::owner(Sig::placeholder(MAKER, digest)),
                PartyAuth::owner(Sig::placeholder(TAKER, digest)),
            ),
            list(&outputs),
        ),
    );
    assert_eq!(provider, Some((TAKER, 6)));
    assert_eq!(client, Some((MAKER, PAYMENT_VALUE - 6)));
}

/// Under a nonzero fee schedule the two routes stop agreeing, and the
/// public helper is what tells an endpoint which one bounds it.
///
/// `Freeze` verifies two signatures where `Adjudicated` verifies none,
/// so the dearer route distributes less and the capacity that matters is
/// the smaller of the two. A helper that read `EdgeState.value`, or that
/// priced only the route it was building, would admit a certificate this
/// channel cannot pay.
#[test]
fn nonzero_fees_separate_the_two_routes_and_the_capacity_they_imply() {
    const FEES: Fees = Fees::new(1, 0, 1, 0);
    let priced = Context::with_fees(
        support::NETWORK,
        BlockHeight::new(1),
        BlockHash::from_bytes([0; BlockHash::LENGTH]),
        FEES,
    );

    let mut state = bonded_state();
    let open = open_tx(payment_funding(), payment_terms());
    let Ok(_outcome) = state.apply(priced, &FAKE_VERIFIER, &open) else {
        panic!("payment open rejected under a nonzero fee schedule");
    };

    let Some(edge) = state.store().edge(payment_edge_id()) else {
        panic!("the payment edge is live");
    };
    let settlement = settlement_of(&state, OMISSION_BOND);
    assert_eq!(edge.close_fees(), FEES);
    assert!(
        settlement.freeze_total() < settlement.adjudicated_total(),
        "the two-signature route must distribute less: {settlement:?}",
    );
    assert_eq!(
        settlement.capacity(),
        settlement.freeze_total() - OMISSION_BOND,
    );

    // The capacity boundary the helper reports is the boundary the real
    // move enforces, exactly.
    apply_move(
        &mut state,
        priced,
        &start_tx(Party::Taker, Some(settlement.capacity())),
    );
    let Some(record) = pending_record(&state) else {
        panic!("the start wrote a contest");
    };
    let Ok(outputs) = adjudicated_payouts(
        settlement,
        PARTIES,
        record.final_cumulative(),
        false,
        [false; 2],
    ) else {
        panic!("a contest at capacity has payouts");
    };
    let seal = record.contest_commitment(support::NETWORK, payment_edge_id(), payment_terms_hash());
    let (provider, client) = apply_payment_close(
        &mut state,
        Context::with_fees(
            support::NETWORK,
            BlockHeight::new(RESPONSE_DEADLINE),
            BlockHash::from_bytes([0; BlockHash::LENGTH]),
            FEES,
        ),
        &Tx::close(payment_edge_id(), Proof::adjudicated(seal), list(&outputs)),
    );
    assert_eq!(provider, Some((TAKER, settlement.capacity())));
    assert_eq!(
        client,
        Some((
            MAKER,
            settlement.adjudicated_total() - settlement.capacity()
        )),
    );
}

/// One unit above the reported capacity is refused by the move that
/// admits certificates, so the helper's number is the consensus number
/// and not an estimate of it.
#[test]
fn a_certificate_one_unit_over_the_reported_capacity_is_refused() {
    const FEES: Fees = Fees::new(1, 0, 1, 0);
    let priced = Context::with_fees(
        support::NETWORK,
        BlockHeight::new(1),
        BlockHash::from_bytes([0; BlockHash::LENGTH]),
        FEES,
    );
    let mut state = bonded_state();
    let open = open_tx(payment_funding(), payment_terms());
    let Ok(_outcome) = state.apply(priced, &FAKE_VERIFIER, &open) else {
        panic!("payment open rejected under a nonzero fee schedule");
    };
    let settlement = settlement_of(&state, OMISSION_BOND);

    assert_eq!(
        state.apply(
            priced,
            &FAKE_VERIFIER,
            &start_tx(Party::Taker, Some(settlement.capacity() + 1)),
        ),
        Err(ApplyError::InvalidMove {
            input: payment_edge_id(),
            reason: InvalidMoveReason::CertificateOverCapacity,
        }),
    );
}

/// An edge whose reserve cannot price its dearer exit has no
/// settlement, and neither does one whose bond exceeds everything the
/// close distributes. Both are refusals, not zeroes.
#[test]
fn a_settlement_that_cannot_be_priced_is_absent() {
    let unpayable = EdgeValues::new(100, 0, Fees::new(1, 1, 1, 1));
    assert_eq!(
        hellas_kernel::work_payment_settlement(unpayable, 0),
        None,
        "a reserve below the committed close fee prices no route",
    );

    let overbonded = EdgeValues::new(10, 0, Fees::ZERO);
    assert_eq!(
        hellas_kernel::work_payment_settlement(overbonded, 11),
        None,
        "a bond above everything the close distributes leaves no capacity",
    );
    let Some(exact) = hellas_kernel::work_payment_settlement(overbonded, 10) else {
        panic!("a bond equal to the distributable total leaves zero capacity");
    };
    assert_eq!(exact.capacity(), 0);

    let Some(settlement) =
        hellas_kernel::work_payment_settlement(EdgeValues::new(u64::MAX, 0, Fees::ZERO), 1)
    else {
        panic!("the largest edge is representable");
    };
    assert_eq!(
        adjudicated_payouts(settlement, PARTIES, u64::MAX, true, [false; 2]),
        Err(InvalidProofReason::PayoutOverCapacity),
        "adding the forfeited bond must not wrap",
    );
    assert_eq!(
        adjudicated_payouts(settlement, PARTIES, u64::MAX, false, [false; 2])
            .map(|payouts| payouts[1].value()),
        Ok(0),
    );
}
