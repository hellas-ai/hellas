//! Coin delegation through the kernel's public apply path.
//!
//! Every test here drives `State::apply` with whole transactions, so a
//! rule is only "enforced" if a transaction breaking it is refused and a
//! transaction honouring it lands. The attacks are the ones in the P5
//! review of the delegation design (findings 1, 3, 7 and 8), plus one
//! test per close rule (C1–C5) and the open rules (F1–F6).
//!
//! The cast: `O` owns coins and runs node key `N`; `N2` is O's second
//! node key; `P` is a provider whose node key is `PN`; `K` is a key a
//! thief holding `N` controls outright.

#![allow(clippy::alloc_instead_of_core)]
#![allow(clippy::disallowed_types)]
#![allow(clippy::expect_used)]
#![allow(clippy::std_instead_of_alloc)]
#![allow(clippy::std_instead_of_core)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::indexing_slicing)] // tests may index; the panic-freedom lock targets src

mod support;

use hellas_kernel::{
    ApplyError, ApplyOutcome, Auth, Authority, BlockHash, BlockHeight, CloseKind, Coin, CoinId,
    Context, EarnedCertificate, EdgeId, EventKind, Funding, Genesis, InvalidMoveReason,
    InvalidOpenReason, InvalidProofReason, InvalidReshapeReason, Key, List, MAX_EDGE_INPUTS,
    MAX_EDGE_OUTPUTS, MAX_PARTY_INPUTS, Move, Parties, Party, PartyAuth, PartyKeys,
    PaymentCloseResponse, PaymentCloseStart, Payout, PendingPaymentClose, Proof, ProtocolCode,
    Reshape, Sig, State, Terms, Tx, WorkPaymentTerms, WorkStakeBondTerms, bond_lease_slots,
    freeze_digest, no_earned_digest, parse_pending_close, pending_payment_close_slot,
    response_digest, start_digest, start_id,
};
use support::{
    FAKE_VERIFIER, NETWORK, coin_id, key,
    map_store::{MapStore, map_state},
};

const O: Key = key(0x10);
const N: Key = key(0x11);
const N2: Key = key(0x12);
const P: Key = key(0x20);
const PN: Key = key(0x21);
const K: Key = key(0x30);

const O_COIN: CoinId = coin_id(0x41);
const O_COIN_2: CoinId = coin_id(0x42);
const P_COIN: CoinId = coin_id(0x43);
const K_COIN: CoinId = coin_id(0x44);

const VALUE: u64 = 100;
const HORIZON: BlockHeight = BlockHeight::new(1_000);
const OMISSION_BOND: u64 = 2;
const RESPONSE_WINDOW: u64 = 64;

const fn at(height: u64) -> Context {
    Context::new(
        NETWORK,
        BlockHeight::new(height),
        BlockHash::from_bytes([0; BlockHash::LENGTH]),
    )
}

fn genesis() -> State<MapStore> {
    map_state([
        Genesis::coin(O_COIN, O, VALUE),
        Genesis::coin(O_COIN_2, O, VALUE),
        Genesis::coin(P_COIN, P, VALUE),
        Genesis::coin(K_COIN, K, DUST),
    ])
}

/// What a thief stakes of its own: enough to fund a channel above its
/// omission bond, and nothing more.
const DUST: u64 = 10;

fn apply(state: &mut State<MapStore>, context: Context, tx: &Tx) -> ApplyOutcome {
    match state.apply(context, &FAKE_VERIFIER, tx) {
        Ok(outcome) => outcome,
        Err(error) => panic!("expected {tx:?} to apply, got {error:?}"),
    }
}

/// Applies `tx`, requires the exact refusal, and requires that nothing
/// moved.
fn refuse(state: &mut State<MapStore>, context: Context, tx: &Tx, expected: ApplyError) {
    let coins: Vec<_> = state.store().coins().collect();
    let edges: Vec<_> = state.store().edges().collect();
    let chunks: Vec<_> = state.store().registry_chunks().collect();
    assert_eq!(state.apply(context, &FAKE_VERIFIER, tx), Err(expected));
    assert_eq!(state.store().coins().collect::<Vec<_>>(), coins);
    assert_eq!(state.store().edges().collect::<Vec<_>>(), edges);
    assert_eq!(state.store().registry_chunks().collect::<Vec<_>>(), chunks);
}

fn inputs(ids: &[CoinId]) -> List<CoinId, MAX_EDGE_INPUTS> {
    support::list(ids)
}

fn payouts(entries: &[Payout]) -> List<Payout, MAX_EDGE_OUTPUTS> {
    support::list(entries)
}

fn party_coins(ids: &[CoinId]) -> List<CoinId, MAX_PARTY_INPUTS> {
    support::list(ids)
}

/// A reshape of `inputs` into `outputs`, authorized by `signer`.
fn reshape(ids: &[CoinId], outputs: &[Payout], signer: Key) -> Tx {
    let inputs = inputs(ids);
    let outputs = payouts(outputs);
    let hash = Reshape::payload_hash(NETWORK, &inputs, &outputs);
    Tx::Owner(Reshape::new(
        inputs,
        outputs,
        Auth::native(Sig::placeholder(signer, hash)),
    ))
}

fn reshape_ids(ids: &[CoinId], outputs: &[Payout]) -> Vec<CoinId> {
    Reshape::output_ids(NETWORK, &inputs(ids), &payouts(outputs))
        .iter()
        .copied()
        .collect()
}

/// O reshapes one of its coins into a coin of the same value delegated
/// to `to`, and returns the new coin's id.
fn delegate(state: &mut State<MapStore>, coin: CoinId, to: Key) -> CoinId {
    let outputs = [Payout::delegated(O, Some(to), VALUE)];
    apply(state, at(1), &reshape(&[coin], &outputs, O));
    reshape_ids(&[coin], &outputs)[0]
}

/// The witness `authority` gives for `party`, over `hash`.
fn witness(party: PartyKeys, authority: Authority, hash: hellas_kernel::PayloadHash) -> PartyAuth {
    PartyAuth::new(
        authority,
        Auth::native(Sig::placeholder(party.key(authority), hash)),
    )
}

fn open(
    maker_coins: &[CoinId],
    taker_coins: &[CoinId],
    terms: &Terms,
    authorities: (Authority, Authority),
) -> Tx {
    let funding = Funding::new(party_coins(maker_coins), party_coins(taker_coins));
    let hash = Tx::open_hash(NETWORK, &funding, terms);
    let parties = terms.parties();
    Tx::open(
        funding,
        terms.clone(),
        witness(parties.maker(), authorities.0, hash),
        witness(parties.taker(), authorities.1, hash),
    )
}

fn edge_of(maker_coins: &[CoinId], taker_coins: &[CoinId], terms: &Terms) -> EdgeId {
    Tx::edge_id_of(
        &Funding::new(party_coins(maker_coins), party_coins(taker_coins)),
        terms,
    )
}

const fn invalid_open(output: EdgeId, reason: InvalidOpenReason) -> ApplyError {
    ApplyError::InvalidOpen { output, reason }
}

fn basic(maker: PartyKeys, taker: PartyKeys, outputs: &[Payout]) -> Terms {
    Terms::basic(
        ProtocolCode::new(5),
        Parties::new(maker, taker),
        HORIZON,
        payouts(outputs),
    )
}

/// O's party as run by node key N, its payouts back to N.
const O_VIA_N: PartyKeys = PartyKeys::new(O, N, Some(N));
/// P's party as run by its node key, payouts undelegated.
const P_VIA_PN: PartyKeys = PartyKeys::new(P, PN, None);

/// A tag-4 bond: `maker` stakes `stake`, returned to the maker's
/// destination at the horizon.
fn bond_terms(maker: PartyKeys, taker: PartyKeys, stake: u64) -> WorkStakeBondTerms {
    WorkStakeBondTerms {
        parties: Parties::new(maker, taker),
        timeout: HORIZON,
        timeout_outputs: payouts(&[maker.payout(stake, false)]),
        max_job_price: 1,
    }
}

fn payment_terms(bond_edge: EdgeId, bond: WorkStakeBondTerms) -> Terms {
    Terms::work_payment(WorkPaymentTerms {
        bond_edge,
        bond_terms: bond,
        private_policy_commitment: [7; 32],
        omit_response_blocks: RESPONSE_WINDOW,
        start_validity_blocks: 8,
        omission_bond: OMISSION_BOND,
    })
}

// ── O1/O2: the owner transaction (finding 1) ──────────────────────────

/// Finding 1: a delegation that edited a coin in place could be
/// replayed after the owner cleared it, re-arming the fired key. A
/// reshape consumes its inputs, so its replay finds them gone.
#[test]
fn a_replayed_delegation_finds_its_input_consumed() {
    let mut state = genesis();
    let to_node = [Payout::delegated(O, Some(N), VALUE)];
    let delegation = reshape(&[O_COIN], &to_node, O);
    apply(&mut state, at(1), &delegation);
    let delegated = reshape_ids(&[O_COIN], &to_node)[0];
    assert_eq!(
        state.store().coin(delegated),
        Some(Coin::issue(O, Some(N), VALUE))
    );

    // O fires N: the delegated coin back to O, undelegated.
    let back = [Payout::new(O, VALUE)];
    let revocation = reshape(&[delegated], &back, O);
    apply(&mut state, at(2), &revocation);
    let swept = reshape_ids(&[delegated], &back)[0];
    assert_eq!(state.store().coin(swept), Some(Coin::issue(O, None, VALUE)));

    // The attacker resubmits the public bytes of both. Neither lands.
    refuse(
        &mut state,
        at(3),
        &delegation,
        ApplyError::MissingCoin { id: O_COIN },
    );
    refuse(
        &mut state,
        at(3),
        &revocation,
        ApplyError::MissingCoin { id: delegated },
    );
}

/// A reshape moves value only for the inputs' one owner, under that
/// owner's own authorization. A delegate cannot produce a coin.
#[test]
fn only_the_owner_reshapes_and_only_its_own_coins() {
    let mut state = genesis();
    let delegated = delegate(&mut state, O_COIN, N);

    // The delegate signs a reshape of a coin delegated to it: refused,
    // because a reshape is verified against the owner and nothing else.
    refuse(
        &mut state,
        at(2),
        &reshape(&[delegated], &[Payout::new(K, VALUE)], N),
        ApplyError::InvalidReshape {
            reason: InvalidReshapeReason::BadSignature,
        },
    );
    // A stranger signs for O's coin.
    refuse(
        &mut state,
        at(2),
        &reshape(&[O_COIN_2], &[Payout::new(P, VALUE)], P),
        ApplyError::InvalidReshape {
            reason: InvalidReshapeReason::BadSignature,
        },
    );
    // Two owners' coins in one reshape: no one key could authorize it.
    refuse(
        &mut state,
        at(2),
        &reshape(&[O_COIN_2, P_COIN], &[Payout::new(O, 2 * VALUE)], O),
        ApplyError::InvalidReshape {
            reason: InvalidReshapeReason::OwnerMismatch,
        },
    );
    // Value is conserved exactly, in both directions.
    for value in [VALUE - 1, VALUE + 1] {
        refuse(
            &mut state,
            at(2),
            &reshape(&[O_COIN_2], &[Payout::new(O, value)], O),
            ApplyError::InvalidReshape {
                reason: InvalidReshapeReason::ValueMismatch,
            },
        );
    }
    // Nothing consumed is nobody authorizing.
    refuse(
        &mut state,
        at(2),
        &reshape(&[], &[], O),
        ApplyError::InvalidReshape {
            reason: InvalidReshapeReason::NoInputs,
        },
    );
    refuse(
        &mut state,
        at(2),
        &reshape(&[O_COIN_2, O_COIN_2], &[Payout::new(O, 2 * VALUE)], O),
        ApplyError::DuplicateInput { id: O_COIN_2 },
    );
}

/// An output id is fresh or the reshape is refused: a hand-picked
/// genesis id that collides with one cannot be overwritten.
#[test]
fn a_reshape_never_overwrites_a_live_coin() {
    let outputs = [Payout::new(P, VALUE)];
    let collision = reshape_ids(&[O_COIN], &outputs)[0];
    let mut state = map_state([
        Genesis::coin(O_COIN, O, VALUE),
        Genesis::coin(collision, K, 1),
    ]);
    refuse(
        &mut state,
        at(1),
        &reshape(&[O_COIN], &outputs, O),
        ApplyError::OutputExists { id: collision },
    );
}

/// The owner may pay anyone, split and merge, and set any delegate: the
/// reshape issues exactly the coins its outputs name, under the ids its
/// derivation gives them, and announces both sides.
#[test]
fn a_reshape_issues_exactly_the_coins_it_names() {
    let mut state = genesis();
    let outputs = [
        Payout::new(P, 30),
        Payout::delegated(O, Some(N2), 120),
        Payout::new(O, 50),
    ];
    let outcome = apply(
        &mut state,
        at(1),
        &reshape(&[O_COIN, O_COIN_2], &outputs, O),
    );
    let ids = reshape_ids(&[O_COIN, O_COIN_2], &outputs);
    assert_eq!(
        outcome.public_event().map(|event| event.kind().clone()),
        Some(EventKind::CoinsReshaped {
            inputs: inputs(&[O_COIN, O_COIN_2]),
            outputs: support::list(&ids),
        }),
    );
    assert_eq!(state.store().coin(O_COIN), None);
    assert_eq!(state.store().coin(O_COIN_2), None);
    assert_eq!(state.store().coin(ids[0]), Some(Coin::issue(P, None, 30)));
    assert_eq!(
        state.store().coin(ids[1]),
        Some(Coin::issue(O, Some(N2), 120))
    );
    assert_eq!(state.store().coin(ids[2]), Some(Coin::issue(O, None, 50)));
}

// ── F1–F6: opens ──────────────────────────────────────────────────────

/// F3: a delegate may not open a basic edge. Its committed timeout pays
/// with no signature, so a delegate that could open one could park its
/// owner's coins until a height of its choosing with no exit for the
/// owner. Everything else about this open is legal: the coin is
/// delegated to the signer and the destination is the signer's.
#[test]
fn a_delegate_signed_basic_open_is_refused() {
    let mut state = genesis();
    let coin = delegate(&mut state, O_COIN, N);
    let terms = basic(O_VIA_N, PartyKeys::sole(K), &[O_VIA_N.payout(VALUE, false)]);
    let output = edge_of(&[coin], &[], &terms);
    refuse(
        &mut state,
        at(2),
        &open(&[coin], &[], &terms, (Authority::Signer, Authority::Owner)),
        invalid_open(output, InvalidOpenReason::BasicAuthNotOwner),
    );
    // The owner itself may open it, delegated coin and all.
    apply(
        &mut state,
        at(2),
        &open(&[coin], &[], &terms, (Authority::Owner, Authority::Owner)),
    );
}

/// F2: a delegate reaches the coins delegated to it and no others of
/// the same owner — not O's undelegated coins, and not O's coins
/// delegated to its other node.
#[test]
fn a_delegate_cannot_fund_with_a_coin_delegated_elsewhere() {
    let mut state = genesis();
    let to_other_node = delegate(&mut state, O_COIN, N2);
    let bond = Terms::work_stake_bond(bond_terms(O_VIA_N, PartyKeys::sole(K), VALUE));
    for coin in [to_other_node, O_COIN_2] {
        let output = edge_of(&[coin], &[], &bond);
        refuse(
            &mut state,
            at(2),
            &open(&[coin], &[], &bond, (Authority::Signer, Authority::Owner)),
            invalid_open(output, InvalidOpenReason::FundingNotDelegated),
        );
    }
    // The coin delegated to N is N's to stake.
    let to_node = delegate(&mut state, O_COIN_2, N);
    apply(
        &mut state,
        at(2),
        &open(
            &[to_node],
            &[],
            &bond,
            (Authority::Signer, Authority::Owner),
        ),
    );
}

/// F2 and finding 7: a delegate may keep its earnings spendable by
/// itself, or hand them back undelegated, and may name no other key. The
/// destination's owner is the party's owner by construction, so a
/// foreign owner is not even expressible.
#[test]
fn a_delegate_signed_open_naming_a_foreign_destination_is_refused() {
    let mut state = genesis();
    let coin = delegate(&mut state, O_COIN, N);
    let foreign = PartyKeys::new(O, N, Some(N2));
    let bond = Terms::work_stake_bond(bond_terms(foreign, PartyKeys::sole(K), VALUE));
    let output = edge_of(&[coin], &[], &bond);
    refuse(
        &mut state,
        at(2),
        &open(&[coin], &[], &bond, (Authority::Signer, Authority::Owner)),
        invalid_open(output, InvalidOpenReason::PayoutDelegateNotSigner),
    );

    // Signer-signed: itself or nobody.
    for destination in [Some(N), None] {
        let mut state = genesis();
        let coin = delegate(&mut state, O_COIN, N);
        let bond = Terms::work_stake_bond(bond_terms(
            PartyKeys::new(O, N, destination),
            PartyKeys::sole(K),
            VALUE,
        ));
        apply(
            &mut state,
            at(2),
            &open(&[coin], &[], &bond, (Authority::Signer, Authority::Owner)),
        );
    }

    // Owner-signed: any delegate.
    let mut state = genesis();
    let bond = Terms::work_stake_bond(bond_terms(foreign, PartyKeys::sole(K), VALUE));
    apply(
        &mut state,
        at(2),
        &open(&[O_COIN], &[], &bond, (Authority::Owner, Authority::Owner)),
    );
}

/// F1: every funding coin belongs to its party's owner, whichever key
/// signs.
#[test]
fn funding_belongs_to_the_party_owner() {
    let mut state = genesis();
    let bond = Terms::work_stake_bond(bond_terms(O_VIA_N, PartyKeys::sole(K), VALUE));
    let output = edge_of(&[P_COIN], &[], &bond);
    for authority in [Authority::Owner, Authority::Signer] {
        refuse(
            &mut state,
            at(1),
            &open(&[P_COIN], &[], &bond, (authority, Authority::Owner)),
            invalid_open(output, InvalidOpenReason::FundingUnauthorized),
        );
    }
}

/// Finding 8: whether a witness is the owner's or the signer's is a byte
/// of the transaction, and the kernel checks exactly the one key that
/// byte names. A signer's signature presented as the owner's, or the
/// other way round, does not verify.
#[test]
fn a_witness_verifies_against_exactly_the_key_its_authority_names() {
    let mut state = genesis();
    let coin = delegate(&mut state, O_COIN, N);
    let bond = Terms::work_stake_bond(bond_terms(O_VIA_N, PartyKeys::sole(K), VALUE));
    let funding = Funding::new(party_coins(&[coin]), party_coins(&[]));
    let hash = Tx::open_hash(NETWORK, &funding, &bond);
    let output = edge_of(&[coin], &[], &bond);
    let taker = witness(PartyKeys::sole(K), Authority::Owner, hash);
    for (authority, signed_by) in [(Authority::Owner, N), (Authority::Signer, O)] {
        let mislabelled =
            PartyAuth::new(authority, Auth::native(Sig::placeholder(signed_by, hash)));
        refuse(
            &mut state,
            at(2),
            &Tx::open(funding.clone(), bond.clone(), mislabelled, taker.clone()),
            invalid_open(output, InvalidOpenReason::BadSignature),
        );
    }
}

/// F4, F5 and finding 7: each work shape is funded by its maker alone,
/// so every party that can act on a work edge has had its owner proved
/// by funding — the provider's by the bond, the client's by the payment.
#[test]
fn work_shapes_are_funded_by_their_maker_alone() {
    let mut state = genesis();
    let bond = bond_terms(P_VIA_PN, PartyKeys::sole(O), VALUE);
    let bond_tx = Terms::work_stake_bond(bond.clone());
    apply(
        &mut state,
        at(1),
        &open(
            &[P_COIN],
            &[],
            &bond_tx,
            (Authority::Owner, Authority::Owner),
        ),
    );
    let bond_edge = edge_of(&[P_COIN], &[], &bond_tx);
    let payment = payment_terms(bond_edge, bond);

    // Client is the payment maker, provider the taker.
    let unfunded = edge_of(&[], &[], &payment);
    refuse(
        &mut state,
        at(2),
        &open(&[], &[], &payment, (Authority::Owner, Authority::Owner)),
        invalid_open(unfunded, InvalidOpenReason::WorkPaymentMakerUnfunded),
    );
}

/// F5's taker half, isolated: the provider funding the payment side is
/// refused even when the coin is its own.
#[test]
fn a_work_payment_refuses_provider_funding() {
    let mut state = map_state([
        Genesis::coin(O_COIN, O, VALUE),
        Genesis::coin(P_COIN, P, VALUE),
        Genesis::coin(coin_id(0x45), P, 1),
    ]);
    let bond = bond_terms(P_VIA_PN, PartyKeys::sole(O), VALUE);
    let bond_tx = Terms::work_stake_bond(bond.clone());
    apply(
        &mut state,
        at(1),
        &open(
            &[P_COIN],
            &[],
            &bond_tx,
            (Authority::Owner, Authority::Owner),
        ),
    );
    let payment = payment_terms(edge_of(&[P_COIN], &[], &bond_tx), bond);
    let output = edge_of(&[O_COIN], &[coin_id(0x45)], &payment);
    refuse(
        &mut state,
        at(2),
        &open(
            &[O_COIN],
            &[coin_id(0x45)],
            &payment,
            (Authority::Owner, Authority::Owner),
        ),
        invalid_open(output, InvalidOpenReason::WorkPaymentTakerFunded),
    );
}

/// F6: a timeout pays with no signature, so every committed timeout
/// payout lands exactly at one of the two committed destinations —
/// owner and delegate both. And F4: a bond pays its maker's destination
/// alone.
#[test]
fn a_timeout_payout_must_land_at_a_committed_destination() {
    let mut state = genesis();
    let taker = PartyKeys::sole(P);
    for outputs in [
        [Payout::new(K, VALUE)],
        [Payout::delegated(O, Some(N2), VALUE)],
        [Payout::new(O, VALUE)],
    ] {
        let terms = basic(O_VIA_N, taker, &outputs);
        let output = edge_of(&[O_COIN], &[], &terms);
        refuse(
            &mut state,
            at(1),
            &open(&[O_COIN], &[], &terms, (Authority::Owner, Authority::Owner)),
            invalid_open(output, InvalidOpenReason::TimeoutPayoutNotCommitted),
        );
    }
    // Both destinations, any split, a zero payout included.
    let terms = basic(
        O_VIA_N,
        taker,
        &[
            O_VIA_N.payout(60, false),
            taker.payout(40, false),
            taker.payout(0, false),
        ],
    );
    apply(
        &mut state,
        at(1),
        &open(&[O_COIN], &[], &terms, (Authority::Owner, Authority::Owner)),
    );

    // A bond returns its stake to its maker's destination and nowhere
    // else: not to the maker's owner under another delegate (not a
    // committed destination at all), and not to the taker's (committed,
    // but not the staker's).
    let taker = PartyKeys::sole(K);
    for (payout, reason) in [
        (
            Payout::new(O, VALUE),
            InvalidOpenReason::TimeoutPayoutNotCommitted,
        ),
        (
            taker.payout(VALUE, false),
            InvalidOpenReason::WorkStakeReturnRouting,
        ),
    ] {
        let mut bond = bond_terms(O_VIA_N, taker, VALUE);
        bond.timeout_outputs = payouts(&[payout]);
        let bond = Terms::work_stake_bond(bond);
        let output = edge_of(&[O_COIN_2], &[], &bond);
        refuse(
            &mut state,
            at(1),
            &open(
                &[O_COIN_2],
                &[],
                &bond,
                (Authority::Owner, Authority::Owner),
            ),
            invalid_open(output, reason),
        );
    }
}

// ── The payment channel: C1–C5 ────────────────────────────────────────

/// A live payment channel: P stakes a bond, O's node N funds the
/// payment from a coin delegated to it, payouts back to N.
struct Channel {
    state: State<MapStore>,
    payment: Terms,
    edge: EdgeId,
}

impl Channel {
    fn open(client: PartyKeys, provider: PartyKeys) -> Self {
        let mut state = genesis();
        let coin = delegate(&mut state, O_COIN, N);
        let bond_body = bond_terms(provider, client, VALUE);
        let bond = Terms::work_stake_bond(bond_body.clone());
        // The provider's own undelegated coin, so its owner signs the
        // bond; the client's node signs for the client.
        apply(
            &mut state,
            at(1),
            &open(&[P_COIN], &[], &bond, (Authority::Owner, Authority::Signer)),
        );
        let bond_edge = edge_of(&[P_COIN], &[], &bond);
        let payment = payment_terms(bond_edge, bond_body);
        apply(
            &mut state,
            at(1),
            &open(
                &[coin],
                &[],
                &payment,
                (Authority::Signer, Authority::Signer),
            ),
        );
        let edge = edge_of(&[coin], &[], &payment);
        Self {
            state,
            payment,
            edge,
        }
    }

    const fn parties(&self) -> Parties {
        self.payment.parties()
    }

    fn apply(&mut self, context: Context, tx: &Tx) -> ApplyOutcome {
        apply(&mut self.state, context, tx)
    }

    fn refuse(&mut self, context: Context, tx: &Tx, expected: ApplyError) {
        refuse(&mut self.state, context, tx, expected);
    }

    fn certificate(&self, amount: u64, authority: Authority) -> (EarnedCertificate, PartyAuth) {
        let certificate = EarnedCertificate::new(self.edge, self.payment.hash(), amount);
        let digest = certificate.digest(NETWORK);
        (
            certificate,
            witness(self.parties().maker(), authority, digest),
        )
    }

    fn start(
        &self,
        role: Party,
        authority: Authority,
        certificate: Option<(EarnedCertificate, PartyAuth)>,
    ) -> Tx {
        let earned = certificate.as_ref().map_or_else(
            || no_earned_digest(self.edge, self.payment.hash()),
            |(certificate, _)| certificate.digest(NETWORK),
        );
        let digest = start_digest(
            NETWORK,
            self.edge,
            self.payment.hash(),
            role,
            (2, 2),
            earned,
        );
        Tx::move_action(Move::StartPaymentClose(PaymentCloseStart::new(
            self.edge,
            self.payment.clone(),
            role,
            (2, 2),
            certificate,
            witness(role.keys_of(self.parties()), authority, digest),
        )))
    }

    fn respond(&self, amount: u64, authority: Authority) -> Tx {
        let record = self.pending().expect("a live contest");
        let certificate = self.certificate(amount, Authority::Signer);
        let digest = response_digest(
            NETWORK,
            self.edge,
            self.payment.hash(),
            record.start_id(),
            Party::Taker,
            certificate.0.digest(NETWORK),
        );
        Tx::move_action(Move::RespondPaymentClose(PaymentCloseResponse::new(
            self.edge,
            record.start_id(),
            Party::Taker,
            certificate,
            witness(self.parties().taker(), authority, digest),
        )))
    }

    fn pending(&self) -> Option<PendingPaymentClose> {
        match parse_pending_close(
            self.state
                .store()
                .registry_chunk(pending_payment_close_slot(NETWORK, self.edge)),
            self.edge,
        ) {
            hellas_kernel::PendingSlot::Present(record) => Some(record),
            hellas_kernel::PendingSlot::Absent => None,
            hellas_kernel::PendingSlot::Faulty(fault) => panic!("faulty contest {fault:?}"),
        }
    }

    fn settlement(&self) -> hellas_kernel::WorkPaymentSettlement {
        let edge = self.state.store().edge(self.edge).expect("live payment");
        hellas_kernel::work_payment_settlement(edge.values(), OMISSION_BOND).expect("settles")
    }

    fn adjudicated(&self, owner_signed: bool) -> (Tx, [Payout; 2]) {
        let record = self.pending().expect("a live contest");
        let payouts = hellas_kernel::adjudicated_payouts(
            self.settlement(),
            self.parties(),
            record.final_cumulative(),
            record.penalty_due(),
            owner_signed,
        )
        .expect("the contest settles");
        let commitment = record.contest_commitment(NETWORK, self.edge, self.payment.hash());
        (
            Tx::close(
                self.edge,
                Proof::adjudicated(commitment),
                support::list(&payouts),
            ),
            payouts,
        )
    }

    fn freeze(&self, earned: u64, authorities: (Authority, Authority), payouts: &[Payout]) -> Tx {
        let digest = freeze_digest(NETWORK, self.edge, self.payment.hash(), earned, (2, 2));
        Tx::close(
            self.edge,
            Proof::freeze(
                earned,
                (2, 2),
                witness(self.parties().maker(), authorities.0, digest),
                witness(self.parties().taker(), authorities.1, digest),
            ),
            support::list(payouts),
        )
    }

    fn freeze_payouts(&self, earned: u64, penalty: u64, owner_signed: bool) -> [Payout; 2] {
        hellas_kernel::freeze_payouts(
            self.settlement(),
            self.parties(),
            earned,
            penalty,
            owner_signed,
        )
        .expect("the freeze settles")
    }

    fn issued(&self, payouts: &[Payout; 2]) -> [Option<Coin>; 2] {
        let ids = Tx::close_output_ids(self.edge, &support::list(payouts));
        [
            self.state.store().coin(ids.as_slice()[0]),
            self.state.store().coin(ids.as_slice()[1]),
        ]
    }
}

const fn after_window() -> Context {
    at(2 + RESPONSE_WINDOW)
}

/// C1: every move takes a party witness and checks it against exactly
/// the key its authority names — the opener's for the action, the
/// client's for the certificate. A delegate runs the whole contest.
#[test]
fn every_channel_move_takes_a_party_witness() {
    let mut channel = Channel::open(O_VIA_N, P_VIA_PN);
    let edge = channel.edge;

    // The client's node key claiming the owner's authority.
    let digest = start_digest(
        NETWORK,
        edge,
        channel.payment.hash(),
        Party::Maker,
        (2, 2),
        no_earned_digest(edge, channel.payment.hash()),
    );
    let mislabelled = Tx::move_action(Move::StartPaymentClose(PaymentCloseStart::new(
        edge,
        channel.payment.clone(),
        Party::Maker,
        (2, 2),
        None,
        PartyAuth::new(Authority::Owner, Auth::native(Sig::placeholder(N, digest))),
    )));
    channel.refuse(
        at(2),
        &mislabelled,
        ApplyError::InvalidMove {
            input: edge,
            reason: InvalidMoveReason::BadSignature,
        },
    );

    // A certificate signed by the provider's own keys is not the client's.
    let (certificate, _) = channel.certificate(5, Authority::Signer);
    let forged = (
        certificate,
        witness(
            channel.parties().taker(),
            Authority::Signer,
            certificate.digest(NETWORK),
        ),
    );
    channel.refuse(
        at(2),
        &channel.start(Party::Taker, Authority::Signer, Some(forged)),
        ApplyError::InvalidMove {
            input: edge,
            reason: InvalidMoveReason::BadCertificateSignature,
        },
    );

    // The provider's node starts on the client node's certificate, and
    // both are signer-authorized.
    let start = channel.start(
        Party::Taker,
        Authority::Signer,
        Some(channel.certificate(5, Authority::Signer)),
    );
    channel.apply(at(2), &start);
    let record = channel.pending().expect("contest open");
    assert_eq!(record.final_cumulative(), 5);
    assert!(!record.owner_signed());
}

/// C2: a cooperative close pays exactly the committed destinations — no
/// third key, and no other delegate — however both parties sign.
#[test]
fn a_mutual_close_pays_only_committed_destinations() {
    let taker = PartyKeys::sole(P);
    let terms = basic(O_VIA_N, taker, &[O_VIA_N.payout(VALUE, false)]);
    let mut state = genesis();
    apply(
        &mut state,
        at(1),
        &open(&[O_COIN], &[], &terms, (Authority::Owner, Authority::Owner)),
    );
    let edge = edge_of(&[O_COIN], &[], &terms);
    let close = |outputs: &[Payout], authorities: (Authority, Authority)| {
        let outputs = payouts(outputs);
        let hash = Tx::payload_hash(NETWORK, edge, CloseKind::Mutual, terms.hash(), &outputs);
        Tx::close(
            edge,
            Proof::mutual(
                witness(O_VIA_N, authorities.0, hash),
                witness(taker, authorities.1, hash),
            ),
            outputs,
        )
    };
    let signers = (Authority::Signer, Authority::Signer);
    for outputs in [
        [Payout::new(K, 50), taker.payout(50, false)],
        [Payout::delegated(O, Some(N2), 50), taker.payout(50, false)],
        [Payout::delegated(P, Some(N), 50), O_VIA_N.payout(50, false)],
    ] {
        refuse(
            &mut state,
            at(2),
            &close(&outputs, signers),
            ApplyError::InvalidProof {
                input: edge,
                reason: InvalidProofReason::PayoutNotCommitted,
            },
        );
    }
    let outputs = [O_VIA_N.payout(70, false), taker.payout(30, false)];
    apply(&mut state, at(2), &close(&outputs, signers));
    let ids = Tx::close_output_ids(edge, &payouts(&outputs));
    assert_eq!(
        state.store().coin(ids.as_slice()[0]),
        Some(Coin::issue(O, Some(N), 70))
    );
}

/// C3′: when an owner signs a close, every payout is issued
/// undelegated, whatever the terms committed. The committed delegate is
/// then refused, and the signer-only close still pays it.
#[test]
fn an_owner_signed_mutual_close_pays_undelegated() {
    let taker = PartyKeys::new(P, PN, Some(PN));
    let terms = basic(O_VIA_N, taker, &[O_VIA_N.payout(VALUE, false)]);
    let mut state = genesis();
    apply(
        &mut state,
        at(1),
        &open(&[O_COIN], &[], &terms, (Authority::Owner, Authority::Owner)),
    );
    let edge = edge_of(&[O_COIN], &[], &terms);
    let close = |outputs: &[Payout], authorities: (Authority, Authority)| {
        let outputs = payouts(outputs);
        let hash = Tx::payload_hash(NETWORK, edge, CloseKind::Mutual, terms.hash(), &outputs);
        Tx::close(
            edge,
            Proof::mutual(
                witness(O_VIA_N, authorities.0, hash),
                witness(taker, authorities.1, hash),
            ),
            outputs,
        )
    };
    let owner = (Authority::Owner, Authority::Signer);
    let committed = [O_VIA_N.payout(60, false), taker.payout(40, false)];
    refuse(
        &mut state,
        at(2),
        &close(&committed, owner),
        ApplyError::InvalidProof {
            input: edge,
            reason: InvalidProofReason::PayoutNotCommitted,
        },
    );
    let stripped = [O_VIA_N.payout(60, true), taker.payout(40, true)];
    assert_eq!(stripped[0], Payout::new(O, 60));
    assert_eq!(stripped[1], Payout::new(P, 40));
    apply(&mut state, at(2), &close(&stripped, owner));
    let ids = Tx::close_output_ids(edge, &payouts(&stripped));
    assert_eq!(
        state.store().coin(ids.as_slice()[0]),
        Some(Coin::issue(O, None, 60))
    );
    assert_eq!(
        state.store().coin(ids.as_slice()[1]),
        Some(Coin::issue(P, None, 40))
    );
}

/// C3′ on the contest: an owner that starts a contest is leaving the
/// delegation, so the adjudicated close it ends in pays undelegated —
/// and a freeze the delegate co-signs afterwards cannot restore the
/// delegate.
#[test]
fn an_owner_started_contest_pays_undelegated_by_either_exit() {
    // Adjudicated.
    let mut channel = Channel::open(O_VIA_N, P_VIA_PN);
    channel.apply(at(2), &channel.start(Party::Maker, Authority::Owner, None));
    assert!(channel.pending().expect("contest").owner_signed());
    let (delegated, _) = channel.adjudicated(false);
    channel.refuse(
        after_window(),
        &delegated,
        ApplyError::InvalidProof {
            input: channel.edge,
            reason: InvalidProofReason::PayoutMismatch,
        },
    );
    let (close, payouts) = channel.adjudicated(true);
    channel.apply(after_window(), &close);
    let [provider, client] = channel.issued(&payouts);
    assert_eq!(client.map(Coin::delegate), Some(None));
    assert_eq!(client.map(Coin::owner), Some(O));
    assert_eq!(provider.map(Coin::owner), Some(P));

    // Freeze by both signers over an owner-started contest.
    let mut channel = Channel::open(O_VIA_N, P_VIA_PN);
    channel.apply(at(2), &channel.start(Party::Maker, Authority::Owner, None));
    let signers = (Authority::Signer, Authority::Signer);
    let delegated = channel.freeze_payouts(0, 0, false);
    channel.refuse(
        at(2),
        &channel.freeze(0, signers, &delegated),
        ApplyError::InvalidProof {
            input: channel.edge,
            reason: InvalidProofReason::PayoutMismatch,
        },
    );
    let stripped = channel.freeze_payouts(0, 0, true);
    channel.apply(at(2), &channel.freeze(0, signers, &stripped));
    let [_, client] = channel.issued(&stripped);
    assert_eq!(client, Some(Coin::issue(O, None, client.unwrap().value())));
}

/// C3′, the other way round: a contest run by delegates alone settles
/// at the committed destinations, delegate included; an owner-signed
/// freeze strips it; an owner-signed response does too.
#[test]
fn a_delegate_run_contest_pays_the_committed_delegate() {
    let mut channel = Channel::open(O_VIA_N, P_VIA_PN);
    channel.apply(at(2), &channel.start(Party::Maker, Authority::Signer, None));
    let (close, payouts) = channel.adjudicated(false);
    channel.apply(after_window(), &close);
    let [_, client] = channel.issued(&payouts);
    assert_eq!(client.map(Coin::delegate), Some(Some(N)));

    // An owner-signed freeze, no contest.
    let mut channel = Channel::open(O_VIA_N, P_VIA_PN);
    let stripped = channel.freeze_payouts(3, 0, true);
    let delegated = channel.freeze_payouts(3, 0, false);
    channel.refuse(
        at(2),
        &channel.freeze(3, (Authority::Owner, Authority::Signer), &delegated),
        ApplyError::InvalidProof {
            input: channel.edge,
            reason: InvalidProofReason::PayoutMismatch,
        },
    );
    channel.apply(
        at(2),
        &channel.freeze(3, (Authority::Owner, Authority::Signer), &stripped),
    );

    // An owner-signed response marks the contest too.
    let mut channel = Channel::open(O_VIA_N, P_VIA_PN);
    channel.apply(at(2), &channel.start(Party::Maker, Authority::Signer, None));
    channel.apply(at(3), &channel.respond(4, Authority::Owner));
    assert!(channel.pending().expect("contest").owner_signed());
}

/// C5: the omission penalty is keyed to the role, not the key. A client
/// start below the provider's certificate forfeits the bond whether the
/// client's node signed it or the client's owner did.
#[test]
fn the_omission_penalty_is_keyed_to_role_not_key() {
    for authority in [Authority::Owner, Authority::Signer] {
        let mut channel = Channel::open(O_VIA_N, P_VIA_PN);
        channel.apply(at(2), &channel.start(Party::Maker, authority, None));
        channel.apply(at(3), &channel.respond(6, Authority::Signer));
        let record = channel.pending().expect("contest");
        assert!(record.penalty_due(), "{authority:?}-signed client start");
        assert_eq!(record.penalty(), OMISSION_BOND);
        let (close, payouts) = channel.adjudicated(record.owner_signed());
        assert_eq!(payouts[0].value(), 6 + OMISSION_BOND);
        channel.apply(after_window(), &close);
    }
}

/// Finding 3 and C4: a thief holding N stakes O's delegated coins in a
/// bond with a horizon of its choosing and leases it to a payment edge
/// funded with its own dust. O exits the payment edge unilaterally with
/// its own key, and then the bond — whose lease names an edge that no
/// longer exists — times out at once instead of at the thief's horizon.
#[test]
fn a_bond_whose_payment_edge_is_gone_times_out_at_once() {
    let mut state = genesis();
    let coin = delegate(&mut state, O_COIN, N);
    // The thief stakes as provider, O's coin, O's destination with N.
    let bond_body = bond_terms(O_VIA_N, PartyKeys::sole(K), VALUE);
    let bond = Terms::work_stake_bond(bond_body.clone());
    apply(
        &mut state,
        at(1),
        &open(&[coin], &[], &bond, (Authority::Signer, Authority::Owner)),
    );
    let bond_edge = edge_of(&[coin], &[], &bond);
    // And leases it to a channel the thief funds with one dust coin.
    let payment = payment_terms(bond_edge, bond_body);
    apply(
        &mut state,
        at(1),
        &open(
            &[K_COIN],
            &[],
            &payment,
            (Authority::Owner, Authority::Signer),
        ),
    );
    let payment_edge = edge_of(&[K_COIN], &[], &payment);
    let mut channel = Channel {
        state,
        payment,
        edge: payment_edge,
    };

    let timeout = Tx::timeout_close(bond_edge, &bond).expect("a bond commits a timeout payout");
    // Leased by a live channel: the horizon governs.
    channel.refuse(
        at(2),
        &timeout,
        ApplyError::InvalidProof {
            input: bond_edge,
            reason: InvalidProofReason::TimeoutNotReached,
        },
    );

    // O, the payment's provider, starts and adjudicates with its own key.
    channel.apply(at(2), &channel.start(Party::Taker, Authority::Owner, None));
    let (close, _) = channel.adjudicated(true);
    channel.apply(after_window(), &close);
    assert_eq!(channel.state.store().edge(payment_edge), None);
    let lease_slots = bond_lease_slots(NETWORK, bond_edge);
    assert!(
        lease_slots
            .iter()
            .all(|slot| channel.state.store().registry_chunk(*slot).is_some())
    );

    // The lease outlived its channel, and no longer holds the bond.
    let outcome = channel.apply(after_window(), &timeout);
    assert_eq!(outcome.registry().len(), 2, "both lease chunks deleted");
    assert_eq!(channel.state.store().edge(bond_edge), None);
    assert!(
        lease_slots
            .iter()
            .all(|slot| channel.state.store().registry_chunk(*slot).is_none())
    );
    let ids = Tx::close_output_ids(bond_edge, bond.timeout_outputs().expect("committed"));
    assert_eq!(
        channel
            .state
            .store()
            .coin(ids.as_slice()[0])
            .map(Coin::owner),
        Some(O),
    );
}

/// A start's identifier is still bound to its digest and inclusion
/// height under the new witness shape: the record names the start that
/// was signed.
#[test]
fn a_start_id_names_the_signed_start() {
    let mut channel = Channel::open(O_VIA_N, P_VIA_PN);
    channel.apply(at(2), &channel.start(Party::Maker, Authority::Signer, None));
    let expected = start_id(
        start_digest(
            NETWORK,
            channel.edge,
            channel.payment.hash(),
            Party::Maker,
            (2, 2),
            no_earned_digest(channel.edge, channel.payment.hash()),
        ),
        2,
    );
    assert_eq!(channel.pending().expect("contest").start_id(), expected);
}

/// The owner is a P-256 passkey and the node is a different secp256k1
/// key. Exercise the cryptographic verifier across the delegation boundary,
/// including attempts to relabel the node's signature as the owner's.
#[cfg(all(feature = "webauthn", feature = "secp256k1"))]
#[test]
fn passkey_owner_delegates_to_a_native_node_and_reclaims_its_coin() {
    use hellas_kernel::{Secp256k1Signer, Secp256k1Verifier, SoftPasskey};
    let owner = SoftPasskey::from_secret_scalar([71; 32]).unwrap();
    let node = Secp256k1Signer::from_secret_scalar([72; 32]).unwrap();
    let taker = Secp256k1Signer::from_secret_scalar([73; 32]).unwrap();
    let mut state = map_state([Genesis::coin(O_COIN, owner.party_key(), VALUE)]);
    let input = inputs(&[O_COIN]);
    let output = payouts(&[Payout::delegated(
        owner.party_key(),
        Some(node.party_key()),
        VALUE,
    )]);
    let hash = Reshape::payload_hash(NETWORK, &input, &output);
    let delegated = Reshape::output_ids(NETWORK, &input, &output).as_slice()[0];
    let tx = Tx::Owner(Reshape::new(
        input,
        output,
        Auth::webauthn(owner.sign(hash).unwrap()),
    ));
    state.apply(at(1), &Secp256k1Verifier, &tx).unwrap();
    assert!(
        state.apply(at(1), &Secp256k1Verifier, &tx).is_err(),
        "signed reshape cannot replay"
    );

    let maker = PartyKeys::new(owner.party_key(), node.party_key(), Some(node.party_key()));
    let terms =
        Terms::work_stake_bond(bond_terms(maker, PartyKeys::sole(taker.party_key()), VALUE));
    let funding = Funding::new(party_coins(&[delegated]), party_coins(&[]));
    let hash = Tx::open_hash(NETWORK, &funding, &terms);
    let edge = Tx::edge_id_of(&funding, &terms);
    let tx = Tx::open(
        funding.clone(),
        terms.clone(),
        PartyAuth::owner(node.sign(hash)),
        PartyAuth::owner(taker.sign(hash)),
    );
    assert!(
        state.apply(at(1), &Secp256k1Verifier, &tx).is_err(),
        "node cannot act as owner"
    );
    let tx = Tx::open(
        funding,
        terms.clone(),
        PartyAuth::signer(node.sign(hash)),
        PartyAuth::owner(taker.sign(hash)),
    );
    state.apply(at(1), &Secp256k1Verifier, &tx).unwrap();
    let output = terms.timeout_outputs().unwrap().clone();
    let returned = Tx::close_output_ids(edge, &output).as_slice()[0];
    state
        .apply(
            at(1),
            &Secp256k1Verifier,
            &Tx::close(edge, Proof::Timeout { terms }, output),
        )
        .unwrap();
    let input = inputs(&[returned]);
    let output = payouts(&[Payout::new(owner.party_key(), VALUE)]);
    let hash = Reshape::payload_hash(NETWORK, &input, &output);
    let reclaimed = Reshape::output_ids(NETWORK, &input, &output).as_slice()[0];
    let forged = Tx::Owner(Reshape::new(
        input.clone(),
        output.clone(),
        Auth::native(node.sign(hash)),
    ));
    assert!(state.apply(at(1), &Secp256k1Verifier, &forged).is_err());
    let tx = Tx::Owner(Reshape::new(
        input,
        output,
        Auth::webauthn(owner.sign(hash).unwrap()),
    ));
    state.apply(at(1), &Secp256k1Verifier, &tx).unwrap();
    assert_eq!(
        state.store().coin(reclaimed),
        Some(Coin::issue(owner.party_key(), None, VALUE))
    );
}
