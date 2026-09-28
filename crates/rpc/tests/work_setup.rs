//! Whether a configured channel is the channel on chain, and whether a
//! job may be signed against it.
//!
//! Every observed object here is built from canonical bytes written out
//! field by field, not from a kernel constructor: an endpoint reads
//! these off a wire, so its side of the agreement is a byte layout. A
//! round trip against the kernel's own encoder would pass with two
//! fields transposed; these do not.

#![cfg(feature = "work")]

use hellas_kernel::{
    BlockHeight, Decode as _, Edge, EdgeId, EdgeValues, Fees, LeaseSlots, List, MAX_EDGE_OUTPUTS,
    NetworkId, Parties, Payout, PendingSlot, RegistryChunk, RegistryNamespace, RegistryRecordTag,
    Terms, TermsHash, WorkPaymentTerms, WorkStakeBondTerms,
};
use hellas_rpc::protocol::work::{
    PaidChannelPolicyV1, PaidExecutionPolicyV1, PaidWorkError, private_policy_commitment,
};
use hellas_rpc::protocol::work_setup::{
    CloseDescriptor, LeaseState, ObservedChannel, PendingState, WorkChannelConfig,
    WorkChannelDescriptor, WorkSetupError, check_collateral, payment_terms_hash,
};
use hellas_rpc::protocol::{ContentId, Digest};

// ── Fixture ───────────────────────────────────────────────────────────

const HORIZON: u64 = 500;
/// One over half the funding: the least bond that exceeds the capacity
/// it leaves behind, at zero fees.
const OMISSION_BOND: u64 = 601;
const PAYMENT_VALUE: u64 = 1_000;
const PAYMENT_RESERVE: u64 = 200;
const STAKE: u64 = 64;
const SALT: [u8; 32] = [0x5a; 32];
/// The response window the fixture's terms admit.
const WINDOW: u64 = hellas_kernel::MIN_OMIT_RESPONSE_BLOCKS;

fn network() -> NetworkId {
    let Some(network) = NetworkId::new("hellas-test") else {
        panic!("a short ascii id is a legal network id");
    };
    network
}

fn provider_key() -> hellas_kernel::Key {
    hellas_kernel::Key::from_bytes([0x02; hellas_kernel::Key::LENGTH])
}

fn client_key() -> hellas_kernel::Key {
    hellas_kernel::Key::from_bytes([0x03; hellas_kernel::Key::LENGTH])
}

fn bond_edge() -> EdgeId {
    EdgeId::from_bytes([0x11; EdgeId::LENGTH])
}

fn payment_edge() -> EdgeId {
    EdgeId::from_bytes([0x22; EdgeId::LENGTH])
}

fn bond_terms() -> WorkStakeBondTerms {
    WorkStakeBondTerms {
        // Maker = provider, taker = client. The payment edge mirrors it.
        parties: Parties::new(provider_key(), client_key()),
        timeout: BlockHeight::new(HORIZON),
        timeout_outputs: List::take([Payout::new(provider_key(), STAKE); MAX_EDGE_OUTPUTS], 1),
        max_job_price: 40,
    }
}

fn channel_policy() -> PaidChannelPolicyV1 {
    PaidChannelPolicyV1 {
        compute_credit_limit: 40,
        delivery_credit_limit: 40,
    }
}

fn payment_terms() -> WorkPaymentTerms {
    WorkPaymentTerms {
        bond_edge: bond_edge(),
        bond_terms: bond_terms(),
        private_policy_commitment: private_policy_commitment(network(), &SALT, &channel_policy()),
        omit_response_blocks: WINDOW,
        start_validity_blocks: 8,
        omission_bond: OMISSION_BOND,
    }
}

fn execution_policy() -> PaidExecutionPolicyV1 {
    PaidExecutionPolicyV1 {
        allowed_environment: ContentId::from_bytes([0x31; 32]),
        generation_policy_digest: Digest::from_bytes([0x32; 32]),
        identity_source_digest: Digest::from_bytes([0x33; 32]),
        max_prompt_tokens: 512,
        max_new_tokens: 128,
        max_stop_token_ids: 4,
        max_spool_bytes: 1_048_576,
        max_encoded_result_frame: 262_144,
        max_encoded_quote_response: 1_048_576,
        dispatch_margin_blocks: 4,
        delivery_margin_blocks: 2,
        oracle_grace_blocks: 6,
        fixed_price: 10,
    }
}

fn payment_values() -> EdgeValues {
    EdgeValues::new(PAYMENT_VALUE, PAYMENT_RESERVE, Fees::new(0, 0, 0, 0))
}

fn config() -> WorkChannelConfig {
    WorkChannelConfig {
        network: network(),
        payment_edge: payment_edge(),
        payment_terms: payment_terms(),
        policy_salt: SALT,
        channel_policy: channel_policy(),
        execution_policy: execution_policy().into(),
        expected_payment_values: payment_values(),
    }
}

fn descriptor() -> WorkChannelDescriptor {
    match WorkChannelDescriptor::open(config()) {
        Ok(descriptor) => descriptor,
        Err(error) => panic!("the fixture channel opens: {error}"),
    }
}

// ── Canonical objects, spelled out ────────────────────────────────────

/// Kernel canonical tags. Written here rather than imported because the
/// point of writing the bytes out is that a reader agrees with a
/// *number*, not with a constant that could move with the encoder.
const FORMAT_VERSION: u8 = 1;
const TAG_BLOCK_HEIGHT: u8 = 1;
const TAG_FEES: u8 = 2;
const TAG_PARTIES: u8 = 3;
const TAG_EDGE: u8 = 5;
const TAG_PAYMENT_CLOSE_PENDING: u8 = 23;
const TAG_BOND_LEASE: u8 = 31;
/// `Freeze | Adjudicated`: close-kind tags 3 and 4.
const WORK_PAYMENT_CLOSES: u8 = 0b0001_1000;
/// `Timeout` alone: close-kind tag 1.
const WORK_STAKE_CLOSES: u8 = 0b0000_0010;

struct EdgeBytes {
    value: u64,
    reserve: u64,
    fees: [u64; 4],
    timeout: u64,
    maker: hellas_kernel::Key,
    taker: hellas_kernel::Key,
    terms: TermsHash,
    allowed: u8,
}

impl EdgeBytes {
    fn build(&self) -> Edge {
        let mut out = vec![FORMAT_VERSION, TAG_EDGE];
        out.extend_from_slice(&self.value.to_be_bytes());
        out.extend_from_slice(&self.reserve.to_be_bytes());
        out.extend_from_slice(&[FORMAT_VERSION, TAG_FEES]);
        for fee in self.fees {
            out.extend_from_slice(&fee.to_be_bytes());
        }
        out.extend_from_slice(&[FORMAT_VERSION, TAG_BLOCK_HEIGHT]);
        out.extend_from_slice(&self.timeout.to_be_bytes());
        out.extend_from_slice(&[FORMAT_VERSION, TAG_PARTIES]);
        out.extend_from_slice(&self.maker.to_bytes());
        out.extend_from_slice(&self.taker.to_bytes());
        out.extend_from_slice(self.terms.as_bytes());
        out.push(self.allowed);
        match Edge::decode_exact(&out) {
            Ok(edge) => edge,
            Err(error) => panic!("the hand-written edge is canonical: {error:?}"),
        }
    }
}

fn bond_object() -> Edge {
    EdgeBytes {
        value: STAKE,
        reserve: 0,
        fees: [0; 4],
        timeout: HORIZON,
        maker: provider_key(),
        taker: client_key(),
        terms: Terms::work_stake_bond(bond_terms()).hash(),
        allowed: WORK_STAKE_CLOSES,
    }
    .build()
}

fn payment_object() -> Edge {
    EdgeBytes {
        value: PAYMENT_VALUE,
        reserve: PAYMENT_RESERVE,
        fees: [0; 4],
        timeout: HORIZON,
        // Mirrored: the client funds the payment edge and is its maker.
        maker: client_key(),
        taker: provider_key(),
        terms: payment_terms_hash(payment_terms()),
        allowed: WORK_PAYMENT_CLOSES,
    }
    .build()
}

/// The canonical bytes of one bond lease, written out field by field.
fn lease_over(bond: EdgeId, payment: EdgeId) -> LeaseSlots {
    let mut value = vec![FORMAT_VERSION, TAG_BOND_LEASE];
    // body version
    value.push(2);
    value.extend_from_slice(&bond.to_bytes());
    value.extend_from_slice(&payment.to_bytes());
    value.extend_from_slice(payment_terms_hash(payment_terms()).as_bytes());
    value.extend_from_slice(&payment_terms().private_policy_commitment);
    value.extend_from_slice(&HORIZON.to_be_bytes());

    let slots = [0, 1].map(|index| {
        RegistryChunk::split(
            RegistryNamespace::BondLease,
            RegistryRecordTag::BondLease,
            &value,
            index,
        )
    });
    assert!(slots.iter().all(Option::is_some), "the lease splits");
    let parsed = hellas_kernel::parse_bond_lease(slots, bond);
    assert!(
        matches!(parsed, LeaseSlots::Present(_)),
        "the hand-written lease is readable, got {parsed:?}",
    );
    parsed
}

fn faulty_lease() -> LeaseSlots {
    let Some(chunk) = RegistryChunk::split(
        RegistryNamespace::BondLease,
        RegistryRecordTag::BondLease,
        &[0xff; 8],
        0,
    ) else {
        panic!("a short value splits into one chunk");
    };
    let parsed = hellas_kernel::parse_bond_lease([Some(chunk), Some(chunk)], bond_edge());
    assert!(matches!(parsed, LeaseSlots::Faulty(_)));
    parsed
}

/// The canonical bytes of one live contest, written out field by field.
///
/// Maker-opened, unresponded, at cumulative 5 with no penalty: the
/// values do not matter, its presence does.
fn live_pending() -> PendingSlot {
    let mut value = vec![FORMAT_VERSION, TAG_PAYMENT_CLOSE_PENDING];
    // body version
    value.push(2);
    value.extend_from_slice(&payment_edge().to_bytes());
    // opener_role: maker
    value.push(0);
    value.extend_from_slice(&[0x33; 32]); // start_id
    value.extend_from_slice(&77_u64.to_be_bytes()); // response_deadline
    value.extend_from_slice(&5_u64.to_be_bytes()); // start_cumulative
    value.extend_from_slice(&5_u64.to_be_bytes()); // final_cumulative
    value.push(0); // responded
    value.push(0); // penalty_due
    value.extend_from_slice(&2_u64.to_be_bytes()); // penalty_amount

    let Some(chunk) = RegistryChunk::split(
        RegistryNamespace::PaymentClose,
        RegistryRecordTag::PaymentPending,
        &value,
        0,
    ) else {
        panic!("a fixed-width value always splits");
    };
    let parsed = hellas_kernel::parse_pending_close(Some(chunk), payment_edge());
    assert!(
        matches!(parsed, PendingSlot::Present(_)),
        "the hand-written contest is readable, got {parsed:?}",
    );
    parsed
}

fn faulty_pending() -> PendingSlot {
    let Some(chunk) = RegistryChunk::split(
        RegistryNamespace::PaymentClose,
        RegistryRecordTag::PaymentPending,
        &[0xff; 8],
        0,
    ) else {
        panic!("a short value splits into one chunk");
    };
    let parsed = hellas_kernel::parse_pending_close(Some(chunk), payment_edge());
    assert!(matches!(parsed, PendingSlot::Faulty(_)));
    parsed
}

fn observed<'a>(bond: &'a Edge, payment: &'a Edge) -> ObservedChannel<'a> {
    ObservedChannel {
        height: HORIZON - 1,
        bond: Some(bond),
        payment: Some(payment),
        lease: lease_over(bond_edge(), payment_edge()),
        pending: PendingSlot::Absent,
    }
}

// ── Collateral ────────────────────────────────────────────────────────

/// The one gate, at its limit and one unit past it.
#[test]
fn the_bond_must_strictly_exceed_the_capacity_it_insures() {
    assert_eq!(
        check_collateral(10, 10),
        Err(WorkSetupError::Undercollateralised {
            bond: 10,
            capacity: 10,
        }),
    );
    assert_eq!(check_collateral(11, 10), Ok(()));
    assert_eq!(
        check_collateral(0, 0),
        Err(WorkSetupError::Undercollateralised {
            bond: 0,
            capacity: 0,
        }),
    );
}

/// A channel whose bond does not exceed its payment capacity is refused
/// at configuration time, before anything is signed.
#[test]
fn a_channel_whose_capacity_defeats_the_bond_does_not_open() {
    // Capacity is `value + reserve - omission_bond` at zero fees, so the
    // two sides meet at half the funding: a bond of exactly half is
    // refused and the fixture's, one over it, opens.
    let half = (PAYMENT_VALUE + PAYMENT_RESERVE) / 2;
    let mut thin = config();
    thin.payment_terms.omission_bond = half;
    assert_eq!(
        WorkChannelDescriptor::open(thin),
        Err(WorkSetupError::Undercollateralised {
            bond: half,
            capacity: PAYMENT_VALUE + PAYMENT_RESERVE - half,
        }),
    );
    assert_eq!(OMISSION_BOND, half + 1);
    assert!(WorkChannelDescriptor::open(config()).is_ok());
}

/// The policy body and its salt have to produce the commitment the
/// terms carry, and the execution policy has to be a usable profile.
#[test]
fn a_descriptor_opens_only_against_its_own_committed_policy() {
    let mut wrong_salt = config();
    wrong_salt.policy_salt = [0x5b; 32];
    assert_eq!(
        WorkChannelDescriptor::open(wrong_salt),
        Err(WorkSetupError::Record(PaidWorkError::Mismatch {
            field: "private_policy_commitment",
        })),
    );

    let mut wrong_policy = config();
    wrong_policy.channel_policy.compute_credit_limit += 1;
    assert_eq!(
        WorkChannelDescriptor::open(wrong_policy),
        Err(WorkSetupError::Record(PaidWorkError::Mismatch {
            field: "private_policy_commitment",
        })),
    );

    let mut zero_price = config();
    let hellas_rpc::protocol::work_profile::PaidWorkPolicy::Evaluate(policy) =
        &mut zero_price.execution_policy
    else {
        panic!("fixture uses Evaluate");
    };
    policy.fixed_price = 0;
    assert_eq!(
        WorkChannelDescriptor::open(zero_price),
        Err(WorkSetupError::Record(PaidWorkError::PolicyZero {
            field: "fixed_price",
        })),
    );

    // A reserve that does not price the dearer exit leaves nothing the
    // channel could bound a certificate by.
    let mut unfunded = config();
    unfunded.expected_payment_values = EdgeValues::new(1, 0, Fees::new(1_000, 0, 0, 0));
    assert_eq!(
        WorkChannelDescriptor::open(unfunded),
        Err(WorkSetupError::Unsettleable),
    );
}

// ── Readiness against a finalized read ────────────────────────────────

/// Every fact readiness rests on, each broken on its own.
#[test]
fn readiness_refuses_each_missing_fact_on_its_own() {
    let descriptor = descriptor();
    let bond = bond_object();
    let payment = payment_object();
    let good = observed(&bond, &payment);

    let ready = match descriptor.check_ready(&good) {
        Ok(ready) => ready,
        Err(error) => panic!("the fixture channel is ready: {error}"),
    };
    assert_eq!(ready.finalized_height(), HORIZON - 1);
    // Capacity is the funded edge's, not the configured expectation's.
    assert_eq!(
        ready.settlement().capacity(),
        PAYMENT_VALUE + PAYMENT_RESERVE - OMISSION_BOND,
    );
    assert_eq!(ready.channel().id(), descriptor.channel().id());

    let missing_bond = ObservedChannel { bond: None, ..good };
    assert_eq!(
        descriptor.check_ready(&missing_bond),
        Err(WorkSetupError::NotLive {
            object: "the bond edge",
        }),
    );
    let missing_payment = ObservedChannel {
        payment: None,
        ..good
    };
    assert_eq!(
        descriptor.check_ready(&missing_payment),
        Err(WorkSetupError::NotLive {
            object: "the payment edge",
        }),
    );

    // A live edge under other terms. Only the terms hash moves.
    let other_bond = EdgeBytes {
        value: STAKE,
        reserve: 0,
        fees: [0; 4],
        timeout: HORIZON,
        maker: provider_key(),
        taker: client_key(),
        terms: TermsHash::from_bytes([0x77; TermsHash::LENGTH]),
        allowed: WORK_STAKE_CLOSES,
    }
    .build();
    assert_eq!(
        descriptor.check_ready(&ObservedChannel {
            bond: Some(&other_bond),
            ..good
        }),
        Err(WorkSetupError::TermsMismatch {
            object: "the bond edge",
        }),
    );
    let other_payment = EdgeBytes {
        value: PAYMENT_VALUE,
        reserve: PAYMENT_RESERVE,
        fees: [0; 4],
        timeout: HORIZON,
        maker: client_key(),
        taker: provider_key(),
        terms: TermsHash::from_bytes([0x78; TermsHash::LENGTH]),
        allowed: WORK_PAYMENT_CLOSES,
    }
    .build();
    assert_eq!(
        descriptor.check_ready(&ObservedChannel {
            payment: Some(&other_payment),
            ..good
        }),
        Err(WorkSetupError::TermsMismatch {
            object: "the payment edge",
        }),
    );

    // The two edges, swapped. Each is live and each hashes to real
    // terms; neither is the object it was asked for.
    assert_eq!(
        descriptor.check_ready(&ObservedChannel {
            bond: Some(&payment),
            payment: Some(&bond),
            ..good
        }),
        Err(WorkSetupError::TermsMismatch {
            object: "the bond edge",
        }),
    );

    // Right terms, wrong parties. Only the party order moves.
    let swapped_bond = EdgeBytes {
        value: STAKE,
        reserve: 0,
        fees: [0; 4],
        timeout: HORIZON,
        maker: client_key(),
        taker: provider_key(),
        terms: Terms::work_stake_bond(bond_terms()).hash(),
        allowed: WORK_STAKE_CLOSES,
    }
    .build();
    assert_eq!(
        descriptor.check_ready(&ObservedChannel {
            bond: Some(&swapped_bond),
            ..good
        }),
        Err(WorkSetupError::PartiesMismatch {
            object: "the bond edge",
        }),
    );
    let swapped_payment = EdgeBytes {
        value: PAYMENT_VALUE,
        reserve: PAYMENT_RESERVE,
        fees: [0; 4],
        timeout: HORIZON,
        maker: provider_key(),
        taker: client_key(),
        terms: payment_terms_hash(payment_terms()),
        allowed: WORK_PAYMENT_CLOSES,
    }
    .build();
    assert_eq!(
        descriptor.check_ready(&ObservedChannel {
            payment: Some(&swapped_payment),
            ..good
        }),
        Err(WorkSetupError::PartiesMismatch {
            object: "the payment edge",
        }),
    );

    // The three lease answers that are not this channel's lease.
    assert_eq!(
        descriptor.check_ready(&ObservedChannel {
            lease: LeaseSlots::Absent,
            ..good
        }),
        Err(WorkSetupError::Lease {
            found: LeaseState::Absent,
        }),
    );
    assert_eq!(
        descriptor.check_ready(&ObservedChannel {
            lease: lease_over(bond_edge(), EdgeId::from_bytes([0x44; EdgeId::LENGTH])),
            ..good
        }),
        Err(WorkSetupError::Lease {
            found: LeaseState::AnotherChannel,
        }),
    );
    assert_eq!(
        descriptor.check_ready(&ObservedChannel {
            lease: faulty_lease(),
            ..good
        }),
        Err(WorkSetupError::Lease {
            found: LeaseState::Faulty,
        }),
    );

    // A contest, and a slot that cannot say whether there is one. Both
    // edges are live and healthy in each case; only the slot moves.
    assert_eq!(
        descriptor.check_ready(&ObservedChannel {
            pending: live_pending(),
            ..good
        }),
        Err(WorkSetupError::PendingClose {
            found: PendingState::Live,
        }),
    );
    assert_eq!(
        descriptor.check_ready(&ObservedChannel {
            pending: faulty_pending(),
            ..good
        }),
        Err(WorkSetupError::PendingClose {
            found: PendingState::Faulty,
        }),
    );

    // The horizon, exactly. One block earlier is admission.
    assert_eq!(
        descriptor.check_ready(&ObservedChannel {
            height: HORIZON,
            ..good
        }),
        Err(WorkSetupError::HorizonPassed {
            height: HORIZON,
            horizon: HORIZON,
        }),
    );
    assert!(
        descriptor
            .check_ready(&ObservedChannel {
                height: HORIZON - 1,
                ..good
            })
            .is_ok()
    );
}

/// A channel funded below what was configured has different economics
/// than the ones that were approved, so the inequality is re-run against
/// the edge that will actually pay.
#[test]
fn readiness_reprices_the_economics_against_the_funded_edge() {
    let descriptor = descriptor();
    let bond = bond_object();
    let payment = payment_object();
    let good = observed(&bond, &payment);

    // The configured expectation is unchanged and still passes; only
    // the funded value moves, and it moves capacity past what the
    // bond insures.
    let overfunded = EdgeBytes {
        value: u64::MAX / 2,
        reserve: PAYMENT_RESERVE,
        fees: [0; 4],
        timeout: HORIZON,
        maker: client_key(),
        taker: provider_key(),
        terms: payment_terms_hash(payment_terms()),
        allowed: WORK_PAYMENT_CLOSES,
    }
    .build();
    assert!(matches!(
        descriptor.check_ready(&ObservedChannel {
            payment: Some(&overfunded),
            ..good
        }),
        Err(WorkSetupError::Undercollateralised { .. }),
    ));

    // A reserve that does not price the dearer exit.
    let starved = EdgeBytes {
        value: 1,
        reserve: 0,
        fees: [1_000, 0, 0, 0],
        timeout: HORIZON,
        maker: client_key(),
        taker: provider_key(),
        terms: payment_terms_hash(payment_terms()),
        allowed: WORK_PAYMENT_CLOSES,
    }
    .build();
    assert_eq!(
        descriptor.check_ready(&ObservedChannel {
            payment: Some(&starved),
            ..good
        }),
        Err(WorkSetupError::Unsettleable),
    );
}

// ── The per-signature gate ────────────────────────────────────────────

/// Readiness is decided at a height; signing is decided at a signature.
#[test]
fn signing_needs_a_caught_up_cursor_and_deadlines_the_margins_fit() {
    let descriptor = descriptor();
    let bond = bond_object();
    let payment = payment_object();
    let height = 100;
    let observed = ObservedChannel {
        height,
        ..observed(&bond, &payment)
    };
    let Ok(ready) = descriptor.check_ready(&observed) else {
        panic!("the fixture channel is ready");
    };

    let policy = execution_policy();
    let margins = policy.dispatch_margin_blocks + policy.delivery_margin_blocks;
    let terminal = height + margins;
    let payment_deadline = terminal + policy.oracle_grace_blocks;

    // Exactly at both bounds.
    assert_eq!(
        ready.check_signable(height, terminal, payment_deadline),
        Ok(())
    );

    // A cursor one block behind the snapshot the decision was read at.
    assert_eq!(
        ready.check_signable(height - 1, terminal, payment_deadline),
        Err(WorkSetupError::CursorBehind {
            cursor: height - 1,
            height,
        }),
    );
    // A cursor ahead of the snapshot is allowed, and the margins move
    // with it: the same job is signable one block later only against
    // deadlines one block later.
    assert_eq!(
        ready.check_signable(height + 1, terminal + 1, payment_deadline + 1),
        Ok(()),
    );

    // A terminal deadline one block inside the measured margins. It is
    // ordered, legal, and unreachable.
    assert_eq!(
        ready.check_signable(height, terminal - 1, payment_deadline),
        Err(WorkSetupError::TerminalUnreachable {
            height,
            dispatch: policy.dispatch_margin_blocks,
            delivery: policy.delivery_margin_blocks,
            terminal: terminal - 1,
        }),
    );

    // A payment deadline one block inside the measured oracle grace.
    assert_eq!(
        ready.check_signable(height, terminal, payment_deadline - 1),
        Err(WorkSetupError::OracleGraceTooShort {
            terminal,
            payment: payment_deadline - 1,
            actual: policy.oracle_grace_blocks - 1,
            grace: policy.oracle_grace_blocks,
        }),
    );

    // A payment deadline before the terminal one is not a short grace,
    // it is not an interval at all.
    assert_eq!(
        ready.check_signable(height, terminal, terminal - 1),
        Err(WorkSetupError::Record(PaidWorkError::Overflow {
            field: "oracle grace interval",
        })),
    );
}

/// Every bound is measured from the moment the signature is asked for,
/// not from the stale moment readiness was decided at.
///
/// Anchored at the readiness height, the whole interval `[H + margins,
/// C + margins)` passes — and that interval is exactly the deadlines
/// already missed by the time the chain has reached `C`. An honest
/// provider signs them, cannot deliver, and goes unpaid.
#[test]
fn signing_measures_the_margins_from_the_cursor_not_the_readiness_height() {
    let descriptor = descriptor();
    let bond = bond_object();
    let payment = payment_object();
    let height = 100;
    let Ok(ready) = descriptor.check_ready(&ObservedChannel {
        height,
        ..observed(&bond, &payment)
    }) else {
        panic!("the fixture channel is ready");
    };

    let policy = execution_policy();
    let margins = policy.dispatch_margin_blocks + policy.delivery_margin_blocks;
    let grace = policy.oracle_grace_blocks;

    // The deadline that is exactly reachable from the readiness height,
    // offered one block after that height. It is already lost.
    let cursor = height + 1;
    assert_eq!(
        ready.check_signable(cursor, height + margins, height + margins + grace),
        Err(WorkSetupError::TerminalUnreachable {
            height: cursor,
            dispatch: policy.dispatch_margin_blocks,
            delivery: policy.delivery_margin_blocks,
            terminal: height + margins,
        }),
    );

    // Not one block of that interval — all of it. Fifty blocks on, every
    // deadline the readiness height would have admitted is refused, and
    // the first one the cursor can actually reach is admitted.
    let far = height + 50;
    for terminal in (height + margins)..(far + margins) {
        assert!(
            ready
                .check_signable(far, terminal, terminal + grace)
                .is_err(),
            "terminal {terminal} is not reachable from height {far}",
        );
    }
    assert_eq!(
        ready.check_signable(far, far + margins, far + margins + grace),
        Ok(()),
    );

    // And the horizon. The readiness height is inside it forever, so
    // only the cursor can carry a channel past it — an endpoint that
    // never re-read its snapshot would otherwise sign new work for as
    // long as it stayed running.
    assert_eq!(
        ready.check_signable(HORIZON, HORIZON + margins, HORIZON + margins + grace),
        Err(WorkSetupError::HorizonPassed {
            height: HORIZON,
            horizon: HORIZON,
        }),
    );
    assert_eq!(
        ready.check_signable(
            HORIZON - 1,
            HORIZON - 1 + margins,
            HORIZON - 1 + margins + grace,
        ),
        Ok(()),
    );
}

#[test]
fn close_descriptor_round_trips_without_new_work_policy() {
    let armed = descriptor().close_descriptor();
    let bytes = armed.encode();
    assert_eq!(CloseDescriptor::decode(&bytes), Ok(armed.clone()));
    assert_eq!(
        armed
            .expected_settlement()
            .expect("the admitted expected funding settles")
            .capacity(),
        PAYMENT_VALUE + PAYMENT_RESERVE - OMISSION_BOND,
    );

    let funded = payment_object();
    assert_eq!(
        armed
            .funded_settlement(&funded)
            .expect("funded recovery uses the edge")
            .capacity(),
        PAYMENT_VALUE + PAYMENT_RESERVE - OMISSION_BOND,
    );

    let mut trailing = bytes;
    trailing.push(0);
    assert_eq!(
        CloseDescriptor::decode(&trailing),
        Err(WorkSetupError::DescriptorMalformed),
    );
}
