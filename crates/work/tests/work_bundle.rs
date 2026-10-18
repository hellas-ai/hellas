//! The offline two-Open handshake, revision by revision.
//!
//! Every signature here is a real secp256k1 settlement signature over
//! the hash the kernel will compute, because the whole point of the
//! bundle is that an endpoint checks the other side's signature before
//! releasing its own.

use hellas_kernel::{
    Auth, BlockHeight, CoinId, EdgeId, Funding, List, MAX_EDGE_OUTPUTS, MAX_PARTY_INPUTS,
    NetworkId, Parties, Payout, Secp256k1Verifier, Terms, Tx, WorkPaymentTerms, WorkStakeBondTerms,
};
use hellas_work::model::bundle::{SetupBundleError, WorkChannelSetupBundleV1};
use hellas_work::test_support::paid::{client, provider};

const HORIZON: u64 = 500;
const STAKE: u64 = 64;

fn network() -> NetworkId {
    let Some(network) = NetworkId::new("hellas-test") else {
        panic!("a short ascii id is a legal network id");
    };
    network
}

fn coins(ids: &[u8]) -> List<CoinId, MAX_PARTY_INPUTS> {
    let mut slots = [CoinId::from_bytes([0; CoinId::LENGTH]); MAX_PARTY_INPUTS];
    for (slot, id) in slots.iter_mut().zip(ids) {
        *slot = CoinId::from_bytes([*id; CoinId::LENGTH]);
    }
    List::take(slots, ids.len())
}

fn empty_coins() -> List<CoinId, MAX_PARTY_INPUTS> {
    coins(&[])
}

fn bond_terms() -> WorkStakeBondTerms {
    WorkStakeBondTerms {
        parties: Parties::new(provider().party_key(), client().party_key()),
        timeout: BlockHeight::new(HORIZON),
        timeout_outputs: List::take(
            [Payout::new(provider().party_key(), STAKE); MAX_EDGE_OUTPUTS],
            1,
        ),
        max_job_price: 40,
    }
}

/// The provider's stake funding: its own coins, none of the client's.
fn bond_funding() -> Funding {
    Funding::new(coins(&[0xa1]), empty_coins())
}

/// The client's capacity funding: its own coins, none of the provider's.
fn payment_funding() -> Funding {
    Funding::new(coins(&[0xb1]), empty_coins())
}

fn payment_terms(bond_edge: EdgeId) -> WorkPaymentTerms {
    WorkPaymentTerms {
        bond_edge,
        bond_terms: bond_terms(),
        private_policy_commitment: [0x25; 32],
        omit_response_blocks: hellas_kernel::MIN_OMIT_RESPONSE_BLOCKS,
        start_validity_blocks: 8,
        omission_bond: 4,
    }
}

/// Revision 1, as the provider exports it.
fn proposed() -> WorkChannelSetupBundleV1 {
    let hash = Tx::open_hash(
        network(),
        &bond_funding(),
        &Terms::work_stake_bond(bond_terms()),
    );
    match WorkChannelSetupBundleV1::propose_bond(
        network(),
        bond_funding(),
        bond_terms(),
        Auth::native(provider().sign(hash)),
    ) {
        Ok(bundle) => bundle,
        Err(error) => panic!("the fixture bond proposes: {error}"),
    }
}

/// Revision 2, as the client exports it.
fn countersigned(bundle: WorkChannelSetupBundleV1) -> WorkChannelSetupBundleV1 {
    let bond_hash = bundle.bond_open_hash();
    let terms = payment_terms(bundle.bond_edge());
    let payment_hash = Tx::open_hash(
        network(),
        &payment_funding(),
        &Terms::work_payment(terms.clone()),
    );
    match bundle.countersign_bond_and_propose_payment(
        Auth::native(client().sign(bond_hash)),
        payment_funding(),
        terms,
        Auth::native(client().sign(payment_hash)),
    ) {
        Ok(bundle) => bundle,
        Err(error) => panic!("the fixture payment proposes: {error}"),
    }
}

/// Revision 3, as the provider exports it.
fn completed(bundle: WorkChannelSetupBundleV1) -> WorkChannelSetupBundleV1 {
    let Some(hash) = bundle.payment_open_hash() else {
        panic!("a proposed payment has an open hash");
    };
    match bundle.countersign_payment(Auth::native(provider().sign(hash))) {
        Ok(bundle) => bundle,
        Err(error) => panic!("the fixture payment countersigns: {error}"),
    }
}

/// Each revision checks, extends the last, and round-trips through its
/// canonical bytes.
#[test]
fn the_three_revisions_check_extend_and_round_trip() {
    let verifier = Secp256k1Verifier::new();

    let one = proposed();
    assert_eq!(one.revision(), 1);
    assert_eq!(one.check(&verifier), Ok(()));
    assert!(one.payment_edge().is_none());
    assert!(one.payment_open_hash().is_none());
    assert!(one.bond_open().is_none());
    assert!(one.payment_open().is_none());
    // The stake is named a revision before the Open that spends it is
    // executable, and the provider's signature over it is already exported:
    // which coins this offer promises is answerable here and nowhere else.
    assert_eq!(one.bond_funding(), &bond_funding());

    let two = countersigned(one.clone());
    assert_eq!(two.revision(), 2);
    assert_eq!(two.check(&verifier), Ok(()));
    assert_eq!(two.check_extends(&one), Ok(()));
    assert!(two.bond_open().is_some());
    assert!(two.payment_open().is_none());

    let three = completed(two.clone());
    assert_eq!(three.revision(), 3);
    assert_eq!(three.check(&verifier), Ok(()));
    assert_eq!(three.check_extends(&two), Ok(()));

    // The two executable transactions, and the edges they create.
    let Some(bond_open) = three.bond_open() else {
        panic!("a complete bundle has a bond open");
    };
    let Some(payment_open) = three.payment_open() else {
        panic!("a complete bundle has a payment open");
    };
    assert_eq!(
        Tx::edge_id_of(&bond_funding(), &Terms::work_stake_bond(bond_terms())),
        three.bond_edge(),
    );
    assert_eq!(three.payment_edge(), Some(payment_edge_of(&three)));
    // The payment terms name the bond edge the bond open will create.
    assert_eq!(
        payment_terms(three.bond_edge()).bond_edge,
        three.bond_edge()
    );
    // Both transactions are the ones whose hashes were signed.
    assert!(matches!(bond_open, Tx::Open { .. }));
    assert!(matches!(payment_open, Tx::Open { .. }));

    for bundle in [&one, &two, &three] {
        // Fixed by revision one and carried unchanged, which is what makes
        // it readable from whichever revision an endpoint has retained.
        assert_eq!(bundle.bond_funding(), &bond_funding());
        let encoded = bundle.encode();
        assert_eq!(
            WorkChannelSetupBundleV1::decode(&encoded).as_ref(),
            Ok(bundle),
        );
        // The digest is over exactly these bytes, and the revision byte
        // is inside them.
        assert_ne!(bundle.digest(), Digest::from_bytes([0; 32]));
    }
    assert_ne!(one.digest(), two.digest());
    assert_ne!(two.digest(), three.digest());
}

use hellas_auth::Digest;

fn payment_edge_of(bundle: &WorkChannelSetupBundleV1) -> EdgeId {
    Tx::edge_id_of(
        &payment_funding(),
        &Terms::work_payment(payment_terms(bundle.bond_edge())),
    )
}

/// A revision may only be built from the one before it.
#[test]
fn a_step_from_the_wrong_revision_is_refused() {
    let one = proposed();
    let two = countersigned(one.clone());
    let three = completed(two.clone());

    assert_eq!(
        one.clone()
            .countersign_payment(Auth::native(provider().sign(one.bond_open_hash()))),
        Err(SetupBundleError::WrongStage { actual: 1 }),
    );
    let bond_hash = two.bond_open_hash();
    assert_eq!(
        two.clone().countersign_bond_and_propose_payment(
            Auth::native(client().sign(bond_hash)),
            payment_funding(),
            payment_terms(two.bond_edge()),
            Auth::native(client().sign(bond_hash)),
        ),
        Err(SetupBundleError::WrongStage { actual: 2 }),
    );
    assert_eq!(
        three
            .clone()
            .countersign_payment(Auth::native(provider().sign(bond_hash))),
        Err(SetupBundleError::WrongStage { actual: 3 }),
    );

    // Replayed, skipped, and backwards revisions.
    assert_eq!(
        three.check_extends(&one),
        Err(SetupBundleError::NotTheNextRevision {
            expected: 2,
            actual: 3,
        }),
    );
    assert_eq!(
        two.check_extends(&two),
        Err(SetupBundleError::NotTheNextRevision {
            expected: 3,
            actual: 2,
        }),
    );
    assert_eq!(
        one.check_extends(&two),
        Err(SetupBundleError::NotTheNextRevision {
            expected: 3,
            actual: 1,
        }),
    );
}

/// An import that changed anything an earlier revision fixed is not the
/// next revision of it.
#[test]
fn an_import_that_rewrote_the_previous_revision_is_refused() {
    let one = proposed();

    // The same handshake, over a bond with different funding. Every
    // signature in it is real; it is simply not a continuation of the
    // revision this endpoint holds.
    let other_bond_funding = Funding::new(coins(&[0xa2]), empty_coins());
    let other_hash = Tx::open_hash(
        network(),
        &other_bond_funding,
        &Terms::work_stake_bond(bond_terms()),
    );
    let Ok(other) = WorkChannelSetupBundleV1::propose_bond(
        network(),
        other_bond_funding,
        bond_terms(),
        Auth::native(provider().sign(other_hash)),
    ) else {
        panic!("the alternative bond proposes");
    };
    let other_two = countersigned(other.clone());
    assert_eq!(other_two.check(&Secp256k1Verifier::new()), Ok(()));
    assert_eq!(
        other_two.check_extends(&one),
        Err(SetupBundleError::Rewritten),
    );
    // It does extend its own predecessor, so the refusal above is about
    // the prefix and not about the revision numbers.
    assert_eq!(other_two.check_extends(&other), Ok(()));
}

/// The payment must be over exactly this bundle's bond, by witness and
/// by derived edge id.
#[test]
fn a_payment_over_another_bond_is_refused() {
    let one = proposed();
    let bond_hash = one.bond_open_hash();

    // A payment naming the right bond terms but the wrong bond edge.
    let mut wrong_edge = payment_terms(one.bond_edge());
    wrong_edge.bond_edge = EdgeId::from_bytes([0x99; EdgeId::LENGTH]);
    let hash = Tx::open_hash(
        network(),
        &payment_funding(),
        &Terms::work_payment(wrong_edge.clone()),
    );
    assert_eq!(
        one.clone().countersign_bond_and_propose_payment(
            Auth::native(client().sign(bond_hash)),
            payment_funding(),
            wrong_edge,
            Auth::native(client().sign(hash)),
        ),
        Err(SetupBundleError::BondEdgeMismatch {
            named: EdgeId::from_bytes([0x99; EdgeId::LENGTH]),
            derived: one.bond_edge(),
        }),
    );

    // A payment embedding different bond terms. Its own `bond_edge` is
    // derived from those other terms, so this reaches the witness check
    // rather than the edge check.
    let mut other_bond = bond_terms();
    other_bond.max_job_price += 1;
    let derived = Tx::edge_id_of(&bond_funding(), &Terms::work_stake_bond(other_bond.clone()));
    let mut wrong_witness = payment_terms(derived);
    wrong_witness.bond_terms = other_bond;
    let hash = Tx::open_hash(
        network(),
        &payment_funding(),
        &Terms::work_payment(wrong_witness.clone()),
    );
    assert_eq!(
        one.countersign_bond_and_propose_payment(
            Auth::native(client().sign(bond_hash)),
            payment_funding(),
            wrong_witness,
            Auth::native(client().sign(hash)),
        ),
        Err(SetupBundleError::BondWitnessMismatch),
    );
}

/// A coin cannot fund both opens, or two inputs of one.
#[test]
fn a_coin_may_fund_only_one_input_of_the_setup() {
    let repeated = CoinId::from_bytes([0xa1; CoinId::LENGTH]);

    // Twice inside the bond's own maker inputs.
    let duplicated = Funding::new(coins(&[0xa1, 0xa1]), empty_coins());
    let hash = Tx::open_hash(
        network(),
        &duplicated,
        &Terms::work_stake_bond(bond_terms()),
    );
    assert_eq!(
        WorkChannelSetupBundleV1::propose_bond(
            network(),
            duplicated,
            bond_terms(),
            Auth::native(provider().sign(hash)),
        ),
        Err(SetupBundleError::DuplicateFunding { coin: repeated }),
    );

    // Once in the bond and once in the payment.
    let one = proposed();
    let bond_hash = one.bond_open_hash();
    let reused = Funding::new(coins(&[0xa1]), empty_coins());
    let terms = payment_terms(one.bond_edge());
    let hash = Tx::open_hash(network(), &reused, &Terms::work_payment(terms.clone()));
    assert_eq!(
        one.countersign_bond_and_propose_payment(
            Auth::native(client().sign(bond_hash)),
            reused,
            terms,
            Auth::native(client().sign(hash)),
        ),
        Err(SetupBundleError::DuplicateFunding { coin: repeated }),
    );
}

/// Every signature is checked against the party the terms name, over
/// the hash the kernel will compute.
#[test]
fn each_signature_is_checked_against_its_own_party_and_hash() {
    let verifier = Secp256k1Verifier::new();
    let three = completed(countersigned(proposed()));
    let bond_hash = three.bond_open_hash();
    let Some(payment_hash) = three.payment_open_hash() else {
        panic!("a complete bundle has a payment open hash");
    };
    assert_ne!(bond_hash.to_bytes(), payment_hash.to_bytes());

    // The client's signature in the provider's bond slot. It is a valid
    // signature over the right bytes by the wrong party.
    let Ok(wrong_party) = WorkChannelSetupBundleV1::propose_bond(
        network(),
        bond_funding(),
        bond_terms(),
        Auth::native(client().sign(bond_hash)),
    ) else {
        panic!("the bundle builds without verifying");
    };
    assert_eq!(
        wrong_party.check(&verifier),
        Err(SetupBundleError::BadAuthorization {
            slot: "bond open",
            party: "the provider",
        }),
    );

    // The provider's signature over the payment hash in its bond slot:
    // the right party over the wrong bytes.
    let Ok(wrong_hash) = WorkChannelSetupBundleV1::propose_bond(
        network(),
        bond_funding(),
        bond_terms(),
        Auth::native(provider().sign(payment_hash)),
    ) else {
        panic!("the bundle builds without verifying");
    };
    assert_eq!(
        wrong_hash.check(&verifier),
        Err(SetupBundleError::BadAuthorization {
            slot: "bond open",
            party: "the provider",
        }),
    );

    // The client's bond countersignature, made over the payment hash.
    let one = proposed();
    let terms = payment_terms(one.bond_edge());
    let real_payment_hash = Tx::open_hash(
        network(),
        &payment_funding(),
        &Terms::work_payment(terms.clone()),
    );
    let Ok(bad_countersign) = one.clone().countersign_bond_and_propose_payment(
        Auth::native(client().sign(real_payment_hash)),
        payment_funding(),
        terms.clone(),
        Auth::native(client().sign(real_payment_hash)),
    ) else {
        panic!("the bundle builds without verifying");
    };
    assert_eq!(
        bad_countersign.check(&verifier),
        Err(SetupBundleError::BadAuthorization {
            slot: "bond open",
            party: "the client",
        }),
    );

    // The client's payment signature made by the provider.
    let Ok(bad_payment) = one.countersign_bond_and_propose_payment(
        Auth::native(client().sign(bond_hash)),
        payment_funding(),
        terms,
        Auth::native(provider().sign(real_payment_hash)),
    ) else {
        panic!("the bundle builds without verifying");
    };
    assert_eq!(
        bad_payment.check(&verifier),
        Err(SetupBundleError::BadAuthorization {
            slot: "payment open",
            party: "the client",
        }),
    );

    // The provider's payment countersignature made by the client.
    let two = countersigned(proposed());
    let Ok(bad_complete) = two.countersign_payment(Auth::native(client().sign(payment_hash)))
    else {
        panic!("the bundle builds without verifying");
    };
    assert_eq!(
        bad_complete.check(&verifier),
        Err(SetupBundleError::BadAuthorization {
            slot: "payment open",
            party: "the provider",
        }),
    );
}

/// The wire is exact: a wrong version, an unknown revision, a truncated
/// body, a trailing byte, and a terms body of the wrong shape all fail.
#[test]
fn decoding_a_bundle_is_exact() {
    let three = completed(countersigned(proposed()));
    let encoded = three.encode();

    let mut wrong_version = encoded.clone();
    wrong_version[0] = 2;
    assert_eq!(
        WorkChannelSetupBundleV1::decode(&wrong_version),
        Err(SetupBundleError::UnknownFormatVersion { actual: 2 }),
    );

    let mut wrong_revision = encoded.clone();
    wrong_revision[1] = 4;
    assert_eq!(
        WorkChannelSetupBundleV1::decode(&wrong_revision),
        Err(SetupBundleError::UnknownRevision { actual: 4 }),
    );

    // Claiming revision 2 over revision-3 bytes leaves the provider's
    // payment countersignature over at the end.
    let mut understated = encoded.clone();
    understated[1] = 2;
    assert_eq!(
        WorkChannelSetupBundleV1::decode(&understated),
        Err(SetupBundleError::Malformed),
    );

    let mut trailing = encoded.clone();
    trailing.push(0);
    assert_eq!(
        WorkChannelSetupBundleV1::decode(&trailing),
        Err(SetupBundleError::Malformed),
    );

    let truncated = &encoded[..encoded.len() - 1];
    assert_eq!(
        WorkChannelSetupBundleV1::decode(truncated),
        Err(SetupBundleError::Malformed),
    );

    assert_eq!(
        WorkChannelSetupBundleV1::decode(&[]),
        Err(SetupBundleError::Malformed),
    );

    // A basic-terms body in the bond slot. The bundle's own bytes with
    // one nested body replaced: only the terms shape moves.
    let one = proposed();
    let mut basic = one.encode();
    let bond_terms_encoded = encode_kernel(&Terms::work_stake_bond(bond_terms()));
    let Some(offset) = find(&basic, &bond_terms_encoded) else {
        panic!("the bond terms are inside the bundle's bytes");
    };
    let substitute = encode_kernel(&Terms::basic(
        hellas_kernel::ProtocolCode::new(1),
        Parties::new(provider().party_key(), client().party_key()),
        BlockHeight::new(HORIZON),
        List::take(
            [Payout::new(provider().party_key(), 1); MAX_EDGE_OUTPUTS],
            1,
        ),
    ));
    basic.splice(
        offset..offset + bond_terms_encoded.len(),
        substitute.iter().copied(),
    );
    assert_eq!(
        WorkChannelSetupBundleV1::decode(&basic),
        Err(SetupBundleError::WrongTermsShape {
            slot: "bond",
            expected: "work-stake bond",
        }),
    );
}

fn encode_kernel<E: hellas_kernel::Encode>(value: &E) -> Vec<u8> {
    let mut buf = vec![0_u8; value.encoded_size()];
    let written = value.write_to(&mut buf);
    buf.truncate(written);
    buf
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}
