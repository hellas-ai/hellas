//! Real-crypto smoke test for the [`Secp256k1Verifier`].
//!
//! Constructs a real keypair, signs the kernel's canonical close hash with
//! ECDSA, and asserts that the kernel accepts the resulting Mutual close
//! through the production verifier. Mutating any of (sig, key, hash) or
//! swapping the kernel for a `RejectVerifier` causes rejection.

#![cfg(feature = "secp256k1")]
#![allow(clippy::alloc_instead_of_core)]
#![allow(clippy::disallowed_types)]
#![allow(clippy::expect_used)]
#![allow(clippy::similar_names)]
#![allow(clippy::std_instead_of_alloc)]
#![allow(clippy::std_instead_of_core)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::indexing_slicing)] // tests may index; the panic-freedom lock targets src

mod support;

use hellas_kernel::{
    ApplyError, Auth, BlockHash, BlockHeight, CloseKind, CoinId, Context, Funding, Genesis,
    InvalidProofReason, Key, List, MAX_EDGE_OUTPUTS, Parties, PayloadHash, Payout, Proof,
    ProtocolCode, Secp256k1Signer, Secp256k1Verifier, Sig, SigVerifier, State, Terms, Tx,
};
use secp256k1::{Message, SecretKey, ecdsa};
use support::{FixedStore, list};

const TIMEOUT: BlockHeight = BlockHeight::new(2);
const CONTEXT: Context = Context::new(
    support::NETWORK,
    BlockHeight::new(1),
    BlockHash::from_bytes([0; BlockHash::LENGTH]),
);

fn keypair(seed: u8) -> (SecretKey, Key) {
    let secret = SecretKey::from_secret_bytes([seed; 32]).expect("non-zero seed");
    let public = secret.public_key();
    (secret, Key::from_bytes(public.serialize()))
}

/// Real ECDSA authorization from `secret` over `hash`.
fn sign(secret: &SecretKey, hash: hellas_kernel::PayloadHash) -> Auth {
    let message = Message::from_digest(hash.to_bytes());
    let signature = ecdsa::sign(message, secret);
    Auth::native(Sig::from_bytes(signature.serialize_compact()))
}

fn payouts(maker: Key, taker: Key) -> List<Payout, MAX_EDGE_OUTPUTS> {
    support::payouts(&[(maker, 7), (taker, 8)])
}

#[test]
fn native_signer_matches_libsecp256k1() {
    let verifier = Secp256k1Verifier::new();
    for seed in 1..=8 {
        let signer = Secp256k1Signer::from_secret_scalar([seed; 32]).unwrap();
        let (secret, public) = keypair(seed);
        let hash = PayloadHash::from_bytes([seed + 8; PayloadHash::LENGTH]);
        let reference = ecdsa::sign(Message::from_digest(hash.to_bytes()), &secret);
        let signature = signer.sign(hash);

        assert_eq!(signer.party_key(), public);
        assert_eq!(signature.as_bytes(), &reference.serialize_compact());
        assert!(verifier.verify_sig(signature, public, hash));
    }
}

#[test]
fn high_s_counterpart_of_valid_signature_is_rejected() {
    let (secret, public) = keypair(1);
    let hash = PayloadHash::from_bytes([9; PayloadHash::LENGTH]);
    let reference = ecdsa::sign(Message::from_digest(hash.to_bytes()), &secret);
    let low = k256::ecdsa::Signature::from_slice(&reference.serialize_compact()).unwrap();
    let high = k256::ecdsa::Signature::from_scalars(low.r().to_bytes(), (-low.s()).to_bytes())
        .expect("negating the non-zero S scalar creates a valid signature");
    let high_bytes: [u8; Sig::LENGTH] = high.to_bytes().into();

    // The reference implementation confirms this is the high-S counterpart of
    // the same valid signature, rather than an invalid or unrelated witness.
    let mut normalized = secp256k1::ecdsa::Signature::from_compact(&high_bytes).unwrap();
    normalized.normalize_s();
    assert_eq!(normalized, reference);
    assert_ne!(high_bytes, reference.serialize_compact());

    let verifier = Secp256k1Verifier::new();
    assert!(verifier.verify_sig(Sig::from_bytes(reference.serialize_compact()), public, hash));
    assert!(!verifier.verify_sig(Sig::from_bytes(high_bytes), public, hash));
}

#[test]
fn mutual_with_real_ecdsa_signatures_closes_under_production_verifier() {
    let (maker_sk, maker_pk) = keypair(1);
    let (taker_sk, taker_pk) = keypair(2);
    let parties = Parties::new(maker_pk, taker_pk);
    let outputs = payouts(maker_pk, taker_pk);
    let timeout_outputs = payouts(maker_pk, taker_pk);
    let terms = Terms::basic(ProtocolCode::new(1), parties, TIMEOUT, timeout_outputs);
    let terms_hash = terms.hash();
    let maker_coin = CoinId::from_bytes([1; CoinId::LENGTH]);
    let taker_coin = CoinId::from_bytes([2; CoinId::LENGTH]);
    let funding = Funding::new(list(&[maker_coin]), list(&[taker_coin]));
    let edge = Tx::edge_id_of(&funding, &terms);
    let open_hash = Tx::open_hash(support::NETWORK, &funding, &terms);
    let open = Tx::open(
        funding,
        terms,
        sign(&maker_sk, open_hash),
        sign(&taker_sk, open_hash),
    );
    let close_hash = Tx::payload_hash(
        support::NETWORK,
        edge,
        CloseKind::Mutual,
        terms_hash,
        &outputs,
    );
    let proof = Proof::mutual(sign(&maker_sk, close_hash), sign(&taker_sk, close_hash));
    let maker_out = outputs.as_slice()[0].id(edge, 0);
    let taker_out = outputs.as_slice()[1].id(edge, 1);
    let close = Tx::close(edge, proof, outputs);
    let store = FixedStore::empty([maker_coin, taker_coin, maker_out, taker_out], [edge]);
    let mut state = State::genesis(
        store,
        &[
            Genesis::coin(maker_coin, maker_pk, 10),
            Genesis::coin(taker_coin, taker_pk, 5),
        ],
    )
    .expect("genesis seeds the store");
    let verifier = Secp256k1Verifier::new();

    state
        .apply(CONTEXT, &verifier, &open)
        .expect("open accepted");
    let event = state
        .apply(CONTEXT, &verifier, &close)
        .expect("mutual with valid ECDSA accepted");
    assert_eq!(state.store().edge(edge), None);
    let _ = event;
}

#[test]
fn forged_signature_is_rejected_by_real_verifier() {
    let (maker_sk, maker_pk) = keypair(1);
    let (taker_sk, taker_pk) = keypair(2);
    let parties = Parties::new(maker_pk, taker_pk);
    let outputs = payouts(maker_pk, taker_pk);
    let terms = Terms::basic(ProtocolCode::new(1), parties, TIMEOUT, outputs.clone());
    let terms_hash = terms.hash();
    let maker_coin = CoinId::from_bytes([1; CoinId::LENGTH]);
    let taker_coin = CoinId::from_bytes([2; CoinId::LENGTH]);
    let funding = Funding::new(list(&[maker_coin]), list(&[taker_coin]));
    let edge = Tx::edge_id_of(&funding, &terms);
    // Open is honestly authorized by both parties; the forgery happens on
    // the close side below (the test's actual subject).
    let open_hash = Tx::open_hash(support::NETWORK, &funding, &terms);
    let open = Tx::open(
        funding,
        terms,
        sign(&maker_sk, open_hash),
        sign(&taker_sk, open_hash),
    );
    let close_hash = Tx::payload_hash(
        support::NETWORK,
        edge,
        CloseKind::Mutual,
        terms_hash,
        &outputs,
    );
    // Sign with maker's key in *both* slots — taker's signature is forged.
    let proof = Proof::mutual(sign(&maker_sk, close_hash), sign(&maker_sk, close_hash));
    let maker_out = outputs.as_slice()[0].id(edge, 0);
    let taker_out = outputs.as_slice()[1].id(edge, 1);
    let close = Tx::close(edge, proof, outputs);
    let store = FixedStore::empty([maker_coin, taker_coin, maker_out, taker_out], [edge]);
    let mut state = State::genesis(
        store,
        &[
            Genesis::coin(maker_coin, maker_pk, 10),
            Genesis::coin(taker_coin, taker_pk, 5),
        ],
    )
    .expect("genesis seeds the store");
    let verifier = Secp256k1Verifier::new();

    state
        .apply(CONTEXT, &verifier, &open)
        .expect("open accepted");
    assert_eq!(
        state.apply(CONTEXT, &verifier, &close),
        Err(ApplyError::InvalidProof {
            input: edge,
            reason: InvalidProofReason::BadSignature,
        }),
    );
}

#[test]
fn close_kind_tags_are_the_assigned_numbers() {
    assert_eq!(CloseKind::Mutual.tag(), 0);
    assert_eq!(CloseKind::Timeout.tag(), 1);
    assert_eq!(CloseKind::Freeze.tag(), 3);
    assert_eq!(CloseKind::Adjudicated.tag(), 4);
}
