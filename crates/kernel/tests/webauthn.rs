//! Kernel-level `WebAuthn` authorization tests.

#![cfg(feature = "test-support")]
#![allow(clippy::alloc_instead_of_core)]
#![allow(clippy::disallowed_types)]
#![allow(clippy::expect_used)]
#![allow(clippy::std_instead_of_alloc)]
#![allow(clippy::std_instead_of_core)]
#![allow(clippy::indexing_slicing)] // tests may index; the panic-freedom lock targets src

mod support;

use hellas_kernel::{
    ApplyError, Auth, BlockHash, BlockHeight, CoinId, Context, Funding, Genesis, InvalidOpenReason,
    Key, List, MAX_EDGE_OUTPUTS, Parties, PayloadHash, Payout, ProtocolCode, Sig, SigVerifier,
    SoftPasskey, Terms, Tx, verify_webauthn_assertion,
};
use support::{FixedStore, coin_id, list, state};

const CONTEXT: Context = Context::new(
    support::NETWORK,
    BlockHeight::new(1),
    BlockHash::from_bytes([0; BlockHash::LENGTH]),
);
const TIMEOUT: BlockHeight = BlockHeight::new(2);
const MAKER_COIN: CoinId = coin_id(1);
const TAKER_COIN: CoinId = coin_id(2);
const TAKER: Key = Key::from_bytes([8; Key::LENGTH]);

#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
struct MixedVerifier;

impl SigVerifier for MixedVerifier {
    fn verify_sig(&self, sig: Sig, party_key: Key, hash: PayloadHash) -> bool {
        sig == Sig::placeholder(party_key, hash)
    }

    fn verify_auth(&self, auth: &Auth, party_key: Key, hash: PayloadHash) -> bool {
        match auth {
            Auth::Native(sig) => self.verify_sig(*sig, party_key, hash),
            Auth::WebAuthn(assertion) => {
                verify_webauthn_assertion(assertion, party_key, hash).is_ok()
            }
        }
    }
}

fn keypair(seed: u8) -> SoftPasskey {
    SoftPasskey::from_secret_scalar([seed; 32]).expect("seed is a valid P-256 scalar")
}

fn make_terms(maker: Key, protocol: u8) -> Terms {
    let parties = Parties::new(maker, TAKER);
    let outputs: List<Payout, MAX_EDGE_OUTPUTS> = support::payouts(&[(maker, 7), (TAKER, 8)]);
    Terms::basic(ProtocolCode::new(protocol), parties, TIMEOUT, outputs)
}

fn funding() -> Funding {
    Funding::new(list(&[MAKER_COIN]), list(&[TAKER_COIN]))
}

#[test]
fn webauthn_open_auth_is_checked_in_kernel() {
    let maker_sk = keypair(1);
    let maker_key = maker_sk.party_key();
    let funding = funding();
    let terms = make_terms(maker_key, 1);
    let hash = Tx::open_hash(support::NETWORK, &funding, &terms);
    let maker_assertion = maker_sk.sign(hash).expect("fixture signing succeeds");
    let taker_sig = Sig::placeholder(TAKER, hash);
    let edge = Tx::edge_id_of(&funding, &terms);
    let open = Tx::open(
        funding,
        terms,
        Auth::webauthn(maker_assertion),
        Auth::native(taker_sig),
    );
    let mut state = state(
        FixedStore::empty([MAKER_COIN, TAKER_COIN], [edge]),
        [
            Genesis::coin(MAKER_COIN, maker_key, 10),
            Genesis::coin(TAKER_COIN, TAKER, 5),
        ],
    );

    let event = state
        .apply(CONTEXT, &MixedVerifier, &open)
        .expect("WebAuthn maker + native taker opens edge");
    assert_eq!(
        state.store().edge(edge).map(hellas_kernel::Edge::value),
        Some(15)
    );
    let _ = event;
}

#[test]
fn webauthn_open_rejects_wrong_challenge() {
    let maker_sk = keypair(1);
    let maker_key = maker_sk.party_key();
    let funding = funding();
    let terms = make_terms(maker_key, 1);
    let wrong_terms = make_terms(maker_key, 2);
    let hash = Tx::open_hash(support::NETWORK, &funding, &terms);
    let wrong_hash = Tx::open_hash(support::NETWORK, &funding, &wrong_terms);
    let maker_assertion = maker_sk.sign(wrong_hash).expect("fixture signing succeeds");
    let taker_sig = Sig::placeholder(TAKER, hash);
    let edge = Tx::edge_id_of(&funding, &terms);
    let open = Tx::open(
        funding,
        terms,
        Auth::webauthn(maker_assertion),
        Auth::native(taker_sig),
    );
    let mut state = state(
        FixedStore::empty([MAKER_COIN, TAKER_COIN], [edge]),
        [
            Genesis::coin(MAKER_COIN, maker_key, 10),
            Genesis::coin(TAKER_COIN, TAKER, 5),
        ],
    );

    assert_eq!(
        state.apply(CONTEXT, &MixedVerifier, &open),
        Err(ApplyError::InvalidOpen {
            output: edge,
            reason: InvalidOpenReason::BadSignature,
        }),
    );
}

#[test]
fn webauthn_open_rejects_assertion_from_wrong_party_key() {
    let maker_sk = keypair(1);
    let wrong_sk = keypair(9);
    let maker_key = maker_sk.party_key();
    let funding = funding();
    let terms = make_terms(maker_key, 1);
    let hash = Tx::open_hash(support::NETWORK, &funding, &terms);
    let maker_assertion = wrong_sk.sign(hash).expect("fixture signing succeeds");
    let assertion_key = wrong_sk.party_key();
    let taker_sig = Sig::placeholder(TAKER, hash);
    let edge = Tx::edge_id_of(&funding, &terms);
    let open = Tx::open(
        funding,
        terms,
        Auth::webauthn(maker_assertion),
        Auth::native(taker_sig),
    );
    let mut state = state(
        FixedStore::empty([MAKER_COIN, TAKER_COIN], [edge]),
        [
            Genesis::coin(MAKER_COIN, maker_key, 10),
            Genesis::coin(TAKER_COIN, TAKER, 5),
        ],
    );

    assert_ne!(assertion_key, maker_key);
    assert_eq!(
        state.apply(CONTEXT, &MixedVerifier, &open),
        Err(ApplyError::InvalidOpen {
            output: edge,
            reason: InvalidOpenReason::BadSignature,
        }),
    );
}

/// End-to-end passkey lifecycle under the bundled production verifier: a
/// native maker and a `WebAuthn` taker open an edge and cooperatively
/// close it, the taker authorizing each payload hash through an assertion
/// (passkey hardware cannot sign bare digests, so the assertion envelope
/// is the only witness shape a passkey party can produce).
#[cfg(feature = "secp256k1")]
#[test]
fn bundled_verifier_accepts_passkey_open_and_mutual_close() {
    use hellas_kernel::{CloseKind, Proof, Secp256k1Verifier};
    use secp256k1::{Message, SecretKey, ecdsa};

    fn secp_keypair(seed: u8) -> (SecretKey, Key) {
        let secret = SecretKey::from_secret_bytes([seed; 32]).expect("non-zero seed");
        let public = secret.public_key();
        (secret, Key::from_bytes(public.serialize()))
    }

    fn secp_sign(secret: &SecretKey, hash: PayloadHash) -> Auth {
        let message = Message::from_digest(hash.to_bytes());
        let signature = ecdsa::sign(message, secret);
        Auth::native(Sig::from_bytes(signature.serialize_compact()))
    }

    let (maker_sk, maker_key) = secp_keypair(3);
    let taker_sk = keypair(4);
    let taker_key = taker_sk.party_key();
    let funding = funding();
    let outputs = support::payouts(&[(maker_key, 7), (taker_key, 8)]);
    let terms = Terms::basic(
        ProtocolCode::new(1),
        Parties::new(maker_key, taker_key),
        TIMEOUT,
        outputs.clone(),
    );
    let terms_hash = terms.hash();
    let open_hash = Tx::open_hash(support::NETWORK, &funding, &terms);
    let taker_assertion = taker_sk.sign(open_hash).expect("fixture signing succeeds");
    let assertion_key = taker_sk.party_key();
    let edge = Tx::edge_id_of(&funding, &terms);
    let maker_out = outputs.as_slice()[0].id(edge, 0);
    let taker_out = outputs.as_slice()[1].id(edge, 1);
    let open = Tx::open(
        funding,
        terms,
        secp_sign(&maker_sk, open_hash),
        Auth::webauthn(taker_assertion),
    );
    let mut state = state(
        FixedStore::empty([MAKER_COIN, TAKER_COIN, maker_out, taker_out], [edge]),
        [
            Genesis::coin(MAKER_COIN, maker_key, 10),
            Genesis::coin(TAKER_COIN, taker_key, 5),
        ],
    );
    let verifier = Secp256k1Verifier::new();

    assert_eq!(assertion_key, taker_key);
    state
        .apply(CONTEXT, &verifier, &open)
        .expect("bundled verifier accepts native maker + WebAuthn taker open");
    assert_eq!(
        state.store().edge(edge).map(hellas_kernel::Edge::value),
        Some(15),
    );

    let close_hash = Tx::payload_hash(
        support::NETWORK,
        edge,
        CloseKind::Mutual,
        terms_hash,
        &outputs,
    );
    let taker_close_assertion = taker_sk.sign(close_hash).expect("fixture signing succeeds");
    let close = Tx::close(
        edge,
        Proof::mutual(
            secp_sign(&maker_sk, close_hash),
            Auth::webauthn(taker_close_assertion),
        ),
        outputs,
    );

    state
        .apply(CONTEXT, &verifier, &close)
        .expect("bundled verifier accepts native maker + WebAuthn taker mutual close");
    assert_eq!(state.store().edge(edge), None);
    assert_eq!(
        state
            .store()
            .coin(maker_out)
            .map(hellas_kernel::Coin::value),
        Some(7),
    );
    assert_eq!(
        state
            .store()
            .coin(taker_out)
            .map(hellas_kernel::Coin::value),
        Some(8),
    );
}
