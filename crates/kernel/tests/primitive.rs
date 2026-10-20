//! Primitive wrapper tests.

#![allow(clippy::indexing_slicing)] // tests may index; the panic-freedom lock targets src
use hellas_kernel::{
    BlockHash, BlockHeight, CoinId, Context, Cost, Decode, DecodeError, EdgeId, Encode, Fees,
    Funding, Key, List, MAX_EDGE_OUTPUTS, MAX_PARTY_INPUTS, Parties, Party, PartyKeys, Payout,
    ProtocolCode, Sig, Terms, Tx,
};

const NETWORK: hellas_kernel::NetworkId = match hellas_kernel::NetworkId::new("hellas-kernel-test")
{
    Some(network) => network,
    None => panic!("literal is a legal network id"),
};

#[test]
fn protocol_code_exposes_value() {
    let code = ProtocolCode::new(7);

    assert_eq!(code.get(), 7);
    assert_eq!(code.encoded_size(), 1);
}

#[test]
fn party_tags_are_stable() {
    assert_eq!(Party::Maker.tag(), 0);
    assert_eq!(Party::Taker.tag(), 1);
    assert_eq!(Party::Maker.encoded_size(), 1);
    assert_eq!(Party::Taker.encoded_size(), 1);
    assert_eq!(Party::from_tag(0), Some(Party::Maker));
    assert_eq!(Party::from_tag(1), Some(Party::Taker));
    assert_eq!(Party::from_tag(2), None);
}

#[test]
fn terms_hash_commits_to_basic_fields() {
    let maker = Key::from_bytes([1; Key::LENGTH]);
    let taker = Key::from_bytes([2; Key::LENGTH]);
    let parties = Parties::new(PartyKeys::sole(maker), PartyKeys::sole(taker));
    let timeout = BlockHeight::new(11);
    let outputs = payouts(Payout::new(maker, 6), Payout::new(taker, 4));
    let other_outputs = payouts(Payout::new(maker, 5), Payout::new(taker, 5));
    let terms = Terms::basic(ProtocolCode::new(7), parties, timeout, outputs.clone());

    assert_eq!(terms.parties(), parties);
    assert_eq!(terms.timeout(), timeout);
    assert_eq!(terms.timeout_outputs(), Some(&outputs));
    assert_eq!(terms.hash(), terms.hash());
    assert_ne!(
        terms.hash(),
        Terms::basic(ProtocolCode::new(8), parties, timeout, outputs.clone()).hash(),
    );
    assert_ne!(
        terms.hash(),
        Terms::basic(ProtocolCode::new(7), parties, BlockHeight::new(12), outputs).hash(),
    );
    assert_ne!(
        terms.hash(),
        Terms::basic(ProtocolCode::new(7), parties, timeout, other_outputs).hash(),
    );
}

#[test]
fn context_prices_resource_costs() {
    let fees = Fees::new(3, 5, 7, 11);
    let block_hash_bytes = [9; BlockHash::LENGTH];
    let context = Context::with_fees(
        NETWORK,
        BlockHeight::new(7),
        BlockHash::from_bytes(block_hash_bytes),
        fees,
    );
    let cost = Cost::new(1, 4, 3);

    assert_eq!(context.previous_hash().to_bytes(), block_hash_bytes);
    assert_eq!(context.previous_hash().as_bytes(), &block_hash_bytes);
    assert_eq!(cost.base(), 1);
    assert_eq!(cost.slots(), 4);
    assert_eq!(cost.proofs(), 3);
    assert_eq!(fees.base(), 3);
    assert_eq!(fees.slot(), 5);
    assert_eq!(fees.proof(), 7);
    assert_eq!(fees.lifetime(), 11);
    assert_eq!(context.fees(), fees);
    // 3*1 + 5*4 + 7*3 = 44
    assert_eq!(context.fee(cost), Some(44));
}

#[test]
fn byte_newtypes_preserve_their_canonical_bytes() {
    let key_bytes = [3; Key::LENGTH];
    let key = Key::from_bytes(key_bytes);
    assert_eq!(key.to_bytes(), key_bytes);
    assert_eq!(key.as_bytes(), &key_bytes);
    assert_eq!(key.encoded_size(), Key::LENGTH);
    assert_round_trips_key(key);

    let coin_bytes = [4; CoinId::LENGTH];
    let coin = CoinId::from_bytes(coin_bytes);
    assert_eq!(coin.to_bytes(), coin_bytes);
    assert_eq!(coin.as_bytes(), &coin_bytes);
    assert_eq!(coin.encoded_size(), CoinId::LENGTH);
    assert_writes_exactly(&coin, &coin_bytes);

    let edge_bytes = [5; EdgeId::LENGTH];
    let edge = EdgeId::from_bytes(edge_bytes);
    assert_eq!(edge.to_bytes(), edge_bytes);
    assert_eq!(edge.as_bytes(), &edge_bytes);
    assert_eq!(edge.encoded_size(), EdgeId::LENGTH);
    assert_writes_exactly(&edge, &edge_bytes);

    let terms_hash = Terms::basic(
        ProtocolCode::new(7),
        Parties::new(
            PartyKeys::sole(key),
            PartyKeys::sole(Key::from_bytes([6; Key::LENGTH])),
        ),
        BlockHeight::new(9),
        payouts(Payout::new(key, 1), Payout::new(key, 2)),
    )
    .hash();
    let terms_hash_bytes = *terms_hash.as_bytes();
    assert_eq!(terms_hash.to_bytes(), terms_hash_bytes);
    assert_eq!(terms_hash.encoded_size(), terms_hash_bytes.len());
    assert_writes_exactly(&terms_hash, &terms_hash_bytes);

    let funding = Funding::new(
        List::<CoinId, MAX_PARTY_INPUTS>::empty(CoinId::from_bytes([0; CoinId::LENGTH])),
        List::<CoinId, MAX_PARTY_INPUTS>::empty(CoinId::from_bytes([0; CoinId::LENGTH])),
    );
    let payload_terms = Terms::basic(
        ProtocolCode::new(9),
        Parties::new(PartyKeys::sole(key), PartyKeys::sole(key)),
        BlockHeight::new(10),
        payouts(Payout::new(key, 0), Payout::new(key, 0)),
    );
    let payload_hash = Tx::open_hash(NETWORK, &funding, &payload_terms);
    let payload_hash_bytes = *payload_hash.as_bytes();
    assert_eq!(payload_hash.to_bytes(), payload_hash_bytes);
    assert_eq!(payload_hash.encoded_size(), payload_hash_bytes.len());
    assert_writes_exactly(&payload_hash, &payload_hash_bytes);

    let sig_bytes = [8; Sig::LENGTH];
    let sig = Sig::from_bytes(sig_bytes);
    assert_eq!(sig.to_bytes(), sig_bytes);
    assert_eq!(sig.as_bytes(), &sig_bytes);
    assert_eq!(sig.encoded_size(), Sig::LENGTH);
    assert_round_trips_sig(sig);
}

#[test]
fn fixed_width_decoders_reject_truncated_inputs() {
    assert_eq!(
        Key::decode(&[0; Key::LENGTH - 1]),
        Err(DecodeError::InsufficientBytes {
            needed: Key::LENGTH,
            got: Key::LENGTH - 1,
        }),
    );
    assert_eq!(
        Sig::decode(&[0; Sig::LENGTH - 1]),
        Err(DecodeError::InsufficientBytes {
            needed: Sig::LENGTH,
            got: Sig::LENGTH - 1,
        }),
    );
}

fn payouts(first: Payout, second: Payout) -> List<Payout, MAX_EDGE_OUTPUTS> {
    let Some(outputs) = List::new([first, second, first, first], 2) else {
        panic!("invalid primitive payout list");
    };
    outputs
}

fn assert_round_trips_key(key: Key) {
    let mut buf = [0; Key::LENGTH];

    assert_eq!(key.write_to(&mut buf), Key::LENGTH);
    assert_eq!(Key::decode(&buf), Ok((key, Key::LENGTH)));
}

fn assert_round_trips_sig(sig: Sig) {
    let mut buf = [0; Sig::LENGTH];

    assert_eq!(sig.write_to(&mut buf), Sig::LENGTH);
    assert_eq!(Sig::decode(&buf), Ok((sig, Sig::LENGTH)));
}

fn assert_writes_exactly(value: &impl Encode, expected: &[u8]) {
    let mut buf = [0; Sig::LENGTH];

    let written = value.write_to(&mut buf);

    assert_eq!(written, expected.len());
    assert_eq!(&buf[..written], expected);
}
