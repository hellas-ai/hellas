//! Allocation hygiene tests for kernel hot-path primitives.
//!
//! These tests assert zero heap allocations across `apply_all` and
//! `Tx::cost`. The invariant rests on every tx-payload type
//! (`Tx`, `Funding`, `Terms`, `Proof`, `List<...>`)
//! being stack-only: clones we make in setup or assertions are pure
//! `memcpy`s, never `Box`/`Vec`/`String` allocations. Adding a heap
//! field to any of those types — or changing `List<T, N>` to back its
//! storage on the heap — would silently regress this without a clippy
//! or rustc warning. Re-run `cargo test --test allocation` after any
//! field-shape change to those types.

#![allow(clippy::indexing_slicing)] // tests may index; the panic-freedom lock targets src
mod support;

use support::{FAKE_VERIFIER, FixedStore, list, open_tx};

use hellas_kernel::{
    Auth, BlockHash, BlockHeight, CloseKind, CoinId, Context, Event, EventKind, Funding, Genesis,
    Key, List, MAX_EDGE_INPUTS, MAX_EDGE_OUTPUTS, MAX_PARTY_INPUTS, Parties, PartyAuth, PartyKeys,
    Payout, Proof, ProtocolCode, Sig, State, Terms, Tx,
};

const CONTEXT: Context = Context::new(
    support::NETWORK,
    BlockHeight::new(1),
    BlockHash::from_bytes([0; BlockHash::LENGTH]),
);

#[test]
fn open_resolve_and_operation_match_do_not_allocate() {
    let maker_key = Key::from_bytes([7; Key::LENGTH]);
    let taker_key = Key::from_bytes([8; Key::LENGTH]);
    let parties = Parties::new(PartyKeys::sole(maker_key), PartyKeys::sole(taker_key));
    let maker = CoinId::from_bytes([1; CoinId::LENGTH]);
    let taker = CoinId::from_bytes([2; CoinId::LENGTH]);
    let funding_value = funding(maker, taker);
    let terms_value = Terms::basic(
        ProtocolCode::new(1),
        parties,
        BlockHeight::new(2),
        payouts(Payout::new(maker_key, 9), Payout::new(taker_key, 6)),
    );
    let edge = Tx::edge_id_of(&funding_value, &terms_value);
    let expected_open = open_tx(funding_value, terms_value.clone(), maker_key, taker_key);
    let close_outputs = payouts(Payout::new(maker_key, 9), Payout::new(taker_key, 6));
    let expected_close_hash = Tx::payload_hash(
        support::NETWORK,
        edge,
        CloseKind::Mutual,
        terms_value.hash(),
        &close_outputs,
    );
    let expected_close = Tx::close(
        edge,
        Proof::mutual(
            PartyAuth::owner(Auth::native(Sig::placeholder(
                maker_key,
                expected_close_hash,
            ))),
            PartyAuth::owner(Auth::native(Sig::placeholder(
                taker_key,
                expected_close_hash,
            ))),
        ),
        close_outputs.clone(),
    );
    let output_id_list = Tx::close_output_ids(edge, &close_outputs);
    let maker_out = nth(&output_id_list, 0);
    let taker_out = nth(&output_id_list, 1);
    let maker_seed = Genesis::coin(maker, maker_key, 10);
    let taker_seed = Genesis::coin(taker, taker_key, 5);
    let store = FixedStore::empty([maker, taker, maker_out, taker_out], [edge]);

    let info = allocation_counter::measure(|| {
        let store = core::hint::black_box(store);

        let outputs = payouts(Payout::new(maker_key, 9), Payout::new(taker_key, 6));
        let terms = Terms::basic(
            ProtocolCode::new(1),
            parties,
            BlockHeight::new(2),
            outputs.clone(),
        );
        let close_hash = Tx::payload_hash(
            support::NETWORK,
            edge,
            CloseKind::Mutual,
            terms.hash(),
            &outputs,
        );
        let proof = Proof::mutual(
            PartyAuth::owner(Auth::native(Sig::placeholder(maker_key, close_hash))),
            PartyAuth::owner(Auth::native(Sig::placeholder(taker_key, close_hash))),
        );
        let open = open_tx(funding(maker, taker), terms, maker_key, taker_key);
        assert_eq!(open, expected_open.clone());
        let is_open = matches!(open, Tx::Open { .. });
        let close = Tx::close(edge, proof, outputs);
        assert_eq!(close, expected_close.clone());
        let is_close = matches!(close, Tx::Close { .. });
        let Ok(mut chain) = State::genesis(store, &[maker_seed, taker_seed]) else {
            panic!("genesis rejected test seed");
        };
        let ops = List::all([open, close]);
        let Ok(diff) = chain.apply_all(CONTEXT, &FAKE_VERIFIER, &ops) else {
            panic!("apply_all rejected");
        };

        assert_eq!(
            diff.event(0).map(Event::kind),
            Some(&EventKind::EdgeOpened {
                inputs: input_ids(maker, taker),
                output: edge,
            }),
        );
        assert_eq!(
            diff.event(1).map(Event::kind),
            Some(&EventKind::EdgeClosed {
                input: edge,
                outputs: output_ids(maker_out, taker_out),
            }),
        );

        core::hint::black_box((is_open, is_close));
    });

    assert_eq!(info.count_total, 0);
    assert_eq!(info.count_current, 0);
    assert_eq!(info.count_max, 0);
    assert_eq!(info.bytes_total, 0);
    assert_eq!(info.bytes_current, 0);
    assert_eq!(info.bytes_max, 0);
}

fn funding(maker: CoinId, taker: CoinId) -> Funding {
    Funding::new(party1(maker), party1(taker))
}

fn party1(id: CoinId) -> List<CoinId, MAX_PARTY_INPUTS> {
    list(&[id])
}

fn payouts(first: Payout, second: Payout) -> List<Payout, MAX_EDGE_OUTPUTS> {
    list(&[first, second])
}

fn input_ids(first: CoinId, second: CoinId) -> List<CoinId, MAX_EDGE_INPUTS> {
    list(&[first, second])
}

fn output_ids(first: CoinId, second: CoinId) -> List<CoinId, MAX_EDGE_OUTPUTS> {
    list(&[first, second])
}

fn nth<const N: usize>(ids: &List<CoinId, N>, index: usize) -> CoinId {
    ids.as_slice()[index]
}
