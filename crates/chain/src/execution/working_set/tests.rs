use super::*;
use hellas_kernel::{
    Auth, CloseKind, Funding, Genesis, Key, List, MAX_EDGE_OUTPUTS, MAX_PARTY_INPUTS, Parties,
    PartyAuth, PartyKeys, PayloadHash, Payout, ProtocolCode, Sig, SigVerifier, State, Terms, Tx,
};

const MAKER: Key = Key::from_bytes([0xaa; Key::LENGTH]);
const TAKER: Key = Key::from_bytes([0xbb; Key::LENGTH]);

struct FakeVerifier;
impl SigVerifier for FakeVerifier {
    fn verify_sig(&self, sig: Sig, key: Key, hash: PayloadHash) -> bool {
        sig == Sig::placeholder(key, hash)
    }
}

fn party_one(id: CoinId) -> List<CoinId, MAX_PARTY_INPUTS> {
    List::new([id; MAX_PARTY_INPUTS], 1).expect("one-coin party")
}

fn payouts(maker_value: u64, taker_value: u64) -> List<Payout, MAX_EDGE_OUTPUTS> {
    let payout = Payout::new(MAKER, maker_value);
    let mut buf = [payout; MAX_EDGE_OUTPUTS];
    buf[1] = Payout::new(TAKER, taker_value);
    List::new(buf, 2).expect("two payouts")
}

#[test]
fn load_apply_replay_round_trip() {
    // -- 1. Genesis: two coins in the durable store, conceptually.
    let maker_coin = CoinId::from_bytes([0x01; CoinId::LENGTH]);
    let taker_coin = CoinId::from_bytes([0x02; CoinId::LENGTH]);

    // -- 2. Build a block: open the edge, immediately mutual-close
    // back to the same parties. Walk the block to enumerate every
    // id it touches; pre-load each into the working set.
    let terms = Terms::basic(
        ProtocolCode::new(1),
        Parties::new(PartyKeys::sole(MAKER), PartyKeys::sole(TAKER)),
        hellas_kernel::BlockHeight::new(2),
        payouts(10, 5),
    );
    let funding = Funding::new(party_one(maker_coin), party_one(taker_coin));
    let edge = Tx::edge_id_of(&funding, &terms);

    let open_hash = Tx::open_hash(crate::domain::TEST_NETWORK, &funding, &terms);
    let open = Tx::open(
        funding,
        terms.clone(),
        PartyAuth::owner(Auth::native(Sig::placeholder(MAKER, open_hash))),
        PartyAuth::owner(Auth::native(Sig::placeholder(TAKER, open_hash))),
    );

    let close_outputs = payouts(10, 5);
    let close_hash = Tx::payload_hash(
        crate::domain::TEST_NETWORK,
        edge,
        CloseKind::Mutual,
        terms.hash(),
        &close_outputs,
    );
    let close_output_ids = Tx::close_output_ids(edge, &close_outputs);
    let close = Tx::close(
        edge,
        hellas_kernel::Proof::mutual(
            PartyAuth::owner(Auth::native(Sig::placeholder(MAKER, close_hash))),
            PartyAuth::owner(Auth::native(Sig::placeholder(TAKER, close_hash))),
        ),
        close_outputs,
    );

    let mut working = BlockWorkingSet::new();
    working.insert_coin_slot(maker_coin, None);
    working.insert_coin_slot(taker_coin, None);
    working.insert_edge_slot(edge, None);
    for id in close_output_ids.iter() {
        working.insert_coin_slot(*id, None);
    }

    // -- 3. Seed genesis into the working set, then drive the
    // kernel against the resulting state.
    let mut state = State::genesis(
        working,
        &[
            Genesis::coin(maker_coin, MAKER, 10),
            Genesis::coin(taker_coin, TAKER, 5),
        ],
    )
    .expect("genesis seeds the working set");
    let ctx = hellas_kernel::Context::new(
        crate::domain::TEST_NETWORK,
        hellas_kernel::BlockHeight::new(1),
        hellas_kernel::BlockHash::from_bytes([0; hellas_kernel::BlockHash::LENGTH]),
    );
    state
        .apply(ctx, &FakeVerifier, &open)
        .expect("open accepted");
    state
        .apply(ctx, &FakeVerifier, &close)
        .expect("close accepted");

    // -- 5. Inspect only the ids named by the authoritative close event.
    let final_set = state.into_store();
    assert!(
        close_output_ids
            .iter()
            .all(|id| final_set.coin(*id).is_some()),
        "expected every payout coin"
    );
    assert!(final_set.edge(edge).is_none(), "edge should be consumed");

    // Input coins are gone.
    assert!(
        final_set.coin(maker_coin).is_none(),
        "maker_coin should be consumed"
    );
    assert!(
        final_set.coin(taker_coin).is_none(),
        "taker_coin should be consumed"
    );
}

#[test]
fn dropped_batch_rolls_back() {
    // Seed one coin into the working set via genesis, then start
    // a batch, remove the coin, and drop the batch without
    // committing. The slot should still hold the original coin.
    let id = CoinId::from_bytes([0x42; CoinId::LENGTH]);
    let mut working = BlockWorkingSet::new();
    working.insert_coin_slot(id, None);
    let state = State::genesis(working, &[Genesis::coin(id, MAKER, 100)])
        .expect("genesis seeds the working set");
    let mut working = state.into_store();
    assert!(
        working.coin(id).is_some(),
        "post-genesis slot must hold a coin"
    );

    {
        let mut batch = working.begin();
        let _ = batch.remove_coin(id);
        // Drop without committing.
    }

    assert!(
        working.coin(id).is_some(),
        "uncommitted remove must roll back"
    );
}
