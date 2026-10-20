//! Network separation of kernel authorizations.
//!
//! The property under test: an authorization is valid on the network it
//! was made for and on no other. It is stated twice on purpose — once
//! over the hashes, which is cheap and catches a dropped
//! `network.encode_to(...)`, and once end-to-end through
//! [`hellas_kernel::State::apply`], which is what actually decides
//! whether a replayed witness settles.
//!
//! An edge id is not enough on its own. Two deployments with the same
//! genesis allocations derive the same coin ids, hence the same edge
//! ids, hence — before this binding existed — the same open hash. The
//! open-hash test pins exactly that case: identical funding, identical
//! terms, different network, and the witness must not carry over.

#![allow(clippy::expect_used)] // a rejected fixture is a test bug worth panicking on
#![allow(clippy::indexing_slicing)] // tests may index; the panic-freedom lock targets src

mod support;

use support::l1::{
    EdgeKey, MAKER, MAKER_ID, ProofKey, TAKER, TAKER_ID, edge_id, funding_for, maker_out, payouts,
    taker_out, terms,
};
use support::{FAKE_VERIFIER, FixedStore, l1};

use hellas_kernel::{
    Auth, BlockHash, BlockHeight, CloseKind, Context, NetworkId, PartyAuth, Sig, State, Tx,
};

/// A second network, identical to the test network in every respect
/// except its name.
const OTHER: NetworkId = match NetworkId::new("hellas-kernel-other") {
    Some(network) => network,
    None => panic!("literal is a legal network id"),
};

type Chain = State<FixedStore<4, 1>>;

const fn context(network: NetworkId) -> Context {
    Context::new(
        network,
        BlockHeight::new(1),
        BlockHash::from_bytes([0; BlockHash::LENGTH]),
    )
}

/// A funded chain with room for the first edge and its payout coins.
fn chain() -> Chain {
    l1::genesis(FixedStore::empty(
        [
            MAKER_ID,
            TAKER_ID,
            maker_out(EdgeKey::First),
            taker_out(EdgeKey::First),
        ],
        [edge_id(EdgeKey::First)],
    ))
}

/// The canonical first-edge open, authorized for `network`.
fn open_for(network: NetworkId) -> Tx {
    let (funding, terms) = (funding_for(EdgeKey::First), terms());
    let hash = Tx::open_hash(network, &funding, &terms);
    Tx::open(
        funding,
        terms,
        PartyAuth::owner(Auth::native(Sig::placeholder(MAKER, hash))),
        PartyAuth::owner(Auth::native(Sig::placeholder(TAKER, hash))),
    )
}

#[test]
fn same_inputs_on_a_different_network_give_a_different_open_hash() {
    let (funding, terms) = (funding_for(EdgeKey::First), terms());

    // The edge id is deliberately identical across the two networks: it
    // is precisely the thing that does not separate them.
    assert_eq!(
        Tx::edge_id_of(&funding, &terms),
        edge_id(EdgeKey::First),
        "the fixture edge id must be the one both networks would derive",
    );
    assert_ne!(
        Tx::open_hash(support::NETWORK, &funding, &terms),
        Tx::open_hash(OTHER, &funding, &terms),
    );
}

#[test]
fn same_close_on_a_different_network_gives_a_different_payload_hash() {
    let terms = terms();
    let edge = edge_id(EdgeKey::First);
    let outputs = payouts();

    for kind in [CloseKind::Mutual, CloseKind::Timeout] {
        assert_ne!(
            Tx::payload_hash(support::NETWORK, edge, kind, terms.hash(), &outputs),
            Tx::payload_hash(OTHER, edge, kind, terms.hash(), &outputs),
            "{kind:?} close hash is not network-separated",
        );
    }
}

/// The end-to-end statement for an open: a witness both parties made
/// for one network is rejected when the identical transaction is
/// applied on another.
#[test]
fn an_open_authorized_for_one_network_does_not_settle_on_another() {
    let open = open_for(support::NETWORK);

    assert!(
        chain()
            .apply(context(support::NETWORK), &FAKE_VERIFIER, &open)
            .is_ok(),
        "the open must settle on the network it was authorized for",
    );
    assert!(
        chain()
            .apply(context(OTHER), &FAKE_VERIFIER, &open)
            .is_err(),
        "the identical open must not settle on a different network",
    );
}

/// The same statement for a mutual close, which is a signature over a
/// payout and therefore the witness with the most to steal.
#[test]
fn a_mutual_close_authorized_for_one_network_does_not_settle_on_another() {
    let close = l1::close(EdgeKey::First, ProofKey::Mutual);

    let mut home = chain();
    home.apply(
        context(support::NETWORK),
        &FAKE_VERIFIER,
        &open_for(support::NETWORK),
    )
    .expect("open settles on its own network");

    // The foreign chain reaches the same edge state by its own
    // authorized open, so the close is the only thing under test there.
    let mut foreign = chain();
    foreign
        .apply(context(OTHER), &FAKE_VERIFIER, &open_for(OTHER))
        .expect("a foreign-authorized open settles on the foreign network");

    assert!(
        home.apply(context(support::NETWORK), &FAKE_VERIFIER, &close)
            .is_ok(),
        "the mutual close must settle on the network it was authorized for",
    );
    assert!(
        foreign
            .apply(context(OTHER), &FAKE_VERIFIER, &close)
            .is_err(),
        "the identical mutual close must not settle on a different network",
    );
}
