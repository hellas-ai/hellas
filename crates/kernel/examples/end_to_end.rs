//! Executable end-to-end reference for the public kernel surface.
//!
//! The example wires the three host-owned boundaries the kernel needs:
//!
//! - `Store`: an inline `BTreeMap` backend with staged rollback semantics.
//! - `SigVerifier`: real secp256k1 ECDSA via `Secp256k1Verifier`.
//! - `Context`: block height, previous hash, and deterministic fees.
//!
//! It runs two small lifecycles:
//!
//! - a bilaterally funded edge closed cooperatively before timeout;
//! - a maker-funded edge closed by timeout, with the taker contributing no
//!   funding but still authorizing the open.
//!
//! Build and run with:
//!
//! ```sh
//! cargo run --example end_to_end --features secp256k1
//! ```

#![allow(clippy::alloc_instead_of_core)]
#![allow(clippy::disallowed_types)]
#![allow(clippy::expect_used)]
#![allow(clippy::print_stdout)]
#![allow(clippy::similar_names)]
#![allow(clippy::std_instead_of_alloc)]
#![allow(clippy::std_instead_of_core)]
// tests may index; the panic-freedom lock targets src
#![allow(clippy::indexing_slicing)]

mod support;

use hellas_kernel::{
    Auth, BlockHeight, CloseKind, EdgeId, Fees, Funding, Genesis, Key, List, MAX_EDGE_OUTPUTS,
    Parties, PartyAuth, PartyKeys, Payout, Proof, ProtocolCode, Secp256k1Verifier, Terms,
    TermsHash, Tx,
};
use secp256k1::SecretKey;
use support::{
    apply_one, coin_id, context, context_fee, empty_party, genesis, lifetime_fee, party_one,
    payout1, payouts2, print_live_coins, schedule_fee, secp_keypair, secp_sign, summarize,
};

const FEES: Fees = Fees::new(1, 1, 2, 1);
const PROTOCOL: ProtocolCode = ProtocolCode::new(1);

#[derive(Debug)]
struct Wallets {
    maker_secret: SecretKey,
    maker_key: Key,
    taker_secret: SecretKey,
    taker_key: Key,
}

impl Wallets {
    fn deterministic() -> Self {
        let (maker_secret, maker_key) = secp_keypair(1);
        let (taker_secret, taker_key) = secp_keypair(2);
        Self {
            maker_secret,
            maker_key,
            taker_secret,
            taker_key,
        }
    }

    const fn parties(&self) -> Parties {
        Parties::new(
            PartyKeys::sole(self.maker_key),
            PartyKeys::sole(self.taker_key),
        )
    }
}

fn main() {
    let verifier = Secp256k1Verifier::new();
    let wallets = Wallets::deterministic();

    println!("== Hellas kernel end-to-end ==");
    println!(
        "fees: base={}, slot={}, proof={}, lifetime={}/block",
        FEES.base(),
        FEES.slot(),
        FEES.proof(),
        FEES.lifetime(),
    );

    run_bilateral_mutual(&wallets, verifier);
    run_maker_funded_timeout(&wallets, verifier);

    println!();
    println!("The kernel saw public keys, signatures, terms, and object ids.");
    println!("Secrets stayed in the host, and dispute seals remain host-defined.");
}

fn run_bilateral_mutual(wallets: &Wallets, verifier: Secp256k1Verifier) {
    let maker_coin = coin_id(0xa1);
    let taker_coin = coin_id(0xb1);
    let open_context = context(1, 0x10, FEES);
    let close_context = context(3, 0x11, FEES);
    let timeout = BlockHeight::new(5);
    let timeout_outputs = payouts2(wallets.maker_key, 30, wallets.taker_key, 16);
    let mutual_outputs = payouts2(wallets.maker_key, 28, wallets.taker_key, 16);
    let terms = Terms::basic(PROTOCOL, wallets.parties(), timeout, timeout_outputs);
    let terms_hash = terms.hash();
    let funding = Funding::new(party_one(maker_coin), party_one(taker_coin));
    let edge_id = Tx::edge_id_of(&funding, &terms);
    let open = signed_open(wallets, funding, terms);
    let open_fee = context_fee(open_context, open.cost());
    let lifetime_fee = lifetime_fee(open_context, timeout);

    let mut state = genesis(&[
        Genesis::coin(maker_coin, wallets.maker_key, 40),
        Genesis::coin(taker_coin, wallets.taker_key, 20),
    ]);

    println!();
    println!("== 1. Bilateral funding, mutual close ==");
    println!(
        "genesis: maker coin=40, taker coin=20; store={} coins/{} edges",
        state.store().coin_count(),
        state.store().edge_count(),
    );

    let event = apply_one(&mut state, &verifier, open_context, open);
    let opened = state.store().edge(edge_id).expect("open inserted edge");
    println!(
        "open @{}: {}",
        open_context.block_height().get(),
        summarize(&event)
    );
    println!(
        "  funding 60 -> principal {}, reserve {} (open fee {}, lifetime fee {})",
        opened.value(),
        opened.reserve(),
        open_fee,
        lifetime_fee,
    );
    println!(
        "  store={} coins/{} edges",
        state.store().coin_count(),
        state.store().edge_count(),
    );

    let close = signed_mutual_close(wallets, edge_id, terms_hash, mutual_outputs);
    let close_fee = schedule_fee(opened.close_fees(), close.cost());
    let event = apply_one(&mut state, &verifier, close_context, close);
    println!(
        "close @{}: {}",
        close_context.block_height().get(),
        summarize(&event),
    );
    println!("  close fee {close_fee} paid from open-time reserve");
    print_live_coins(state.store());
}

fn run_maker_funded_timeout(wallets: &Wallets, verifier: Secp256k1Verifier) {
    let maker_coin = coin_id(0xa2);
    let open_context = context(1, 0x20, FEES);
    let close_context = context(3, 0x21, FEES);
    let timeout = BlockHeight::new(3);
    let timeout_outputs = payout1(wallets.maker_key, 60);
    let terms = Terms::basic(
        PROTOCOL,
        wallets.parties(),
        timeout,
        timeout_outputs.clone(),
    );
    let funding = Funding::new(party_one(maker_coin), empty_party());
    let edge_id = Tx::edge_id_of(&funding, &terms);
    let open = signed_open(wallets, funding, terms.clone());
    let open_fee = context_fee(open_context, open.cost());
    let lifetime_fee = lifetime_fee(open_context, timeout);

    let mut state = genesis(&[Genesis::coin(maker_coin, wallets.maker_key, 70)]);

    println!();
    println!("== 2. Maker-funded edge, timeout close ==");
    println!("genesis: maker coin=70, taker contributes no coin but signs the open");

    let event = apply_one(&mut state, &verifier, open_context, open);
    let opened = state.store().edge(edge_id).expect("open inserted edge");
    println!(
        "open @{}: {}",
        open_context.block_height().get(),
        summarize(&event)
    );
    println!(
        "  funding 70 -> principal {}, reserve {} (open fee {}, lifetime fee {})",
        opened.value(),
        opened.reserve(),
        open_fee,
        lifetime_fee,
    );

    let close = Tx::close(edge_id, Proof::timeout(terms, None), timeout_outputs);
    let close_fee = schedule_fee(opened.close_fees(), close.cost());
    let event = apply_one(&mut state, &verifier, close_context, close);
    println!(
        "timeout close @{}: {}",
        close_context.block_height().get(),
        summarize(&event),
    );
    println!("  close fee {close_fee} paid from reserve; surplus returns through timeout terms");
    print_live_coins(state.store());
}

fn signed_open(wallets: &Wallets, funding: Funding, terms: Terms) -> Tx {
    let hash = Tx::open_hash(support::NETWORK, &funding, &terms);
    Tx::open(
        funding,
        terms,
        PartyAuth::owner(Auth::native(secp_sign(&wallets.maker_secret, hash))),
        PartyAuth::owner(Auth::native(secp_sign(&wallets.taker_secret, hash))),
    )
}

fn signed_mutual_close(
    wallets: &Wallets,
    edge_id: EdgeId,
    terms_hash: TermsHash,
    outputs: List<Payout, MAX_EDGE_OUTPUTS>,
) -> Tx {
    let hash = Tx::payload_hash(
        support::NETWORK,
        edge_id,
        CloseKind::Mutual,
        terms_hash,
        &outputs,
    );
    Tx::close(
        edge_id,
        Proof::mutual(
            PartyAuth::owner(Auth::native(secp_sign(&wallets.maker_secret, hash))),
            PartyAuth::owner(Auth::native(secp_sign(&wallets.taker_secret, hash))),
        ),
        outputs,
    )
}
