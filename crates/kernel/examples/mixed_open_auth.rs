//! Mixed native/WebAuthn open authorization.
//!
//! This example opens one maker-funded edge with:
//!
//! - maker authorization as a native secp256k1 signature over `Tx::open_hash`;
//! - taker authorization as a `WebAuthn` assertion whose challenge is the same
//!   canonical open hash.
//!
//! The taker contributes no funding coin, but still signs as the taker party.
//! That is the one-key rule at the API boundary: funding ownership, terms party,
//! and open authorization all use the same kernel `Key` space.
//!
//! The bundled `Secp256k1Verifier` accepts this shape when both `secp256k1`
//! and `webauthn` are enabled. The example closes by timeout, because a
//! passkey-backed party does not have a portable raw close-signature path in
//! the bundled verifier.
//!
//! Build and run with:
//!
//! ```sh
//! cargo run --example mixed_open_auth --features secp256k1,webauthn
//! ```

#![allow(clippy::alloc_instead_of_core)]
#![allow(clippy::disallowed_types)]
#![allow(clippy::expect_used)]
#![allow(clippy::print_stdout)]
#![allow(clippy::similar_names)]
#![allow(clippy::std_instead_of_alloc)]
#![allow(clippy::std_instead_of_core)]
#![allow(clippy::indexing_slicing)] // tests may index; the panic-freedom lock targets src

mod support;

use hellas_kernel::{
    Auth, BlockHeight, CloseKind, Fees, Funding, Genesis, Parties, PartyAuth, PartyKeys, Proof,
    ProtocolCode, Secp256k1Verifier, SoftPasskey, Terms, Tx,
};
use support::{
    apply_one, coin_id, context, context_fee, empty_party, genesis, lifetime_fee, party_one,
    payouts2, print_live_coins, schedule_fee, secp_keypair, secp_sign, summarize,
};

const FEES: Fees = Fees::new(1, 1, 2, 1);
const PROTOCOL: ProtocolCode = ProtocolCode::new(1);

fn main() {
    let verifier = Secp256k1Verifier::new();
    let (maker_secret, maker_key) = secp_keypair(3);
    let taker_passkey = SoftPasskey::from_secret_scalar([4; 32]).expect("fixture scalar is valid");
    let taker_key = taker_passkey.party_key();

    let maker_coin = coin_id(0xc1);
    let open_context = context(1, 0x30, FEES);
    // Mutual closes are pre-expiry: the close happens strictly before the
    // committed timeout height.
    let close_context = context(3, 0x31, FEES);
    let timeout = BlockHeight::new(5);
    let terms = Terms::basic(
        PROTOCOL,
        Parties::new(PartyKeys::sole(maker_key), PartyKeys::sole(taker_key)),
        timeout,
        payouts2(maker_key, 31, taker_key, 16),
    );
    let funding = Funding::new(party_one(maker_coin), empty_party());
    let edge_id = Tx::edge_id_of(&funding, &terms);
    let open_hash = Tx::open_hash(support::NETWORK, &funding, &terms);
    let taker_assertion = taker_passkey
        .sign(open_hash)
        .expect("fixture signing succeeds");

    let open = Tx::open(
        funding,
        terms.clone(),
        PartyAuth::owner(Auth::native(secp_sign(&maker_secret, open_hash))),
        PartyAuth::owner(Auth::webauthn(taker_assertion)),
    );
    let open_fee = context_fee(open_context, open.cost());
    let lifetime_fee = lifetime_fee(open_context, timeout);
    let mut state = genesis(&[Genesis::coin(maker_coin, maker_key, 60)]);

    println!("== Hellas mixed auth ==");
    println!("maker: native secp256k1 auth");
    println!("taker: WebAuthn passkey auth (P-256), no funding input");

    let event = apply_one(&mut state, &verifier, open_context, open);
    let opened = state.store().edge(edge_id).expect("open inserted edge");
    println!();
    println!(
        "open @{}: {}",
        open_context.block_height().get(),
        summarize(&event),
    );
    println!(
        "  maker funding 60 -> principal {}, reserve {} (open fee {}, lifetime fee {})",
        opened.value(),
        opened.reserve(),
        open_fee,
        lifetime_fee,
    );

    // Renegotiated cooperative split: principal plus the reserve surplus
    // left after the committed mutual-close fee. The passkey authorizes
    // the close payload hash the same way it authorized the open.
    let mutual_outputs = payouts2(maker_key, 30, taker_key, 15);
    let close_hash = Tx::payload_hash(
        support::NETWORK,
        edge_id,
        CloseKind::Mutual,
        terms.hash(),
        &mutual_outputs,
    );
    let taker_close_assertion = taker_passkey
        .sign(close_hash)
        .expect("fixture signing succeeds");
    let close = Tx::close(
        edge_id,
        Proof::mutual(
            PartyAuth::owner(Auth::native(secp_sign(&maker_secret, close_hash))),
            PartyAuth::owner(Auth::webauthn(taker_close_assertion)),
        ),
        mutual_outputs,
    );
    let close_fee = schedule_fee(opened.close_fees(), close.cost());
    let event = apply_one(&mut state, &verifier, close_context, close);
    println!(
        "mutual close @{}: {}",
        close_context.block_height().get(),
        summarize(&event),
    );
    println!("  close fee {close_fee} paid from reserve; both parties authorized the new split");
    print_live_coins(state.store());
}
