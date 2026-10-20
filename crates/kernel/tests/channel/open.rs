use super::*;
use hellas_kernel::PartyKeys;

#[test]
fn open_locks_two_coins_into_one_edge() {
    let mut state = funded_state();
    let event = apply(
        &mut state,
        &open_tx(funding(MAKER_COIN, TAKER_COIN), basic_terms()),
    );

    assert_eq!(
        event.kind(),
        &EventKind::EdgeOpened {
            inputs: input_ids2(MAKER_COIN, TAKER_COIN),
            output: edge(),
        },
    );
    assert_eq!(state.store().coin(MAKER_COIN), None);
    assert_eq!(state.store().coin(TAKER_COIN), None);
    assert_eq!(
        state.store().edge(edge()).as_ref().map(edge_view),
        Some((15, 0, TIMEOUT, PARTIES, terms())),
    );
}

#[test]
fn open_locks_three_coins_into_one_edge() {
    let funding_value = maker2_funding(MAKER_COIN, EXTRA_COIN, TAKER_COIN);
    let terms_value = terms_paying(10, 8);
    let terms_hash = terms_value.hash();
    let output = Tx::edge_id_of(&funding_value, &terms_value);
    let open = open_tx(funding_value, terms_value);
    let mut state = state(
        store_for(&open),
        [MAKER_SEED, TAKER_SEED, Genesis::coin(EXTRA_COIN, MAKER, 3)],
    );
    let event = apply(&mut state, &open);

    assert_eq!(
        event.kind(),
        &EventKind::EdgeOpened {
            inputs: input_ids3(MAKER_COIN, EXTRA_COIN, TAKER_COIN),
            output,
        },
    );
    assert_eq!(state.store().coin(EXTRA_COIN), None);
    assert_eq!(
        state.store().edge(output).as_ref().map(edge_view),
        Some((18, 0, TIMEOUT, PARTIES, terms_hash)),
    );
}

#[test]
fn open_allows_maker_only_funding() {
    let funding_value = Funding::new(party1(MAKER_COIN), empty_party());
    let terms_value = terms_paying(10, 0);
    let terms_hash = terms_value.hash();
    let output = Tx::edge_id_of(&funding_value, &terms_value);
    let open = open_tx(funding_value, terms_value);
    let mut state = funded_state_for(&open);
    let event = apply(&mut state, &open);

    assert_eq!(
        event.kind(),
        &EventKind::EdgeOpened {
            inputs: input_ids1(MAKER_COIN),
            output,
        },
    );
    assert_eq!(state.store().coin(MAKER_COIN), None);
    assert_eq!(
        state.store().coin(TAKER_COIN).map(coin_view),
        Some((TAKER, 5))
    );
    assert_eq!(
        state.store().edge(output).as_ref().map(edge_view),
        Some((10, 0, TIMEOUT, PARTIES, terms_hash)),
    );
}

#[test]
fn open_allows_taker_only_funding() {
    let funding_value = Funding::new(empty_party(), party1(TAKER_COIN));
    let terms_value = terms_paying(0, 5);
    let terms_hash = terms_value.hash();
    let output = Tx::edge_id_of(&funding_value, &terms_value);
    let open = open_tx(funding_value, terms_value);
    let mut state = funded_state_for(&open);
    let event = apply(&mut state, &open);

    assert_eq!(
        event.kind(),
        &EventKind::EdgeOpened {
            inputs: input_ids1(TAKER_COIN),
            output,
        },
    );
    assert_eq!(
        state.store().coin(MAKER_COIN).map(coin_view),
        Some((MAKER, 10))
    );
    assert_eq!(state.store().coin(TAKER_COIN), None);
    assert_eq!(
        state.store().edge(output).as_ref().map(edge_view),
        Some((5, 0, TIMEOUT, PARTIES, terms_hash)),
    );
}

#[test]
fn open_allows_same_maker_and_taker_party() {
    // Both parties = MAKER. The funding ownership rule now requires every
    // coin to be owned by the matching party key, so both coins are seeded
    // as MAKER-owned (using `EXTRA_COIN` as the second slot).
    let parties = Parties::new(PartyKeys::sole(MAKER), PartyKeys::sole(MAKER));
    let outputs = payouts(Payout::new(MAKER, 7), Payout::new(MAKER, 8));
    let terms_value = Terms::basic(PROTOCOL, parties, TIMEOUT, outputs);
    let terms_hash = terms_value.hash();
    let funding_value = funding(MAKER_COIN, EXTRA_COIN);
    let output = Tx::edge_id_of(&funding_value, &terms_value);
    let open = open_tx_with(
        funding_value,
        terms_value,
        (
            hellas_kernel::PartyKeys::sole(MAKER),
            hellas_kernel::Authority::Owner,
        ),
        (
            hellas_kernel::PartyKeys::sole(MAKER),
            hellas_kernel::Authority::Owner,
        ),
    );
    let mut state = state(
        store_for(&open),
        [MAKER_SEED, TAKER_SEED, Genesis::coin(EXTRA_COIN, MAKER, 5)],
    );
    let event = apply(&mut state, &open);

    assert_eq!(
        event.kind(),
        &EventKind::EdgeOpened {
            inputs: input_ids2(MAKER_COIN, EXTRA_COIN),
            output,
        },
    );
    assert_eq!(
        state.store().edge(output).as_ref().map(edge_view),
        Some((15, 0, TIMEOUT, parties, terms_hash)),
    );
}

#[test]
fn open_allows_empty_funding_when_fee_is_zero() {
    let funding_value = Funding::new(empty_party(), empty_party());
    let terms_value = terms_with(&no_payouts());
    let terms_hash = terms_value.hash();
    let output = Tx::edge_id_of(&funding_value, &terms_value);
    let open = open_tx(funding_value, terms_value);
    let mut state = funded_state_for(&open);
    let event = apply(&mut state, &open);

    assert_eq!(
        event.kind(),
        &EventKind::EdgeOpened {
            inputs: input_ids0(),
            output,
        },
    );
    assert_eq!(
        state.store().coin(MAKER_COIN).map(coin_view),
        Some((MAKER, 10)),
    );
    assert_eq!(
        state.store().coin(TAKER_COIN).map(coin_view),
        Some((TAKER, 5)),
    );
    assert_eq!(
        state.store().edge(output).as_ref().map(edge_view),
        Some((0, 0, TIMEOUT, PARTIES, terms_hash)),
    );
}

#[test]
fn open_pays_fee_from_funding() {
    let terms_value = terms_paying(4, 5);
    let terms_hash = terms_value.hash();
    let funding_value = funding(MAKER_COIN, TAKER_COIN);
    let output = Tx::edge_id_of(&funding_value, &terms_value);
    let open = open_tx(funding_value, terms_value);
    let mut state = state(store_for(&open), [MAKER_SEED, TAKER_SEED]);
    let Ok(outcome) = state.apply(FEE_CONTEXT, &FAKE_VERIFIER, &open) else {
        panic!("operation rejected");
    };
    let Some(event) = outcome.public_event() else {
        panic!("an open applied without announcing itself");
    };

    assert_eq!(
        event.kind(),
        &EventKind::EdgeOpened {
            inputs: input_ids2(MAKER_COIN, TAKER_COIN),
            output,
        },
    );
    assert_eq!(
        state.store().edge(output).as_ref().map(edge_view),
        Some((9, 3, TIMEOUT, PARTIES, terms_hash)),
    );
}

#[test]
fn open_fee_uses_resource_cost() {
    let terms_value = terms_paying(14, 13);
    let terms_hash = terms_value.hash();
    let funding_value = funding(MAKER_COIN, TAKER_COIN);
    let output = Tx::edge_id_of(&funding_value, &terms_value);
    let open = open_tx(funding_value, terms_value);
    let mut state = state(
        store_for(&open),
        [
            Genesis::coin(MAKER_COIN, MAKER, 30),
            Genesis::coin(TAKER_COIN, TAKER, 20),
        ],
    );
    let cost = open.cost();
    let reserve_cost = reserve_cost_for(output);
    let lifetime_fee = lifetime_fee_for(RESOURCE_CONTEXT, TIMEOUT);
    let Ok(outcome) = state.apply(RESOURCE_CONTEXT, &FAKE_VERIFIER, &open) else {
        panic!("operation rejected");
    };
    let Some(event) = outcome.public_event() else {
        panic!("an open applied without announcing itself");
    };

    assert_eq!(
        event.kind(),
        &EventKind::EdgeOpened {
            inputs: input_ids2(MAKER_COIN, TAKER_COIN),
            output,
        },
    );
    assert_eq!(RESOURCE_CONTEXT.fee(cost), Some(10));
    assert_eq!(RESOURCE_CONTEXT.fee(reserve_cost), Some(16));
    assert_eq!(lifetime_fee, Some(3));
    assert_eq!(
        state.store().edge(output).as_ref().map(edge_view),
        Some((21, 16, TIMEOUT, PARTIES, terms_hash)),
    );
}

#[test]
fn open_lifetime_fee_scales_with_timeout_span() {
    let lifetime_priced = Context::with_fees(
        crate::support::NETWORK,
        BlockHeight::new(1),
        BlockHash::from_bytes([0; BlockHash::LENGTH]),
        Fees::new(0, 1, 0, 1),
    );
    let funding_value = funding(MAKER_COIN, TAKER_COIN);
    let short_timeout = BlockHeight::new(2);
    let short_outputs = payouts(Payout::new(MAKER, 12), Payout::new(TAKER, 11));
    let short_terms = terms_with_timeout(short_timeout, &short_outputs);
    let short_hash = short_terms.hash();
    let short_output = Tx::edge_id_of(&funding_value, &short_terms);
    let short_open = open_tx(funding_value.clone(), short_terms);
    let long_timeout = BlockHeight::new(4);
    let long_outputs = payouts(Payout::new(MAKER, 11), Payout::new(TAKER, 10));
    let long_terms = terms_with_timeout(long_timeout, &long_outputs);
    let long_hash = long_terms.hash();
    let long_output = Tx::edge_id_of(&funding_value, &long_terms);
    let long_open = open_tx(funding_value, long_terms);

    let mut short_state = state(
        store_for(&short_open),
        [
            Genesis::coin(MAKER_COIN, MAKER, 20),
            Genesis::coin(TAKER_COIN, TAKER, 10),
        ],
    );
    let mut long_state = state(
        store_for(&long_open),
        [
            Genesis::coin(MAKER_COIN, MAKER, 20),
            Genesis::coin(TAKER_COIN, TAKER, 10),
        ],
    );

    let _event = apply_with(&mut short_state, lifetime_priced, &short_open);
    let _event = apply_with(&mut long_state, lifetime_priced, &long_open);

    assert_eq!(lifetime_priced.fee(short_open.cost()), Some(3));
    assert_eq!(lifetime_priced.fee(reserve_cost_for(short_output)), Some(5));
    assert_eq!(lifetime_fee_for(lifetime_priced, short_timeout), Some(1));
    assert_eq!(lifetime_fee_for(lifetime_priced, long_timeout), Some(3));
    assert_eq!(
        short_state
            .store()
            .edge(short_output)
            .as_ref()
            .map(edge_view),
        Some((21, 5, short_timeout, PARTIES, short_hash)),
    );
    assert_eq!(
        long_state.store().edge(long_output).as_ref().map(edge_view),
        Some((19, 5, long_timeout, PARTIES, long_hash)),
    );
}

#[test]
fn open_allows_exact_fee_and_reserve_funding() {
    let terms_value = terms_paying(6, 0);
    let terms_hash = terms_value.hash();
    let funding_value = funding(MAKER_COIN, TAKER_COIN);
    let output = Tx::edge_id_of(&funding_value, &terms_value);
    let open = open_tx(funding_value, terms_value);
    let cost = open.cost();
    let reserve_cost = reserve_cost_for(output);
    let lifetime_fee = lifetime_fee_for(RESOURCE_CONTEXT, TIMEOUT);
    let mut state = state(
        store_for(&open),
        [
            Genesis::coin(MAKER_COIN, MAKER, 23),
            Genesis::coin(TAKER_COIN, TAKER, 6),
        ],
    );
    let event = apply_with(&mut state, RESOURCE_CONTEXT, &open);

    assert_eq!(
        event.kind(),
        &EventKind::EdgeOpened {
            inputs: input_ids2(MAKER_COIN, TAKER_COIN),
            output,
        },
    );
    assert_eq!(RESOURCE_CONTEXT.fee(cost), Some(10));
    assert_eq!(RESOURCE_CONTEXT.fee(reserve_cost), Some(16));
    assert_eq!(lifetime_fee, Some(3));
    assert_eq!(
        state.store().edge(output).as_ref().map(edge_view),
        Some((0, 16, TIMEOUT, PARTIES, terms_hash)),
    );
}

#[test]
fn open_rejects_nonfuture_timeout_without_mutation() {
    let terms_value = Terms::basic(PROTOCOL, PARTIES, CONTEXT.block_height(), l1::payouts());
    let funding_value = funding(MAKER_COIN, TAKER_COIN);
    let output = Tx::edge_id_of(&funding_value, &terms_value);
    let open = open_tx(funding_value, terms_value);
    let mut state = funded_state_for(&open);
    let store = *state.store();

    assert_eq!(
        state.apply(CONTEXT, &FAKE_VERIFIER, &open),
        Err(ApplyError::InvalidOpen {
            output,
            reason: InvalidOpenReason::TimeoutNotFuture,
        }),
    );
    assert_eq!(*state.store(), store);
}

#[test]
fn open_rejects_terms_that_exceed_net_principal_without_mutation() {
    let funding_value = funding(MAKER_COIN, TAKER_COIN);
    let terms_value = terms_paying(7, 9);
    let output = Tx::edge_id_of(&funding_value, &terms_value);
    let open = open_tx(funding_value, terms_value);
    let mut state = funded_state_for(&open);
    let store = *state.store();

    assert_eq!(
        state.apply(CONTEXT, &FAKE_VERIFIER, &open),
        Err(ApplyError::InvalidOpen {
            output,
            reason: InvalidOpenReason::TermsValueMismatch,
        }),
    );
    assert_eq!(*state.store(), store);
}

#[test]
fn open_rejects_terms_with_overflowing_payouts_without_mutation() {
    let outputs = payouts(Payout::new(MAKER, u64::MAX), Payout::new(TAKER, 1));
    let terms_value = terms_with(&outputs);
    let funding_value = funding(MAKER_COIN, TAKER_COIN);
    let output = Tx::edge_id_of(&funding_value, &terms_value);
    let open = open_tx(funding_value, terms_value);
    let mut state = funded_state_for(&open);
    let store = *state.store();

    assert_eq!(
        state.apply(CONTEXT, &FAKE_VERIFIER, &open),
        Err(ApplyError::InvalidOpen {
            output,
            reason: InvalidOpenReason::TermsPayoutOverflow,
        }),
    );
    assert_eq!(*state.store(), store);
}

#[test]
fn open_rejects_funding_below_fee_and_reserve_without_mutation() {
    let open = open_op();
    let output = open_edge_id(&open);
    let cost = open.cost();
    let reserve_cost = reserve_cost_for(output);
    let mut state = state(
        empty_store(),
        [
            Genesis::coin(MAKER_COIN, MAKER, 20),
            Genesis::coin(TAKER_COIN, TAKER, 5),
        ],
    );
    let store = *state.store();

    assert_eq!(RESOURCE_CONTEXT.fee(cost), Some(10));
    assert_eq!(RESOURCE_CONTEXT.fee(reserve_cost), Some(16));
    assert_eq!(lifetime_fee_for(RESOURCE_CONTEXT, TIMEOUT), Some(3));
    assert_eq!(
        state.apply(RESOURCE_CONTEXT, &FAKE_VERIFIER, &open),
        Err(ApplyError::InvalidOpen {
            output,
            reason: InvalidOpenReason::FundingInsufficient,
        }),
    );
    assert_eq!(*state.store(), store);
}

#[test]
fn open_rejects_funding_below_fee_without_mutation() {
    let funding_value = Funding::new(empty_party(), empty_party());
    let output = Tx::edge_id_of(&funding_value, &basic_terms());
    let open = open_tx(funding_value, basic_terms());
    let mut state = funded_state();
    let store = *state.store();

    assert_eq!(
        state.apply(FEE_CONTEXT, &FAKE_VERIFIER, &open),
        Err(ApplyError::InvalidOpen {
            output,
            reason: InvalidOpenReason::FundingInsufficient,
        }),
    );
    assert_eq!(*state.store(), store);
}

#[test]
fn open_rejects_missing_funding_coin_without_mutation() {
    // EXTRA_COIN has a store slot but was never seeded, so validation
    // fails coin lookup before any ownership or signature work.
    let open = open_tx(funding(MAKER_COIN, EXTRA_COIN), basic_terms());
    let mut state = funded_state_for(&open);
    let store = *state.store();

    assert_eq!(
        state.apply(CONTEXT, &FAKE_VERIFIER, &open),
        Err(ApplyError::MissingCoin { id: EXTRA_COIN }),
    );
    assert_eq!(*state.store(), store);
}

#[test]
fn open_rejects_replayed_open_while_edge_lives() {
    // Replaying the exact open hits the edge-occupancy check first —
    // it fires before the (also failing) consumed-funding lookup.
    let mut state = open_state();
    let store = *state.store();

    assert_eq!(
        state.apply(CONTEXT, &FAKE_VERIFIER, &open_op()),
        Err(ApplyError::EdgeExists { id: edge() }),
    );
    assert_eq!(*state.store(), store);
}

#[test]
fn open_rejects_duplicate_funding_without_mutation() {
    let mut state = funded_state();
    let store = *state.store();

    assert_eq!(
        state.apply(
            CONTEXT,
            &FAKE_VERIFIER,
            &open_tx(
                Funding::new(party1(MAKER_COIN), party1(MAKER_COIN)),
                basic_terms(),
            ),
        ),
        Err(ApplyError::DuplicateInput { id: MAKER_COIN }),
    );
    assert_eq!(*state.store(), store);
}

#[test]
fn open_rejects_unavailable_edge_without_mutation() {
    let mut state = state(coin_store(), [MAKER_SEED, TAKER_SEED]);
    let store = *state.store();

    assert_eq!(
        state.apply(
            CONTEXT,
            &FAKE_VERIFIER,
            &open_tx(funding(MAKER_COIN, TAKER_COIN), basic_terms()),
        ),
        Err(ApplyError::EdgeInsertRejected {
            id: edge(),
            reason: InsertError::Unavailable,
        }),
    );
    assert_eq!(*state.store(), store);
}

#[test]
fn open_rejects_overflow_without_mutation() {
    let mut state = state(
        empty_store(),
        [
            Genesis::coin(MAKER_COIN, MAKER, u64::MAX),
            Genesis::coin(TAKER_COIN, TAKER, 1),
        ],
    );
    let store = *state.store();

    assert_eq!(
        state.apply(
            CONTEXT,
            &FAKE_VERIFIER,
            &open_tx(funding(MAKER_COIN, TAKER_COIN), basic_terms()),
        ),
        Err(ApplyError::InvalidOpen {
            output: edge(),
            reason: InvalidOpenReason::FundingOverflow,
        }),
    );
    assert_eq!(*state.store(), store);
}

/// Worst-case close cost reserved at open-time. Mirrors `apply_open`'s
/// `reserve_cost`: `MAX_EDGE_OUTPUTS` payouts under `Mutual` (the proof
/// kind charging the most proof units).
fn reserve_cost_for(edge: EdgeId) -> Cost {
    Tx::close(edge, mutual_proof(edge, &payouts4()), payouts4()).cost()
}

// ---------------------------------------------------------------------
// Authorization
//
// `Tx::Open` consumes coins. Each coin is owner-keyed; opening an edge
// must require consent from each consumed coin's owner. Without that,
// any party who knows live coin ids can lock them into terms of their
// choosing and drain them via a structural Timeout close at the
// committed height.
//
// The tests below construct unauthorized opens — opens where the coins
// being consumed are owned by keys distinct from the claimed party
// identities, with no signature binding consent — and assert the kernel
// rejects them. They demonstrate the security property the open path
// must enforce.
// ---------------------------------------------------------------------

const EVE: Key = Key::from_bytes([0xee; Key::LENGTH]);
const EVE_PARTIES: Parties = Parties::new(PartyKeys::sole(EVE), PartyKeys::sole(EVE));

fn eve_terms() -> Terms {
    Terms::basic(
        PROTOCOL,
        EVE_PARTIES,
        TIMEOUT,
        payouts(Payout::new(EVE, 7), Payout::new(EVE, 8)),
    )
}

#[test]
fn open_rejects_funding_owned_by_other_keys() {
    // Eve constructs an Open consuming Maker's + Taker's coins while
    // naming herself as both parties. Without an authorization check,
    // the kernel accepts this; a subsequent timeout close at the
    // committed height pays everything to Eve.
    let funding = funding(MAKER_COIN, TAKER_COIN);
    // Eve constructs sigs over EVE/EVE (the parties she names). She
    // cannot produce Maker's or Taker's signature, so any choice she
    // makes here is unauthenticated; the funding ownership check fires
    // first regardless.
    let attack = open_tx_with(
        funding,
        eve_terms(),
        (
            hellas_kernel::PartyKeys::sole(EVE),
            hellas_kernel::Authority::Owner,
        ),
        (
            hellas_kernel::PartyKeys::sole(EVE),
            hellas_kernel::Authority::Owner,
        ),
    );
    let mut state = funded_state_for(&attack);
    let output = open_edge_id(&attack);
    let store = *state.store();

    assert_eq!(
        state.apply(CONTEXT, &FAKE_VERIFIER, &attack),
        Err(ApplyError::InvalidOpen {
            output,
            reason: InvalidOpenReason::FundingUnauthorized,
        }),
    );
    assert_eq!(*state.store(), store);
}

#[test]
fn open_rejects_terms_party_that_does_not_own_funding() {
    // The taker is honest (TAKER owns TAKER_COIN), but the "maker"
    // party in the terms is Eve. Even if Eve signs the open as the
    // named maker, she cannot move Maker's coin into those terms.
    let funding = funding(MAKER_COIN, TAKER_COIN);
    let mixed_terms = Terms::basic(
        PROTOCOL,
        Parties::new(PartyKeys::sole(EVE), PartyKeys::sole(TAKER)),
        TIMEOUT,
        payouts(Payout::new(EVE, 10), Payout::new(TAKER, 5)),
    );
    let attack = open_tx_with(
        funding,
        mixed_terms,
        (
            hellas_kernel::PartyKeys::sole(EVE),
            hellas_kernel::Authority::Owner,
        ),
        (
            hellas_kernel::PartyKeys::sole(TAKER),
            hellas_kernel::Authority::Owner,
        ),
    );
    let mut state = funded_state_for(&attack);
    let output = open_edge_id(&attack);
    let store = *state.store();

    assert_eq!(
        state.apply(CONTEXT, &FAKE_VERIFIER, &attack),
        Err(ApplyError::InvalidOpen {
            output,
            reason: InvalidOpenReason::FundingUnauthorized,
        }),
    );
    assert_eq!(*state.store(), store);
}

#[test]
fn open_rejects_wrong_maker_auth_even_when_taker_funds_everything() {
    let funding = Funding::new(empty_party(), party1(TAKER_COIN));
    let terms = terms_paying(0, 5);
    let open = open_tx_with(
        funding,
        terms,
        (
            hellas_kernel::PartyKeys::sole(EVE),
            hellas_kernel::Authority::Owner,
        ),
        (
            hellas_kernel::PartyKeys::sole(TAKER),
            hellas_kernel::Authority::Owner,
        ),
    );
    let mut state = funded_state_for(&open);
    let output = open_edge_id(&open);
    let store = *state.store();

    assert_eq!(
        state.apply(CONTEXT, &FAKE_VERIFIER, &open),
        Err(ApplyError::InvalidOpen {
            output,
            reason: InvalidOpenReason::BadSignature,
        }),
    );
    assert_eq!(*state.store(), store);
}

#[test]
fn open_rejects_wrong_taker_auth_even_when_maker_funds_everything() {
    let funding = Funding::new(party1(MAKER_COIN), empty_party());
    let terms = terms_paying(10, 0);
    let open = open_tx_with(
        funding,
        terms,
        (
            hellas_kernel::PartyKeys::sole(MAKER),
            hellas_kernel::Authority::Owner,
        ),
        (
            hellas_kernel::PartyKeys::sole(EVE),
            hellas_kernel::Authority::Owner,
        ),
    );
    let mut state = funded_state_for(&open);
    let output = open_edge_id(&open);
    let store = *state.store();

    assert_eq!(
        state.apply(CONTEXT, &FAKE_VERIFIER, &open),
        Err(ApplyError::InvalidOpen {
            output,
            reason: InvalidOpenReason::BadSignature,
        }),
    );
    assert_eq!(*state.store(), store);
}

#[test]
fn open_rejects_empty_funding_without_both_party_auth() {
    let funding = Funding::new(empty_party(), empty_party());
    let terms = terms_with(&no_payouts());
    let open = open_tx_with(
        funding,
        terms,
        (
            hellas_kernel::PartyKeys::sole(MAKER),
            hellas_kernel::Authority::Owner,
        ),
        (
            hellas_kernel::PartyKeys::sole(EVE),
            hellas_kernel::Authority::Owner,
        ),
    );
    let mut state = funded_state_for(&open);
    let output = open_edge_id(&open);
    let store = *state.store();

    assert_eq!(
        state.apply(CONTEXT, &FAKE_VERIFIER, &open),
        Err(ApplyError::InvalidOpen {
            output,
            reason: InvalidOpenReason::BadSignature,
        }),
    );
    assert_eq!(*state.store(), store);
}
