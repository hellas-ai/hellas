use super::*;
use hellas_kernel::PartyAuth;

#[test]
fn close_zero_edge_without_outputs() {
    let terms_value = terms_with(&no_payouts());
    let funding_value = Funding::new(empty_party(), empty_party());
    let edge = Tx::edge_id_of(&funding_value, &terms_value);
    let open = open_tx(funding_value, terms_value.clone());
    let mut state = funded_state_for(&open);
    let _event = apply(&mut state, &open);
    let event = apply_with(
        &mut state,
        TIMEOUT_CONTEXT,
        &Tx::close(edge, Proof::timeout(terms_value, None), no_payouts()),
    );

    assert_eq!(
        event.kind(),
        &EventKind::EdgeClosed {
            input: edge,
            outputs: output_ids0(),
        },
    );
    assert_eq!(state.store().edge(edge), None);
    assert_eq!(
        state.store().coin(MAKER_COIN).map(coin_view),
        Some((MAKER, 10)),
    );
    assert_eq!(
        state.store().coin(TAKER_COIN).map(coin_view),
        Some((TAKER, 5)),
    );
}

#[test]
fn close_spends_edge_into_two_payout_coins() {
    let mut state = open_state();
    let event = apply_with(
        &mut state,
        TIMEOUT_CONTEXT,
        &Tx::close(
            edge(),
            proof(),
            payouts(Payout::new(MAKER, 7), Payout::new(TAKER, 8)),
        ),
    );

    assert_eq!(
        event.kind(),
        &EventKind::EdgeClosed {
            input: edge(),
            outputs: output_ids2(maker_out(), taker_out()),
        },
    );
    assert_eq!(state.store().edge(edge()), None);
    assert_eq!(
        state.store().coin(maker_out()).map(coin_view),
        Some((MAKER, 7))
    );
    assert_eq!(
        state.store().coin(taker_out()).map(coin_view),
        Some((TAKER, 8)),
    );
}

#[test]
fn close_uses_prepaid_reserve() {
    let outputs = payouts(Payout::new(MAKER, 14), Payout::new(TAKER, 13));
    let terms_value = terms_with(&outputs);
    let funding_value = funding(MAKER_COIN, TAKER_COIN);
    let edge = Tx::edge_id_of(&funding_value, &terms_value);
    let open = open_tx(funding_value, terms_value.clone());
    let close = Tx::close(edge, Proof::timeout(terms_value, None), outputs.clone());
    let output_ids = Tx::close_output_ids(edge, &outputs);
    let maker_out = nth(&output_ids, 0);
    let taker_out = nth(&output_ids, 1);
    let mut state = state(
        store_for_close(&open, &outputs),
        [
            Genesis::coin(MAKER_COIN, MAKER, 30),
            Genesis::coin(TAKER_COIN, TAKER, 20),
        ],
    );
    let Some(open_fee) = RESOURCE_CONTEXT.fee(open.cost()) else {
        panic!("open fee overflow");
    };
    let Some(lifetime_fee) = lifetime_fee_for(RESOURCE_CONTEXT, TIMEOUT) else {
        panic!("lifetime fee overflow");
    };
    let Some(reserve) = RESOURCE_CONTEXT.fee(worst_case_close_cost(edge)) else {
        panic!("reserve fee overflow");
    };
    let Some(committed_close_fee) = RESOURCE_CONTEXT.fee(close.cost()) else {
        panic!("committed close fee overflow");
    };
    let _event = apply_with(&mut state, RESOURCE_CONTEXT, &open);
    let event = apply_with(&mut state, TIMEOUT_CONTEXT, &close);

    assert_eq!(
        event.kind(),
        &EventKind::EdgeClosed {
            input: edge,
            outputs: output_ids2(maker_out, taker_out),
        },
    );
    assert_eq!(state.store().edge(edge), None);
    assert_eq!(
        state.store().coin(maker_out).map(coin_view),
        Some((MAKER, 14)),
    );
    assert_eq!(
        state.store().coin(taker_out).map(coin_view),
        Some((TAKER, 13)),
    );
    assert_eq!(14 + 13 + open_fee + lifetime_fee + committed_close_fee, 50);
    assert_eq!(reserve - committed_close_fee, 6);
}

#[test]
fn close_has_no_marginal_fee_after_zero_fee_open() {
    let mut state = open_state();
    let close = Tx::close(
        edge(),
        proof(),
        payouts(Payout::new(MAKER, 7), Payout::new(TAKER, 8)),
    );
    let event = apply_with(&mut state, RESOURCE_TIMEOUT_CONTEXT, &close);

    assert_eq!(
        event.kind(),
        &EventKind::EdgeClosed {
            input: edge(),
            outputs: output_ids2(maker_out(), taker_out()),
        },
    );
    assert_eq!(state.store().edge(edge()), None);
}

#[test]
fn close_accepts_when_current_fee_exceeds_open_reserve() {
    let cheap = Context::with_fees(
        crate::support::NETWORK,
        BlockHeight::new(1),
        BlockHash::from_bytes([0; BlockHash::LENGTH]),
        Fees::new(0, 0, 1, 0),
    );
    let expensive = Context::with_fees(
        crate::support::NETWORK,
        TIMEOUT,
        BlockHash::from_bytes([0; BlockHash::LENGTH]),
        Fees::new(0, 0, 3, 0),
    );
    let outputs = payouts(Payout::new(MAKER, 15), Payout::new(TAKER, 14));
    let terms_value = terms_with(&outputs);
    let terms_hash = terms_value.hash();
    let funding_value = funding(MAKER_COIN, TAKER_COIN);
    let edge = Tx::edge_id_of(&funding_value, &terms_value);
    let open = open_tx(funding_value, terms_value.clone());
    let reserve_cost = worst_case_close_cost(edge);
    let mut state = state(
        store_for_close(&open, &outputs),
        [
            // 32 funds the open's two proof units, the 2-unit
            // reserve, and the 28 the edge locks.
            Genesis::coin(MAKER_COIN, MAKER, 22),
            Genesis::coin(TAKER_COIN, TAKER, 10),
        ],
    );
    let _event = apply_with(&mut state, cheap, &open);
    let close = Tx::close(edge, Proof::timeout(terms_value, None), outputs.clone());
    let close_cost = close.cost();
    let output_ids = Tx::close_output_ids(edge, &outputs);
    let maker_out = nth(&output_ids, 0);
    let taker_out = nth(&output_ids, 1);

    assert_eq!(cheap.fee(reserve_cost), Some(2));
    assert_eq!(
        state.store().edge(edge).as_ref().map(edge_view),
        Some((28, 2, TIMEOUT, PARTIES, terms_hash)),
    );
    assert_eq!(expensive.fee(close_cost), Some(3));
    let event = apply_with(&mut state, expensive, &close);

    assert_eq!(
        event.kind(),
        &EventKind::EdgeClosed {
            input: edge,
            outputs: output_ids2(maker_out, taker_out),
        },
    );
    assert_eq!(state.store().edge(edge), None);
    assert_eq!(
        state.store().coin(maker_out).map(coin_view),
        Some((MAKER, 15)),
    );
    assert_eq!(
        state.store().coin(taker_out).map(coin_view),
        Some((TAKER, 14)),
    );
}

#[test]
fn close_surplus_uses_selected_close_kind() {
    let proof_priced = Context::with_fees(
        crate::support::NETWORK,
        BlockHeight::new(1),
        BlockHash::from_bytes([0; BlockHash::LENGTH]),
        Fees::new(0, 0, 1, 0),
    );
    let timeout_outputs = payouts(Payout::new(MAKER, 15), Payout::new(TAKER, 14));
    let terms_value = terms_with(&timeout_outputs);
    let funding_value = funding(MAKER_COIN, TAKER_COIN);
    let edge = Tx::edge_id_of(&funding_value, &terms_value);
    let terms_hash = terms_value.hash();
    let open = open_tx(funding_value, terms_value);
    let mutual_outputs = payouts(Payout::new(MAKER, 14), Payout::new(TAKER, 14));
    let close = Tx::close(
        edge,
        support::placeholder_mutual(edge, terms_hash, &mutual_outputs, MAKER, TAKER),
        mutual_outputs.clone(),
    );
    let output_ids = Tx::close_output_ids(edge, &mutual_outputs);
    let maker_out = nth(&output_ids, 0);
    let taker_out = nth(&output_ids, 1);
    let mut state = state(
        store_for_close(&open, &mutual_outputs),
        [
            Genesis::coin(MAKER_COIN, MAKER, 22),
            Genesis::coin(TAKER_COIN, TAKER, 10),
        ],
    );
    let _event = apply_with(&mut state, proof_priced, &open);
    let event = apply_with(&mut state, proof_priced, &close);

    assert_eq!(
        event.kind(),
        &EventKind::EdgeClosed {
            input: edge,
            outputs: output_ids2(maker_out, taker_out),
        },
    );
    assert_eq!(
        state.store().coin(maker_out).map(coin_view),
        Some((MAKER, 14)),
    );
    assert_eq!(
        state.store().coin(taker_out).map(coin_view),
        Some((TAKER, 14)),
    );
}

#[test]
fn close_accepts_mutual_witness() {
    let mut state = open_state();
    let outputs = payouts(Payout::new(MAKER, 7), Payout::new(TAKER, 8));
    let event = apply(
        &mut state,
        &Tx::close(edge(), mutual_proof(edge(), &outputs), outputs),
    );

    assert_eq!(
        event.kind(),
        &EventKind::EdgeClosed {
            input: edge(),
            outputs: output_ids2(maker_out(), taker_out()),
        },
    );
    assert_eq!(state.store().edge(edge()), None);
    assert_eq!(
        state.store().coin(maker_out()).map(coin_view),
        Some((MAKER, 7))
    );
    assert_eq!(
        state.store().coin(taker_out()).map(coin_view),
        Some((TAKER, 8)),
    );
}

#[test]
fn close_rejects_mutual_after_deadline_without_mutation() {
    let mut state = open_state();
    let store = *state.store();
    let outputs = payouts(Payout::new(MAKER, 7), Payout::new(TAKER, 8));

    assert_eq!(
        state.apply(
            TIMEOUT_CONTEXT,
            &FAKE_VERIFIER,
            &Tx::close(edge(), mutual_proof(edge(), &outputs), outputs),
        ),
        Err(ApplyError::InvalidProof {
            input: edge(),
            reason: InvalidProofReason::ProofExpired,
        }),
    );
    assert_eq!(*state.store(), store);
}

#[test]
fn close_rejects_bad_mutual_signature_without_mutation() {
    let mut state = open_state();
    let store = *state.store();
    let outputs = payouts(Payout::new(MAKER, 7), Payout::new(TAKER, 8));
    // Maker's witness authorizes the wrong payload (other terms); taker's
    // is canonical. One bad witness fails the whole mutual close.
    let bad_hash = Tx::payload_hash(
        crate::support::NETWORK,
        edge(),
        CloseKind::Mutual,
        other_terms(),
        &outputs,
    );
    let proof = Proof::mutual(
        PartyAuth::owner(Auth::native(Sig::placeholder(MAKER, bad_hash))),
        PartyAuth::owner(Auth::native(Sig::placeholder(
            TAKER,
            mutual_hash(edge(), &outputs),
        ))),
    );

    assert_eq!(
        state.apply(CONTEXT, &FAKE_VERIFIER, &Tx::close(edge(), proof, outputs),),
        Err(ApplyError::InvalidProof {
            input: edge(),
            reason: InvalidProofReason::BadSignature,
        }),
    );
    assert_eq!(*state.store(), store);
}

#[test]
fn close_accepts_timeout_witness_at_deadline() {
    let mut state = open_state();
    let event = apply_with(
        &mut state,
        TIMEOUT_CONTEXT,
        &Tx::close(
            edge(),
            Proof::timeout(basic_terms(), None),
            payouts(Payout::new(MAKER, 7), Payout::new(TAKER, 8)),
        ),
    );

    assert_eq!(
        event.kind(),
        &EventKind::EdgeClosed {
            input: edge(),
            outputs: output_ids2(maker_out(), taker_out()),
        },
    );
    assert_eq!(state.store().edge(edge()), None);
}

#[test]
fn close_rejects_timeout_before_deadline_without_mutation() {
    let mut state = open_state();
    let store = *state.store();

    assert_eq!(
        state.apply(
            CONTEXT,
            &FAKE_VERIFIER,
            &Tx::close(
                edge(),
                Proof::timeout(basic_terms(), None),
                payouts(Payout::new(MAKER, 7), Payout::new(TAKER, 8)),
            ),
        ),
        Err(ApplyError::InvalidProof {
            input: edge(),
            reason: InvalidProofReason::TimeoutNotReached,
        }),
    );
    assert_eq!(*state.store(), store);
}

#[test]
fn close_rejects_timeout_with_nondefault_payouts_without_mutation() {
    let mut state = open_state();
    let store = *state.store();

    assert_eq!(
        state.apply(
            TIMEOUT_CONTEXT,
            &FAKE_VERIFIER,
            &Tx::close(
                edge(),
                Proof::timeout(basic_terms(), None),
                payouts(Payout::new(MAKER, 8), Payout::new(TAKER, 7)),
            ),
        ),
        Err(ApplyError::InvalidProof {
            input: edge(),
            reason: InvalidProofReason::PayoutMismatch,
        }),
    );
    assert_eq!(*state.store(), store);
}

#[test]
fn close_rejects_wrong_timeout_terms_without_mutation() {
    let mut state = open_state();
    let store = *state.store();

    assert_eq!(
        state.apply(
            TIMEOUT_CONTEXT,
            &FAKE_VERIFIER,
            &Tx::close(
                edge(),
                Proof::timeout(other_terms_value(), None),
                payouts(Payout::new(MAKER, 7), Payout::new(TAKER, 8)),
            ),
        ),
        Err(ApplyError::InvalidProof {
            input: edge(),
            reason: InvalidProofReason::TermsMismatch,
        }),
    );
    assert_eq!(*state.store(), store);
}

#[test]
fn placeholder_witnesses_do_not_verify_under_reject_verifier() {
    let mut state = open_state();
    let store = *state.store();
    let outputs = payouts(Payout::new(MAKER, 7), Payout::new(TAKER, 8));

    assert_eq!(
        state.apply(
            CONTEXT,
            &REJECT_VERIFIER,
            &Tx::close(edge(), mutual_proof(edge(), &outputs), outputs),
        ),
        Err(ApplyError::InvalidProof {
            input: edge(),
            reason: InvalidProofReason::BadSignature,
        }),
    );
    assert_eq!(*state.store(), store);
}

#[test]
fn close_spends_edge_into_three_payout_coins() {
    let outputs = payouts3(
        Payout::new(MAKER, 6),
        Payout::new(TAKER, 5),
        Payout::new(MAKER, 4),
    );
    let terms_value = terms_with(&outputs);
    let funding_value = funding(MAKER_COIN, TAKER_COIN);
    let edge = Tx::edge_id_of(&funding_value, &terms_value);
    let open = open_tx(funding_value, terms_value.clone());
    let close = Tx::close(edge, Proof::timeout(terms_value, None), outputs.clone());
    let output_ids = Tx::close_output_ids(edge, &outputs);
    let maker_out = nth(&output_ids, 0);
    let taker_out = nth(&output_ids, 1);
    let extra_out = nth(&output_ids, 2);
    let mut state = state(store_for_close(&open, &outputs), [MAKER_SEED, TAKER_SEED]);
    let event = apply(&mut state, &open);
    assert_eq!(
        event.kind(),
        &EventKind::EdgeOpened {
            inputs: input_ids2(MAKER_COIN, TAKER_COIN),
            output: edge,
        },
    );
    let event = apply_with(&mut state, TIMEOUT_CONTEXT, &close);

    assert_eq!(
        event.kind(),
        &EventKind::EdgeClosed {
            input: edge,
            outputs: output_ids3(maker_out, taker_out, extra_out),
        },
    );
    assert_eq!(state.store().edge(edge), None);
    assert_eq!(
        state.store().coin(extra_out).map(coin_view),
        Some((MAKER, 4))
    );
}

#[test]
fn close_allows_zero_value_payout_coin() {
    let outputs = payouts(Payout::new(MAKER, 0), Payout::new(TAKER, 15));
    let terms_value = terms_with(&outputs);
    let funding_value = funding(MAKER_COIN, TAKER_COIN);
    let edge = Tx::edge_id_of(&funding_value, &terms_value);
    let open = open_tx(funding_value, terms_value.clone());
    let close = Tx::close(edge, Proof::timeout(terms_value, None), outputs.clone());
    let output_ids = Tx::close_output_ids(edge, &outputs);
    let maker_out = nth(&output_ids, 0);
    let taker_out = nth(&output_ids, 1);
    let mut state = state(store_for_close(&open, &outputs), [MAKER_SEED, TAKER_SEED]);
    let _event = apply(&mut state, &open);
    let event = apply_with(&mut state, TIMEOUT_CONTEXT, &close);

    assert_eq!(
        event.kind(),
        &EventKind::EdgeClosed {
            input: edge,
            outputs: output_ids2(maker_out, taker_out),
        },
    );
    assert_eq!(
        state.store().coin(maker_out).map(coin_view),
        Some((MAKER, 0)),
    );
    assert_eq!(
        state.store().coin(taker_out).map(coin_view),
        Some((TAKER, 15)),
    );
}

#[test]
fn close_rejects_occupied_output_id_without_mutation() {
    // A coin already sits at the id the first payout would derive; the
    // close must refuse rather than overwrite it. Only trusted genesis
    // configuration can produce this collision — payout ids bind their
    // producing edge, so no in-protocol close can pre-occupy another's.
    let mut state = state(
        empty_store(),
        [MAKER_SEED, TAKER_SEED, Genesis::coin(maker_out(), MAKER, 1)],
    );
    let _event = apply(&mut state, &open_op());
    let store = *state.store();

    assert_eq!(
        state.apply(
            TIMEOUT_CONTEXT,
            &FAKE_VERIFIER,
            &Tx::close(
                edge(),
                proof(),
                payouts(Payout::new(MAKER, 7), Payout::new(TAKER, 8)),
            ),
        ),
        Err(ApplyError::OutputExists { id: maker_out() }),
    );
    assert_eq!(*state.store(), store);
}

#[test]
fn close_rejects_non_conserving_payouts_without_mutation() {
    let outputs = payouts(Payout::new(MAKER, 7), Payout::new(TAKER, 9));
    let edge = edge();
    let open = open_tx(funding(MAKER_COIN, TAKER_COIN), basic_terms());
    let mut state = state(store_for_close(&open, &outputs), [MAKER_SEED, TAKER_SEED]);
    let _event = apply(&mut state, &open);
    let store = *state.store();

    assert_eq!(
        state.apply(
            CONTEXT,
            &FAKE_VERIFIER,
            &Tx::close(edge, Proof::timeout(basic_terms(), None), outputs),
        ),
        Err(ApplyError::InvalidClose {
            input: edge,
            reason: InvalidCloseReason::ValueMismatch,
        }),
    );
    assert_eq!(*state.store(), store);
}

#[test]
fn close_rejects_wrong_proof_without_mutation() {
    let mut state = open_state();
    let store = *state.store();

    // other_proof() is a Timeout proof under different terms; the terms hash
    // differs from the edge's commitment, so the kernel rejects with
    // TermsMismatch regardless of feature config.
    assert_eq!(
        state.apply(
            CONTEXT,
            &FAKE_VERIFIER,
            &Tx::close(
                edge(),
                other_proof(),
                payouts(Payout::new(MAKER, 7), Payout::new(TAKER, 8)),
            ),
        ),
        Err(ApplyError::InvalidProof {
            input: edge(),
            reason: InvalidProofReason::TermsMismatch,
        }),
    );
    assert_eq!(*state.store(), store);
}

/// Worst-case close cost reserved at open-time: `MAX_EDGE_OUTPUTS` payouts
/// under `Mutual` (the proof kind charging the most proof units).
fn worst_case_close_cost(edge: EdgeId) -> Cost {
    Tx::close(edge, mutual_proof(edge, &payouts4()), payouts4()).cost()
}
