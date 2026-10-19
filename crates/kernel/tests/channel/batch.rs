use super::*;

#[test]
fn apply_all_opens_and_closes_one_batch() {
    let mut state = funded_state();
    let outputs = payouts(Payout::new(MAKER, 7), Payout::new(TAKER, 8));
    let ops = List::all([
        open_tx(funding(MAKER_COIN, TAKER_COIN), basic_terms()),
        Tx::close(edge(), mutual_proof(edge(), &outputs), outputs),
    ]);

    let block = Block::new(CONTEXT, ops);
    let Ok(diff) = state.apply_block(&FAKE_VERIFIER, &block) else {
        panic!("valid batch rejected");
    };

    assert_eq!(diff.len(), 2);
    assert!(!diff.is_empty());
    assert_eq!(
        diff.event(0).map(Event::kind),
        Some(&EventKind::EdgeOpened {
            inputs: input_ids2(MAKER_COIN, TAKER_COIN),
            output: edge(),
        }),
    );
    assert_eq!(
        diff.event(1).map(Event::kind),
        Some(&EventKind::EdgeClosed {
            input: edge(),
            outputs: output_ids2(maker_out(), taker_out()),
        }),
    );
    assert_eq!(diff.event(2), None);
    assert_eq!(state.store().edge(edge()), None);
    assert_eq!(
        state.store().coin(maker_out()).map(coin_view),
        Some((MAKER, 7)),
    );
    assert_eq!(
        state.store().coin(taker_out()).map(coin_view),
        Some((TAKER, 8)),
    );
}

#[test]
fn apply_all_reports_first_operation_error_index() {
    let mut state = funded_state();
    let outputs = payouts(Payout::new(MAKER, 7), Payout::new(TAKER, 8));
    let ops = List::all([Tx::close(edge(), Proof::timeout(basic_terms()), outputs)]);

    let Err(error) = state.apply_all(CONTEXT, &FAKE_VERIFIER, &ops) else {
        panic!("invalid first operation accepted");
    };

    assert_eq!(error.index(), 0);
    assert_eq!(error.source(), ApplyError::MissingEdge { id: edge() });
}

#[test]
fn apply_all_allows_empty_batch() {
    let mut state = funded_state();
    let store = *state.store();
    let ops: List<Tx, 0> = List::all([]);
    let Ok(diff) = state.apply_all(CONTEXT, &FAKE_VERIFIER, &ops) else {
        panic!("empty batch rejected");
    };

    assert!(diff.is_empty());
    assert_eq!(diff.len(), 0);
    assert_eq!(*state.store(), store);
}

#[test]
fn apply_all_rolls_back_on_error() {
    let outputs = payouts(Payout::new(MAKER, 7), Payout::new(TAKER, 9));
    let open = open_tx(funding(MAKER_COIN, TAKER_COIN), basic_terms());
    let mut state = state(store_for_close(&open, &outputs), [MAKER_SEED, TAKER_SEED]);
    let store = *state.store();
    let ops = List::all([
        open,
        Tx::close(edge(), Proof::timeout(basic_terms()), outputs),
    ]);

    let Err(error) = state.apply_all(CONTEXT, &FAKE_VERIFIER, &ops) else {
        panic!("invalid batch accepted");
    };

    assert_eq!(error.index(), 1);
    assert_eq!(
        error.source(),
        ApplyError::InvalidClose {
            input: edge(),
            reason: InvalidCloseReason::ValueMismatch,
        },
    );
    assert_eq!(*state.store(), store);
}

#[test]
fn apply_iter_emits_events_per_op() {
    let mut state = funded_state();
    let funding_value = funding(MAKER_COIN, TAKER_COIN);
    let edge_id = Tx::edge_id_of(&funding_value, &basic_terms());
    let open = open_tx(funding_value, basic_terms());
    let outputs = payouts(Payout::new(MAKER, 7), Payout::new(TAKER, 8));
    let ops = [
        open,
        Tx::close(edge_id, mutual_proof(edge_id, &outputs), outputs),
    ];

    let mut observed: Vec<(usize, EventKind)> = Vec::new();
    let Ok(()) = state.apply_iter(CONTEXT, &FAKE_VERIFIER, ops, |i, outcome| {
        assert!(outcome.registry().is_empty(), "op {i} wrote registry state");
        let Some(event) = outcome.public_event() else {
            panic!("op {i} applied without announcing itself");
        };
        observed.push((i, event.kind().clone()));
    }) else {
        panic!("valid batch rejected");
    };

    assert_eq!(observed.len(), 2);
    assert_eq!(observed[0].0, 0);
    assert!(matches!(
        observed[0].1,
        EventKind::EdgeOpened { output, .. } if output == edge_id,
    ));
    assert_eq!(observed[1].0, 1);
    assert!(matches!(
        observed[1].1,
        EventKind::EdgeClosed { input, .. } if input == edge_id,
    ));
    assert_eq!(state.store().edge(edge_id), None);
    assert_eq!(
        state.store().coin(maker_out()).map(coin_view),
        Some((MAKER, 7)),
    );
}

#[test]
fn apply_iter_accepts_borrowed_ops() {
    let mut state = funded_state();
    let ops = [open_op()];

    let mut observed: Vec<usize> = Vec::new();
    let Ok(()) = state.apply_iter(CONTEXT, &FAKE_VERIFIER, ops.iter(), |i, _| {
        observed.push(i);
    }) else {
        panic!("valid borrowed batch rejected");
    };

    assert_eq!(observed, vec![0]);
    assert!(state.store().edge(edge()).is_some());
}

#[test]
fn apply_iter_rolls_back_on_mid_batch_failure() {
    let outputs = payouts(Payout::new(MAKER, 7), Payout::new(TAKER, 9));
    let edge_id = edge();
    let open = open_tx(funding(MAKER_COIN, TAKER_COIN), basic_terms());
    let mut state = state(store_for_close(&open, &outputs), [MAKER_SEED, TAKER_SEED]);
    let store_before = *state.store();
    let ops = [
        open,
        Tx::close(edge_id, Proof::timeout(basic_terms()), outputs),
    ];

    let mut observed = Vec::new();
    let Err(error) = state.apply_iter(CONTEXT, &FAKE_VERIFIER, ops, |i, outcome| {
        observed.push((i, outcome.public_event().map(|event| event.kind().clone())));
    }) else {
        panic!("invalid batch accepted");
    };

    assert_eq!(error.index(), 1);
    assert_eq!(
        error.source(),
        ApplyError::InvalidClose {
            input: edge_id,
            reason: InvalidCloseReason::ValueMismatch,
        },
    );
    // op-0's event was observed before op-1 failed, but the transaction
    // rolled back, so the store must be unchanged regardless.
    assert_eq!(observed.len(), 1);
    assert_eq!(observed[0].0, 0);
    assert_eq!(*state.store(), store_before);
}

#[test]
fn apply_iter_accepts_empty_batch() {
    let mut state = funded_state();
    let store_before = *state.store();
    let ops: [Tx; 0] = [];

    let mut observed: Vec<usize> = Vec::new();
    let Ok(()) = state.apply_iter(CONTEXT, &FAKE_VERIFIER, ops, |i, _| observed.push(i)) else {
        panic!("empty batch rejected");
    };

    assert_eq!(observed, Vec::<usize>::new());
    assert_eq!(*state.store(), store_before);
}
