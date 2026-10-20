use super::*;

#[test]
fn operations_report_deterministic_cost() {
    let open = open_op();
    let close_outputs = payouts(Payout::new(MAKER, 7), Payout::new(TAKER, 8));
    let close = Tx::close(edge(), proof(), close_outputs.clone());
    let open_cost = open.cost();
    let close_cost = close.cost();
    // Worst-case reserve mirrors `apply_open` reserve_cost: MAX_EDGE_OUTPUTS
    // payouts under `Mutual` (the proof kind charging the most proof units).
    let worst_case = Tx::close(edge(), mutual_proof(edge(), &payouts4()), payouts4()).cost();

    // One proof unit per party witness, Basic included.
    assert_eq!(open_cost, Cost::new(1, 3, 2));
    assert_eq!(close_cost, Cost::new(1, 3, 1));
    assert_eq!(worst_case, Cost::new(1, 5, 2));
    assert!(close_cost.fits(worst_case));
    assert_eq!(
        mutual_proof(edge(), &close_outputs).cost(),
        Cost::new(0, 0, 2)
    );
    assert_eq!(proof().kind(), CloseKind::Timeout);
    assert_eq!(Proof::timeout(basic_terms()).cost(), Cost::new(0, 0, 1));
}

#[test]
fn open_reserves_worst_case_close_cost() {
    let outputs = payouts4();
    // `Mutual` charges 2 proof units (two signatures); `Timeout` charges
    // 1. The reserved worst case is Mutual at MAX_EDGE_OUTPUTS payouts.
    let mutual = Tx::close(edge(), mutual_proof(edge(), &outputs), outputs.clone());
    let timeout = Tx::close(edge(), proof(), outputs);

    assert_eq!(mutual.cost(), Cost::new(1, 5, 2));
    assert_eq!(timeout.cost(), Cost::new(1, 5, 1));
}

#[test]
fn operations_derive_output_ids() {
    let open = open_op();
    let outputs = payouts(Payout::new(MAKER, 7), Payout::new(TAKER, 8));
    let edge_id = open_edge_id(&open);
    let close = Tx::close(edge_id, proof(), outputs.clone());
    let ids = Tx::close_output_ids(edge_id, &outputs);

    assert_eq!(
        edge_id,
        Tx::edge_id_of(&funding(MAKER_COIN, TAKER_COIN), &basic_terms()),
    );
    assert_eq!(ids.as_slice()[0], Payout::new(MAKER, 7).id(edge(), 0));
    assert_eq!(ids.as_slice()[1], Payout::new(TAKER, 8).id(edge(), 1));
    assert_ne!(ids.as_slice()[0], ids.as_slice()[1]);
    // Sanity: the close still reports the configured outputs through pattern match.
    let Tx::Close {
        outputs: tx_outputs,
        ..
    } = &close
    else {
        panic!("expected close");
    };
    assert_eq!(tx_outputs, &outputs);
}

#[test]
fn block_reports_deterministic_cost_and_fee() {
    let ops = List::all([
        open_op(),
        Tx::close(
            edge(),
            proof(),
            payouts(Payout::new(MAKER, 7), Payout::new(TAKER, 8)),
        ),
    ]);
    let block = Block::new(RESOURCE_CONTEXT, ops);

    assert_eq!(block.cost(), Some(Cost::new(2, 6, 3)));
    // 1*2 + 3*6 + 0*3 = 20 under RESOURCE_CONTEXT.
    assert_eq!(block.fee(), Some(20));
    assert!(Cost::new(2, 6, 3).fits(Cost::new(2, 6, 3)));
    assert!(block.fits(Cost::new(2, 6, 3)));
    assert!(block.fits(Cost::new(3, 6, 3)));
    assert!(!block.fits(Cost::new(1, 6, 3)));
    assert!(!block.fits(Cost::new(2, 5, 3)));
    assert!(!block.fits(Cost::new(2, 6, 2)));
}

#[test]
fn view_tracks_live_objects() {
    let funded = funded_state();
    let funded_view: View<6, 1> = funded.view();

    assert_eq!(funded_view.coin_len(), 2);
    assert_eq!(funded_view.edge_len(), 0);
    assert_eq!(
        funded_view.coin(MAKER_COIN).map(coin_view),
        Some((MAKER, 10))
    );
    assert_eq!(
        funded_view.coin(TAKER_COIN).map(coin_view),
        Some((TAKER, 5))
    );

    let mut resolved = open_state();
    let _event = apply_with(
        &mut resolved,
        TIMEOUT_CONTEXT,
        &Tx::close(
            edge(),
            proof(),
            payouts(Payout::new(MAKER, 7), Payout::new(TAKER, 8)),
        ),
    );
    let resolved_view: View<6, 1> = resolved.view();

    assert_eq!(resolved_view.coin_len(), 2);
    assert_eq!(resolved_view.edge_len(), 0);
    assert_eq!(resolved_view.edge(edge()), None);
    assert_eq!(
        resolved_view.coin(maker_out()).map(coin_view),
        Some((MAKER, 7)),
    );
    assert_eq!(
        resolved_view.coin(taker_out()).map(coin_view),
        Some((TAKER, 8)),
    );
}
