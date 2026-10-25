use super::*;
use hellas_kernel::test_support::valid_open_tx;

fn proto_snapshot() -> FinalizedSnapshot {
    FinalizedSnapshot {
        height: 7,
        payload: Digest::from([2u8; 32]).to_vec(),
        state_root: Digest::from([1u8; 32]).to_vec(),
        finalization: vec![1],
    }
}

fn proto_block(block: Vec<u8>, payload: Digest) -> hellas_rpc::pb::chain::FinalizedBlock {
    hellas_rpc::pb::chain::FinalizedBlock {
        snapshot: Some(FinalizedSnapshot {
            payload: payload.to_vec(),
            ..proto_snapshot()
        }),
        block,
    }
}

fn proto_edge_state() -> hellas_rpc::pb::chain::EdgeState {
    hellas_rpc::pb::chain::EdgeState {
        value: 100,
        reserve: 4,
        close_fees: Some(KernelFees {
            base: 1,
            slot: 2,
            proof: 3,
            lifetime: 4,
        }),
        timeout: 9,
        maker: vec![3; SettlementKey::LENGTH],
        taker: vec![4; SettlementKey::LENGTH],
        terms_hash: vec![5; hellas_kernel::TermsHash::LENGTH],
    }
}

fn proto_edge_record(object_id: u8, maker: SettlementKey, taker: SettlementKey) -> EdgeEntry {
    EdgeEntry {
        object_id: vec![object_id; 32],
        maker: maker.to_bytes().to_vec(),
        taker: taker.to_bytes().to_vec(),
    }
}

#[test]
fn finalized_block_verification_checks_block_bytes() {
    let block = b"encoded-block".to_vec();
    let payload = Sha256::hash(&block);

    let verified = finalized_block_from_proto(proto_block(block.clone(), payload), None)
        .expect("matching block bytes should verify without a configured certificate verifier");
    assert_eq!(verified.snapshot.payload, payload);
    assert_eq!(verified.block, block);

    let mismatched_payload = Sha256::hash(b"different-block");
    assert!(
        finalized_block_from_proto(
            proto_block(b"encoded-block".to_vec(), mismatched_payload),
            None
        )
        .is_err()
    );
}

#[test]
fn kernel_transaction_uses_canonical_submit_payload() {
    let kernel = valid_open_tx().expect("valid kernel open fixture");
    let request = transaction_to_proto(Transaction::Kernel(kernel.clone()))
        .expect("kernel transaction encodes");
    let Some(submit_tx_request::Tx::KernelTx(bytes)) = request.tx else {
        panic!("expected kernel transaction arm")
    };
    assert_eq!(hellas_kernel::Tx::decode_exact(&bytes), Ok(kernel));
}

#[test]
fn protobuf_zero_submit_outcome_is_an_error() {
    assert!(matches!(
        submit_tx_outcome_from_proto(SubmitTxOutcome::Unspecified as i32),
        Err(QueryError::Remote(message))
            if message == "submit response contained an unspecified outcome"
    ));
}

#[test]
fn remote_edge_decode_rejects_malformed_presence_and_required_fields() {
    assert!(
        edge_lookup_from_proto(GetEdgeResponse {
            edge: None,
            state_root: Some(vec![0; 31]),
        })
        .is_err()
    );

    let mut missing_fees = proto_edge_state();
    missing_fees.close_fees = None;
    assert!(
        edge_lookup_from_proto(GetEdgeResponse {
            edge: Some(missing_fees),
            state_root: Some(vec![0; 32]),
        })
        .is_err()
    );

    assert!(
        edge_lookup_from_proto(GetEdgeResponse {
            edge: Some(proto_edge_state()),
            state_root: None,
        })
        .is_err()
    );
}

#[test]
fn remote_owner_edges_decode_records_and_reject_malformed_keys() {
    let owner = SettlementKey::from_bytes([7; SettlementKey::LENGTH]);
    let taker = SettlementKey::from_bytes([8; SettlementKey::LENGTH]);
    let decoded = owner_edges_from_proto(
        owner,
        GetEdgesByOwnerResponse {
            snapshot: Some(proto_snapshot()),
            edges: vec![proto_edge_record(9, owner, taker)],
        },
    )
    .expect("valid owner edge response")
    .expect("snapshot is present");
    assert_eq!(
        decoded.edges,
        vec![EdgeRecord {
            object_id: Digest::from([9; 32]),
            maker: owner,
            taker,
        }]
    );

    let mut malformed_maker = proto_edge_record(9, owner, taker);
    malformed_maker.maker.pop();
    let mut malformed_taker = proto_edge_record(9, owner, taker);
    malformed_taker.taker.pop();
    for malformed in [malformed_maker, malformed_taker] {
        assert!(
            owner_edges_from_proto(
                owner,
                GetEdgesByOwnerResponse {
                    snapshot: Some(proto_snapshot()),
                    edges: vec![malformed],
                },
            )
            .is_err()
        );
    }
}

#[test]
fn remote_owner_edges_reject_duplicates_and_unrelated_records() {
    let owner = SettlementKey::from_bytes([7; SettlementKey::LENGTH]);
    let taker = SettlementKey::from_bytes([8; SettlementKey::LENGTH]);
    let duplicate = proto_edge_record(9, owner, taker);
    assert!(
        owner_edges_from_proto(
            owner,
            GetEdgesByOwnerResponse {
                snapshot: Some(proto_snapshot()),
                edges: vec![duplicate.clone(), duplicate],
            },
        )
        .is_err()
    );

    let maker = SettlementKey::from_bytes([6; SettlementKey::LENGTH]);
    assert!(
        owner_edges_from_proto(
            owner,
            GetEdgesByOwnerResponse {
                snapshot: Some(proto_snapshot()),
                edges: vec![proto_edge_record(9, maker, taker)],
            },
        )
        .is_err()
    );
}
