use super::*;
use hellas_kernel::Decode as _;
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

#[test]
fn finalized_block_verification_checks_block_bytes() {
    let block = b"encoded-block".to_vec();
    let payload = Sha256::hash(&block);

    let verified = finalized_block_from_proto(proto_block(block.clone(), payload))
        .expect("matching block bytes should verify without a configured certificate verifier");
    assert_eq!(verified.snapshot.payload, payload);
    assert_eq!(verified.block, block);

    let mismatched_payload = Sha256::hash(b"different-block");
    assert!(
        finalized_block_from_proto(proto_block(b"encoded-block".to_vec(), mismatched_payload),)
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
