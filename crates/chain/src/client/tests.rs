use super::*;
use hellas_kernel::Decode as _;
use hellas_kernel::test_support::valid_open_tx;

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
