//! Pays for one authenticated, durable result.
//!
//! The client commits its certificate and binding before sending them. The
//! provider commits the same payment before acknowledging it. Repeating the
//! call re-sends retained bytes and never credits the job twice.

use hellas_rpc::protocol::Digest;
use hellas_rpc::services::work::WorkClientImpl;
use hellas_wire::StreamTransport;
use hellas_work::work::{ClientChannel, PaymentError, admit_payment};

/// Signs and admits payment for one authenticated result.
///
/// Returns the cumulative amount acknowledged by the provider. Both endpoints
/// commit the payment before sending or acknowledging it. The operation is
/// idempotent: retrying the same `work_id` re-sends its retained certificate
/// without further credit.
///
/// # Errors
///
/// [`PaymentError`] if the result is not payable, the deadline passed, the
/// journal rejects the transition, or the acknowledgement names another amount.
pub async fn pay_for_result<T>(
    transport: T,
    endpoint: &mut impl ClientChannel,
    work_id: Digest,
) -> Result<u64, PaymentError>
where
    T: StreamTransport + Sync,
    T::Error: std::error::Error + Send + Sync + 'static,
    T::Stream: 'static,
{
    admit_payment(&WorkClientImpl::new(transport), endpoint, work_id).await
}
