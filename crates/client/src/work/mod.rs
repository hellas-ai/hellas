//! Collect and authenticate the selected provider's signed invocation result.
pub mod payment;
use hellas_channel::model::setup::ReadyChannel;
use hellas_channel::model::work::PaidJobResultV1;
use hellas_channel::work::{ClientChannel, DeliverError, fetch_result_stream};
use hellas_wire::StreamTransport;

/// One provider-authenticated answer, durably recorded and still inside
/// the payment window.
///
/// This is the ordinary paid-work result. It proves who authorized the
/// job and who signed the returned transcript; it does not claim that a
/// second engine independently reproduced the computation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CollectedResult {
    /// The provider's signed result.
    pub result: PaidJobResultV1,
    /// The signed events it summarises, as delivered.
    pub transcript: Vec<u8>,
}

/// What one ordinary attempt to collect a job's answer found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CollectResultOutcome {
    /// The authenticated answer arrived, and the client's certified cursor
    /// is still inside the job's payment window.
    Collected(CollectedResult),
    /// The provider cannot answer yet. Retrying does not create a
    /// second delivery or payment.
    NotReady {
        /// The provider's diagnostic text. Nothing decides on it.
        reason: String,
    },
}

/// Why ordinary result collection failed.
#[derive(Debug, thiserror::Error)]
pub enum CollectResultError {
    /// The delivery did not complete, or was refused permanently.
    #[error(transparent)]
    Deliver(#[from] DeliverError),
    /// The client's certified cursor is past the job's last safe payment
    /// height.
    #[error(
        "the result became stale at certified height {height}; payment deadline was {deadline}"
    )]
    Stale {
        /// Certified height the client's journal holds after delivery.
        height: u64,
        /// Payment deadline both parties authorized.
        deadline: u64,
    },
}

/// Fetches and authenticates a provider's answer without mandatory
/// independent re-execution.
///
/// The delivery path verifies the provider signature, rebuilds the
/// result from the signed transcript, and journals it before returning.
/// This function then refuses a result whose payment window the client's
/// own certified cursor has already passed; the channel's observer keeps
/// that cursor current. A caller may
/// pass the returned result directly to [`payment::pay_for_result`], after it passes the invocation result checks.
pub async fn collect_result<T>(
    transport: T,
    endpoint: &mut impl ClientChannel,
    ready: &ReadyChannel,
    work_id: hellas_auth::Digest,
) -> Result<CollectResultOutcome, CollectResultError>
where
    T: StreamTransport + Sync,
    T::Error: std::error::Error + Send + Sync + 'static,
    T::Stream: 'static,
{
    let delivery = match fetch_result_stream(transport, endpoint, ready, work_id, |_| Ok(())).await
    {
        Ok(delivery) => delivery,
        Err(DeliverError::Refused { refusal, reason }) if refusal.is_retryable() => {
            return Ok(CollectResultOutcome::NotReady { reason });
        }
        Err(error) => return Err(error.into()),
    };

    let (deadline, height) = {
        let client = endpoint.client().await.map_err(DeliverError::from)?;
        let state = client.state();
        let deadline = state
            .job_by_id(work_id)
            .ok_or(DeliverError::NoSuchJob)?
            .authorization()
            .payment_deadline;
        (deadline, state.cursor().0)
    };
    if height > deadline {
        return Err(CollectResultError::Stale { height, deadline });
    }

    Ok(CollectResultOutcome::Collected(CollectedResult {
        result: delivery.result,
        transcript: delivery.transcript.to_vec(),
    }))
}
