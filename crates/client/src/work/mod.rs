//! Collect and authenticate the selected provider's signed invocation result.
pub mod payment;
use hellas_channel::model::setup::ReadyChannel;
use hellas_channel::model::work::PaidJobResultV1;
use hellas_channel::work::{ClientEndpoint, DeliverError, fetch_result_stream};
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
    /// The authenticated answer arrived and the client caught up to a
    /// finalized height from which it can still safely pay.
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
    /// The post-answer finalized-height barrier could not be made.
    #[error("the post-answer catch-up failed: {0}")]
    CatchUp(#[from] hellas_channel::work_close::CatchUpError),
    /// Catch-up crossed the job's last safe payment height.
    #[error(
        "the result became stale at finalized height {height}; payment deadline was {deadline}"
    )]
    Stale {
        /// Finalized height reached after delivery.
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
/// This function then catches the client up to the finalized tip and
/// refuses a result whose payment window elapsed meanwhile. A caller may
/// pass the returned result directly to [`payment::pay_for_result`], after it passes the invocation result checks.
pub async fn collect_result<T, C>(
    transport: T,
    endpoint: &mut ClientEndpoint,
    ready: &ReadyChannel,
    source: &C,
    work_id: hellas_auth::Digest,
) -> Result<CollectResultOutcome, CollectResultError>
where
    T: StreamTransport + Sync,
    T::Error: std::error::Error + Send + Sync + 'static,
    T::Stream: 'static,
    C: hellas_channel::work_close::FinalizedBlocks + ?Sized,
{
    let delivery = match fetch_result_stream(transport, endpoint, ready, work_id, |_| Ok(())).await
    {
        Ok(delivery) => delivery,
        Err(DeliverError::Refused { refusal, reason }) if refusal.is_retryable() => {
            return Ok(CollectResultOutcome::NotReady { reason });
        }
        Err(error) => return Err(error.into()),
    };

    let deadline = endpoint
        .state()
        .job_by_id(work_id)
        .ok_or(DeliverError::NoSuchJob)?
        .authorization()
        .payment_deadline;
    endpoint.catch_up(source).await?;
    let height = endpoint.state().cursor().0;
    if height > deadline {
        return Err(CollectResultError::Stale { height, deadline });
    }

    Ok(CollectResultOutcome::Collected(CollectedResult {
        result: delivery.result,
        transcript: delivery.transcript,
    }))
}
