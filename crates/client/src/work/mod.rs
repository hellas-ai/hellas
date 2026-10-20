//! The client half of a paid job, from a co-signed authorization to a
//! result this client has checked itself.
//!
//! # The one thing this module is for
//!
//! Everything before it moves authenticated bytes. This is where the
//! client decides the bytes are *right* by reproducing them itself, and
//! it is the difference between paying for a reproduced result and paying
//! for a signature.
//!
//! # The order, and why it is this order
//!
//! 1. **Fetch.** One unary call, whose answer the endpoint journals
//!    before returning it. The journal is where the delivered result is
//!    rebuilt from the delivered transcript, checked against the
//!    provider's key, and timed against the terminal deadline; none of
//!    those is spelled again here.
//! 2. **Reproduce.** The engine is handed the bundle the *journal*
//!    holds — not the one the response carried, and not one this module
//!    reassembled — because that bundle's digest is inside the
//!    authorization both parties signed and is re-checked every time
//!    the journal is opened.
//! 3. **Catch up, then record.** The cursor is caught up to the finalized
//!    tip, and only then is the outcome fsynced — a match that a
//!    certificate may be signed from, or a permanent refutation that no
//!    payment can follow. A match reaches
//!    [`payment::pay_for_result`], the step that turns the
//!    reproduced answer into a payment.
//!
//! Reversed, the third step would be a claim about a re-execution that
//! had not finished, and the second would reproduce bytes nothing durable
//! bound to the job.
//!
//! # What a match means, and what it does not
//!
//! It means: an engine this client chose, given the inputs this client
//! signed for, produced the answer the provider signed — the same
//! tokens in the same order, stopping for the same reason, with the same
//! output artifact and the same usage. It does not mean the provider
//! computed rather than recalled that answer, and it is no stronger than
//! the engine behind [`reproduce::Reproducer`]. See [`reproduce`].
//!
//! # What is not here
//!
//! No retry loop and no deadline timer. The cursor they would be
//! bounded by does move — `hellas_work::work_close::catch_up` is what
//! moves it, and `ClientEndpoint::catch_up` is how this endpoint asks
//! it to — but nothing here owns a clock, and a loop written without
//! one polls until it is killed. What this module gives a caller
//! instead is the provider's own answer about whether asking again
//! could help — [`CollectOutcome::NotReady`] — so the policy that owns
//! a clock can be written over a signal rather than a guess.

pub mod payment;
pub mod reproduce;

use hellas_wire::StreamTransport;
use hellas_work::model::prepared_input::PreparedPaidInputV1;
use hellas_work::model::setup::ReadyChannel;
use hellas_work::model::work::PaidJobResultV1;
use hellas_work::work::{ClientEndpoint, DeliverError, fetch_result};
use hellas_work::work_store::journal::MAX_RECORD_BYTES;

use reproduce::{ReproduceFault, Reproducer, Reproduction};

/// One job's answer, checked and durably recorded as checked.
///
/// What [`payment::pay_for_result`] is called for. The
/// transcript rides with it because it is the answer the user asked
/// for; the result is what the payment chain names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckedResult {
    /// The provider's signed result.
    pub result: PaidJobResultV1,
    /// The signed events it summarises, as delivered.
    pub transcript: Vec<u8>,
}

/// One provider-authenticated answer, durably recorded and still inside
/// the payment window.
///
/// This is the ordinary paid-work result. It proves who authorized the
/// job and who signed the returned transcript; it does not claim that a
/// second engine independently reproduced the computation. Call
/// [`collect_checked_result`] when that additional check is desired.
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
    CatchUp(#[from] hellas_work::work_close::CatchUpError),
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
/// pass the returned result directly to [`payment::pay_for_result`], or
/// choose [`collect_checked_result`] for independent reproduction.
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
    C: hellas_work::work_close::FinalizedBlocks + ?Sized,
{
    let delivery = match fetch_result(transport, endpoint, ready, work_id).await {
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

/// What one attempt to collect a job's answer found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CollectOutcome {
    /// The answer arrived, reproduced, matched, and the match is on the
    /// disk.
    Checked(CheckedResult),
    /// The provider cannot answer yet. The identical call may be made
    /// again, and nothing was recorded.
    NotReady {
        /// The provider's diagnostic text. Nothing decides on it.
        reason: String,
    },
}

/// Why one attempt to collect a job's answer failed.
///
/// The three shapes a caller must tell apart: a delivery that did not
/// happen or was refused, a check that could not be made, and a check
/// that was made and *failed*. Only the last is evidence about the
/// provider.
#[derive(Debug, thiserror::Error)]
pub enum CollectError {
    /// The delivery did not complete, or was refused permanently.
    #[error(transparent)]
    Deliver(#[from] DeliverError),
    /// The post-answer catch-up — the barrier — could not be made.
    ///
    /// Nothing durable was recorded, so a caller may retry: the answer is
    /// on the disk from the fetch, and a fresh attempt re-runs the
    /// re-execution and the catch-up.
    #[error("the post-answer catch-up failed: {0}")]
    CatchUp(#[from] hellas_work::work_close::CatchUpError),
    /// The journal holds a bundle that does not parse.
    ///
    /// Unreachable through an honest path: the bundle was parsed and
    /// hashed before the job was ever proposed, and again whenever the
    /// journal is opened. It is a refusal rather than a panic because
    /// nothing in this crate panics on stored bytes.
    #[error("the stored prepared input does not parse: {0}")]
    Bundle(String),
    /// The reproduction could not be performed.
    ///
    /// The re-execution did not happen. It is not evidence that the
    /// provider was wrong, and a caller must not treat it as either
    /// verdict.
    #[error("the separate re-execution could not be made: {0}")]
    Unchecked(ReproduceFault),
    /// The reproduction ran and did not reproduce the answer.
    ///
    /// This job must not be paid for. The refutation is durable — the
    /// job rests at a permanent refuted terminal — so a later call cannot
    /// pay for it and a second proposal of it fails.
    #[error("the separate re-execution refuted this result")]
    Refuted {
        /// The answer digest the client's own re-execution produced.
        reproduction_digest: hellas_auth::Digest,
    },
}

/// Fetches one accepted job's answer, reproduces it separately, and
/// records the outcome durably.
///
/// Four phases, in order, and the order is the whole of the safety:
///
/// 1. **Network / re-execution.** One unary fetch, whose answer the
///    endpoint journals before returning it, and then the separate
///    re-execution over the bundle the *journal* holds — not the one the
///    response carried. Neither holds a durable barrier; the fetch's own
///    journal write and the re-execution are the unlocked work.
/// 2. **Post-answer catch-up.** Once there is an answer, the cursor is
///    caught up to the finalized tip. This is the barrier: a re-execution
///    that stalled past the height the client signed to pay by advances
///    the cursor past it here, so the durable step below — and the
///    payment it enables — is judged against a fresh clock rather than
///    the stale one the fetch left.
/// 3. **Checked apply.** A match is recorded as [`ClientEndpoint::matched`];
///    a mismatch is recorded as [`ClientEndpoint::refuted`] — a permanent
///    refuted terminal, so the job can never afterwards be paid for and a
///    second proposal of it fails.
///
/// Idempotent in every step, so a caller whose process died anywhere in
/// it may call this again with the same `work_id`: the delivery is
/// answered from the provider's spool at no second credit cost, the
/// journal takes the same result as one, the engine is deterministic,
/// and a repeated match or refutation is the same one.
///
/// # Errors
///
/// [`CollectError::Deliver`] when the answer did not arrive or the
/// journal refused it — which is what it does for a late receipt or a
/// transcript that does not rebuild the result — [`CollectError::CatchUp`]
/// when the post-answer catch-up failed, and [`CollectError::Unchecked`]
/// or [`CollectError::Refuted`] for the two outcomes of the re-execution
/// itself. Nothing is recorded as checked unless this returns
/// [`CollectOutcome::Checked`].
pub async fn collect_checked_result<T, C, E>(
    transport: T,
    endpoint: &mut ClientEndpoint,
    ready: &ReadyChannel,
    source: &C,
    engine: &E,
    work_id: hellas_auth::Digest,
) -> Result<CollectOutcome, CollectError>
where
    T: StreamTransport + Sync,
    T::Error: std::error::Error + Send + Sync + 'static,
    T::Stream: 'static,
    C: hellas_work::work_close::FinalizedBlocks + ?Sized,
    E: Reproducer + ?Sized,
{
    // Phase 1 — network and re-execution, holding no durable barrier.
    let delivery = match fetch_result(transport, endpoint, ready, work_id).await {
        Ok(delivery) => delivery,
        Err(DeliverError::Refused { refusal, reason }) if refusal.is_retryable() => {
            return Ok(CollectOutcome::NotReady { reason });
        }
        Err(error) => return Err(error.into()),
    };

    // The bundle the journal holds, not the one any response carried.
    let Some(job) = endpoint.state().job_by_id(work_id) else {
        return Err(CollectError::Deliver(DeliverError::NoSuchJob));
    };
    let bundle = PreparedPaidInputV1::decode(job.prepared_input(), MAX_RECORD_BYTES)
        .map_err(|error| CollectError::Bundle(error.to_string()))?;
    let network = endpoint.state().channel().network();

    let reproduction =
        reproduce::reproduce(engine, network, work_id, &bundle, &delivery.result).await;

    // Phase 2 — post-answer catch-up. The barrier: the cursor the durable
    // step below is judged against is the finalized tip now, not the one
    // the fetch left before the re-execution ran. A re-execution that
    // stalled past the height the client signed to pay by advances the
    // cursor past it here, so the checked apply and the payment it enables
    // are judged against a fresh clock rather than the stale one.
    endpoint.catch_up(source).await?;

    // Phase 3 — checked apply, durable either way.
    match reproduction {
        Ok(Reproduction::Matched) => {
            endpoint.matched(work_id).await?;
            Ok(CollectOutcome::Checked(CheckedResult {
                result: delivery.result,
                transcript: delivery.transcript,
            }))
        }
        Ok(Reproduction::Refuted {
            reproduction_digest,
        }) => {
            endpoint.refuted(work_id, reproduction_digest).await?;
            Err(CollectError::Refuted {
                reproduction_digest,
            })
        }
        Err(fault) => Err(CollectError::Unchecked(fault)),
    }
}
