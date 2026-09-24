//! The provider's real execution backend, behind the paid gate.
//!
//! # What this is
//!
//! One implementation of [`PaidWorkBackend`], over this crate's own
//! Evaluate engine. The gate that decides whether a backend may be
//! called at all is [`hellas_work::work::run_accepted_work`]'s, and it is
//! not here: it belongs beside the journal that records the decision,
//! and a second copy of it in front of one backend would be a second
//! opinion about when a paid job may run.
//!
//! So what is here is exactly the seam. A request that this endpoint
//! rebuilt from its own journal goes in; the complete signed transcript
//! of one invocation comes back, or a fault does.
//!
//! # Invoked once
//!
//! Not by anything in this file. This starts the engine every time it is
//! called, and that is the honest shape for it: what makes a second call
//! not come is the running marker the gate journaled, and nothing here
//! can see one.
//!
//! Which is also to say what this is not: a paid gate on the executor's
//! own front door. An owner of the [`ExecutorHandle`] can call it
//! directly and get an execution for nothing, because the handle is held
//! in-process and no RPC route exposes it.
//!
//! One thing this file must not do, and deliberately does not: consult
//! the engine's completed-execution map. That map is keyed by request
//! commitment, so a second paid job carrying the same request would be
//! answered out of the first one's transcript, with nothing invoked and
//! a price charged. `EvaluateEngine::start_prepared_input` instead creates
//! one fresh invocation and hands it to the actor's owed FIFO exactly once.
//!
//! # What is not covered by a test here
//!
//! That the exact Catena environment, given this request, produces that
//! transcript. Running it needs a compatible GPU and the committed content,
//! so the ordinary unit suite does not execute this path end to end; the ROCm
//! integration test does. What the gate does with a transcript, and how many
//! times it asks for one, is tested against a counting double at this trait in
//! `hellas-rpc`.

use crate::ExecutorError;
use crate::executor::{ExecutorHandle, ExecutorOwedRequest};
use hellas_rpc::OutputEventEnvelope;
use hellas_work::work::{BackendFault, PaidProgress, PaidWorkBackend, PreparedEvaluateInput};

impl ExecutorHandle {
    /// Runs one already-authorized paid job to its terminal.
    ///
    /// The receiver is owned by this future, not by a transport. A
    /// caller that disconnects mid-generation therefore detaches its own
    /// reader and nothing else — the invocation is not cancelled by the
    /// wire, because the wire never held it.
    ///
    /// # Errors
    ///
    /// [`ExecutorError`] when the engine will not start the request,
    /// when the stream ends without a terminal, when the execution
    /// failed, or when an event does not decode.
    pub async fn run_paid_evaluate(
        &self,
        input: PreparedEvaluateInput,
    ) -> Result<Vec<OutputEventEnvelope>, ExecutorError> {
        self.run_paid_evaluate_stream(input, None).await
    }

    async fn run_paid_evaluate_stream(
        &self,
        input: PreparedEvaluateInput,
        progress: Option<PaidProgress>,
    ) -> Result<Vec<OutputEventEnvelope>, ExecutorError> {
        use tracing::Instrument;
        async move {
            // The actor admits this durable obligation exactly once. If the GPU
            // worker is occupied, EvaluateEngine retains it in its owed FIFO and
            // dispatches it ahead of peer-admitted work.
            let outcome = self
                .send_owed(|reply| ExecutorOwedRequest::RunPaidEvaluate {
                    span: tracing::Span::current(),
                    input: Box::new(input),
                    reply,
                })
                .await?;
            drain_transcript_with_progress(outcome, progress).await
        }
        .instrument(hellas_rpc::request_span!(target: "hellas_request", "paid.executor.stream"))
        .await
    }
}

/// Reads one execution's events to its end, and returns the transcript
/// it finished with.
///
/// A failure and a stream that simply stops are two different faults and
/// are reported as two: the first is what the engine said went wrong,
/// the second is that it never said anything.
#[cfg(test)]
async fn drain_transcript(
    outcome: crate::executor::ExecuteOutcome,
) -> Result<Vec<OutputEventEnvelope>, ExecutorError> {
    drain_transcript_with_progress(outcome, None).await
}

async fn drain_transcript_with_progress(
    outcome: crate::executor::ExecuteOutcome,
    progress: Option<PaidProgress>,
) -> Result<Vec<OutputEventEnvelope>, ExecutorError> {
    use hellas_rpc::pb::execute::work_event;

    let mut events = outcome.events;
    let mut transcript = Vec::new();
    let mut terminal_seen = false;
    while let Some(event) = events.recv().await {
        if terminal_seen {
            return Err(ExecutorError::Execution(
                "paid evaluate stream emitted an item after its terminal outcome".to_string(),
            ));
        }
        let event = event.map_err(|status| {
            ExecutorError::Execution(format!("paid evaluate stream failed: {status}"))
        })?;
        match event.kind {
            Some(work_event::Kind::Chunk(chunk)) => {
                let event = chunk.output_event.ok_or_else(|| {
                    ExecutorError::Execution(
                        "paid evaluate chunk is missing its signed output event".to_string(),
                    )
                })?;
                transcript.push(hellas_rpc::stream::output_event_from_pb(event).map_err(
                    |err| ExecutorError::Execution(format!("paid evaluate output event: {err}")),
                )?);
                if let Some(progress) = &progress {
                    progress(transcript.last().expect("chunk was appended").clone())
                        .map_err(|error| ExecutorError::Execution(error.to_string()))?;
                }
            }
            Some(work_event::Kind::Finished(finished)) => {
                let event = finished.terminal_output_event.ok_or_else(|| {
                    ExecutorError::Execution(
                        "paid evaluate completion is missing its signed terminal event".to_string(),
                    )
                })?;
                transcript.push(hellas_rpc::stream::output_event_from_pb(event).map_err(
                    |err| ExecutorError::Execution(format!("paid evaluate terminal event: {err}")),
                )?);
                terminal_seen = true;
            }
            Some(work_event::Kind::Failed(failed)) => {
                return Err(ExecutorError::Execution(format!(
                    "paid evaluate failed at position {}: {}",
                    failed.position, failed.error
                )));
            }
            None => {
                return Err(ExecutorError::Execution(
                    "paid evaluate stream event has no body".to_string(),
                ));
            }
        }
    }
    if terminal_seen {
        Ok(transcript)
    } else {
        Err(ExecutorError::Execution(
            "paid evaluate stream ended without a terminal".to_string(),
        ))
    }
}

impl PaidWorkBackend for ExecutorHandle {
    async fn fetch(
        &self,
        input: hellas_work::work::PreparedFetchInput,
    ) -> Result<Vec<OutputEventEnvelope>, BackendFault> {
        self.send_owed(|reply| ExecutorOwedRequest::RunPaidFetch {
            input: Box::new(input),
            reply,
        })
        .await
        .map_err(|error| BackendFault::new(error.to_string()))
    }

    async fn evaluate(
        &self,
        input: PreparedEvaluateInput,
    ) -> Result<Vec<OutputEventEnvelope>, BackendFault> {
        self.run_paid_evaluate(input)
            .await
            .map_err(|error| BackendFault::new(error.to_string()))
    }
    async fn evaluate_stream(
        &self,
        input: PreparedEvaluateInput,
        progress: PaidProgress,
    ) -> Result<Vec<OutputEventEnvelope>, BackendFault> {
        self.run_paid_evaluate_stream(input, Some(progress))
            .await
            .map_err(|error| BackendFault::new(error.to_string()))
    }
}

#[cfg(test)]
mod tests;
