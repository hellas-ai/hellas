//! Run one admitted Fetch and build its signed transcript.
use crate::executor::{FetchProviderFailure, FetchProviderRun};
use crate::fetch_projection::{FetchProjector, ProjectedFetch};
use crate::fetch_provider::{FetchProvider, FetchProviderError, PreparedFetchRequest};
use futures_util::StreamExt;
use hellas_rpc::execution_event::{WorkChunk, WorkEvent, work_event};
use hellas_rpc::fetch::{
    FetchOutputTranscriptBuilder, MAX_FETCH_OUTPUT_EVENTS, MAX_FETCH_OUTPUT_PAYLOAD_BYTES,
};
use hellas_rpc::stream::output_event_to_pb;
use hellas_rpc::{InputCommitment, ProducerSigningKey};
use std::sync::Arc;
use tokio::sync::mpsc;
pub(super) const PER_EXECUTION_CHANNEL_CAPACITY: usize = 64;
const FETCH_STREAM_DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(90);
const FETCH_STREAM_STALLED_ERROR: &str =
    "fetch stream consumer did not drain its bounded event channel";

#[derive(Debug, Default)]
struct FetchProjectionBudget {
    events: usize,
    signed_payload_bytes: usize,
}

impl FetchProjectionBudget {
    fn record_event(&mut self, payload_len: usize) -> Result<u64, FetchProviderError> {
        let streamed_event_limit = MAX_FETCH_OUTPUT_EVENTS
            .checked_sub(1)
            .expect("Fetch output limit includes one terminal event");
        self.record(payload_len, streamed_event_limit)
    }

    fn record_terminal(&mut self, payload_len: usize) -> Result<(), FetchProviderError> {
        self.record(payload_len, MAX_FETCH_OUTPUT_EVENTS)
            .map(|_| ())
    }

    fn record(
        &mut self,
        payload_len: usize,
        event_limit: usize,
    ) -> Result<u64, FetchProviderError> {
        let events = self.events.checked_add(1).ok_or_else(|| {
            FetchProviderError::failed(format!(
                "fetch projection exceeded the {event_limit}-event limit"
            ))
        })?;
        let signed_payload_bytes = self
            .signed_payload_bytes
            .checked_add(payload_len)
            .ok_or_else(|| {
                FetchProviderError::failed(format!(
                    "fetch projection exceeded the {MAX_FETCH_OUTPUT_PAYLOAD_BYTES}-byte signed payload limit"
                ))
            })?;
        if events > event_limit {
            return Err(FetchProviderError::failed(format!(
                "fetch projection exceeded the {event_limit}-event limit"
            )));
        }
        if signed_payload_bytes > MAX_FETCH_OUTPUT_PAYLOAD_BYTES {
            return Err(FetchProviderError::failed(format!(
                "fetch projection exceeded the {MAX_FETCH_OUTPUT_PAYLOAD_BYTES}-byte signed payload limit"
            )));
        }

        self.events = events;
        self.signed_payload_bytes = signed_payload_bytes;
        u64::try_from(payload_len)
            .map_err(|_| FetchProviderError::failed("fetch output position overflow"))
    }
}

pub(super) async fn run_fetch_provider(
    provider: Arc<dyn FetchProvider>,
    request: PreparedFetchRequest,
    mut projector: Box<dyn FetchProjector>,
    input_commitment: InputCommitment,
    assurance: hellas_rpc::Assurance,
    producer_key: &ProducerSigningKey,
    sender: mpsc::Sender<Result<WorkEvent, hellas_wire::WireStatus>>,
) -> Result<FetchProviderRun, FetchProviderFailure> {
    let mut builder = FetchOutputTranscriptBuilder::new(input_commitment, assurance, producer_key);
    let mut position = 0_u64;
    let mut terminal = None;
    let mut projection_budget = FetchProjectionBudget::default();
    let response = tokio::select! {
        response = provider.run(request) => response,
        _ = sender.closed() => Err(FetchProviderError::failed("fetch stream consumer disconnected")),
    }
        .map_err(|error| FetchProviderFailure { position, error })?;
    let projected = projector
        .begin(response.head)
        .map_err(|err| FetchProviderFailure {
            position,
            error: FetchProviderError::failed(format!("fetch projection failed: {err}")),
        })?;
    process_projected_fetch(
        projected,
        &mut builder,
        &mut terminal,
        &mut projection_budget,
        &mut position,
        &sender,
    )
    .await?;
    let mut stream = response.stream;

    loop {
        let next = tokio::select! {
            next = stream.next() => next,
            _ = sender.closed() => return Err(FetchProviderFailure {
                position, error: FetchProviderError::failed("fetch stream consumer disconnected"),
            }),
        };
        let Some(next) = next else {
            break;
        };
        let chunk = next.map_err(|error| FetchProviderFailure { position, error })?;
        let projected = projector
            .project(&chunk)
            .map_err(|err| FetchProviderFailure {
                position,
                error: FetchProviderError::failed(format!("fetch projection failed: {err}")),
            })?;
        let reached_terminal = process_projected_fetch(
            projected,
            &mut builder,
            &mut terminal,
            &mut projection_budget,
            &mut position,
            &sender,
        )
        .await?;
        if reached_terminal {
            // A terminal projection is the trusted end of the operation. Do
            // not let an upstream keep this task, connection, or credential
            // alive after it has supplied the complete result.
            drop(stream);
            break;
        }
    }

    if terminal.is_none() {
        let projected = projector.finish().map_err(|err| FetchProviderFailure {
            position,
            error: FetchProviderError::failed(format!("fetch projection failed: {err}")),
        })?;
        process_projected_fetch(
            projected,
            &mut builder,
            &mut terminal,
            &mut projection_budget,
            &mut position,
            &sender,
        )
        .await?;
    }
    let terminal_payload = terminal.ok_or_else(|| FetchProviderFailure {
        position,
        error: FetchProviderError::failed(
            "fetch provider ended without terminal event".to_string(),
        ),
    })?;
    let output_events = builder
        .finish(terminal_payload)
        .map_err(|err| FetchProviderFailure {
            position,
            error: FetchProviderError::failed(format!("fetch output transcript failed: {err}")),
        })?;
    Ok(FetchProviderRun { output_events })
}
async fn process_projected_fetch(
    projected: Vec<ProjectedFetch>,
    builder: &mut FetchOutputTranscriptBuilder<'_>,
    terminal: &mut Option<Vec<u8>>,
    projection_budget: &mut FetchProjectionBudget,
    position: &mut u64,
    sender: &mpsc::Sender<Result<WorkEvent, hellas_wire::WireStatus>>,
) -> Result<bool, FetchProviderFailure> {
    for item in projected {
        match item {
            ProjectedFetch::Event(payload) => {
                if terminal.is_some() {
                    return Err(FetchProviderFailure {
                        position: *position,
                        error: FetchProviderError::failed(
                            "fetch projection emitted an event after terminal".to_string(),
                        ),
                    });
                }
                // Reserve the event and terminal slots together. Temporary
                // backpressure must not truncate a valid upstream response.
                let mut permits =
                    tokio::time::timeout(FETCH_STREAM_DRAIN_TIMEOUT, sender.reserve_many(2))
                        .await
                        .map_err(|_| FetchProviderFailure {
                            position: *position,
                            error: FetchProviderError::failed(FETCH_STREAM_STALLED_ERROR),
                        })?
                        .map_err(|_| FetchProviderFailure {
                            position: *position,
                            error: FetchProviderError::failed("fetch stream consumer disconnected"),
                        })?;
                let payload_len =
                    projection_budget
                        .record_event(payload.len())
                        .map_err(|error| FetchProviderFailure {
                            position: *position,
                            error,
                        })?;
                let next_position =
                    position
                        .checked_add(payload_len)
                        .ok_or_else(|| FetchProviderFailure {
                            position: *position,
                            error: FetchProviderError::failed("fetch output position overflow"),
                        })?;
                let output_event =
                    builder
                        .push_event(payload)
                        .map_err(|err| FetchProviderFailure {
                            position: *position,
                            error: FetchProviderError::failed(format!(
                                "fetch output event transcript failed: {err}"
                            )),
                        })?;
                permits
                    .next()
                    .expect("two reserved permits")
                    .send(Ok(WorkEvent {
                        kind: Some(work_event::Kind::Chunk(WorkChunk {
                            output_event: Some(output_event_to_pb(&output_event)),
                        })),
                    }));
                drop(permits);
                *position = next_position;
            }
            ProjectedFetch::Terminal(payload) => {
                if terminal.is_some() {
                    return Err(FetchProviderFailure {
                        position: *position,
                        error: FetchProviderError::failed(
                            "fetch projection emitted multiple terminal events".to_string(),
                        ),
                    });
                }
                projection_budget
                    .record_terminal(payload.len())
                    .map_err(|error| FetchProviderFailure {
                        position: *position,
                        error,
                    })?;
                *terminal = Some(payload);
            }
        }
    }
    Ok(terminal.is_some())
}
