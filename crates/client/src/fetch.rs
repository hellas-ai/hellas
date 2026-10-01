use std::sync::Arc;

use hellas_rpc::execution_event::{WorkEvent, WorkFinished, work_event};
#[cfg(test)]
use hellas_rpc::fetch::verify_output_events;
use hellas_rpc::fetch::{
    FetchInput, FetchTerminalPayload, MAX_FETCH_OUTPUT_EVENTS, MAX_FETCH_OUTPUT_PAYLOAD_BYTES,
    decode_fetch_event_payload, decode_fetch_terminal_payload, output_canonicalization,
    verify_input_events,
};
use hellas_rpc::output::OutputEvent;
use hellas_rpc::pb::fetch::FetchRequest;
use hellas_rpc::stream::{input_event_from_pb, output_event_from_pb};
use hellas_rpc::{
    Assurance, EventCommitment, InputCommitment, Operation, OutputEventEnvelope, PublicKey,
    StreamId, output_genesis, scheme_id, verify_output_event_continuation,
};

use crate::{ClientError, ClientResult};

// Stream items move once per chunk; boxing the envelope would trade a large
// move for a per-chunk allocation with no call-site benefit.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq)]
pub enum FetchExecutionEvent {
    Chunk {
        position: u64,
        output_event: OutputEventEnvelope,
        event: OutputEvent,
    },
    Done(FetchOutcome),
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
enum DecodedFetchWireEvent {
    Chunk {
        output_event: OutputEventEnvelope,
        event: OutputEvent,
    },
    Finished {
        terminal_output_event: OutputEventEnvelope,
    },
    Failed {
        position: u64,
        error: String,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub enum FetchOutcome {
    /// A complete producer-signed output transcript.
    Completed {
        output_events: Vec<OutputEventEnvelope>,
        terminal: FetchTerminalPayload,
    },
    /// An unsigned execution failure. Remote Fetch authenticates its source
    /// only through the retained verified transport; this is not transcript
    /// evidence and callers must surface it as failure.
    Failed { position: u64, error: String },
}

/// Producer keys a fetch caller accepts signed output from.
#[derive(Clone, Debug)]
pub struct ProducerTrust {
    keys: Arc<Vec<PublicKey>>,
}

impl ProducerTrust {
    pub fn keys(keys: impl IntoIterator<Item = PublicKey>) -> Self {
        Self {
            keys: Arc::new(keys.into_iter().collect()),
        }
    }

    fn allows(&self, key: &PublicKey) -> bool {
        self.keys.contains(key)
    }
}

pub struct FetchChunkVerifier {
    input: InputCommitment,
    stream_id: StreamId,
    previous_event: EventCommitment,
    next_sequence: u64,
    next_position: u64,
    trust: ProducerTrust,
    producer_key: Option<PublicKey>,
    assurance: Assurance,
    events: Vec<OutputEventEnvelope>,
    finalized: bool,
}

impl FetchChunkVerifier {
    pub fn new(input: InputCommitment, assurance: Assurance, trust: ProducerTrust) -> Self {
        let stream_id = StreamId::from_input_commitment(input);
        Self {
            input,
            stream_id,
            previous_event: output_genesis(input, stream_id),
            next_sequence: 0,
            next_position: 0,
            trust,
            producer_key: None,
            assurance,
            events: Vec::new(),
            finalized: false,
        }
    }

    fn ensure_open(&self) -> ClientResult<()> {
        if self.finalized {
            Err(ClientError::protocol(
                "fetch stream emitted an event after its terminal outcome",
            ))
        } else {
            Ok(())
        }
    }

    pub fn verify_chunk(
        &mut self,
        event: OutputEventEnvelope,
    ) -> ClientResult<(u64, OutputEventEnvelope)> {
        self.ensure_open()?;
        let max_streamed_events = MAX_FETCH_OUTPUT_EVENTS
            .checked_sub(1)
            .expect("Fetch output limit includes one terminal event");
        if self.events.len() >= max_streamed_events {
            return Err(ClientError::protocol(format!(
                "fetch output stream exceeds the {max_streamed_events}-chunk limit"
            )));
        }
        let public_key = *event.event().public_key();
        match self.producer_key {
            Some(expected) if expected != public_key => {
                return Err(ClientError::protocol(
                    "fetch output chunk producer key changed mid-stream",
                ));
            }
            Some(_) => {}
            None => {
                if !self.trust.allows(&public_key) {
                    return Err(ClientError::protocol(
                        "fetch output chunk signed by untrusted producer key",
                    ));
                }
            }
        }
        event.verify(&public_key).map_err(|source| {
            ClientError::source("fetch output chunk signature verification failed", source)
        })?;
        let body = event.event().body();
        if body.scheme() != scheme_id(Operation::Fetch, self.assurance) {
            return Err(ClientError::protocol(
                "fetch output chunk used the wrong scheme",
            ));
        }
        if body.input() != self.input {
            return Err(ClientError::protocol(
                "fetch output chunk input commitment mismatch",
            ));
        }
        if body.stream_id() != self.stream_id {
            return Err(ClientError::protocol(
                "fetch output chunk stream id mismatch",
            ));
        }
        if body.sequence() != self.next_sequence {
            return Err(ClientError::protocol(format!(
                "fetch output chunk sequence mismatch: expected {}, got {}",
                self.next_sequence,
                body.sequence()
            )));
        }
        if body.previous_event() != self.previous_event {
            return Err(ClientError::protocol(
                "fetch output chunk previous-event mismatch",
            ));
        }
        if body.kind() != "response.event" {
            return Err(ClientError::protocol(format!(
                "fetch output chunk must be response.event, got {}",
                body.kind()
            )));
        }
        if body.canonicalization() != output_canonicalization() {
            return Err(ClientError::protocol(
                "fetch output chunk canonicalization mismatch",
            ));
        }
        let payload_len = u64::try_from(event.payload().len()).map_err(|_| {
            ClientError::protocol("fetch output chunk length exceeds u64 position range")
        })?;
        let next_position = self.next_position.checked_add(payload_len).ok_or_else(|| {
            ClientError::protocol("fetch output position exceeds u64 position range")
        })?;
        if next_position > MAX_FETCH_OUTPUT_PAYLOAD_BYTES as u64 {
            return Err(ClientError::protocol(format!(
                "fetch output stream exceeds the {MAX_FETCH_OUTPUT_PAYLOAD_BYTES}-byte signed payload limit"
            )));
        }
        let next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or_else(|| ClientError::protocol("fetch output sequence exceeds u64 range"))?;
        self.next_position = next_position;
        self.previous_event = event.event_commitment();
        self.next_sequence = next_sequence;
        if self.producer_key.is_none() {
            self.producer_key = Some(public_key);
        }
        self.events.push(event.clone());
        Ok((self.next_position, event))
    }

    pub fn verify_terminal(
        &mut self,
        terminal: OutputEventEnvelope,
    ) -> ClientResult<FetchTerminalPayload> {
        self.ensure_open()?;
        let event_count = self.events.len().checked_add(1).ok_or_else(|| {
            ClientError::protocol("fetch terminal transcript event count exceeds usize range")
        })?;
        if event_count > MAX_FETCH_OUTPUT_EVENTS {
            return Err(ClientError::protocol(format!(
                "fetch output transcript exceeds the {MAX_FETCH_OUTPUT_EVENTS}-event limit"
            )));
        }
        if terminal.event().body().input() != self.input {
            return Err(ClientError::protocol(
                "fetch terminal event input commitment mismatch",
            ));
        }
        let terminal_key = *terminal.event().public_key();
        match self.producer_key {
            Some(pinned) if pinned != terminal_key => {
                return Err(ClientError::protocol(
                    "fetch terminal event producer key does not match streamed chunks",
                ));
            }
            Some(_) => {}
            None => {
                if !self.trust.allows(&terminal_key) {
                    return Err(ClientError::protocol(
                        "fetch terminal event signed by untrusted producer key",
                    ));
                }
            }
        }
        verify_output_event_continuation(
            scheme_id(Operation::Fetch, self.assurance),
            self.input,
            &terminal_key,
            self.next_sequence,
            self.previous_event,
            &terminal,
        )
        .map_err(|source| ClientError::FetchTranscript {
            source: source.into(),
        })?;
        let body = terminal.event().body();
        if body.kind() != "response.terminal" {
            return Err(ClientError::protocol(format!(
                "fetch terminal event must be response.terminal, got {}",
                body.kind()
            )));
        }
        if body.canonicalization() != output_canonicalization() {
            return Err(ClientError::protocol(
                "fetch terminal event canonicalization mismatch",
            ));
        }
        let terminal_payload_len = u64::try_from(terminal.payload().len()).map_err(|_| {
            ClientError::protocol("fetch terminal payload length exceeds u64 range")
        })?;
        let payload_bytes = self
            .next_position
            .checked_add(terminal_payload_len)
            .ok_or_else(|| {
                ClientError::protocol("fetch output payload length exceeds u64 range")
            })?;
        if payload_bytes > MAX_FETCH_OUTPUT_PAYLOAD_BYTES as u64 {
            return Err(ClientError::protocol(format!(
                "fetch output transcript exceeds the {MAX_FETCH_OUTPUT_PAYLOAD_BYTES}-byte signed payload limit"
            )));
        }
        let terminal_payload =
            decode_fetch_terminal_payload(terminal.payload()).map_err(|source| {
                ClientError::source("fetch terminal payload decode failed", source)
            })?;
        self.events.push(terminal);
        self.finalized = true;
        Ok(terminal_payload)
    }

    fn verify_failed_terminal(&mut self, position: u64) -> ClientResult<()> {
        self.ensure_open()?;
        if position != self.next_position {
            return Err(ClientError::protocol(format!(
                "fetch failure position mismatch: expected {}, got {position}",
                self.next_position
            )));
        }
        self.finalized = true;
        Ok(())
    }
}

pub fn verify_fetch_work_event(
    verifier: &mut FetchChunkVerifier,
    event: WorkEvent,
) -> ClientResult<FetchExecutionEvent> {
    match convert_fetch_wire_event(event)? {
        DecodedFetchWireEvent::Chunk {
            output_event,
            event,
        } => {
            let (position, output_event) = verifier.verify_chunk(output_event)?;
            Ok(FetchExecutionEvent::Chunk {
                position,
                output_event,
                event,
            })
        }
        DecodedFetchWireEvent::Finished {
            terminal_output_event,
        } => {
            let terminal = verifier.verify_terminal(terminal_output_event)?;
            let output_events = std::mem::take(&mut verifier.events);
            Ok(FetchExecutionEvent::Done(FetchOutcome::Completed {
                output_events,
                terminal,
            }))
        }
        DecodedFetchWireEvent::Failed { position, error } => {
            verifier.verify_failed_terminal(position)?;
            Ok(FetchExecutionEvent::Done(FetchOutcome::Failed {
                position,
                error,
            }))
        }
    }
}

fn convert_fetch_wire_event(event: WorkEvent) -> ClientResult<DecodedFetchWireEvent> {
    let Some(event) = event.kind else {
        return Err(ClientError::protocol("wire event with no body"));
    };
    match event {
        work_event::Kind::Chunk(chunk) => {
            let output_event = chunk.output_event.ok_or_else(|| {
                ClientError::protocol("fetch work chunk missing signed output event")
            })?;
            let output_event = output_event_from_pb(output_event)
                .map_err(|source| ClientError::FetchStreamEnvelope { source })?;
            let event = decode_fetch_event_payload(output_event.payload()).map_err(|source| {
                ClientError::source("fetch output event payload decode failed", source)
            })?;
            Ok(DecodedFetchWireEvent::Chunk {
                output_event,
                event,
            })
        }
        work_event::Kind::Finished(finished) => Ok(DecodedFetchWireEvent::Finished {
            terminal_output_event: decode_fetch_terminal(finished)?,
        }),
        work_event::Kind::Failed(failed) => Ok(DecodedFetchWireEvent::Failed {
            position: failed.position,
            error: failed.error,
        }),
    }
}

#[cfg(test)]
pub(crate) fn parse_fetch_finished(
    finished: WorkFinished,
    input_commitment: InputCommitment,
    assurance: Assurance,
) -> ClientResult<FetchOutcome> {
    let output_events = vec![decode_fetch_terminal(finished)?];
    let output = verify_output_events(input_commitment, assurance, &output_events)
        .map_err(|source| ClientError::FetchTranscript { source })?;
    let (_, terminal_payload) = output.output_event_payloads();
    let terminal = decode_fetch_terminal_payload(terminal_payload)
        .map_err(|source| ClientError::source("fetch terminal payload decode failed", source))?;
    Ok(FetchOutcome::Completed {
        output_events,
        terminal,
    })
}

fn decode_fetch_terminal(finished: WorkFinished) -> ClientResult<OutputEventEnvelope> {
    let terminal = finished
        .terminal_output_event
        .ok_or_else(|| ClientError::protocol("fetch WorkFinished missing signed terminal event"))?;
    if terminal.payload.len() > MAX_FETCH_OUTPUT_PAYLOAD_BYTES {
        return Err(ClientError::protocol(format!(
            "fetch terminal event exceeds the {MAX_FETCH_OUTPUT_PAYLOAD_BYTES}-byte signed payload limit"
        )));
    }
    output_event_from_pb(terminal).map_err(|source| ClientError::FetchStreamEnvelope { source })
}

pub fn verified_fetch_input(request: &FetchRequest) -> ClientResult<FetchInput> {
    let input = request
        .input
        .iter()
        .cloned()
        .map(input_event_from_pb)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| ClientError::FetchStreamEnvelope { source })?;
    verify_input_events(&input).map_err(|source| ClientError::FetchTranscript { source })
}

#[cfg(test)]
mod tests;
