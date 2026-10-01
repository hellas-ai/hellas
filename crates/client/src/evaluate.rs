use hellas_rpc::evaluate::{
    EvaluateOutput, EvaluateTokenDelta, TERMINAL_EVENT_KIND, TOKEN_DELTA_EVENT_KIND,
    decode_terminal_payload, decode_token_delta_payload, output_canonicalization,
};
use hellas_rpc::execution_event::{WorkEvent, work_event};
use hellas_rpc::protocol::artifacts::{OutputAddressed, TextExecutionId, completed_text};
use hellas_rpc::stream::output_event_from_pb;
use hellas_rpc::{
    Assurance, Digest, EventCommitment, InputCommitment, Operation, OutputEventEnvelope, PublicKey,
    StreamId, normalize_stop_token_ids, output_genesis, scheme_id,
    verify_output_event_continuation,
};

use crate::{ClientError, ClientResult};

/// One verified observation from an evaluate execution stream.
#[derive(Debug, Clone)]
pub enum EvaluateExecutionEvent {
    Chunk {
        /// Cumulative token position after this chunk.
        position: u64,
        /// Little-endian `u32` token IDs for caller-selected local decoding.
        tokens: Vec<u8>,
    },
    Done(EvaluateOutcome),
}

/// Terminal result of a verified evaluate execution stream.
#[derive(Debug, Clone)]
pub enum EvaluateOutcome {
    Completed {
        output: EvaluateOutput,
        output_events: Vec<OutputEventEnvelope>,
    },
    Failed {
        position: u64,
        error: String,
    },
}

pub struct EvaluateChunkVerifier {
    input: InputCommitment,
    stream_id: StreamId,
    previous_event: EventCommitment,
    next_sequence: u64,
    next_position: u64,
    expected_producer_key: PublicKey,
    max_output_tokens: u64,
    vocabulary_size: u64,
    stop_token_ids: Vec<u32>,
    assurance: Assurance,
    events: Vec<OutputEventEnvelope>,
    generated_token_ids: Vec<u32>,
    text_artifact_expectation: Option<TextArtifactExpectation>,
    finalized: bool,
}

struct TextArtifactExpectation {
    execution: TextExecutionId,
    full_input_ids: Vec<u32>,
}

impl EvaluateChunkVerifier {
    pub fn new(
        input: InputCommitment,
        assurance: Assurance,
        expected_producer_key: PublicKey,
        max_output_tokens: u32,
        vocabulary_size: u64,
        mut stop_token_ids: Vec<u32>,
    ) -> Self {
        normalize_stop_token_ids(&mut stop_token_ids);
        let stream_id = StreamId::from_input_commitment(input);
        Self {
            input,
            stream_id,
            previous_event: output_genesis(input, stream_id),
            next_sequence: 0,
            next_position: 0,
            expected_producer_key,
            max_output_tokens: u64::from(max_output_tokens),
            vocabulary_size,
            stop_token_ids,
            assurance,
            events: Vec::new(),
            generated_token_ids: Vec::new(),
            text_artifact_expectation: None,
            finalized: false,
        }
    }

    /// Require the signed terminal artifact to be the canonical artifact
    /// derived from this text execution, its full input, and the verified
    /// streamed output tokens.
    #[must_use]
    pub fn with_text_artifact_expectation(
        mut self,
        execution: TextExecutionId,
        full_input_ids: Vec<u32>,
    ) -> Self {
        self.text_artifact_expectation = Some(TextArtifactExpectation {
            execution,
            full_input_ids,
        });
        self
    }

    pub const fn assurance(&self) -> Assurance {
        self.assurance
    }

    pub fn verify_chunk(
        &mut self,
        event: OutputEventEnvelope,
    ) -> ClientResult<(u64, EvaluateTokenDelta)> {
        self.ensure_active()?;
        let public_key = *event.event().public_key();
        if public_key != self.expected_producer_key {
            return Err(ClientError::protocol(
                "evaluate output chunk signed by the wrong producer key",
            ));
        }
        event
            .verify(&self.expected_producer_key)
            .map_err(|source| {
                ClientError::source(
                    "evaluate output chunk signature verification failed",
                    source,
                )
            })?;
        let body = event.event().body();
        if body.scheme() != scheme_id(Operation::Evaluate, self.assurance) {
            return Err(ClientError::protocol(
                "evaluate output chunk used the wrong scheme",
            ));
        }
        if body.input() != self.input {
            return Err(ClientError::protocol(
                "evaluate output chunk input commitment mismatch",
            ));
        }
        if body.stream_id() != self.stream_id {
            return Err(ClientError::protocol(
                "evaluate output chunk stream id mismatch",
            ));
        }
        if body.sequence() != self.next_sequence {
            return Err(ClientError::protocol(format!(
                "evaluate output chunk sequence mismatch: expected {}, got {}",
                self.next_sequence,
                body.sequence()
            )));
        }
        if body.previous_event() != self.previous_event {
            return Err(ClientError::protocol(
                "evaluate output chunk previous-event mismatch",
            ));
        }
        if body.kind() != TOKEN_DELTA_EVENT_KIND {
            return Err(ClientError::protocol(format!(
                "evaluate output chunk must be {TOKEN_DELTA_EVENT_KIND}, got {}",
                body.kind()
            )));
        }
        if body.canonicalization() != output_canonicalization() {
            return Err(ClientError::protocol(
                "evaluate output chunk canonicalization mismatch",
            ));
        }
        let delta = decode_token_delta_payload(event.payload())
            .map_err(|source| ClientError::EvaluateTranscript { source })?;
        if delta.start_position != self.next_position {
            return Err(ClientError::protocol(format!(
                "evaluate output chunk token position mismatch: expected {}, got {}",
                self.next_position, delta.start_position
            )));
        }
        if let Some(token_id) = delta
            .token_ids
            .iter()
            .copied()
            .find(|token_id| u64::from(*token_id) >= self.vocabulary_size)
        {
            return Err(ClientError::protocol(format!(
                "evaluate output token {token_id} is outside the committed vocabulary of {} tokens",
                self.vocabulary_size
            )));
        }
        let next_position = delta
            .end_position()
            .map_err(|source| ClientError::EvaluateTranscript { source })?;
        self.ensure_output_position(next_position)?;
        let next_sequence = self.next_sequence.checked_add(1).ok_or_else(|| {
            ClientError::protocol("evaluate output chunk sequence exceeds u64 range")
        })?;

        self.next_position = next_position;
        self.previous_event = event.event_commitment();
        self.next_sequence = next_sequence;
        self.generated_token_ids
            .extend(delta.token_ids.iter().copied());
        self.events.push(event);
        Ok((self.next_position, delta))
    }

    pub fn verify_terminal(
        &mut self,
        terminal: OutputEventEnvelope,
    ) -> ClientResult<EvaluateOutput> {
        self.ensure_active()?;
        if *terminal.event().public_key() != self.expected_producer_key {
            return Err(ClientError::protocol(
                "evaluate terminal event signed by the wrong producer key",
            ));
        }
        if terminal.event().body().input() != self.input {
            return Err(ClientError::protocol(
                "evaluate terminal event input commitment mismatch",
            ));
        }
        let expected_event_count = self.events.len().checked_add(1).ok_or_else(|| {
            ClientError::protocol("evaluate terminal transcript event count exceeds usize range")
        })?;
        let event_count = u64::try_from(expected_event_count).map_err(|_| {
            ClientError::protocol("evaluate terminal transcript event count exceeds u64 range")
        })?;
        let max_event_count = self.max_output_tokens + 1;
        if event_count > max_event_count {
            return Err(ClientError::protocol(format!(
                "evaluate terminal transcript has {event_count} events, exceeding the limit of {max_event_count}"
            )));
        }
        verify_output_event_continuation(
            scheme_id(Operation::Evaluate, self.assurance),
            self.input,
            &self.expected_producer_key,
            self.next_sequence,
            self.previous_event,
            &terminal,
        )
        .map_err(|source| ClientError::EvaluateTranscript {
            source: source.into(),
        })?;
        let body = terminal.event().body();
        if body.kind() != TERMINAL_EVENT_KIND {
            return Err(ClientError::protocol(format!(
                "evaluate terminal event must be {TERMINAL_EVENT_KIND}, got {}",
                body.kind()
            )));
        }
        if body.canonicalization() != output_canonicalization() {
            return Err(ClientError::protocol(
                "evaluate terminal event canonicalization mismatch",
            ));
        }
        let terminal_payload = decode_terminal_payload(terminal.payload())
            .map_err(|source| ClientError::EvaluateTranscript { source })?;
        if terminal_payload.final_position != self.next_position {
            return Err(ClientError::protocol(format!(
                "evaluate terminal position mismatch: expected {}, got {}",
                self.next_position, terminal_payload.final_position
            )));
        }
        let token_deltas = self
            .events
            .iter()
            .map(|event| decode_token_delta_payload(event.payload()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|source| ClientError::EvaluateTranscript { source })?;
        let output = EvaluateOutput {
            producer_key: self.expected_producer_key,
            token_deltas,
            terminal: terminal_payload,
        };
        self.ensure_output_position(output.terminal.final_position)?;
        if output.terminal.stop_reason == hellas_rpc::evaluate::EvaluateStopReason::MAX_OUTPUT
            && output.terminal.final_position != self.max_output_tokens
        {
            return Err(ClientError::protocol(format!(
                "evaluate MAX_OUTPUT terminal position must equal the requested maximum {}: got {}",
                self.max_output_tokens, output.terminal.final_position
            )));
        }
        if output.terminal.stop_reason == hellas_rpc::evaluate::EvaluateStopReason::STOP_TOKEN {
            if output.terminal.final_position >= self.max_output_tokens {
                return Err(ClientError::protocol(
                    "evaluate STOP_TOKEN terminal must occur before the requested maximum",
                ));
            }
            let matched = output.terminal.matched_stop_token_id.ok_or_else(|| {
                ClientError::protocol("evaluate STOP_TOKEN terminal is missing its matched token")
            })?;
            if self.stop_token_ids.binary_search(&matched).is_err() {
                return Err(ClientError::protocol(format!(
                    "evaluate STOP_TOKEN terminal matched uncommitted token {matched}"
                )));
            }
        }
        if let Some(expected) = &self.text_artifact_expectation {
            let input_units = u64::try_from(expected.full_input_ids.len()).map_err(|_| {
                ClientError::protocol("evaluate input token count exceeds u64 range")
            })?;
            if output.terminal.usage.input_units != input_units {
                return Err(ClientError::protocol(format!(
                    "evaluate terminal input usage mismatch: expected {input_units}, got {}",
                    output.terminal.usage.input_units
                )));
            }
            let derived = completed_text(
                expected.execution,
                &expected.full_input_ids,
                &self.generated_token_ids,
            )
            .artifact
            .output_id()
            .digest();
            if output.terminal.text_artifact != derived {
                return Err(ClientError::protocol(format!(
                    "evaluate terminal text artifact does not match the verified token stream: claimed {}, derived {derived}",
                    output.terminal.text_artifact
                )));
            }
        }
        self.events.push(terminal);
        self.finalized = true;
        Ok(output)
    }

    fn verify_failure(&mut self, position: u64) -> ClientResult<()> {
        self.ensure_active()?;
        self.ensure_output_position(position)?;
        if position != self.next_position {
            return Err(ClientError::protocol(format!(
                "evaluate failure position mismatch: expected {}, got {position}",
                self.next_position
            )));
        }
        self.finalized = true;
        Ok(())
    }

    fn ensure_active(&self) -> ClientResult<()> {
        if self.finalized {
            return Err(ClientError::protocol("evaluate stream already finalized"));
        }
        Ok(())
    }

    fn ensure_output_position(&self, position: u64) -> ClientResult<()> {
        if position > self.max_output_tokens {
            return Err(ClientError::protocol(format!(
                "evaluate output position {position} exceeds requested maximum {}",
                self.max_output_tokens
            )));
        }
        Ok(())
    }
}

pub fn evaluate_input_from_request_commitment(
    request_commitment: &[u8],
) -> ClientResult<InputCommitment> {
    let digest: [u8; 32] = request_commitment.try_into().map_err(|_| {
        ClientError::protocol(format!(
            "request_commitment must be 32 bytes, got {}",
            request_commitment.len()
        ))
    })?;
    Ok(InputCommitment::from_digest(Digest::from_bytes(digest)))
}

/// Decode and verify one evaluate [`WorkEvent`].
///
/// This is transport-neutral: callers may obtain events through iroh,
/// WebSocket, an in-process executor, or any other Hellas `StreamTransport`.
pub fn verify_evaluate_work_event(
    verifier: &mut EvaluateChunkVerifier,
    event: WorkEvent,
    input_commitment: InputCommitment,
) -> ClientResult<EvaluateExecutionEvent> {
    if input_commitment != verifier.input {
        return Err(ClientError::protocol(
            "evaluate work verifier input commitment mismatch",
        ));
    }
    let Some(event) = event.kind else {
        return Err(ClientError::protocol("wire event with no body"));
    };
    verifier.ensure_active()?;
    match event {
        work_event::Kind::Chunk(chunk) => {
            let output_event = chunk.output_event.ok_or_else(|| {
                ClientError::protocol("evaluate work chunk missing signed output event")
            })?;
            let output_event = output_event_from_pb(output_event).map_err(|source| {
                ClientError::source("evaluate output event decode failed", source)
            })?;
            let (position, delta) = verifier.verify_chunk(output_event)?;
            Ok(EvaluateExecutionEvent::Chunk {
                position,
                tokens: delta.token_bytes(),
            })
        }
        work_event::Kind::Finished(finished) => {
            let terminal = finished.terminal_output_event.ok_or_else(|| {
                ClientError::protocol("evaluate WorkFinished missing signed terminal event")
            })?;
            let terminal = output_event_from_pb(terminal).map_err(|source| {
                ClientError::source("evaluate terminal event decode failed", source)
            })?;
            let output = verifier.verify_terminal(terminal)?;
            let output_events = std::mem::take(&mut verifier.events);
            Ok(EvaluateExecutionEvent::Done(EvaluateOutcome::Completed {
                output,
                output_events,
            }))
        }
        work_event::Kind::Failed(failed) => {
            verifier.verify_failure(failed.position)?;
            Ok(EvaluateExecutionEvent::Done(EvaluateOutcome::Failed {
                position: failed.position,
                error: failed.error,
            }))
        }
    }
}

#[cfg(test)]
mod tests;
