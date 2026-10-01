use super::*;

use hellas_rpc::evaluate::{
    EvaluateOutputTranscriptBuilder, EvaluateStopReason, EvaluateTerminal, EvaluateUsage,
    input_commitment,
};
use hellas_rpc::execution_event::{WorkChunk, WorkEvent, WorkFailed, WorkFinished, work_event};
use hellas_rpc::stream::output_event_to_pb;
use hellas_rpc::{Assurance, ContentId, Digest, EvaluateRequest, ProducerSigningKey, Retention};
use tokio::sync::mpsc;

use crate::executor::ExecuteOutcome;

fn key() -> ProducerSigningKey {
    match ProducerSigningKey::from_secret_bytes([0x22; 32]) {
        Ok(key) => key,
        Err(error) => panic!("a fixed scalar is a producer key: {error}"),
    }
}

fn request() -> EvaluateRequest {
    EvaluateRequest {
        text_execution: Digest::from_bytes([0x31; 32]),
        runner_public_key: key().public_key(),
        execution_environment: ContentId::from_bytes([0x32; 32]),
        nonce: [0x33; 32],
        assurance: Assurance::ProducerSigned,
        retain: true,
    }
}

/// One complete signed transcript for [`request`].
fn transcript() -> Vec<OutputEventEnvelope> {
    let request = request();
    let signer = key();
    let mut builder = EvaluateOutputTranscriptBuilder::new(
        input_commitment(&request),
        request.assurance,
        &signer,
    );
    if let Err(error) = builder.push_token_delta(vec![7, 8]) {
        panic!("a non-empty delta pushes: {error}");
    }
    let usage = EvaluateUsage {
        input_units: 3,
        output_units: 2,
    };
    let terminal = EvaluateTerminal {
        final_position: 2,
        stop_reason: EvaluateStopReason::STOP_TOKEN,
        matched_stop_token_id: Some(1),
        text_artifact: Digest::from_bytes([0x77; 32]),
        usage,
        billable_units: 5,
    };
    match builder.finish(terminal) {
        Ok(events) => events,
        Err(error) => panic!("the fixture transcript finishes: {error}"),
    }
}

/// An execution whose stream is exactly `events`, already ended.
fn outcome_items(events: Vec<Result<WorkEvent, hellas_wire::WireStatus>>) -> ExecuteOutcome {
    let (sender, receiver) = mpsc::channel(events.len().max(1));
    for event in events {
        if sender.try_send(event).is_err() {
            panic!("the fixture channel takes its own events");
        }
    }
    drop(sender);
    ExecuteOutcome { events: receiver }
}

fn outcome(events: Vec<WorkEvent>) -> ExecuteOutcome {
    outcome_items(events.into_iter().map(Ok).collect())
}

fn finished(transcript: &[OutputEventEnvelope]) -> WorkEvent {
    let terminal = transcript.last().expect("fixture terminal event");
    WorkEvent {
        kind: Some(work_event::Kind::Finished(WorkFinished {
            terminal_output_event: Some(output_event_to_pb(terminal)),
            assurance_evidence: Vec::new(),
        })),
    }
}

/// One streamed token-delta chunk, carrying a real signed event, as
/// the worker emits during generation.
fn chunk() -> WorkEvent {
    let Some(first) = transcript().first().map(output_event_to_pb) else {
        panic!("the fixture transcript has a first event");
    };
    WorkEvent {
        kind: Some(work_event::Kind::Chunk(WorkChunk {
            output_event: Some(first),
        })),
    }
}

/// Prefix chunks and the singular terminal frame reconstruct one transcript.
#[tokio::test]
async fn the_answer_combines_prefix_chunks_and_terminal() {
    let expected = transcript();
    let events = vec![chunk(), finished(&expected)];
    match drain_transcript(outcome(events)).await {
        Ok(drained) => assert_eq!(drained, expected),
        Err(error) => panic!("a finished execution has a transcript: {error}"),
    }
}

#[tokio::test]
async fn a_post_terminal_event_is_a_protocol_fault() {
    let transcript = transcript();
    for suffix in [chunk(), finished(&transcript)] {
        let events = vec![chunk(), finished(&transcript), suffix];
        let error = drain_transcript(outcome(events))
            .await
            .expect_err("an event after WorkFinished must be rejected");
        assert!(error.to_string().contains("after its terminal outcome"));
    }
}

#[tokio::test]
async fn a_post_terminal_stream_error_is_a_protocol_fault() {
    let transcript = transcript();
    let events = vec![
        Ok(chunk()),
        Ok(finished(&transcript)),
        Err(hellas_wire::WireStatus::internal("late transport failure")),
    ];
    let error = drain_transcript(outcome_items(events))
        .await
        .expect_err("an error after WorkFinished must be rejected");
    assert!(error.to_string().contains("after its terminal outcome"));
}

/// A failed execution is a fault, not an empty answer.
///
/// The difference matters to the gate above: a fault ends the job
/// and charges the client nothing, while an empty transcript would
/// be offered to `terminal_result` as if the provider had computed
/// something.
#[tokio::test]
async fn a_failed_execution_is_a_fault() {
    let events = vec![
        chunk(),
        WorkEvent {
            kind: Some(work_event::Kind::Failed(WorkFailed {
                position: 4,
                error: "the Catena environment did not run".to_string(),
            })),
        },
    ];
    let Err(error) = drain_transcript(outcome(events)).await else {
        panic!("a failed execution has no transcript");
    };
    let text = error.to_string();
    assert!(
        text.contains("the Catena environment did not run"),
        "{text}"
    );
    assert!(text.contains('4'), "{text}");
}

/// A stream that stops without saying anything is a fault too.
#[tokio::test]
async fn a_stream_without_a_terminal_is_a_fault() {
    for events in [Vec::new(), vec![chunk()]] {
        let Err(error) = drain_transcript(outcome(events)).await else {
            panic!("a stream with no terminal has no transcript");
        };
        assert!(error.to_string().contains("without a terminal"), "{error}",);
    }
}

/// Retention is a field of the request, not a gate on this seam.
///
/// A `retain=false` request is drained here exactly as a retained one
/// is, and the transcript that comes back is complete — which is
/// what the paid endpoint needs, because the evidence it journals is
/// the signed result and not a stored artifact. Nothing here reads
/// the artifact store, so nothing here can suppress the answer.
///
/// It says nothing about artifact publication. The evaluate engine
/// computes an ephemeral result without publishing its token graph.
#[tokio::test]
async fn an_unretained_request_still_yields_its_transcript() {
    let mut unretained = request();
    unretained.retain = false;
    assert_eq!(unretained.retention(), Retention::Ephemeral);
    assert_eq!(
        unretained.text_execution,
        request().text_execution,
        "retention is the only thing varied",
    );

    let signer = key();
    let mut builder = EvaluateOutputTranscriptBuilder::new(
        input_commitment(&unretained),
        unretained.assurance,
        &signer,
    );
    if let Err(error) = builder.push_token_delta(vec![7, 8]) {
        panic!("a non-empty delta pushes: {error}");
    }
    let events = match builder.finish(EvaluateTerminal {
        final_position: 2,
        stop_reason: EvaluateStopReason::STOP_TOKEN,
        matched_stop_token_id: Some(1),
        text_artifact: Digest::from_bytes([0x77; 32]),
        usage: EvaluateUsage {
            input_units: 3,
            output_units: 2,
        },
        billable_units: 5,
    }) {
        Ok(events) => events,
        Err(error) => panic!("the fixture transcript finishes: {error}"),
    };

    let prefix = WorkEvent {
        kind: Some(work_event::Kind::Chunk(WorkChunk {
            output_event: events.first().map(output_event_to_pb),
        })),
    };
    match drain_transcript(outcome(vec![prefix, finished(&events)])).await {
        Ok(drained) => assert_eq!(drained, events),
        Err(error) => panic!("an ephemeral request still has a transcript: {error}"),
    }

    // And it is a different transcript than the retained request's,
    // because the request commitment binds retention.
    assert_ne!(events, transcript());
}
