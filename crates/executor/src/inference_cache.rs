use hellas_rpc::cache::{
    CacheKey, CachePolicy, EvaluateEvent, EvaluateOutcome, EvaluateStop, Transcript,
};
use hellas_rpc::evaluate::{EvaluateStopReason, verify_output_events_for_producer};
use hellas_rpc::protocol::artifacts::{OutputAddressed, TextExecutionId, completed_text};
use hellas_rpc::provenance::ExecutionProvenance;
use hellas_rpc::{Assurance, Digest, InputCommitment, PublicKey};

use crate::ExecutorError;
use crate::state::{Invocation, StopReason};
use crate::worker::ExecuteJob;

pub(crate) fn replay(
    job: &ExecuteJob,
    on_progress: &mut impl FnMut(u32) -> Result<(), ExecutorError>,
) -> Result<Option<(StopReason, Vec<u32>)>, ExecutorError> {
    if job.output_cache.policy == CachePolicy::Off {
        return Ok(None);
    }
    let store = job
        .output_cache
        .store
        .as_ref()
        .ok_or_else(|| error("enabled cache has no store"))?;
    let key = CacheKey::evaluate(job.evaluate_request.text_execution);
    let Some(bytes) = store.get(&key).map_err(error)? else {
        if job.output_cache.policy == CachePolicy::ReplayOnly {
            return Err(error(format!("replay miss: {}", key.identity)));
        }
        return Ok(None);
    };
    let transcript: Transcript<EvaluateEvent, ExecutionProvenance> =
        serde_ipld_dagcbor::from_slice(&bytes).map_err(error)?;
    let output = validate(
        &transcript,
        &key,
        &job.invocation,
        job.evaluate_request.assurance,
        &job.producer_key.public_key(),
    )?;
    for token in &output.1 {
        on_progress(*token)?;
    }
    Ok(Some(output))
}

fn validate(
    transcript: &Transcript<EvaluateEvent, ExecutionProvenance>,
    key: &CacheKey,
    invocation: &Invocation,
    assurance: Assurance,
    producer_key: &PublicKey,
) -> Result<(StopReason, Vec<u32>), ExecutorError> {
    transcript
        .validate(key, EvaluateEvent::terminal)
        .map_err(error)?;
    let mut tokens = Vec::new();
    for event in &transcript.events {
        if let EvaluateEvent::Chunk {
            position,
            tokens: chunk,
        } = event
        {
            tokens.extend(hellas_rpc::decode_token_ids(chunk).map_err(error)?);
            if *position != tokens.len() as u64 {
                return Err(error("noncontiguous cached token stream"));
            }
        }
    }
    let Some(EvaluateEvent::Done(EvaluateOutcome::Completed {
        total_tokens,
        stop_reason,
        text_artifact,
        output_events,
    })) = transcript.events.last()
    else {
        return Err(error("missing cached evaluate terminal"));
    };
    let original_input = transcript
        .initial_provenance
        .as_ref()
        .ok_or_else(|| error("missing recorded input commitment"))?;
    let verified = verify_output_events_for_producer(
        InputCommitment::from_digest(Digest::from_bytes(original_input.commitment_id)),
        assurance,
        producer_key,
        output_events,
    )
    .map_err(error)?;
    let signed_stop = match verified.terminal.stop_reason {
        EvaluateStopReason::MAX_OUTPUT => EvaluateStop::MaxNewTokens,
        EvaluateStopReason::STOP_TOKEN => EvaluateStop::StopToken(
            verified
                .terminal
                .matched_stop_token_id
                .expect("verified stop witness"),
        ),
        _ => return Err(error("invalid signed stop reason")),
    };
    if !verified
        .token_deltas
        .iter()
        .flat_map(|delta| &delta.token_ids)
        .eq(tokens.iter())
        || verified.terminal.text_artifact != *text_artifact
        || verified.terminal.usage.input_units != invocation.input_ids.len() as u64
        || verified.terminal.billable_units != *total_tokens
        || signed_stop != *stop_reason
    {
        return Err(error("cached output disagrees with its signed transcript"));
    }
    let execution = key.identity.parse().map_err(error)?;
    let expected = completed_text(
        TextExecutionId::from_digest(execution),
        &invocation.input_ids,
        &tokens,
    )
    .artifact
    .output_id()
    .digest();
    if expected != *text_artifact
        || *total_tokens != (invocation.input_ids.len() + tokens.len()) as u64
        || tokens.len() > invocation.max_new_tokens as usize
    {
        return Err(error(
            "cached tokens disagree with the execution artifact or usage",
        ));
    }
    let stop = match stop_reason {
        EvaluateStop::MaxNewTokens if tokens.len() == invocation.max_new_tokens as usize => {
            StopReason::MaxNewTokens
        }
        EvaluateStop::StopToken(token) if invocation.stop_token_ids.contains(token) => {
            StopReason::StopToken(*token)
        }
        _ => return Err(error("cached stop reason disagrees with decode policy")),
    };
    Ok((stop, tokens))
}

pub(crate) async fn record(
    recording: Option<&hellas_rpc::cache::CacheRecording>,
    request: &hellas_rpc::EvaluateRequest,
    invocation: &Invocation,
    tokens: &[u32],
    stop: StopReason,
    text_artifact: hellas_rpc::Digest,
    output_events: &[hellas_rpc::OutputEventEnvelope],
) -> Result<(), ExecutorError> {
    let Some(recording) = recording.cloned() else {
        return Ok(());
    };
    let key = CacheKey::evaluate(request.text_execution);
    let transcript = Transcript {
        version: 1,
        key: key.clone(),
        initial_provenance: Some(ExecutionProvenance {
            commitment_id: *hellas_rpc::Evaluate::commit_request(request).as_bytes(),
        }),
        events: vec![
            EvaluateEvent::Chunk {
                position: tokens.len() as u64,
                tokens: hellas_rpc::encode_token_ids(tokens),
            },
            EvaluateEvent::Done(EvaluateOutcome::Completed {
                total_tokens: (invocation.input_ids.len() + tokens.len()) as u64,
                stop_reason: match stop {
                    StopReason::MaxNewTokens => EvaluateStop::MaxNewTokens,
                    StopReason::StopToken(token) => EvaluateStop::StopToken(token),
                },
                text_artifact,
                output_events: output_events.to_vec(),
            }),
        ],
    };
    let bytes = serde_ipld_dagcbor::to_vec(&transcript).map_err(error)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(error)?
        .as_secs();
    tokio::task::spawn_blocking(move || recording.insert(&key, &bytes, now))
        .await
        .map_err(error)?
        .map_err(error)
}

fn error(message: impl std::fmt::Display) -> ExecutorError {
    ExecutorError::ArtifactStore(format!("inference cache: {message}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hellas_rpc::cache::{CacheOptions, CacheStore, MemoryCacheStore};
    use hellas_rpc::evaluate::{
        EvaluateOutputTranscriptBuilder, EvaluateStopReason, EvaluateTerminal, EvaluateUsage,
        input_commitment, verify_output_events_for_producer,
    };
    use hellas_rpc::{Assurance, Digest, EvaluateRequest, ProducerSigningKey};
    use std::sync::Arc;

    async fn recorded_job() -> (ExecuteJob, Arc<MemoryCacheStore>, EvaluateTerminal) {
        let fixture = crate::evaluate::environment_admission_tests::EnvironmentFixture::new();
        let source = crate::environment::CausalLmEnvironmentSource::bind_manifest(
            &fixture.store,
            crate::environment::CausalLmEnvironmentSource::parse_manifest(&fixture.manifest_bytes)
                .unwrap(),
        )
        .unwrap();
        let producer = Arc::new(ProducerSigningKey::from_secret_bytes([1; 32]).unwrap());
        let mut request = EvaluateRequest {
            text_execution: Digest::from_bytes([9; 32]),
            execution_environment: fixture.manifest_id,
            runner_public_key: producer.public_key(),
            nonce: [2; 32],
            assurance: Assurance::ProducerSigned,
            retain: false,
        };
        let invocation = Invocation {
            input_ids: vec![1],
            max_new_tokens: 2,
            stop_token_ids: Vec::new(),
        };
        let tokens = vec![2, 3];
        let artifact = completed_text(
            TextExecutionId::from_digest(request.text_execution),
            &invocation.input_ids,
            &tokens,
        )
        .artifact
        .output_id()
        .digest();
        let terminal = EvaluateTerminal {
            final_position: 2,
            stop_reason: EvaluateStopReason::MAX_OUTPUT,
            matched_stop_token_id: None,
            text_artifact: artifact,
            usage: EvaluateUsage {
                input_units: 1,
                output_units: 2,
            },
            billable_units: 3,
        };
        let original_input = input_commitment(&request);
        let mut original =
            EvaluateOutputTranscriptBuilder::new(original_input, request.assurance, &producer);
        original.push_token_delta(tokens.clone()).unwrap();
        let original_events = original.finish(terminal.clone()).unwrap();
        let store = Arc::new(MemoryCacheStore::default());
        let options = CacheOptions {
            policy: CachePolicy::Record,
            store: Some(store.clone()),
        };
        record(
            options.recording().unwrap().as_ref(),
            &request,
            &invocation,
            &tokens,
            StopReason::MaxNewTokens,
            artifact,
            &original_events,
        )
        .await
        .unwrap();

        request.nonce = [4; 32];
        request.runner_public_key = ProducerSigningKey::from_secret_bytes([5; 32])
            .unwrap()
            .public_key();
        let fresh_input = input_commitment(&request);
        assert!(
            verify_output_events_for_producer(
                fresh_input,
                request.assurance,
                &producer.public_key(),
                &original_events,
            )
            .is_err()
        );
        let (sender, _receiver) = tokio::sync::mpsc::channel(4);
        let job = ExecuteJob {
            cache_recording: options.recording().unwrap(),
            output_cache: options,
            execution_id: "cached".into(),
            request_commitment: *fresh_input.as_bytes(),
            evaluate_request: request.clone(),
            source,
            invocation,
            prepared_artifacts: None,
            accepted_at: std::time::Instant::now(),
            sender,
            producer_key: producer.clone(),
        };
        (job, store, terminal)
    }

    #[tokio::test]
    async fn reset_prevents_an_old_evaluate_job_from_repopulating_the_index() {
        let (job, store, terminal) = recorded_job().await;
        let key = CacheKey::evaluate(job.evaluate_request.text_execution);
        let original: Transcript<EvaluateEvent, ExecutionProvenance> =
            serde_ipld_dagcbor::from_slice(&store.get(&key).unwrap().unwrap()).unwrap();
        let EvaluateEvent::Done(EvaluateOutcome::Completed { output_events, .. }) =
            original.events.last().unwrap()
        else {
            panic!("completed recording")
        };
        store
            .evict(&hellas_rpc::cache::Eviction::default())
            .unwrap();
        record(
            job.cache_recording.as_ref(),
            &job.evaluate_request,
            &job.invocation,
            &[2, 3],
            StopReason::MaxNewTokens,
            terminal.text_artifact,
            output_events,
        )
        .await
        .unwrap();
        assert!(store.list().unwrap().is_empty());
    }

    #[tokio::test]
    async fn another_ticket_reuses_tokens_and_signs_evidence_for_its_own_input() {
        let (mut job, store, terminal) = recorded_job().await;
        let request = &job.evaluate_request;
        let producer = &job.producer_key;
        let fresh_input = input_commitment(request);
        let mut fresh =
            EvaluateOutputTranscriptBuilder::new(fresh_input, request.assurance, producer);
        let result = replay(&job, &mut |token| {
            fresh.push_token_delta(vec![token]).map_err(error)?;
            Ok(())
        })
        .unwrap()
        .unwrap();
        assert_eq!(result, (StopReason::MaxNewTokens, vec![2, 3]));
        let fresh_events = fresh.finish(terminal).unwrap();
        verify_output_events_for_producer(
            fresh_input,
            request.assurance,
            &producer.public_key(),
            &fresh_events,
        )
        .unwrap();
        assert_eq!(store.list().unwrap().len(), 1);
        job.output_cache.policy = CachePolicy::ReplayOnly;
        job.evaluate_request.text_execution = Digest::from_bytes([10; 32]);
        assert!(
            replay(&job, &mut |_| panic!("miss must not emit tokens"))
                .unwrap_err()
                .to_string()
                .contains("replay miss")
        );
    }

    #[tokio::test]
    async fn unauthenticated_cache_entries_fail_before_emitting_any_tokens() {
        let (mut job, store, terminal) = recorded_job().await;
        let key = CacheKey::evaluate(job.evaluate_request.text_execution);
        let original: Transcript<EvaluateEvent, ExecutionProvenance> =
            serde_ipld_dagcbor::from_slice(&store.get(&key).unwrap().unwrap()).unwrap();
        let mut cases = Vec::new();

        let mut missing = original.clone();
        let EvaluateEvent::Done(EvaluateOutcome::Completed { output_events, .. }) =
            missing.events.last_mut().unwrap()
        else {
            unreachable!()
        };
        output_events.clear();
        cases.push(("missing signatures", missing));

        let mut foreign = original.clone();
        let attacker = ProducerSigningKey::from_secret_bytes([8; 32]).unwrap();
        let original_input = InputCommitment::from_digest(Digest::from_bytes(
            original.initial_provenance.as_ref().unwrap().commitment_id,
        ));
        let mut forged = EvaluateOutputTranscriptBuilder::new(
            original_input,
            job.evaluate_request.assurance,
            &attacker,
        );
        forged.push_token_delta(vec![2, 3]).unwrap();
        let EvaluateEvent::Done(EvaluateOutcome::Completed { output_events, .. }) =
            foreign.events.last_mut().unwrap()
        else {
            unreachable!()
        };
        *output_events = forged.finish(terminal).unwrap();
        cases.push(("different producer", foreign));

        let mut corrupt = original.clone();
        let EvaluateEvent::Done(EvaluateOutcome::Completed { output_events, .. }) =
            corrupt.events.last_mut().unwrap()
        else {
            unreachable!()
        };
        let mut envelope = hellas_rpc::stream::output_event_to_pb(&output_events[0]);
        envelope.signature = Some(hellas_rpc::run_ticket::signature_to_pb(
            &hellas_rpc::Signature::Secp256k1([0; 64]),
        ));
        output_events[0] = hellas_rpc::stream::output_event_from_pb(envelope).unwrap();
        cases.push(("corrupt signature", corrupt));

        let mut changed_input = original.clone();
        changed_input
            .initial_provenance
            .as_mut()
            .unwrap()
            .commitment_id = [99; 32];
        cases.push(("different input commitment", changed_input));

        let mut unsigned_tokens = original.clone();
        unsigned_tokens.events[0] = EvaluateEvent::Chunk {
            position: 2,
            tokens: hellas_rpc::encode_token_ids(&[7, 8]),
        };
        let EvaluateEvent::Done(EvaluateOutcome::Completed { text_artifact, .. }) =
            unsigned_tokens.events.last_mut().unwrap()
        else {
            unreachable!()
        };
        *text_artifact = completed_text(
            TextExecutionId::from_digest(job.evaluate_request.text_execution),
            &job.invocation.input_ids,
            &[7, 8],
        )
        .artifact
        .output_id()
        .digest();
        cases.push(("rewritten tokens and artifact", unsigned_tokens));

        let mut unsigned_stop = original.clone();
        let EvaluateEvent::Done(EvaluateOutcome::Completed { stop_reason, .. }) =
            unsigned_stop.events.last_mut().unwrap()
        else {
            unreachable!()
        };
        *stop_reason = EvaluateStop::StopToken(42);
        job.invocation.stop_token_ids.push(42);
        cases.push(("rewritten stop reason", unsigned_stop));

        for (name, transcript) in cases {
            store.remove(&key).unwrap();
            store
                .insert(&key, &serde_ipld_dagcbor::to_vec(&transcript).unwrap(), 0)
                .unwrap();
            for policy in [CachePolicy::Record, CachePolicy::ReplayOnly] {
                job.output_cache.policy = policy;
                assert!(
                    replay(&job, &mut |_| panic!(
                        "{name}: emitted unauthenticated tokens"
                    ))
                    .is_err(),
                    "{name}: accepted in {policy:?}"
                );
            }
        }

        store.remove(&key).unwrap();
        store
            .insert(&key, &serde_ipld_dagcbor::to_vec(&original).unwrap(), 0)
            .unwrap();
        job.evaluate_request.assurance = Assurance::AppleAppAttest;
        assert!(replay(&job, &mut |_| panic!("assurance upgrade emitted tokens")).is_err());
    }
}
