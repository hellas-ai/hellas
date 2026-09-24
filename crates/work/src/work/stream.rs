//! Live delivery over the existing job authorization and payment lifecycle.
use super::*;
use futures::{StreamExt, stream::BoxStream};
use hellas_rpc::pb::work::{WorkStreamEvent, work_stream_event};
use hellas_rpc::protocol::work::decode_transcript;
use hellas_rpc::protocol::work_fetch::MAX_FETCH_TRANSCRIPT_BYTES;
use hellas_rpc::{
    Operation, StreamId, output_genesis, scheme_id, verify_output_event_continuation,
};

pub type PaidProgress = Arc<dyn Fn(OutputEventEnvelope) -> Result<(), BackendFault> + Send + Sync>;
pub type PaidResultStream = BoxStream<'static, Result<WorkStreamEvent, WireStatus>>;

#[derive(Debug, Default)]
pub(super) struct Progress {
    events: Vec<OutputEventEnvelope>,
    bytes: usize,
}

/// Fetch's terminal authenticates the assembled transcript without repeating it
/// in one wire frame. Signatures, result digests and payment records are unchanged.
pub(super) fn fetch_frames<'a>(
    delivered: &'a WorkDelivered,
    events: &'a [OutputEventEnvelope],
) -> impl Iterator<Item = Result<WorkStreamEvent, PaidWorkError>> + 'a {
    events.iter().enumerate().map(|(index, event)| {
        let transcript = encode_transcript(std::slice::from_ref(event))?;
        let outcome = if index + 1 == events.len() {
            work_stream_event::Outcome::Terminal(hellas_rpc::pb::work::WorkStreamTerminal {
                result: delivered.result.clone(),
                provider_signature: delivered.provider_signature.clone(),
                terminal_transcript: transcript,
            })
        } else {
            work_stream_event::Outcome::Prefix(transcript)
        };
        Ok(WorkStreamEvent {
            outcome: Some(outcome),
        })
    })
}

fn spool_charge(event: &OutputEventEnvelope, fetch: bool) -> usize {
    // The canonical envelope represents payload bytes as CBOR integers, up to
    // two encoded bytes each. Include signature/structure overhead before decode.
    event
        .payload()
        .len()
        .saturating_mul(if fetch { 2 } else { 1 })
        .saturating_add(1024)
}

impl ProviderEndpoint {
    fn reserve_stream(
        &mut self,
        request: &DeliverResultRequest,
        exporter: &[u8; 32],
    ) -> Result<(), DeliverError> {
        // Delivery authenticates the client and connection before looking at
        // the phase. A ready result takes the ordinary durable release path.
        match self.deliver_with_readiness(request, None, exporter) {
            Ok(_) => return Ok(()),
            Err(DeliverError::NoResult {
                phase: JobPhase::Running | JobPhase::Streaming,
            }) => {}
            Err(error) => return Err(error),
        }
        let ready = self.admitting()?.clone();
        let work_id = work_id_bytes(&request.work_id).ok_or(DeliverError::Malformed("work id"))?;
        let job = self
            .state()
            .job_by_id(work_id)
            .ok_or(DeliverError::NoSuchJob)?;
        if self.state().job_is_indeterminate(work_id) {
            return Err(DeliverError::NoSuchJob);
        }
        ready.check_releasable(
            self.state().cursor().0,
            job.authorization().terminal_deadline,
        )?;
        self.close.store.commit(
            ChannelRecord::PlaintextReleased { work_id },
            &Secp256k1Verifier::new(),
        )?;
        Ok(())
    }
}

impl WorkService {
    pub(super) fn publish_progress(
        &self,
        work_id: Digest,
        event: OutputEventEnvelope,
    ) -> Result<(), BackendFault> {
        let policy = self
            .endpoint()
            .map_err(|error| BackendFault::new(error.to_string()))?
            .admitting()
            .map_err(|error| BackendFault::new(error.to_string()))?
            .execution_policy()
            .clone();
        let limit = match &policy {
            PaidWorkPolicy::Fetch { .. } => policy
                .max_spool_bytes()
                .min(MAX_FETCH_TRANSCRIPT_BYTES as u64),
            PaidWorkPolicy::Evaluate(_) => policy.max_spool_bytes(),
        };
        let mut jobs = self.progress.lock().expect("paid progress poisoned");
        let progress = jobs.entry(work_id).or_default();
        // Signed prefixes are bounded by the same spool as final delivery.
        let fetch = matches!(policy, PaidWorkPolicy::Fetch { .. });
        let bytes = spool_charge(&event, fetch);
        let retained = progress.bytes.saturating_add(bytes);
        if retained as u64 > limit {
            return Err(BackendFault::new(
                "live result exceeds its authorized spool",
            ));
        }
        progress.bytes = retained;
        progress.events.push(event);
        drop(jobs);
        self.changed.notify_waiters();
        Ok(())
    }

    pub(super) fn result_stream(
        &self,
        request: DeliverResultRequest,
        context: TransportContext,
    ) -> PaidResultStream {
        let service = self.clone();
        Box::pin(async_stream::stream! {
            let Some(exporter) = context.open_exporter else {
                yield Err(WireStatus::new(hellas_wire::WireCode::PermissionDenied, "delivery requires a bound connection"));
                return;
            };
            let Some(work_id) = work_id_bytes(&request.work_id) else {
                yield Err(WireStatus::new(hellas_wire::WireCode::InvalidArgument, "invalid work id"));
                return;
            };
            let mut position = 0;
            loop {
                let changed = service.changed.notified();
                tokio::pin!(changed);
                changed.as_mut().enable();
                let reserved = service.endpoint().map_err(DeliverError::from)
                    .and_then(|mut endpoint| endpoint.reserve_stream(&request, &exporter));
                match reserved {
                    Ok(()) => {
                        let response = service.release(&request, &context);
                        match response.outcome {
                            Some(DeliverOutcome::Delivered(delivered)) => {
                                let events = match decode_transcript(&delivered.transcript, MAX_FETCH_TRANSCRIPT_BYTES) {
                                    Ok(events) => events,
                                    Err(error) => {
                                        yield Err(WireStatus::new(hellas_wire::WireCode::Internal, error.to_string()));
                                        return;
                                    }
                                };
                                if events.last().is_some_and(|event| event.event().body().kind() == hellas_rpc::fetch::OUTPUT_TERMINAL_KIND) {
                                    for frame in fetch_frames(&delivered, &events).skip(position) {
                                        yield frame.map_err(|error| WireStatus::new(hellas_wire::WireCode::Internal, error.to_string()));
                                    }
                                } else {
                                    yield Ok(WorkStreamEvent { outcome: Some(work_stream_event::Outcome::Delivered(delivered)) });
                                }
                                return;
                            }
                            Some(DeliverOutcome::Refused(refused)) if refused.code != WorkRefusal::NotReady.code() as i32 => {
                                yield Ok(WorkStreamEvent { outcome: Some(work_stream_event::Outcome::Refused(refused)) });
                                return;
                            }
                            _ => {}
                        }
                        let pending = {
                            let progress = service.progress.lock().expect("paid progress poisoned");
                            progress.get(&work_id).map(|progress| progress.events[position.min(progress.events.len())..].to_vec()).unwrap_or_default()
                        };
                        for event in pending {
                            match encode_transcript(&[event]) {
                                Ok(prefix) => {
                                    position += 1;
                                    yield Ok(WorkStreamEvent { outcome: Some(work_stream_event::Outcome::Prefix(prefix)) });
                                }
                                Err(error) => {
                                    yield Err(WireStatus::new(hellas_wire::WireCode::Internal, error.to_string()));
                                    return;
                                }
                            }
                        }
                    }
                    Err(DeliverError::NoResult { .. }) => {},
                    Err(error) => {
                        let refusal = Refusal::from(error);
                        yield Ok(WorkStreamEvent { outcome: Some(work_stream_event::Outcome::Refused(WorkRefused {
                            code: refusal.code.code() as i32, reason: refusal.reason,
                        })) });
                        return;
                    }
                }
                // Recheck finalized deadlines even when a failed worker never
                // sends another notification. This is one open subscription.
                let _ = tokio::time::timeout(std::time::Duration::from_secs(30), changed).await;
            }
        })
    }
}

/// Deliver verified prefixes and finally journal the complete result.
/// The caller pays only after this returns; it must keep running if its UI drops.
pub async fn fetch_result_stream<T>(
    transport: T,
    endpoint: &mut ClientEndpoint,
    ready: &ReadyChannel,
    work_id: Digest,
    mut progress: impl FnMut(&OutputEventEnvelope) -> Result<(), PaidWorkError>,
) -> Result<Delivery, DeliverError>
where
    T: StreamTransport + Sync,
    T::Error: std::error::Error + Send + Sync + 'static,
    T::Stream: 'static,
{
    let exporter = transport
        .context()
        .open_exporter
        .ok_or(DeliverError::Unbindable)?;
    let request = endpoint.request_delivery(work_id, &exporter)?;
    let job = endpoint
        .state()
        .job_by_id(work_id)
        .ok_or(DeliverError::NoSuchJob)?;
    let prepared = PreparedPaidWorkInput::decode(job.prepared_input(), MAX_RECORD_BYTES)
        .map_err(PaidWorkError::from)?;
    let input = prepared.input_commitment()?;
    let (operation, kind, max_tokens, max_events, max_bytes) =
        match (&prepared, ready.execution_policy()) {
            (PreparedPaidWorkInput::Evaluate(prepared), PaidWorkPolicy::Evaluate(_)) => (
                Operation::Evaluate,
                hellas_rpc::evaluate::TOKEN_DELTA_EVENT_KIND,
                u64::from(
                    prepared
                        .parts()
                        .map_err(PaidWorkError::from)?
                        .text_policy
                        .max_new_tokens(),
                ),
                u64::MAX,
                u64::MAX,
            ),
            (PreparedPaidWorkInput::Fetch(_), PaidWorkPolicy::Fetch { policy, .. }) => (
                Operation::Fetch,
                hellas_rpc::fetch::OUTPUT_EVENT_KIND,
                0,
                u64::from(policy.max_output_events)
                    .min(hellas_rpc::fetch::MAX_FETCH_OUTPUT_EVENTS as u64),
                u64::from(policy.max_output_bytes)
                    .min(hellas_rpc::fetch::MAX_FETCH_OUTPUT_PAYLOAD_BYTES as u64),
            ),
            _ => {
                return Err(DeliverError::Malformed(
                    "stream profile differs from channel",
                ));
            }
        };
    let mut token_count = 0u64;
    let mut payload_bytes = 0u64;
    let mut retained_bytes = 0usize;
    let spool_limit = if operation == Operation::Fetch {
        ready
            .execution_policy()
            .max_spool_bytes()
            .min(MAX_FETCH_TRANSCRIPT_BYTES as u64)
    } else {
        ready.execution_policy().max_spool_bytes()
    };
    let key = hellas_rpc::PublicKey::Secp256k1(ready.channel().provider_key().to_bytes());
    let scheme = scheme_id(operation, prepared.assurance()?);
    let mut previous = output_genesis(input, StreamId::from_input_commitment(input));
    let mut streamed = Vec::new();
    let mut stream = WorkClientImpl::new(transport)
        .stream_result(request)
        .await?;
    while let Some(event) = stream.next().await {
        let event = event?;
        let frame_limit = ready.execution_policy().max_encoded_result_frame() as u64;
        if operation == Operation::Fetch && event.encoded_len() as u64 > frame_limit {
            return Err(DeliverError::OverFrame {
                actual: event.encoded_len() as u64,
                limit: frame_limit,
            });
        }
        match event.outcome {
            Some(work_stream_event::Outcome::Prefix(prefix)) => {
                let events = decode_transcript(&prefix, MAX_RECORD_BYTES)?;
                for event in events {
                    previous = verify_output_event_continuation(
                        scheme,
                        input,
                        &key,
                        streamed.len() as u64,
                        previous,
                        &event,
                    )
                    .map_err(|error| PaidWorkError::Transcript(error.to_string()))?;
                    if event.event().body().kind() != kind {
                        return Err(DeliverError::Malformed(
                            "live prefix has the wrong event kind",
                        ));
                    }
                    if operation == Operation::Evaluate {
                        let delta =
                            hellas_rpc::evaluate::decode_token_delta_payload(event.payload())
                                .map_err(|error| PaidWorkError::Transcript(error.to_string()))?;
                        token_count = token_count.saturating_add(delta.token_ids.len() as u64);
                    } else {
                        hellas_rpc::fetch::decode_fetch_event_payload(event.payload())
                            .map_err(|error| PaidWorkError::Transcript(error.to_string()))?;
                    }
                    payload_bytes = payload_bytes.saturating_add(event.payload().len() as u64);
                    retained_bytes = retained_bytes
                        .saturating_add(spool_charge(&event, operation == Operation::Fetch));
                    // Reserve one envelope for the required terminal.
                    if token_count > max_tokens
                        || streamed.len() as u64 + 1 >= max_events
                        || payload_bytes > max_bytes
                        || retained_bytes as u64 > spool_limit
                    {
                        return Err(DeliverError::Malformed(
                            "live result exceeds authorized output",
                        ));
                    }
                    progress(&event)?;
                    streamed.push(event);
                }
            }
            Some(work_stream_event::Outcome::Delivered(delivered)) => {
                let events = decode_transcript(&delivered.transcript, MAX_RECORD_BYTES)?;
                if !events.starts_with(&streamed) {
                    return Err(DeliverError::Malformed(
                        "terminal result changed streamed output",
                    ));
                }
                if stream.next().await.transpose()?.is_some() {
                    return Err(DeliverError::Malformed("event after terminal result"));
                }
                stream.finish()?;
                let result = endpoint.receive(work_id, ready, &delivered)?;
                for event in &events[streamed.len()..] {
                    if event.event().body().kind() == kind {
                        progress(event)?;
                    }
                }
                return Ok(result);
            }
            Some(work_stream_event::Outcome::Terminal(terminal)) => {
                if operation != Operation::Fetch {
                    return Err(DeliverError::Malformed("stream terminal requires Fetch"));
                }
                let mut tail = decode_transcript(&terminal.terminal_transcript, MAX_RECORD_BYTES)?;
                if tail.len() != 1
                    || tail[0].event().body().kind() != hellas_rpc::fetch::OUTPUT_TERMINAL_KIND
                {
                    return Err(DeliverError::Malformed(
                        "stream terminal must contain one terminal envelope",
                    ));
                }
                if payload_bytes.saturating_add(tail[0].payload().len() as u64) > max_bytes
                    || retained_bytes.saturating_add(spool_charge(&tail[0], true)) as u64
                        > spool_limit
                {
                    return Err(DeliverError::Malformed(
                        "live result exceeds authorized output",
                    ));
                }
                // No delivery or payment is recorded before the stream's final
                // status and the complete signed transcript have both verified.
                if stream.next().await.transpose()?.is_some() {
                    return Err(DeliverError::Malformed("event after terminal result"));
                }
                stream.finish()?;
                streamed.append(&mut tail);
                let transcript = encode_transcript(&streamed)?;
                return endpoint.receive_inner(
                    work_id,
                    ready,
                    &WorkDelivered {
                        result: terminal.result,
                        provider_signature: terminal.provider_signature,
                        transcript,
                    },
                    true,
                );
            }
            Some(work_stream_event::Outcome::Refused(refused)) => {
                return Err(DeliverError::Refused {
                    refusal: WorkRefusal::from_code(refused.code)
                        .ok_or(DeliverError::Malformed("refusal code"))?,
                    reason: refused.reason,
                });
            }
            None => return Err(DeliverError::Malformed("empty stream event")),
        }
    }
    stream.finish()?;
    Err(DeliverError::Malformed(
        "result stream ended without terminal result",
    ))
}
