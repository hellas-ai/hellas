//! Streaming delivery over the existing authorization and payment lifecycle.
use super::*;
use crate::model::work::decode_transcript;
use futures::StreamExt;
use hellas_rpc::pb::work::{WorkStreamEvent, work_stream_event};
use hellas_rpc::protocol::invocation::output;

pub type PaidProgress = Arc<dyn Fn(OutputEventEnvelope) -> Result<(), BackendFault> + Send + Sync>;
pub type PaidResultStream = hellas_rpc::call::ResponseStream<WorkStreamEvent>;

#[derive(Debug, thiserror::Error)]
pub enum ProgressError {
    #[error("live result exceeds its authorized spool")]
    SpoolBound,
    #[error("progress state lock is poisoned")]
    Poisoned,
}
#[derive(Debug, Default)]
pub(super) struct Progress {
    events: Vec<OutputEventEnvelope>,
    bytes: usize,
}

// The terminal authenticates the complete stream without repeating it in one frame.
pub(super) fn result_frames<'a>(
    delivered: &'a ResultTranscript,
    events: &'a [OutputEventEnvelope],
    frame_limit: u32,
) -> impl Iterator<Item = Result<WorkStreamEvent, PaidWorkError>> + 'a {
    let prefixes = &events[..events.len().saturating_sub(1)];
    prefix_batches(prefixes, frame_limit)
        .map(|batch| {
            Ok(WorkStreamEvent {
                outcome: Some(work_stream_event::Outcome::Prefix(encode_transcript(
                    batch,
                )?)),
            })
        })
        .chain(events.last().into_iter().map(|event| {
            Ok(WorkStreamEvent {
                outcome: Some(work_stream_event::Outcome::Terminal(
                    hellas_rpc::pb::work::WorkStreamTerminal {
                        result: delivered.result.clone(),
                        provider_signature: delivered.provider_signature.clone(),
                        terminal_transcript: encode_transcript(std::slice::from_ref(event))?,
                    },
                )),
            })
        }))
}
fn prefix_batches(
    mut events: &[OutputEventEnvelope],
    frame_limit: u32,
) -> impl Iterator<Item = &[OutputEventEnvelope]> {
    std::iter::from_fn(move || {
        if events.is_empty() {
            return None;
        }
        let mut count = 1;
        while count < events.len() {
            let Ok(bytes) = encode_transcript(&events[..count + 1]) else {
                break;
            };
            let frame = WorkStreamEvent {
                outcome: Some(work_stream_event::Outcome::Prefix(bytes)),
            };
            if frame.encoded_len() > (frame_limit as usize).min(64 * 1024) {
                break;
            }
            count += 1;
        }
        let (batch, rest) = events.split_at(count);
        events = rest;
        Some(batch)
    })
}
impl ProviderEndpoint {
    fn job_facts(&self, work_id: Digest) -> Result<AdmissionFacts, DeliverError> {
        let job = self
            .state()
            .job_by_id(work_id)
            .ok_or(DeliverError::NoSuchJob)?;
        let input = PreparedInvocation::from_canonical_bytes(
            job.prepared_input(),
            crate::content::MAX_CONTENT_BYTES,
        )
        .map_err(PaidWorkError::from)?;
        Ok(crate::job::check_paid_input(
            self.state().channel(),
            job.authorization(),
            self.admitting()?.invocation_policy(),
            &input,
        )?)
    }
    async fn reserve_stream(
        &mut self,
        request: &StreamResultRequest,
        exporter: &[u8; 32],
    ) -> Result<(), DeliverError> {
        // This authenticates route, caller and connection before any phase is disclosed.
        match self.release_ready(request, None, exporter).await {
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
        crate::model::work::check_payment_policy_binding(
            ready.channel(),
            job.authorization(),
            ready.payment_policy(),
        )?;
        self.job_facts(work_id)?;
        ready.check_releasable(
            self.state().cursor().0,
            job.authorization().terminal_deadline,
        )?;
        self.close
            .store
            .commit(
                ChannelRecord::PlaintextReleased { work_id },
                &Secp256k1Verifier::new(),
            )
            .await?;
        Ok(())
    }
}
impl WorkService {
    async fn reserve_stream_durably(
        &self,
        request: &StreamResultRequest,
        exporter: &[u8; 32],
    ) -> Result<(), DeliverError> {
        let mut endpoint = self
            .endpoint
            .lock_owned()
            .await
            .map_err(|_| EndpointError::Poisoned)?;
        let (request, exporter) = (request.clone(), *exporter);
        // A started SQLite append outlives its RPC. Acquire first to bound detached tasks.
        tokio::spawn(async move { endpoint.reserve_stream(&request, &exporter).await })
            .await
            .map_err(|_| DeliverError::Endpoint(EndpointError::Poisoned))?
    }
    async fn check_stream_release(
        &self,
        request: &StreamResultRequest,
        exporter: &[u8; 32],
    ) -> Result<(), WireStatus> {
        self.reserve_stream_durably(request, exporter)
            .await
            .map_err(|error| WireStatus::new(hellas_wire::WireCode::Unavailable, error.to_string()))
    }
    pub(super) fn publish_progress(
        &self,
        work_id: Digest,
        facts: &AdmissionFacts,
        event: OutputEventEnvelope,
    ) -> Result<(), BackendFault> {
        if matches!(
            event.event().body().kind(),
            output::TERMINAL | output::FAILURE
        ) {
            return Ok(());
        }
        let mut jobs = self
            .progress
            .lock()
            .map_err(|_| BackendFault::caused_by(ProgressError::Poisoned))?;
        let progress = jobs.entry(work_id).or_default();
        let mut events = progress.events.clone();
        events.push(event.clone());
        let bytes = encode_transcript(&events)
            .map_err(BackendFault::caused_by)?
            .len();
        if bytes as u64 > facts.max_spool_bytes || events.len() as u64 >= facts.max_output_events {
            return Err(BackendFault::caused_by(ProgressError::SpoolBound));
        }
        progress.bytes = bytes;
        progress.events.push(event);
        drop(jobs);
        self.changed.notify_waiters();
        Ok(())
    }
    pub(super) fn result_stream(
        &self,
        request: StreamResultRequest,
        context: TransportContext,
    ) -> PaidResultStream {
        let service = self.clone();
        PaidResultStream::new(async_stream::stream! {
            let Some(exporter) = context.open_exporter else {
                yield Err(WireStatus::new(hellas_wire::WireCode::PermissionDenied, "delivery requires a bound connection")); return;
            };
            let Some(work_id) = work_id_bytes(&request.work_id) else {
                yield Err(WireStatus::new(hellas_wire::WireCode::InvalidArgument, "invalid work id")); return;
            };
            let mut position = 0;
            loop {
                let changed = service.changed.notified(); tokio::pin!(changed); changed.as_mut().enable();
                match service.reserve_stream_durably(&request, &exporter).await {
                    Ok(()) => {},
                    Err(DeliverError::NoResult { phase: JobPhase::HalfSigned | JobPhase::Accepted | JobPhase::Running | JobPhase::Streaming }) => {
                        let _ = tokio::time::timeout(std::time::Duration::from_secs(30), changed).await;
                        continue;
                    }
                    Err(error) => {
                        let refusal = Refusal::from(error);
                        yield Ok(WorkStreamEvent { outcome: Some(work_stream_event::Outcome::Refused(WorkRefused {
                            grant: None, code: refusal.code.code() as i32, reason: refusal.reason,
                        })) }); return;
                    }
                }
                let facts = match service.endpoint().await.and_then(|endpoint| endpoint.job_facts(work_id).map_err(|_| EndpointError::NotAdmitting)) {
                    Ok(facts) => facts,
                    Err(error) => { yield Err(WireStatus::new(hellas_wire::WireCode::Unavailable, error.to_string())); return; }
                };
                match service.retained_delivery(&request, &context).await {
                    Ok(delivery) => {
                        let events = match decode_transcript(&delivery.transcript, facts.max_spool_bytes as usize) {
                            Ok(events) => events,
                            Err(error) => { yield Err(WireStatus::new(hellas_wire::WireCode::Internal, error.to_string())); return; }
                        };
                        let Some(tail) = events.get(position..) else {
                            yield Err(WireStatus::new(hellas_wire::WireCode::Internal, "result shorter than streamed prefix")); return;
                        };
                        let delivered = ResultTranscript { result: delivery.result.encode(), provider_signature: delivery.signature.as_bytes().to_vec(), transcript: Vec::new() };
                        for frame in result_frames(&delivered, tail, facts.max_encoded_result_frame) {
                            if let Err(error) = service.check_stream_release(&request, &exporter).await { yield Err(error); return; }
                            match frame {
                                Ok(frame) if frame.encoded_len() <= facts.max_encoded_result_frame as usize => yield Ok(frame),
                                _ => { yield Err(WireStatus::new(hellas_wire::WireCode::Internal, "result frame exceeds bound")); return; }
                            }
                        }
                        return;
                    }
                    Err(refusal) if refusal.code != WorkRefusal::NotReady => {
                        yield Ok(WorkStreamEvent { outcome: Some(work_stream_event::Outcome::Refused(WorkRefused {
                            grant: None, code: refusal.code.code() as i32, reason: refusal.reason,
                        })) }); return;
                    }
                    Err(_) => {},
                }
                let pending = service.progress.lock().map(|jobs| jobs.get(&work_id)
                    .map(|p| p.events[position.min(p.events.len())..].to_vec()).unwrap_or_default()).map_err(|_| ProgressError::Poisoned);
                let pending = match pending {
                    Ok(events) => events,
                    Err(_) => { yield Err(WireStatus::new(hellas_wire::WireCode::Unavailable, "progress lock poisoned")); return; }
                };
                for batch in prefix_batches(&pending, facts.max_encoded_result_frame) {
                    if let Err(error) = service.check_stream_release(&request, &exporter).await { yield Err(error); return; }
                    match encode_transcript(batch) {
                        Ok(prefix) => {
                            let frame = WorkStreamEvent { outcome: Some(work_stream_event::Outcome::Prefix(prefix)) };
                            if frame.encoded_len() > facts.max_encoded_result_frame as usize {
                                yield Err(WireStatus::new(hellas_wire::WireCode::Internal, "prefix exceeds frame bound")); return;
                            }
                            position += batch.len(); yield Ok(frame);
                        }
                        Err(error) => { yield Err(WireStatus::new(hellas_wire::WireCode::Internal, error.to_string())); return; }
                    }
                }
                let _ = tokio::time::timeout(std::time::Duration::from_secs(30), changed).await;
            }
        })
    }
}
pub async fn fetch_result_stream<T>(
    transport: T,
    endpoint: &mut impl ClientChannel,
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
    let (request, prepared, facts) = {
        let endpoint = endpoint.client().await?;
        let job = endpoint
            .state()
            .job_by_id(work_id)
            .ok_or(DeliverError::NoSuchJob)?;
        let prepared = PreparedInvocation::from_canonical_bytes(
            job.prepared_input(),
            crate::content::MAX_CONTENT_BYTES,
        )
        .map_err(PaidWorkError::from)?;
        let facts = crate::job::check_paid_input(
            ready.channel(),
            job.authorization(),
            ready.invocation_policy(),
            &prepared,
        )?;
        (
            endpoint.request_delivery(work_id, &exporter)?,
            prepared,
            facts,
        )
    };
    let mut verifier = output::StreamVerifier::new(
        prepared.request.clone(),
        hellas_auth::PublicKey::Secp256k1(ready.channel().provider_key().to_bytes()),
        facts.max_transcript_payload_bytes as usize,
    )
    .map_err(PaidWorkError::from)?;
    let mut events = Vec::new();
    let mut stream = WorkClientImpl::new(transport)
        .stream_result(request)
        .await?;
    while let Some(frame) = stream.next().await {
        let frame = frame?;
        if frame.encoded_len() > facts.max_encoded_result_frame as usize {
            return Err(DeliverError::OverFrame {
                actual: frame.encoded_len() as u64,
                limit: facts.max_encoded_result_frame as u64,
            });
        }
        let (bytes, terminal) = match frame.outcome {
            Some(work_stream_event::Outcome::Prefix(bytes)) => (bytes, None),
            Some(work_stream_event::Outcome::Terminal(terminal)) => {
                (terminal.terminal_transcript.clone(), Some(terminal))
            }
            Some(work_stream_event::Outcome::Refused(refused)) => {
                return Err(DeliverError::Refused {
                    refusal: WorkRefusal::from_code(refused.code)
                        .ok_or(DeliverError::Malformed("refusal code"))?,
                    reason: refused.reason,
                });
            }
            _ => return Err(DeliverError::Malformed("invalid streaming result frame")),
        };
        let batch = decode_transcript(&bytes, facts.max_spool_bytes as usize)?;
        if batch.is_empty() || (terminal.is_some() && batch.len() != 1) {
            return Err(DeliverError::Malformed("invalid stream terminal"));
        }
        for event in batch {
            verifier.push(event.clone()).map_err(PaidWorkError::from)?;
            if terminal.is_none() && verifier.terminal_seen() {
                return Err(DeliverError::Malformed("terminal in prefix frame"));
            }
            events.push(event.clone());
            if events.len() as u64 > facts.max_output_events
                || encode_transcript(&events)?.len() as u64 > facts.max_spool_bytes
            {
                return Err(DeliverError::Malformed(
                    "live result exceeds authorized output",
                ));
            }
            if terminal.is_none() {
                progress(&event)?;
            }
        }
        if let Some(terminal) = terminal {
            if stream.next().await.transpose()?.is_some() {
                return Err(DeliverError::Malformed("event after terminal result"));
            }
            stream.finish()?;
            verifier.finish().map_err(PaidWorkError::from)?;
            prepared
                .verify_output(
                    ready.invocation_policy(),
                    &hellas_auth::PublicKey::Secp256k1(ready.channel().client_key().to_bytes()),
                    &hellas_auth::PublicKey::Secp256k1(ready.channel().provider_key().to_bytes()),
                    &events,
                )
                .map_err(PaidWorkError::from)?;
            let delivered = ResultTranscript {
                result: terminal.result,
                provider_signature: terminal.provider_signature,
                transcript: encode_transcript(&events)?,
            };
            return endpoint
                .client()
                .await?
                .receive_stream(work_id, ready, &delivered)
                .await;
        }
    }
    stream.finish()?;
    Err(DeliverError::Malformed(
        "result stream ended without terminal result",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn disconnect_during_plaintext_append_cannot_poison_the_provider_journal() {
        use crate::model::setup::ObservedChannel;
        use crate::test_support::channel as fixture;
        use hellas_kernel::PendingSlot;
        let provider_root = tempfile::tempdir().unwrap();
        let client_root = tempfile::tempdir().unwrap();
        let ready = fixture::descriptor()
            .check_ready(&ObservedChannel {
                height: fixture::CURSOR,
                bond: Some(&fixture::bond_object()),
                payment: Some(&fixture::payment_object()),
                lease: fixture::lease_over(fixture::bond_edge(), fixture::payment_edge()),
                pending: PendingSlot::Absent,
            })
            .unwrap();
        let mut provider = ProviderEndpoint::new(
            ready.clone(),
            fixture::store_at(
                provider_root.path(),
                &ready,
                Role::Provider,
                fixture::CURSOR,
            )
            .await,
            fixture::provider(),
        )
        .unwrap();
        let mut client = ClientEndpoint::new(
            ready.clone(),
            fixture::store_at(client_root.path(), &ready, Role::Client, fixture::CURSOR).await,
            fixture::client(),
        )
        .unwrap();
        let proposal = client
            .propose(&JobProposal {
                prepared_input: fixture::bundle(1),
                deadlines: fixture::deadlines(),
            })
            .await
            .unwrap();
        let response = fixture::accept_uploaded(&mut provider, &proposal).await;
        let work = client.accepted(&response).await.unwrap();
        provider.begin_run(work, &ready).await.unwrap();
        let request = client.request_delivery(work, &[7; 32]).unwrap();
        let service = WorkService::new(provider);
        let (entered, release) = service
            .endpoint()
            .await
            .unwrap()
            .close
            .store
            .pause_next_statement_for_test()
            .await;
        {
            let reserve = service.reserve_stream_durably(&request, &[7; 32]);
            tokio::pin!(reserve);
            tokio::select! {
                result = &mut reserve => panic!("append completed before cancellation: {result:?}"),
                result = entered => result.unwrap(),
            }
        }
        drop(release);
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let mut endpoint = service.endpoint().await.unwrap();
            endpoint
                .close
                .store
                .commit(
                    ChannelRecord::CursorAdvanced {
                        height: fixture::CURSOR + 1,
                        parent: fixture::payload_at(fixture::CURSOR),
                        payload: fixture::payload_at(fixture::CURSOR + 1),
                    },
                    &Secp256k1Verifier::new(),
                )
                .await
                .unwrap();
            assert_eq!(
                endpoint.state().job_by_id(work).unwrap().phase(),
                JobPhase::Streaming
            );
        })
        .await
        .expect("the detached durable append finishes and the journal remains writable");
        drop(service);
        let store = ChannelStore::open(
            provider_root.path(),
            ready.channel().clone(),
            fixture::settlement(),
            Role::Provider,
            fixture::origin(),
            hellas_store::ContentStore::new(),
            &Secp256k1Verifier::new(),
        )
        .await
        .unwrap();
        assert_eq!(
            store.state().job_by_id(work).unwrap().phase(),
            JobPhase::Streaming
        );
        assert_eq!(store.state().cursor().0, fixture::CURSOR + 1);
    }

    #[test]
    fn batched_fetch_preserves_every_envelope_and_bounds_each_frame() {
        let key = hellas_auth::ProducerSigningKey::from_secret_bytes([1; 32]).unwrap();
        let mut builder = hellas_rpc::OutputTranscriptBuilder::new(
            hellas_rpc::scheme_id(
                hellas_rpc::Operation::Fetch,
                hellas_rpc::Assurance::ProducerSigned,
            ),
            hellas_rpc::InputCommitment::from_digest(hellas_auth::Digest::from_bytes([2; 32])),
            &key,
            hellas_rpc::protocol::invocation::output::canonicalization(),
        );
        for _ in 0..100 {
            builder.push("response.event", vec![7; 256]).unwrap();
        }
        builder.push("response.terminal", vec![8; 16]).unwrap();
        let (events, _) = builder.finish().unwrap();
        let delivered = ResultTranscript {
            result: vec![3; 128],
            provider_signature: vec![4; 64],
            transcript: encode_transcript(&events).unwrap(),
        };
        for limit in [4096, 65536] {
            // Resuming after an arbitrary prefix must skip envelopes, not batches.
            for position in [0, 1, 47, 100] {
                let frames = result_frames(&delivered, &events[position..], limit)
                    .collect::<Result<Vec<_>, _>>()
                    .unwrap();
                let mut decoded = Vec::new();
                for frame in &frames {
                    assert!(frame.encoded_len() <= limit as usize);
                    let bytes = match frame.outcome.as_ref().unwrap() {
                        work_stream_event::Outcome::Prefix(bytes) => bytes,
                        work_stream_event::Outcome::Terminal(end) => &end.terminal_transcript,
                        _ => panic!("unexpected frame"),
                    };
                    decoded.extend(
                        decode_transcript(bytes, crate::work_store::journal::MAX_RECORD_BYTES)
                            .unwrap(),
                    );
                }
                assert_eq!(decoded, events[position..]);
                assert!(matches!(
                    frames.last().unwrap().outcome,
                    Some(work_stream_event::Outcome::Terminal(_))
                ));
                if position == 0 {
                    assert!(frames.len() < events.len());
                }
            }
        }
    }
}
