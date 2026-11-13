//! Streaming delivery over the existing authorization and payment lifecycle.
use super::*;
use crate::model::work::decode_transcript;
use futures::StreamExt;
use hellas_rpc::pb::work::{WorkStreamEvent, work_stream_event};
use hellas_rpc::protocol::invocation::output;

/// Receives a running job's signed output prefix, one event at a time. Work
/// run through this crate never passes it the terminal or failure event.
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
    size: TranscriptSize,
}

// DAG-CBOR arrays encode each member independently; only the array header
// changes as events arrive. Count each envelope once instead of re-encoding
// the entire prefix for every output event. This preserves the wire format.
#[derive(Clone, Copy, Debug, Default)]
struct TranscriptSize {
    events: u64,
    members: usize,
}

impl TranscriptSize {
    fn appended(self, event: &OutputEventEnvelope) -> Result<Self, PaidWorkError> {
        let overflow = || PaidWorkError::Overflow {
            field: "transcript length",
        };
        let bytes = hellas_rpc::value::canonical_dag_cbor(event)
            .map_err(|error| PaidWorkError::Transcript(error.to_string()))?;
        Ok(Self {
            events: self.events.checked_add(1).ok_or_else(overflow)?,
            members: self.members.checked_add(bytes.len()).ok_or_else(overflow)?,
        })
    }

    fn encoded_len(self) -> Result<usize, PaidWorkError> {
        let mut header = hellas_rpc::value::DagCborEncoder::new();
        header.array(self.events);
        self.members
            .checked_add(header.into_bytes().len())
            .ok_or(PaidWorkError::Overflow {
                field: "transcript length",
            })
    }
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
        let mut count = 0;
        let mut size = TranscriptSize::default();
        for event in events {
            let Ok(next) = size.appended(event) else {
                break;
            };
            let Ok(bytes) = next.encoded_len() else {
                break;
            };
            // WorkStreamEvent.prefix is length-delimited protobuf field 1.
            let frame_bytes = prost::encoding::key_len(1)
                + prost::encoding::encoded_len_varint(bytes as u64)
                + bytes;
            if frame_bytes > (frame_limit as usize).min(64 * 1024) {
                break;
            }
            count += 1;
            size = next;
        }
        // An oversized or unencodable single event is returned for the caller
        // to reject, rather than silently dropping it or stalling the iterator.
        let count = count.max(1);
        let (batch, rest) = events.split_at(count);
        events = rest;
        Some(batch)
    })
}
impl ProviderEndpoint {
    pub(super) fn job_facts(&self, work_id: Digest) -> Result<AdmissionFacts, DeliverError> {
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
        match self.reserve_ready_release(request, exporter).await {
            Ok(_) => return Ok(()),
            Err(DeliverError::NoResult {
                phase: JobPhase::Running | JobPhase::Streaming,
            }) => {}
            Err(DeliverError::Endpoint(EndpointError::ObservationStale)) => {
                // Authentication has succeeded. The held decision may refuse an
                // expired job while stale, but cannot authorize plaintext release.
                let work_id =
                    work_id_bytes(&request.work_id).ok_or(DeliverError::Malformed("work id"))?;
                let job = self
                    .state()
                    .job_by_id(work_id)
                    .ok_or(DeliverError::NoSuchJob)?;
                self.ready
                    .as_ref()
                    .ok_or(EndpointError::NotAdmitting)?
                    .check_releasable(
                        self.state().cursor().0,
                        job.authorization().terminal_deadline,
                    )?;
                return Err(EndpointError::ObservationStale.into());
            }
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
        let terminal_deadline = job.authorization().terminal_deadline;
        ready.check_releasable(self.state().cursor().0, terminal_deadline)?;
        self.close.store.load_retained_input(work_id).await?;
        self.job_facts(work_id)?;
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
    ) -> Result<crate::endpoint_lock::OwnedEndpointGuard<ProviderEndpoint>, DeliverError> {
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let mut endpoint = self
                .endpoint
                .lock_owned()
                .await
                .map_err(|_| EndpointError::Poisoned)?;
            let (request, exporter) = (request.clone(), *exporter);
            // A started SQLite append outlives its RPC. Acquire first to bound detached tasks.
            let reserved = tokio::spawn(async move {
                endpoint.reserve_stream(&request, &exporter).await?;
                Ok(endpoint)
            })
            .await
            .map_err(|_| DeliverError::Endpoint(EndpointError::Poisoned))?;
            match reserved {
                Err(DeliverError::Endpoint(EndpointError::ObservationStale)) => {
                    // Keep this stream's position; every wake rechecks its authorization.
                    let _ = tokio::time::timeout(std::time::Duration::from_secs(30), changed).await;
                }
                result => return result,
            }
        }
    }
    async fn check_stream_release(
        &self,
        request: &StreamResultRequest,
        exporter: &[u8; 32],
    ) -> Result<(), WireStatus> {
        self.reserve_stream_durably(request, exporter)
            .await
            .map(|_| ())
            .map_err(|error| WireStatus::new(hellas_wire::WireCode::Unavailable, error.to_string()))
    }
    pub(super) fn publish_progress(
        &self,
        work_id: Digest,
        facts: &AdmissionFacts,
        event: OutputEventEnvelope,
    ) -> Result<(), BackendFault> {
        let mut jobs = self
            .progress
            .lock()
            .map_err(|_| BackendFault::caused_by(ProgressError::Poisoned))?;
        let progress = jobs.entry(work_id).or_default();
        let size = progress
            .size
            .appended(&event)
            .map_err(BackendFault::caused_by)?;
        if size.encoded_len().map_err(BackendFault::caused_by)? as u64 > facts.max_spool_bytes
            || size.events >= facts.max_output_events
        {
            return Err(BackendFault::caused_by(ProgressError::SpoolBound));
        }
        progress.size = size;
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
                let reserved = async {
                    let mut endpoint = service.reserve_stream_durably(&request, &exporter).await?;
                    endpoint.close.store.load_retained_input(work_id).await?;
                    endpoint.job_facts(work_id)
                }.await;
                let facts = match reserved {
                    Ok(facts) => facts,
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
                        // A released failure is never paid for; end it now
                        // rather than hold its price until the payment deadline.
                        if delivery.result.outcome == ResultOutcome::Failed
                            && let Err(error) = service.end_failed_delivery(work_id).await
                        {
                            tracing::warn!(target: TARGET, %error, "a released failed result stays open until its deadline");
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
        let mut endpoint = endpoint.client().await?;
        endpoint.load_retained_input(work_id).await?;
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
    let mut size = TranscriptSize::default();
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
            size = size.appended(&event)?;
            if size.events > facts.max_output_events
                || size.encoded_len()? as u64 > facts.max_spool_bytes
            {
                return Err(DeliverError::Malformed(
                    "live result exceeds authorized output",
                ));
            }
            if terminal.is_none() {
                progress(&event)?;
            }
            events.push(event);
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
                .receive_stream(work_id, ready, &delivered, &prepared)
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
    use hellas_private::StoreLocation;

    #[test]
    fn incremental_spool_size_matches_wire_encoding_at_array_boundaries() {
        use crate::test_support::channel as fixture;
        let sample = fixture::transcript_for(&fixture::invocation_request(1), &[0, 255, u32::MAX]);
        let mut events = Vec::new();
        let mut size = TranscriptSize::default();
        for count in 0..=256 {
            if [0, 1, 23, 24, 255, 256].contains(&count) {
                assert_eq!(
                    size.encoded_len().unwrap(),
                    encode_transcript(&events).unwrap().len()
                );
            }
            let event = sample[count % sample.len()].clone();
            size = size.appended(&event).unwrap();
            events.push(event);
        }
    }

    #[tokio::test]
    async fn cancelled_paid_acceptance_finishes_journaling_and_ram_transfer_before_upload_cleanup()
    {
        use crate::test_support::channel as fixture;
        let root = tempfile::tempdir().unwrap();
        let client_root = tempfile::tempdir().unwrap();
        let ready = fixture::ready_of(
            &fixture::descriptor_with(fixture::fetch_policy()),
            fixture::CURSOR,
        );
        let journal = fixture::store_at(root.path(), &ready, Role::Provider, fixture::CURSOR).await;
        let node = journal.content_store();
        let service = WorkService::new(
            ProviderEndpoint::new(ready.clone(), journal, fixture::provider()).unwrap(),
        );
        let mut client = ClientEndpoint::new(
            ready.clone(),
            fixture::store_at(client_root.path(), &ready, Role::Client, fixture::CURSOR).await,
            fixture::client(),
        )
        .unwrap();
        let input = fixture::fetch_bundle(1);
        let request = client
            .propose(
                &JobProposal {
                    prepared_input: input.clone(),
                    deadlines: fixture::deadlines(),
                },
                &fixture::program_content().await,
            )
            .await
            .unwrap();
        let (wire, frames) =
            fixture::input_uploads(ready.channel(), &request, &input.canonical_bytes().unwrap());
        let connection = admission::Cancellation::new();
        crate::test_support::drive_upload(
            service
                .upload_stream(
                    Box::pin(futures::stream::iter(frames.into_iter().map(Ok))),
                    TransportContext {
                        open_exporter: Some([7; 32]),
                        ..Default::default()
                    },
                    connection.clone(),
                )
                .await,
        )
        .await
        .unwrap();
        let refusal = service
            .accept(
                &wire,
                Some(Box::new(|_, _, _| {
                    Err(admission::AdmissionError::Capacity.into())
                })),
            )
            .await;
        assert!(matches!(
            refusal.outcome,
            Some(hellas_rpc::pb::work::accept_work_response::Outcome::Refused(_))
        ));
        assert!(
            service
                .with_state(|state| state.jobs().next().is_none())
                .await
                .unwrap()
        );
        let capacity = Arc::new(tokio::sync::Semaphore::new(1));
        let reserved = capacity.clone();
        let (started, executed) = tokio::sync::oneshot::channel();
        let execution: super::AcceptExecution = Box::new(move |input, caller, _ready| {
            assert_eq!(
                caller,
                hellas_auth::PublicKey::Secp256k1(fixture::client().party_key().to_bytes())
            );
            let key = admission::BackendKey::of(input)?;
            let permit =
                admission::WorkPermit::new(key.domain(), reserved.try_acquire_owned().unwrap());
            Ok(Box::new(move |work| {
                started.send((work, permit)).unwrap();
            }))
        });
        let (entered, release) = service
            .endpoint()
            .await
            .unwrap()
            .close
            .store
            .pause_next_statement_for_test()
            .await;
        let (accepting, proposal) = (service.clone(), wire.clone());
        let caller =
            tokio::spawn(async move { accepting.accept(&proposal, Some(execution)).await });
        tokio::time::timeout(crate::test_support::HANG_GUARD, entered)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            capacity.available_permits(),
            0,
            "reserved before the first journal frame"
        );
        caller.abort();
        let _ = caller.await;
        connection.cancel();
        assert!(
            node.ram_pool().held() > 0,
            "the owned transition retains staged bytes while the real SQLite worker waits"
        );
        release.send(()).unwrap();
        let response =
            tokio::time::timeout(crate::test_support::HANG_GUARD, service.accept(&wire, None))
                .await
                .unwrap();
        let work = client.accepted(&response).await.unwrap();
        let (executed, permit) = executed.await.unwrap();
        assert_eq!(
            executed, work,
            "the accepted owner survives the dropped RPC"
        );
        drop(permit);
        assert_eq!(capacity.available_permits(), 1);

        assert_eq!(
            node.ram_pool().held(),
            0,
            "accepted input moves out of staging accounting"
        );
        assert!(matches!(
            service.begin_run(work, &ready).await.unwrap(),
            RunAdmission::Invoke(_)
        ));
        service.end_run(work).await.unwrap();
        for path in crate::test_support::all_files(root.path()) {
            let bytes = std::fs::read(path).unwrap();
            let body = input.canonical_bytes().unwrap();
            assert!(!bytes.windows(body.len()).any(|window| window == body));
        }
    }

    #[tokio::test]
    async fn retained_restart_delivers_and_verifies_when_input_plus_transcript_exceeds_ram() {
        use crate::test_support::channel as fixture;
        use hellas_rpc::protocol::invocation::{Artifact, InvocationInput, compute, output};
        use hellas_store::content::{DiskStore, IndexMode, Reservations};

        async fn reopen(
            root: &std::path::Path,
            ready: &ReadyChannel,
            role: Role,
            bytes: u64,
        ) -> ChannelStore {
            let location = StoreLocation::for_test(root);
            let content = DiskStore::open(
                location.child("content"),
                vec![],
                IndexMode::Resume,
                None,
                Reservations::ram(bytes),
                false,
            )
            .await
            .unwrap();
            let store = ChannelStore::open(
                &location,
                ready.channel().clone(),
                fixture::settlement(),
                role,
                fixture::origin(),
                content.clone(),
                &Secp256k1Verifier::new(),
            )
            .await
            .unwrap();
            content.finish_recovery().await.unwrap();
            store
        }

        let provider_root = tempfile::tempdir().unwrap();
        let client_root = tempfile::tempdir().unwrap();
        let policy = fixture::work_policy();
        let ready = fixture::ready_of(&fixture::descriptor_with(policy.clone()), fixture::CURSOR);
        let mut plan = fixture::plan();
        plan.calls[0].args.push(compute::Arg::Input {
            object: "prompt".into(),
        });
        plan.outputs[0].kind = compute::OutputKind::Buffer {
            max_bytes: 768 << 10,
        };
        let invocation = InvocationInput {
            artifacts: vec![Artifact::new(
                "prompt",
                "catena.bytes.v1",
                vec![3; 768 << 10],
            )],
            parameters: hellas_rpc::JsonBytes(plan.canonical_bytes().unwrap()),
        };
        let mut request = fixture::invocation_request(1);
        request.input = invocation.content_id().unwrap();
        let input = PreparedInvocation::new(
            request,
            &fixture::manifest(),
            invocation,
            policy.canonical_bytes().unwrap(),
        )
        .unwrap();
        let input_len = input.canonical_bytes().unwrap().len() as u64;
        let mut client = ClientEndpoint::new(
            ready.clone(),
            fixture::store_at(client_root.path(), &ready, Role::Client, fixture::CURSOR).await,
            fixture::client(),
        )
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
        let request = client
            .propose(
                &JobProposal {
                    prepared_input: input.clone(),
                    deadlines: fixture::deadlines(),
                },
                &fixture::program_content().await,
            )
            .await
            .unwrap();
        let authorization = PaidJobAuthorizationV2::decode(&request.authorization).unwrap();
        fixture::seed_content(
            provider.fixture_store(),
            authorization,
            input.canonical_bytes().unwrap().into(),
        )
        .await;
        let reply = provider.accept(&request, None).await;
        let work = client.accepted(&reply).await.unwrap();
        provider.begin_run(work, &ready).await.unwrap();
        let transcript = output::InvocationOutput {
            outcome: output::Outcome::Succeeded,
            artifacts: vec![Artifact::new(
                "answer",
                "catena.bytes.v1",
                vec![7; 768 << 10],
            )],
            metadata: hellas_rpc::JsonBytes(
                hellas_rpc::value::canonical_dag_cbor(&compute::RunMetadata {
                    steps: 0,
                    stop: None,
                })
                .unwrap(),
            ),
        }
        .sign(&input.request, &fixture::provider_producer(), 16 << 10)
        .unwrap();
        let transcript_len = encode_transcript(&transcript).unwrap().len() as u64;
        provider.record_result(work, &transcript).await.unwrap();
        let pool_bytes = input_len + transcript_len - 1;
        assert!(input_len < pool_bytes && transcript_len < pool_bytes);
        let provider_node = provider.close.store.content_store();
        let client_node = client.store.content_store();
        drop(provider);
        drop(client);
        provider_node.close().await;
        client_node.close().await;
        drop(provider_node);
        drop(client_node);

        let provider = reopen(provider_root.path(), &ready, Role::Provider, pool_bytes).await;
        let node = provider.content_store();
        let service = WorkService::new(
            ProviderEndpoint::new(ready.clone(), provider, fixture::provider()).unwrap(),
        );
        let client_store = reopen(client_root.path(), &ready, Role::Client, pool_bytes).await;
        let client_node = client_store.content_store();
        let mut client =
            ClientEndpoint::new(ready.clone(), client_store, fixture::client()).unwrap();
        let (transport, server) = crate::test_support::transport::transport_pair();
        let serving = fixture::serve_work(server, service.clone());
        let delivery =
            fetch_result_stream(transport.clone(), &mut client, &ready, work, |_| Ok(()))
                .await
                .unwrap();
        assert_eq!(delivery.transcript.len() as u64, transcript_len);
        assert_eq!(node.ram_pool().held(), transcript_len);
        drop(delivery);
        drop(client);
        client_node.close().await;
        drop(client_node);

        // Ready recovery validates against the caller's original input while
        // a charged transcript snapshot outlives the endpoint's cache changes.
        let client_store = reopen(client_root.path(), &ready, Role::Client, pool_bytes).await;
        let client_node = client_store.content_store();
        let mut client =
            ClientEndpoint::new(ready.clone(), client_store, fixture::client()).unwrap();
        client.load_retained_transcript(work, &input).await.unwrap();
        let retained = client.state().job_by_id(work).unwrap().transcript.clone();
        assert_eq!(client_node.ram_pool().held(), transcript_len);
        let records = client.store.len();
        let roots = client.state().retained_roots().clone();
        let mut wrong = input.clone();
        wrong.request.nonce = [2; 32];
        assert!(client.verified(work, &wrong).await.is_err());
        assert_eq!(client.store.len(), records);
        assert_eq!(client.state().retained_roots(), &roots);
        assert_eq!(
            client.state().job_by_id(work).unwrap().phase(),
            JobPhase::Ready
        );
        client.verified(work, &input).await.unwrap();
        assert_eq!(client_node.ram_pool().held(), transcript_len);
        assert_eq!(
            ContentRef::for_bytes(&retained),
            client
                .state()
                .job_by_id(work)
                .unwrap()
                .result()
                .unwrap()
                .0
                .transcript_content
        );
        let payment = client.pay(work).await.unwrap();
        let credited = service.credit(&payment).await;
        assert_eq!(
            client.acknowledged(work, &credited).unwrap(),
            fixture::PRICE
        );
        serving.abort();
    }

    #[tokio::test]
    async fn retained_hydration_preserves_ephemeral_bodies_until_their_terminal() {
        use crate::test_support::channel as fixture;
        use base64::Engine as _;
        use hellas_rpc::output::{AdaptorEvent, HttpResponseEvent, OutputEvent, StopReason};
        let provider_root = tempfile::tempdir().unwrap();
        let client_root = tempfile::tempdir().unwrap();
        let mut policy = fixture::work_policy();
        policy.admissions.extend(fixture::fetch_policy().admissions);
        let ready = fixture::ready_of(&fixture::descriptor_with(policy.clone()), fixture::CURSOR);
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
        let mut retained = fixture::bundle(1);
        retained.application_policy = hellas_rpc::JsonBytes(policy.canonical_bytes().unwrap());
        let mut ephemeral = fixture::fetch_bundle(2);
        ephemeral.application_policy = retained.application_policy.clone();
        let content = fixture::program_content().await;
        let mut ids = Vec::new();
        for input in [&retained, &ephemeral] {
            let proposal = client
                .propose(
                    &JobProposal {
                        prepared_input: input.clone(),
                        deadlines: fixture::deadlines(),
                    },
                    &content,
                )
                .await
                .unwrap();
            let authorization = PaidJobAuthorizationV2::decode(&proposal.authorization).unwrap();
            fixture::seed_content(
                provider.fixture_store(),
                authorization,
                input.canonical_bytes().unwrap().into(),
            )
            .await;
            let reply = provider.accept(&proposal, None).await;
            ids.push(client.accepted(&reply).await.unwrap());
        }
        provider.begin_run(ids[0], &ready).await.unwrap();
        provider
            .record_result(
                ids[0],
                &fixture::transcript_for(&retained.request, &[9, 10]),
            )
            .await
            .unwrap();
        provider
            .close
            .store
            .load_retained_input(ids[0])
            .await
            .unwrap();
        let facts = provider.job_facts(ids[0]).unwrap();
        provider
            .close
            .store
            .load_retained_transcript(ids[0], facts.max_spool_bytes, false)
            .await
            .unwrap();
        assert_eq!(
            provider.state().job_by_id(ids[1]).unwrap().prepared_input(),
            ephemeral.canonical_bytes().unwrap()
        );
        provider.begin_run(ids[1], &ready).await.unwrap();
        let payloads = [
            OutputEvent::Adaptor(AdaptorEvent::Http(HttpResponseEvent::Head {
                status: 200,
                headers: vec![],
            })),
            OutputEvent::Adaptor(AdaptorEvent::Http(HttpResponseEvent::Body {
                base64: base64::engine::general_purpose::STANDARD.encode([11, 12]),
            })),
        ]
        .iter()
        .map(|event| hellas_rpc::fetch::encode_fetch_event_payload(event).unwrap())
        .collect::<Vec<_>>();
        let terminal = hellas_rpc::fetch::encode_fetch_terminal_payload(&OutputEvent::Finished {
            stop_reason: StopReason::EndOfText,
            usage: None,
        })
        .unwrap();
        let output = hellas_rpc::protocol::invocation::fetch::output(&payloads, &terminal)
            .unwrap()
            .sign(&ephemeral.request, &fixture::provider_producer(), 1024)
            .unwrap();
        provider.record_result(ids[1], &output).await.unwrap();
        let service = WorkService::new(provider);
        let (transport, server) = crate::test_support::transport::transport_pair();
        let serving = fixture::serve_work(server, service);
        fetch_result_stream(transport, &mut client, &ready, ids[1], |_| Ok(()))
            .await
            .unwrap();
        assert_eq!(
            client.state().job_by_id(ids[1]).unwrap().prepared_input(),
            ephemeral.canonical_bytes().unwrap()
        );
        client.verified(ids[1], &ephemeral).await.unwrap();
        assert!(
            !client
                .state()
                .job_by_id(ids[1])
                .unwrap()
                .prepared_input()
                .is_empty()
        );
        serving.abort();
    }

    #[tokio::test]
    async fn owned_collected_body_stays_verified_and_charged_when_another_job_evicts_its_cache() {
        use crate::test_support::channel as fixture;
        let root = tempfile::tempdir().unwrap();
        let client_root = tempfile::tempdir().unwrap();
        let ready = fixture::ready();
        let mut provider = ProviderEndpoint::new(
            ready.clone(),
            fixture::store_at(root.path(), &ready, Role::Provider, fixture::CURSOR).await,
            fixture::provider(),
        )
        .unwrap();
        let mut client = ClientEndpoint::new(
            ready.clone(),
            fixture::store_at(client_root.path(), &ready, Role::Client, fixture::CURSOR).await,
            fixture::client(),
        )
        .unwrap();
        let content = fixture::program_content().await;
        let mut jobs = Vec::new();
        for nonce in 1..=2 {
            let input = fixture::bundle(nonce);
            let proposal = client
                .propose(
                    &JobProposal {
                        prepared_input: input.clone(),
                        deadlines: fixture::deadlines(),
                    },
                    &content,
                )
                .await
                .unwrap();
            let response = fixture::accept_uploaded(&mut provider, &proposal).await;
            let work = client.accepted(&response).await.unwrap();
            provider.begin_run(work, &ready).await.unwrap();
            let events = fixture::transcript_for(&input.request, &[9, 10]);
            provider.record_result(work, &events).await.unwrap();
            jobs.push(work);
        }
        provider
            .close
            .store
            .load_retained_content(jobs[0])
            .await
            .unwrap();
        let job = provider.state().job_by_id(jobs[0]).unwrap();
        let expected = job.result().unwrap().0.transcript_content;
        let snapshot = job.transcript.clone();
        provider
            .close
            .store
            .load_retained_content(jobs[1])
            .await
            .unwrap();
        assert!(
            provider
                .state()
                .job_by_id(jobs[0])
                .unwrap()
                .transcript()
                .is_empty()
        );
        assert_eq!(ContentRef::for_bytes(&snapshot), expected);
        let current = provider.state().job_by_id(jobs[1]).unwrap();
        let pool = provider.close.store.content_store().ram_pool();
        assert_eq!(
            pool.held(),
            snapshot.len() as u64
                + current.prepared_input().len() as u64
                + current.transcript().len() as u64
        );
        let events = decode_transcript(&snapshot, fixture::WIDE_FRAME as usize).unwrap();
        let reconstructed = crate::job::paid_terminal_result(
            ready.channel(),
            provider.state().job_by_id(jobs[0]).unwrap().authorization(),
            ready.invocation_policy(),
            &fixture::bundle(1),
            &events,
        )
        .unwrap();
        assert_eq!(reconstructed.transcript_content, expected);
        let held = pool.held();
        let bytes = snapshot.len() as u64;
        drop(snapshot);
        assert_eq!(pool.held(), held - bytes);
    }

    #[tokio::test]
    async fn live_stream_authorization_reloads_its_body_after_another_retained_job_was_loaded() {
        use crate::test_support::channel as fixture;
        let root = tempfile::tempdir().unwrap();
        let client_root = tempfile::tempdir().unwrap();
        let ready = fixture::ready();
        let mut provider = ProviderEndpoint::new(
            ready.clone(),
            fixture::store_at(root.path(), &ready, Role::Provider, fixture::CURSOR).await,
            fixture::provider(),
        )
        .unwrap();
        let mut client = ClientEndpoint::new(
            ready.clone(),
            fixture::store_at(client_root.path(), &ready, Role::Client, fixture::CURSOR).await,
            fixture::client(),
        )
        .unwrap();
        let content = fixture::program_content().await;
        let mut jobs = Vec::new();
        for nonce in 1..=2 {
            let proposal = client
                .propose(
                    &JobProposal {
                        prepared_input: fixture::bundle(nonce),
                        deadlines: fixture::deadlines(),
                    },
                    &content,
                )
                .await
                .unwrap();
            let response = fixture::accept_uploaded(&mut provider, &proposal).await;
            jobs.push(client.accepted(&response).await.unwrap());
        }
        provider.begin_run(jobs[0], &ready).await.unwrap();
        provider
            .close
            .store
            .load_retained_content(jobs[1])
            .await
            .unwrap();
        assert!(
            provider
                .state()
                .job_by_id(jobs[0])
                .unwrap()
                .prepared_input()
                .is_empty()
        );
        let request = client.request_delivery(jobs[0], &[7; 32]).unwrap();
        let service = WorkService::new(provider);
        let mut reserved = service
            .reserve_stream_durably(&request, &[7; 32])
            .await
            .unwrap();
        reserved
            .close
            .store
            .load_retained_input(jobs[0])
            .await
            .unwrap();
        assert!(reserved.job_facts(jobs[0]).unwrap().max_spool_bytes > 0);
        drop(reserved);
        let endpoint = service.endpoint().await.unwrap();
        assert_eq!(
            endpoint.state().job_by_id(jobs[0]).unwrap().phase(),
            JobPhase::Streaming
        );
        assert!(
            !endpoint
                .state()
                .job_by_id(jobs[0])
                .unwrap()
                .prepared_input()
                .is_empty()
        );
        assert!(
            endpoint
                .state()
                .job_by_id(jobs[1])
                .unwrap()
                .prepared_input()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn disconnect_during_plaintext_append_cannot_poison_the_provider_journal() {
        use crate::test_support::channel as fixture;
        use hellas_kernel::PendingSlot;
        let provider_root = tempfile::tempdir().unwrap();
        let client_root = tempfile::tempdir().unwrap();
        let ready = fixture::descriptor()
            .check_ready(&fixture::observed_at(
                fixture::CURSOR,
                &fixture::bond_object(),
                &fixture::payment_object(),
                PendingSlot::Absent,
            ))
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
            .propose(
                &JobProposal {
                    prepared_input: fixture::bundle(1),
                    deadlines: fixture::deadlines(),
                },
                &fixture::program_content().await,
            )
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
                result = &mut reserve => panic!("append completed before cancellation: {:?}", result.err()),
                result = entered => result.unwrap(),
            }
        }
        drop(release);
        tokio::time::timeout(crate::test_support::HANG_GUARD, async {
            let mut endpoint = service.endpoint().await.unwrap();
            endpoint
                .close
                .store
                .commit(
                    ChannelRecord::Anchored {
                        height: fixture::CURSOR + 1,
                        payload: fixture::payload_at(fixture::CURSOR + 1),
                        certified_at_ms: fixture::now_ms(),
                        pending: None,
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
        // Finish the content pool's asynchronous close before reopening its upper.
        service
            .endpoint()
            .await
            .unwrap()
            .close
            .store
            .content_store()
            .close()
            .await;
        drop(service);
        let store = fixture::store_at(
            provider_root.path(),
            &ready,
            Role::Provider,
            fixture::CURSOR + 1,
        )
        .await;
        assert_eq!(
            store.state().job_by_id(work).unwrap().phase(),
            JobPhase::Streaming
        );
        assert_eq!(store.state().cursor().0, fixture::CURSOR + 1);
    }

    #[derive(Clone, Copy)]
    enum PauseAt {
        Loop,
        LiveBatch,
        Retained,
    }

    #[derive(Clone, Copy)]
    enum AfterPause {
        Resume,
        Expire,
        Close,
    }

    async fn paused_stream(pause_at: PauseAt, after: AfterPause) {
        use crate::test_support::channel as fixture;
        use base64::Engine as _;
        use hellas_rpc::output::{AdaptorEvent, HttpResponseEvent, OutputEvent, StopReason};
        use hellas_rpc::protocol::invocation::{Admission, fetch};
        use std::time::Duration;

        let provider_root = tempfile::tempdir().unwrap();
        let client_root = tempfile::tempdir().unwrap();
        let mut policy = fixture::fetch_policy();
        let Admission::Fetch { admission } = &mut policy.admissions[0] else {
            unreachable!();
        };
        admission.limits.max_encoded_result_frame = 8192;
        let descriptor = fixture::descriptor_with(policy.clone());
        let ready = fixture::ready_of(&descriptor, fixture::CURSOR);
        let mut input = fixture::fetch_bundle(1);
        input.application_policy = hellas_rpc::JsonBytes(policy.canonical_bytes().unwrap());
        let provider = ProviderEndpoint::new(
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
        let mut client = fixture::client_service(
            ClientEndpoint::new(
                ready.clone(),
                fixture::store_at(client_root.path(), &ready, Role::Client, fixture::CURSOR).await,
                fixture::client(),
            )
            .unwrap(),
            ready.clone(),
        )
        .await;
        let proposal = client
            .propose(
                &JobProposal {
                    prepared_input: input.clone(),
                    deadlines: fixture::deadlines(),
                },
                &fixture::program_content().await,
                None,
            )
            .await
            .unwrap();
        let service = WorkService::new(provider);
        let response = fixture::accept_uploaded_client(&service, &client, &proposal).await;
        let work = client
            .client()
            .await
            .unwrap()
            .accepted(&response)
            .await
            .unwrap();
        service.begin_run(work, &ready).await.unwrap();
        let facts = service.endpoint().await.unwrap().job_facts(work).unwrap();
        service.observe_ready(ready.clone()).await.unwrap();
        let payloads = [
            OutputEvent::Adaptor(AdaptorEvent::Http(HttpResponseEvent::Head {
                status: 200,
                headers: vec![],
            })),
            OutputEvent::Adaptor(AdaptorEvent::Http(HttpResponseEvent::Body {
                base64: base64::engine::general_purpose::STANDARD.encode(vec![7; 96]),
            })),
        ]
        .iter()
        .map(|event| hellas_rpc::fetch::encode_fetch_event_payload(event).unwrap())
        .collect::<Vec<_>>();
        let terminal = hellas_rpc::fetch::encode_fetch_terminal_payload(&OutputEvent::Finished {
            stop_reason: StopReason::EndOfText,
            usage: None,
        })
        .unwrap();
        let transcript = fetch::output(&payloads, &terminal)
            .unwrap()
            .sign(&input.request, &fixture::provider_producer(), 8)
            .unwrap();
        let prefixes = &transcript[..transcript.len() - 1];
        assert!(prefix_batches(prefixes, facts.max_encoded_result_frame).count() > 1);
        match pause_at {
            PauseAt::Retained => {
                service.record_result(work, &transcript).await.unwrap();
            }
            PauseAt::Loop | PauseAt::LiveBatch => {
                let initial = if matches!(pause_at, PauseAt::Loop) {
                    &prefixes[..1]
                } else {
                    prefixes
                };
                for event in initial {
                    service
                        .publish_progress(work, &facts, event.clone())
                        .unwrap();
                }
            }
        }
        let mut stream = service.result_stream(
            client
                .client()
                .await
                .unwrap()
                .request_delivery(work, &[7; 32])
                .unwrap(),
            TransportContext {
                open_exporter: Some([7; 32]),
                ..Default::default()
            },
        );
        let first = stream.next().await.unwrap().unwrap();
        assert!(matches!(
            first.outcome,
            Some(work_stream_event::Outcome::Prefix(_))
        ));
        service.suspend().await.unwrap();
        if !matches!(pause_at, PauseAt::Retained) {
            // Completion may be persisted while stale, but it must not be released.
            service.record_result(work, &transcript).await.unwrap();
        }
        let mut frames = vec![first];
        let next = stream.next();
        tokio::pin!(next);
        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut next)
                .await
                .is_err(),
            "stale observation must expose neither plaintext nor a terminal refusal"
        );
        assert!(
            service.observe_ready(ready.clone()).await.is_err(),
            "rereading the old certified height must not restore freshness"
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut next)
                .await
                .is_err(),
            "rereading the old certified height must not restore freshness"
        );

        let height = if matches!(after, AfterPause::Expire) {
            fixture::deadlines().terminal - 1
        } else {
            fixture::CURSOR + 1
        };
        use hellas_kernel::PendingSlot;
        let pending = if matches!(after, AfterPause::Close) {
            let start = crate::work_close::close_start(
                ready.channel(),
                hellas_kernel::Party::Maker,
                fixture::CURSOR,
                None,
                &fixture::client(),
            )
            .unwrap();
            PendingSlot::Present(
                hellas_kernel::PendingPaymentClose::from_accepted_start(
                    ready.channel().network(),
                    height,
                    fixture::now_ms(),
                    &start,
                )
                .unwrap(),
            )
        } else {
            PendingSlot::Absent
        };
        fixture::observe_service(&service, height, pending).await;
        if matches!(after, AfterPause::Resume) {
            service
                .observe_ready(fixture::ready_of(&descriptor, height))
                .await
                .unwrap();
        }
        let resumed = tokio::time::timeout(crate::test_support::HANG_GUARD, &mut next)
            .await
            .expect("finalized progress must wake the same stream")
            .unwrap();
        if !matches!(after, AfterPause::Resume) {
            match resumed {
                Ok(WorkStreamEvent {
                    outcome: Some(work_stream_event::Outcome::Refused(refusal)),
                }) => {
                    assert_eq!(
                        refusal.code,
                        if matches!(after, AfterPause::Expire) {
                            WorkRefusalCode::Expired as i32
                        } else {
                            WorkRefusalCode::Declined as i32
                        }
                    );
                }
                Err(error) => {
                    assert_eq!(error.code, hellas_wire::WireCode::Unavailable);
                    if matches!(after, AfterPause::Expire) {
                        assert!(error.to_string().contains("delivery"), "{error}");
                    }
                }
                other => panic!("ended stream released output: {other:?}"),
            }
            assert!(stream.next().await.is_none());
            assert_eq!(
                service
                    .with_state(|state| state.ledger().credited_cumulative())
                    .await
                    .unwrap(),
                0
            );
            return;
        }
        frames.push(resumed.unwrap());
        while let Some(frame) = stream.next().await {
            frames.push(frame.unwrap());
        }
        let mut received = Vec::new();
        let mut completed = None;
        for frame in frames {
            let bytes = match frame.outcome.unwrap() {
                work_stream_event::Outcome::Prefix(bytes) => {
                    assert!(completed.is_none(), "prefix after terminal");
                    bytes
                }
                work_stream_event::Outcome::Terminal(end) => {
                    assert!(completed.is_none(), "duplicate terminal");
                    let bytes = end.terminal_transcript.clone();
                    completed = Some(end);
                    bytes
                }
                other => panic!("unexpected resumed frame: {other:?}"),
            };
            received.extend(decode_transcript(&bytes, facts.max_spool_bytes as usize).unwrap());
        }
        assert_eq!(received, transcript, "no skipped or replayed envelopes");
        let completed = completed.expect("exactly one terminal");
        client
            .client()
            .await
            .unwrap()
            .receive_stream(
                work,
                &ready,
                &ResultTranscript {
                    result: completed.result,
                    provider_signature: completed.provider_signature,
                    transcript: encode_transcript(&received).unwrap(),
                },
                &input,
            )
            .await
            .unwrap();
        client
            .client()
            .await
            .unwrap()
            .verified(work, &input)
            .await
            .unwrap();
        let payment = client.client().await.unwrap().pay(work).await.unwrap();
        let credited = service.credit(&payment).await;
        assert_eq!(
            client
                .client()
                .await
                .unwrap()
                .acknowledged(work, &credited)
                .unwrap(),
            fixture::PRICE
        );
        assert_eq!(
            service.credit(&payment).await,
            credited,
            "payment is idempotent"
        );
        service
            .with_state(|state| {
                assert_eq!(state.ledger().credited_cumulative(), fixture::PRICE);
                assert_eq!(state.jobs().count(), 0);
                assert!(matches!(
                    state.terminal_by_id(work).unwrap().outcome,
                    TerminalOutcome::Certified { .. }
                ));
            })
            .await
            .unwrap();
        assert!(matches!(
            client
                .client()
                .await
                .unwrap()
                .state()
                .terminal_by_id(work)
                .unwrap()
                .outcome,
            TerminalOutcome::Certified { .. }
        ));
    }

    #[tokio::test]
    async fn stale_live_stream_pauses_at_loop_admission_and_settles_once() {
        paused_stream(PauseAt::Loop, AfterPause::Resume).await;
    }

    #[tokio::test]
    async fn stale_live_stream_pauses_between_batches_and_settles_once() {
        paused_stream(PauseAt::LiveBatch, AfterPause::Resume).await;
    }

    #[tokio::test]
    async fn stale_retained_stream_pauses_between_frames_and_settles_once() {
        paused_stream(PauseAt::Retained, AfterPause::Resume).await;
    }

    #[tokio::test]
    async fn stale_stream_still_expires_at_its_signed_delivery_deadline() {
        for pause_at in [PauseAt::Loop, PauseAt::LiveBatch, PauseAt::Retained] {
            paused_stream(pause_at, AfterPause::Expire).await;
        }
    }

    #[tokio::test]
    async fn stale_stream_stops_at_a_journaled_close_before_readiness_refresh() {
        for pause_at in [PauseAt::Loop, PauseAt::LiveBatch, PauseAt::Retained] {
            paused_stream(pause_at, AfterPause::Close).await;
        }
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
        let exact = WorkStreamEvent {
            outcome: Some(work_stream_event::Outcome::Prefix(
                encode_transcript(&events[..24]).unwrap(),
            )),
        }
        .encoded_len() as u32;
        assert_eq!(prefix_batches(&events, exact).next().unwrap().len(), 24);
        assert_eq!(prefix_batches(&events, exact - 1).next().unwrap().len(), 23);
        for limit in [4096, 65536, exact, exact - 1] {
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
