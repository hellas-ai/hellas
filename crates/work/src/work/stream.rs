//! Live delivery over the existing job authorization and payment lifecycle.
use super::*;
use futures::{StreamExt, stream::BoxStream};
use hellas_rpc::pb::work::{WorkStreamEvent, work_stream_event};
use hellas_rpc::protocol::work::decode_transcript;
use hellas_rpc::{
    Operation, StreamId, output_genesis, scheme_id, verify_output_event_continuation,
};

pub type PaidProgress = Arc<dyn Fn(OutputEventEnvelope) -> Result<(), BackendFault> + Send + Sync>;
pub type PaidResultStream = BoxStream<'static, Result<WorkStreamEvent, WireStatus>>;

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
        let limit = self
            .endpoint()
            .map_err(|error| BackendFault::new(error.to_string()))?
            .admitting()
            .map_err(|error| BackendFault::new(error.to_string()))?
            .execution_policy()
            .max_spool_bytes;
        let mut progress = self.progress.lock().expect("paid progress poisoned");
        let events = progress.entry(work_id).or_default();
        // Signed token events are bounded by the same spool as final delivery.
        let bytes = event.payload().len() + 1024;
        let retained = events
            .iter()
            .map(|event| event.payload().len() + 1024)
            .sum::<usize>();
        if retained.saturating_add(bytes) as u64 > limit {
            return Err(BackendFault::new(
                "live result exceeds its authorized spool",
            ));
        }
        events.push(event);
        drop(progress);
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
                                yield Ok(WorkStreamEvent { outcome: Some(work_stream_event::Outcome::Delivered(delivered)) });
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
                            progress.get(&work_id).map(|events| events[position.min(events.len())..].to_vec()).unwrap_or_default()
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

/// Deliver verified token prefixes and finally journal the complete result.
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
    let prepared = PreparedPaidInputV1::decode(job.prepared_input(), MAX_RECORD_BYTES)
        .map_err(PaidWorkError::from)?;
    let parts = prepared.parts().map_err(PaidWorkError::from)?;
    let input = hellas_rpc::evaluate::input_commitment(&parts.evaluate_request);
    let mut token_count = 0u64;
    let mut retained_bytes = 0usize;
    let key = hellas_rpc::PublicKey::Secp256k1(ready.channel().provider_key().to_bytes());
    let scheme = scheme_id(Operation::Evaluate, hellas_rpc::Assurance::ProducerSigned);
    let mut previous = output_genesis(input, StreamId::from_input_commitment(input));
    let mut streamed = Vec::new();
    let mut stream = WorkClientImpl::new(transport)
        .stream_result(request)
        .await?;
    while let Some(event) = stream.next().await {
        match event?.outcome {
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
                    if event.event().body().kind() != hellas_rpc::evaluate::TOKEN_DELTA_EVENT_KIND {
                        return Err(DeliverError::Malformed(
                            "live prefix must contain token deltas",
                        ));
                    }
                    let delta = hellas_rpc::evaluate::decode_token_delta_payload(event.payload())
                        .map_err(|error| PaidWorkError::Transcript(error.to_string()))?;
                    token_count = token_count.saturating_add(delta.token_ids.len() as u64);
                    retained_bytes = retained_bytes.saturating_add(event.payload().len() + 1024);
                    if token_count > u64::from(parts.text_policy.max_new_tokens())
                        || retained_bytes as u64 > ready.execution_policy().max_spool_bytes
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
                    if event.event().body().kind() == hellas_rpc::evaluate::TOKEN_DELTA_EVENT_KIND {
                        progress(event)?;
                    }
                }
                return Ok(result);
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
