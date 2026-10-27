use super::principal;
use crate::work::{admission::*, *};
use hellas_rpc::{fetch::*, output::*};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tokio::sync::{Notify, Semaphore};

#[derive(Clone)]
pub enum Completion {
    Immediate,
    Notified(Arc<Notify>),
    Permits(Arc<Semaphore>),
}
impl Completion {
    pub async fn wait(&self) {
        match self {
            Self::Immediate => {}
            Self::Notified(gate) => gate.notified().await,
            Self::Permits(gate) => gate.acquire().await.unwrap().forget(),
        }
    }
    pub fn release(&self) {
        match self {
            Self::Immediate => panic!("immediate backend has no completion gate"),
            Self::Notified(gate) => gate.notify_one(),
            Self::Permits(gate) => gate.add_permits(1),
        }
    }
}

#[derive(Clone)]
pub enum Reply {
    Events {
        prefixes: Vec<OutputEvent>,
        replacement: Option<Vec<OutputEvent>>,
    },
    Failure {
        panic: bool,
    },
}
impl Reply {
    pub fn events(prefixes: Vec<OutputEvent>) -> Self {
        Self::Events {
            prefixes,
            replacement: None,
        }
    }
    pub fn text(text: &str, count: usize) -> Self {
        Self::events(
            (0..count)
                .map(|_| OutputEvent::TextDelta {
                    index: 0,
                    delta: text.into(),
                    channel: TextChannel::Output,
                })
                .collect(),
        )
    }
    pub fn http(status: u16, content_type: &str, body: &str) -> Vec<OutputEvent> {
        use base64::Engine as _;
        [
            HttpResponseEvent::Head {
                status,
                headers: vec![("content-type".into(), content_type.into())],
            },
            HttpResponseEvent::Body {
                base64: base64::engine::general_purpose::STANDARD.encode(body),
            },
        ]
        .into_iter()
        .map(|event| OutputEvent::Adaptor(AdaptorEvent::Http(event)))
        .collect()
    }
    pub fn usage(status: u16, rewrite: bool) -> Self {
        Self::Events {
            prefixes: Self::http(
                status,
                "application/json",
                r#"{"usage":{"prompt_tokens":3,"completion_tokens":2}}"#,
            ),
            replacement: rewrite.then(|| {
                Self::http(
                    status,
                    "application/json",
                    r#"{"usage":{"prompt_tokens":3,"completion_tokens":1}}"#,
                )
            }),
        }
    }
}

pub type ContentInspection = Arc<
    dyn Fn(
            &hellas_rpc::protocol::invocation::PreparedInvocation,
            &crate::content::InvocationContent,
        ) + Send
        + Sync,
>;

/// One signed Fetch backend; replies, completion gates and cancellation remain explicit.
#[derive(Clone)]
pub struct Backend {
    pub slots: Arc<Semaphore>,
    pub calls: Arc<AtomicUsize>,
    pub queued: Option<Arc<Notify>>,
    pub started: Arc<Notify>,
    pub finish: Completion,
    /// Released once before each prefix after the first.
    pub pace: Option<Completion>,
    pub cancelled: Arc<Notify>,
    pub stop_on_cancel: bool,
    pub reply: Reply,
    pub inspect: Option<fn(&FetchInput)>,
    pub inspect_content: Option<ContentInspection>,
    pub signer: Arc<hellas_auth::ProducerSigningKey>,
}
impl Default for Backend {
    fn default() -> Self {
        Self {
            slots: Arc::new(Semaphore::new(1)),
            calls: Arc::new(AtomicUsize::new(0)),
            queued: None,
            started: Arc::new(Notify::new()),
            finish: Completion::Notified(Arc::new(Notify::new())),
            pace: None,
            cancelled: Arc::new(Notify::new()),
            stop_on_cancel: false,
            reply: Reply::text("private-grant-result", 1),
            inspect: None,
            inspect_content: None,
            signer: Arc::new(principal(2).1),
        }
    }
}
impl WorkBackend for Backend {
    async fn execute(
        &self,
        input: Admitted<hellas_rpc::protocol::invocation::PreparedInvocation>,
    ) -> Result<Vec<hellas_rpc::OutputEventEnvelope>, BackendFault> {
        self.execute_stream(input, Arc::new(|_| Ok(()))).await
    }
    async fn execute_stream(
        &self,
        prepared: Admitted<hellas_rpc::protocol::invocation::PreparedInvocation>,
        progress: PaidProgress,
    ) -> Result<Vec<hellas_rpc::OutputEventEnvelope>, BackendFault> {
        use hellas_rpc::protocol::invocation::{
            fetch as invocation_fetch, output as invocation_output,
        };
        let domain = prepared.capacity_domain();
        let (prepared, limits, content, admission) = prepared.into_parts_and_admission();
        if let Some(queued) = &self.queued {
            queued.notified().await;
        }
        let running = admission
            .reserve(domain, async { self.try_admit(domain) })
            .await?
            .dispatch()
            .await?;
        self.calls.fetch_add(1, Ordering::SeqCst);
        if let Some(inspect) = &self.inspect_content {
            inspect(&prepared, &content);
        }
        let mut stream = invocation_output::OutputStream::new(
            &prepared.request,
            &self.signer,
            limits.max_output_bytes as usize,
        )
        .unwrap();
        let output = if domain == CapacityDomain::Gpu {
            let output = invocation_output::InvocationOutput {
                outcome: invocation_output::Outcome::Succeeded,
                artifacts: vec![hellas_rpc::protocol::invocation::Artifact::new(
                    "answer",
                    "catena.bytes.v1",
                    vec![0],
                )],
                metadata: hellas_rpc::JsonBytes(
                    hellas_rpc::protocol::value::canonical_dag_cbor(
                        &hellas_rpc::protocol::invocation::compute::RunMetadata {
                            steps: 0,
                            stop: None,
                        },
                    )
                    .unwrap(),
                ),
            };
            progress(stream.push("answer", "catena.bytes.v1", 0, &[0]).unwrap())?;
            output
        } else {
            let artifact = &prepared.input.artifacts[0];
            let events: Vec<hellas_rpc::InputEventEnvelope> =
                hellas_rpc::protocol::value::decode_canonical_dag_cbor(artifact.bytes.as_bytes())
                    .unwrap();
            let request = verify_input_events(&events).unwrap();
            if let Some(inspect) = self.inspect {
                inspect(&request);
            }
            let Reply::Events {
                prefixes,
                replacement,
            } = &self.reply
            else {
                self.started.notify_one();
                self.finish.wait().await;
                assert!(
                    !matches!(self.reply, Reply::Failure { panic: true }),
                    "backend fixture panic"
                );
                return Err(BackendFault::caused_by(std::io::Error::other(
                    "backend fixture stopped",
                )));
            };
            let mut offset = 0;
            let mut payloads = Vec::new();
            for (index, event) in prefixes.iter().enumerate() {
                if index > 0
                    && let Some(pace) = &self.pace
                {
                    pace.wait().await;
                }
                let payload = encode_fetch_event_payload(event).unwrap();
                let bytes = invocation_fetch::frame_event(&payload).unwrap();
                progress(
                    stream
                        .push(
                            invocation_fetch::RESPONSE_EVENTS,
                            invocation_fetch::RESPONSE_EVENTS_FORMAT,
                            offset,
                            &bytes,
                        )
                        .unwrap(),
                )?;
                offset += bytes.len() as u64;
                payloads.push(payload);
            }
            if let Some(events) = replacement {
                payloads = events
                    .iter()
                    .map(|event| encode_fetch_event_payload(event).unwrap())
                    .collect();
                stream = invocation_output::OutputStream::new(
                    &prepared.request,
                    &self.signer,
                    limits.max_output_bytes as usize,
                )
                .unwrap();
            }
            invocation_fetch::output(
                &payloads,
                &encode_fetch_terminal_payload(&OutputEvent::Finished {
                    stop_reason: StopReason::EndOfText,
                    usage: None,
                })
                .unwrap(),
            )
            .unwrap()
        };
        self.started.notify_one();
        if matches!(self.finish, Completion::Notified(_)) {
            tokio::select! {
                () = self.finish.wait() => {},
                () = running.cancelled() => {
                    self.cancelled.notify_one(); self.finish.wait().await;
                    if self.stop_on_cancel { return Err(AdmissionError::Cancelled.into()); }
                }
            }
        } else {
            self.finish.wait().await;
        }
        Ok(stream.finish(&output, 1024).unwrap())
    }

    fn try_admit(&self, domain: CapacityDomain) -> Result<WorkPermit, BackendFault> {
        Ok(WorkPermit::new(
            domain,
            self.slots
                .clone()
                .try_acquire_owned()
                .map_err(|_| AdmissionError::Capacity)?,
        ))
    }
}
