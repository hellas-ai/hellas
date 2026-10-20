use super::principal;
use crate::work::{admission::*, *};
use hellas_rpc::{OutputEventEnvelope, fetch::*, output::*};
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
            signer: Arc::new(principal(2).1),
        }
    }
}
impl WorkBackend for Backend {
    async fn evaluate_stream(
        &self,
        input: PreparedEvaluateInput,
        progress: PaidProgress,
    ) -> Result<Vec<OutputEventEnvelope>, BackendFault> {
        use hellas_rpc::evaluate::*;
        let (parts, admission) = input.into_parts_and_admission();
        let _running = admission
            .reserve(CapacityDomain::Gpu, async {
                self.try_admit(CapacityDomain::Gpu)
            })
            .await?
            .dispatch()
            .await?;
        self.calls.fetch_add(1, Ordering::SeqCst);
        let mut output = EvaluateOutputTranscriptBuilder::new(
            input_commitment(&parts.evaluate_request),
            parts.evaluate_request.assurance,
            &self.signer,
        );
        progress(output.push_token_delta(vec![0]).unwrap())?;
        self.started.notify_one();
        self.finish.wait().await;
        let usage = EvaluateUsage {
            input_units: parts.prompt_tokens.as_slice().len() as u64,
            output_units: 1,
        };
        Ok(output
            .finish(EvaluateTerminal {
                final_position: 1,
                stop_reason: EvaluateStopReason::MAX_OUTPUT,
                matched_stop_token_id: None,
                text_artifact: hellas_auth::Digest::hash(b"test native result"),
                usage,
                billable_units: usage.billable_units().unwrap(),
            })
            .unwrap())
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
    async fn fetch_stream(
        &self,
        input: PreparedFetchInput,
        progress: PaidProgress,
    ) -> Result<Vec<OutputEventEnvelope>, BackendFault> {
        let (parts, admission) = input.into_parts_and_admission();
        if let Some(queued) = &self.queued {
            queued.notified().await;
        }
        let running = admission
            .reserve(CapacityDomain::Fetch, async {
                self.try_admit(CapacityDomain::Fetch)
            })
            .await?
            .dispatch()
            .await?;
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
        self.calls.fetch_add(1, Ordering::SeqCst);
        let request = verify_input_events(&parts.fetch_input_transcript).unwrap();
        if let Some(inspect) = self.inspect {
            inspect(&request);
        }
        let key = self.signer.clone();
        let mut output =
            FetchOutputTranscriptBuilder::new(request.input_commitment, request.assurance, &key);
        for (index, event) in prefixes.iter().enumerate() {
            if index > 0
                && let Some(pace) = &self.pace
            {
                pace.wait().await;
            }
            progress(
                output
                    .push_event(encode_fetch_event_payload(event).unwrap())
                    .unwrap(),
            )?;
        }
        self.started.notify_one();
        if matches!(self.finish, Completion::Notified(_)) {
            tokio::select! {
                () = self.finish.wait() => {},
                () = running.cancelled() => {
                    self.cancelled.notify_one();
                    // Physical teardown still owns its permit after the cancellation signal.
                    self.finish.wait().await;
                    if self.stop_on_cancel { return Err(AdmissionError::Cancelled.into()); }
                }
            }
        } else {
            self.finish.wait().await;
        }
        if let Some(events) = replacement {
            output = FetchOutputTranscriptBuilder::new(
                request.input_commitment,
                request.assurance,
                &key,
            );
            for event in events {
                output
                    .push_event(encode_fetch_event_payload(event).unwrap())
                    .unwrap();
            }
        }
        Ok(output
            .finish(
                encode_fetch_terminal_payload(&OutputEvent::Finished {
                    stop_reason: StopReason::EndOfText,
                    usage: None,
                })
                .unwrap(),
            )
            .unwrap())
    }
}
