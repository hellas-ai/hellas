//! Paid Fetch runs have their own durable admission in hellas-work. Bodies
//! remain in memory; neither Courtesy replay nor its transcript store is used.

use std::sync::Arc;

use hellas_rpc::OutputEventEnvelope;
use hellas_work::work::PreparedFetchInput;
use tokio::sync::{mpsc, oneshot};

use super::Executor;
use crate::ExecutorError;
use crate::executor::ExecutorCompletion;
use crate::fetch_policy::FetchRoute;
use crate::fetch_provider::FetchCall;

impl Executor {
    pub(super) fn start_paid_fetch(
        &mut self,
        input: PreparedFetchInput,
        progress: Option<hellas_work::work::PaidProgress>,
        reply: oneshot::Sender<Result<Vec<OutputEventEnvelope>, ExecutorError>>,
    ) {
        let prepared = self.prepare_paid_fetch(input);
        let (entry, session, request, policy) = match prepared {
            Ok(prepared) => prepared,
            Err(error) => {
                let _ = reply.send(Err(error));
                return;
            }
        };
        self.active_fetches += 1;
        let completion = self.completion_tx.clone();
        let key = Arc::clone(&self.provider.producer_key);
        tokio::spawn(async move {
            let (sender, mut receiver) = mpsc::channel(64);
            let run = super::execution::run_fetch_provider(
                entry.provider,
                session.provider_request,
                session.projector,
                request.input_commitment,
                request.assurance,
                &key,
                sender,
            );
            let drain = async move {
                while let Some(event) = receiver.recv().await {
                    let event =
                        event.map_err(|error| ExecutorError::Execution(error.to_string()))?;
                    if let Some(hellas_rpc::pb::execute::work_event::Kind::Chunk(chunk)) =
                        event.kind
                        && let Some(progress) = &progress
                    {
                        let event = chunk.output_event.ok_or_else(|| {
                            ExecutorError::Execution(
                                "paid Fetch chunk omitted its signature".into(),
                            )
                        })?;
                        let event = hellas_rpc::stream::output_event_from_pb(event)
                            .map_err(|error| ExecutorError::Execution(error.to_string()))?;
                        progress(event)
                            .map_err(|error| ExecutorError::Execution(error.to_string()))?;
                    }
                }
                Ok::<_, ExecutorError>(())
            };
            let (result, drained) = tokio::join!(run, drain);
            let result = drained.and_then(|()| {
                result
                    .map_err(|_| {
                        ExecutorError::Execution("paid fetch upstream or projection failed".into())
                    })
                    .and_then(|run| {
                        hellas_rpc::protocol::work_fetch::check_fetch_output_limits(
                            &policy,
                            &run.output_events,
                        )
                        .map_err(|_| {
                            ExecutorError::Execution(
                                "paid fetch output exceeds its signed limits".into(),
                            )
                        })?;
                        Ok(run.output_events)
                    })
            });
            let _ = completion
                .send(ExecutorCompletion::PaidFetch { reply, result })
                .await;
        });
    }

    fn prepare_paid_fetch(
        &self,
        input: PreparedFetchInput,
    ) -> Result<
        (
            crate::FetchRouteEntry,
            crate::FetchAdaptorSession,
            hellas_rpc::fetch::FetchInput,
            hellas_rpc::protocol::work_fetch::PaidFetchPolicyV1,
        ),
        ExecutorError,
    > {
        if self.active_fetches >= self.fetch_max_in_flight {
            return Err(ExecutorError::ResourceExhausted(
                "fetch concurrency limit reached".into(),
            ));
        }
        let policy = *input.policy();
        let parts = input.into_parts();
        let request = hellas_rpc::fetch::verify_input_events(&parts.fetch_input_transcript)
            .map_err(|_| ExecutorError::InvalidQuoteRequest("invalid paid fetch input".into()))?;
        if request.retention != hellas_rpc::Retention::Ephemeral
            || request.assurance != self.provider.assurance
            || request.execution_environment != parts.manifest.content_id()
        {
            return Err(ExecutorError::InvalidQuoteRequest(
                "paid fetch contract mismatch".into(),
            ));
        }
        let route = FetchRoute::new(&request.service, &request.method);
        let entry = self.fetch_routes.entry(&route).cloned().ok_or_else(|| {
            ExecutorError::InvalidQuoteRequest("paid fetch route is unavailable".into())
        })?;
        if entry.execution_environment() != request.execution_environment {
            return Err(ExecutorError::InvalidQuoteRequest(
                "paid fetch route manifest mismatch".into(),
            ));
        }
        let call = FetchCall::new(
            &request.service,
            &request.method,
            request.body.clone(),
            request.input_commitment,
        );
        let session = entry.adaptor_factory.create(&call).map_err(|_| {
            ExecutorError::InvalidQuoteRequest("paid fetch adaptor rejected request".into())
        })?;
        entry
            .capabilities
            .validate(&session.request_view)
            .map_err(|_| {
                ExecutorError::PolicyDenied("paid fetch exceeds route capabilities".into())
            })?;
        Ok((entry, session, request, policy))
    }
}
