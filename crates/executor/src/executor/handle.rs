//! Server-side handler implementations.
//!
//! `ExecutorHandle` implements one Handler trait per service (Execute,
//! Evaluate, Fetch, Courtesy) — the codegen-emitted dispatcher routes
//! inbound RPCs here.

use std::pin::Pin;

use crate::ExecutorError;
use futures_core::Stream;
use hellas_rpc::call::WithTrailer;
use hellas_rpc::pb::courtesy::{
    GetArtifactRequest, GetArtifactResponse, GetStatsRequest, GetStatsResponse, QuoteResponse,
    QuoteTokensRequest,
};
use hellas_rpc::pb::evaluate::EvaluateRequest as PbEvaluateRequest;
use hellas_rpc::pb::execute::{OpenRequest, OpenResponse, RunTicketRequest, Ticket, WorkEvent};
use hellas_rpc::pb::fetch::FetchRequest as PbFetchRequest;
use hellas_rpc::provenance::write_provenance_metadata;
use hellas_rpc::services::courtesy::CourtesyHandler;
use hellas_rpc::services::evaluate::EvaluateHandler;
use hellas_rpc::services::execute::ExecuteHandler;
use hellas_rpc::services::fetch::FetchHandler;
use hellas_wire::{Metadata, WireCode, WireStatus};
use tokio::sync::oneshot;
use tokio_stream::wrappers::ReceiverStream;

use super::{ExecuteOutcome, ExecutorHandle, ExecutorOwedRequest, ExecutorRequest, TicketOutcome};

type ExecuteStream = Pin<Box<dyn Stream<Item = Result<WorkEvent, WireStatus>> + Send>>;
impl ExecutorHandle {
    /// Submit one request that may originate at the peer-facing RPC surface.
    ///
    /// Refusal is immediate when the bounded actor mailbox is full. Waiting
    /// here would let one adversarial client turn executor pressure into an
    /// unbounded population of suspended RPC tasks.
    pub(crate) async fn send<T>(
        &self,
        make_request: impl FnOnce(oneshot::Sender<Result<T, ExecutorError>>) -> ExecutorRequest,
    ) -> Result<T, ExecutorError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        match self.tx.try_send(make_request(reply_tx)) {
            Ok(()) => {}
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                return Err(ExecutorError::ResourceExhausted(
                    "executor request mailbox is full".to_string(),
                ));
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                return Err(ExecutorError::ChannelClosed);
            }
        }
        reply_rx.await.map_err(|_| ExecutorError::ChannelClosed)?
    }

    /// Submit work whose dispatch is already durable and therefore owed.
    ///
    /// Unlike peer-facing admission, this waits for bounded mailbox capacity:
    /// refusing a journaled `RunPaidEvaluate` because unrelated RPCs filled the
    /// ingress queue would strand a decision the paid-work gate already made.
    pub(crate) async fn send_owed<T>(
        &self,
        make_request: impl FnOnce(oneshot::Sender<Result<T, ExecutorError>>) -> ExecutorOwedRequest,
    ) -> Result<T, ExecutorError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.owed_tx
            .send(make_request(reply_tx))
            .await
            .map_err(|_| ExecutorError::ChannelClosed)?;
        reply_rx.await.map_err(|_| ExecutorError::ChannelClosed)?
    }

    pub async fn create_evaluate_ticket(
        &self,
        request: PbEvaluateRequest,
    ) -> Result<TicketOutcome<Ticket>, ExecutorError> {
        self.send(|reply| ExecutorRequest::QuoteEvaluate { request, reply })
            .await
    }

    pub async fn create_fetch_ticket(
        &self,
        request: PbFetchRequest,
    ) -> Result<TicketOutcome<Ticket>, ExecutorError> {
        self.send(|reply| ExecutorRequest::QuoteFetch { request, reply })
            .await
    }

    pub async fn quote_tokens(
        &self,
        request: QuoteTokensRequest,
    ) -> Result<TicketOutcome<QuoteResponse>, ExecutorError> {
        self.send(|reply| ExecutorRequest::QuoteTokens { request, reply })
            .await
    }

    /// Read from the retained Courtesy artifact namespace. Ephemeral job
    /// artifacts are held by a separate memory store in the evaluate engine
    /// and are intentionally unreachable through this handle.
    pub async fn get_artifact_handle(
        &self,
        request: GetArtifactRequest,
    ) -> Result<GetArtifactResponse, ExecutorError> {
        self.send(|reply| ExecutorRequest::GetArtifact { request, reply })
            .await
    }

    pub async fn run_ticket_handle(
        &self,
        request: RunTicketRequest,
    ) -> Result<ExecuteOutcome, ExecutorError> {
        self.send(|reply| ExecutorRequest::Execute {
            span: tracing::Span::current(),
            request,
            reply,
        })
        .await
    }

    pub async fn get_stats_handle(&self) -> Result<GetStatsResponse, ExecutorError> {
        self.send(|reply| ExecutorRequest::GetStats { reply }).await
    }
}

fn with_provenance<R>(outcome: TicketOutcome<R>) -> WithTrailer<R> {
    let mut metadata = Metadata::new();
    write_provenance_metadata(&mut metadata, &outcome.provenance);
    WithTrailer::with_metadata(outcome.response, metadata)
}

// -- ExecuteHandler -----------------------------------------------------------
//
// `run_ticket` is server-streaming. We return a `WorkEvent` stream; the
// codegen wraps it via the call helpers for the wire layer.

impl ExecuteHandler for ExecutorHandle {
    async fn run_ticket(&self, request: RunTicketRequest) -> Result<ExecuteStream, WireStatus> {
        let outcome = self.run_ticket_handle(request).await?;
        let ExecuteOutcome {
            events,
            provenance: _,
        } = outcome;
        let stream: ExecuteStream = Box::pin(ReceiverStream::new(events));
        Ok(stream)
    }
}

// -- EvaluateHandler / FetchHandler -----------------------------------------

// The generated trait method declares `impl Into<WithTrailer<T>> + Send`
// as its return; we provide `WithTrailer<T>` directly. The refinement is
// intentional: handler-emitted trailers are concrete.
#[allow(refining_impl_trait)]
impl EvaluateHandler for ExecutorHandle {
    async fn create_ticket(
        &self,
        request: PbEvaluateRequest,
    ) -> Result<WithTrailer<Ticket>, WireStatus> {
        let outcome = self.create_evaluate_ticket(request).await?;
        let result = with_provenance(outcome);
        Ok(result)
    }
}

#[allow(refining_impl_trait)]
impl FetchHandler for ExecutorHandle {
    async fn open(&self, _request: OpenRequest) -> Result<OpenResponse, WireStatus> {
        Err(WireStatus::new(
            WireCode::FailedPrecondition,
            "confidential open dispatcher is unavailable",
        ))
    }

    async fn create_ticket(
        &self,
        request: PbFetchRequest,
    ) -> Result<WithTrailer<Ticket>, WireStatus> {
        let outcome = self.create_fetch_ticket(request).await?;
        let result = with_provenance(outcome);
        Ok(result)
    }
}

// -- CourtesyHandler ---------------------------------------------------------

#[allow(refining_impl_trait)]
impl CourtesyHandler for ExecutorHandle {
    async fn open(&self, _request: OpenRequest) -> Result<OpenResponse, WireStatus> {
        Err(WireStatus::new(
            WireCode::FailedPrecondition,
            "confidential open dispatcher is unavailable",
        ))
    }

    async fn quote_tokens(
        &self,
        request: QuoteTokensRequest,
    ) -> Result<WithTrailer<QuoteResponse>, WireStatus> {
        let outcome = self.quote_tokens(request).await?;
        let result = with_provenance(outcome);
        Ok(result)
    }

    async fn get_artifact(
        &self,
        request: GetArtifactRequest,
    ) -> Result<GetArtifactResponse, WireStatus> {
        Ok(self.get_artifact_handle(request).await?)
    }

    async fn get_stats(&self, _request: GetStatsRequest) -> Result<GetStatsResponse, WireStatus> {
        Ok(self.get_stats_handle().await?)
    }
}

#[cfg(test)]
mod mailbox_tests {
    use std::time::Duration;

    use tokio::sync::{mpsc, oneshot};
    use tokio::time::timeout;

    use super::*;

    fn handle_with_capacity(capacity: usize) -> (ExecutorHandle, mpsc::Receiver<ExecutorRequest>) {
        let (tx, rx) = mpsc::channel(capacity);
        let (owed_tx, _owed_rx) = mpsc::channel(capacity);
        (ExecutorHandle { tx, owed_tx }, rx)
    }

    fn stats_request() -> ExecutorRequest {
        let (reply, _receiver) = oneshot::channel();
        ExecutorRequest::GetStats { reply }
    }

    #[tokio::test]
    async fn peer_request_refuses_a_full_mailbox_immediately() {
        let (handle, _rx) = handle_with_capacity(1);
        assert!(handle.tx.try_send(stats_request()).is_ok());

        let result = timeout(Duration::from_millis(100), handle.get_stats_handle())
            .await
            .expect("full-mailbox refusal must not wait");

        assert!(matches!(result, Err(ExecutorError::ResourceExhausted(_))));
    }

    #[tokio::test]
    async fn peer_submission_reports_actor_closure() {
        let (handle, rx) = handle_with_capacity(1);
        drop(rx);

        assert!(matches!(
            handle.get_stats_handle().await,
            Err(ExecutorError::ChannelClosed)
        ));
    }
}
