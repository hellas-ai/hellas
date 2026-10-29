//! The text presentation: requests rendered locally into Compute text jobs.
use super::{TextOptions, WorkExecutionBackend};
use crate::ComputeEvent;
use axum::{Router, routing::post};
use hellas_adaptors::{BackendError, ExecutionRequest as WireExecutionRequest};
use hellas_client::model::ModelPackage;
use hellas_presentation::{ChatTemplate, TextPresentation};
use hellas_rpc::provenance::ExecutionProvenance;
use std::{error::Error as StdError, sync::Arc};
use tokio::time::Duration;

/// The paths the text presentation serves.
pub(super) const PATHS: [&str; 4] = [
    "/v1/chat/completions",
    "/v1/responses",
    "/v1/messages",
    "/v1/completions",
];

pub(super) fn router(state: Arc<TextState>) -> Router {
    Router::new()
        .route(PATHS[0], post(super::openai::handle))
        .route(PATHS[1], post(super::responses::handle))
        .route(PATHS[2], post(super::anthropic::handle))
        .route(PATHS[3], post(super::plain::handle))
        .with_state(state)
}

pub(super) struct TextState {
    pub(super) inference_metrics: super::backend::telemetry::InferenceMetrics,
    default_max_tokens: u32,
    pub(super) model_name: String,
    pub(super) inference_timeout: Option<Duration>,
    presentation: Arc<TextPresentation>,
    text: Arc<ModelPackage>,
    work: Arc<dyn WorkExecutionBackend>,
}

pub(super) type TextEvents = crate::WorkOutputStream<ComputeEvent>;

pub(super) struct PreparedGeneration {
    pub(super) chat: Option<hellas_presentation::chat::ChatTurn>,
    pub(super) prepared: TextEvents,
    /// The job identity the provider accepted, once [`Self::accept`] has
    /// seen it; `None` for a source that reports no acceptance.
    pub(super) provenance: Option<ExecutionProvenance>,
    pub(super) prompt_tokens: u32,
    pub(super) presentation: Arc<TextPresentation>,
    pub(super) deadline: Option<tokio::time::Instant>,
}

impl TextState {
    pub(super) async fn open(
        options: &TextOptions,
        work: Arc<dyn WorkExecutionBackend>,
    ) -> crate::GatewayResult<Self> {
        if options.default_max_tokens == 0 {
            return Err(crate::GatewayConfigError::MaxTokens.into());
        }
        let path = options.model.clone();
        let (text, presentation) =
            tokio::task::spawn_blocking(move || -> Result<_, Box<dyn StdError + Send + Sync>> {
                Ok((
                    ModelPackage::open(&path)?,
                    TextPresentation::from_gguf(&path)?
                        .with_chat_template(Some(ChatTemplate::Qwen3)),
                ))
            })
            .await
            .map_err(crate::GatewayError::Task)?
            .map_err(crate::GatewayError::Presentation)?;
        Ok(Self {
            inference_metrics: super::backend::telemetry::InferenceMetrics::new(),
            default_max_tokens: options.default_max_tokens,
            model_name: options.model_name.clone(),
            inference_timeout: work.timeout(),
            presentation: Arc::new(presentation),
            text: Arc::new(text),
            work,
        })
    }

    pub(super) fn prepare_wire_execution(
        &self,
        req: &WireExecutionRequest,
    ) -> Result<PreparedGeneration, BackendError> {
        let max_tokens = req
            .canonical
            .sampling
            .max_output_tokens
            .unwrap_or(self.default_max_tokens);
        let chat = self.presentation.prepare(&req.canonical).map_err(|err| {
            BackendError::rejected(format!("Failed to prepare model input: {err:#}"))
        })?;
        self.prepare_ids(chat.input_ids, max_tokens, Some(chat.turn))
    }

    /// Render a prompt into a text job and start it on the work source.
    fn prepare_ids(
        &self,
        input_ids: Vec<u32>,
        max_tokens: u32,
        chat: Option<hellas_presentation::chat::ChatTurn>,
    ) -> Result<PreparedGeneration, BackendError> {
        let deadline = self
            .inference_timeout
            .map(|timeout| tokio::time::Instant::now() + timeout);
        let prompt_tokens = input_ids.len() as u32;
        let prompt = input_ids.into_iter().map(u64::from).collect::<Vec<_>>();
        let job = self
            .text
            .render_job(&hellas_client::model::ModelRequest::Text {
                prompt_ids: &prompt,
                max_new: u64::from(max_tokens),
                stops: &[],
            })
            .map_err(|error| {
                BackendError::rejected(format!("Failed to prepare model input: {error:#}"))
            })?;
        if deadline.is_some_and(|deadline| tokio::time::Instant::now() >= deadline) {
            return Err(BackendError::Timeout(
                "inference preparation timed out".into(),
            ));
        }
        Ok(PreparedGeneration {
            chat,
            prepared: self.work.run(job)?,
            provenance: None,
            prompt_tokens,
            presentation: self.presentation.clone(),
            deadline,
        })
    }
}

impl PreparedGeneration {
    /// Wait, within the inference budget, for the provider to accept the
    /// job, so that its identity can head the response.
    pub(super) async fn accept(&mut self) -> Result<(), BackendError> {
        let deadline = self.deadline();
        self.provenance = crate::before_deadline(deadline, crate::accepted(&mut self.prepared))
            .await
            .map_err(|_| BackendError::failed("inference timed out"))?;
        Ok(())
    }

    /// The same absolute budget covers preparation, acceptance and output.
    pub(super) fn deadline(&self) -> Option<tokio::time::Instant> {
        self.deadline
    }
}

#[cfg(test)]
mod tests;
