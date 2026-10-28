//! The text presentation: requests rendered locally into Compute text jobs.
use super::{TextOptions, WorkExecutionBackend, WorkGatewayError};
use crate::ExecutionEvent;
use axum::{Router, routing::post};
use hellas_adaptors::{BackendError, ExecutionRequest as WireExecutionRequest};
use hellas_client::text::TextPackage;
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
    pub(super) inference_timeout: Duration,
    presentation: Arc<TextPresentation>,
    text: Arc<TextPackage>,
    work: Arc<dyn WorkExecutionBackend>,
}

pub(super) type TextEvents =
    futures::stream::BoxStream<'static, Result<ExecutionEvent, WorkGatewayError>>;

pub(super) struct PreparedGeneration {
    pub(super) chat: Option<hellas_presentation::chat::ChatTurn>,
    pub(super) prepared: TextEvents,
    /// Pre-flight provenance the executor committed to. `None` for routes
    /// whose funded execution starts while the response is streaming;
    /// in that case headers can't be set and clients must rely on the
    /// in-band SSE `hellas-provenance` event.
    pub(super) provenance: Option<ExecutionProvenance>,
    pub(super) prompt_tokens: u32,
    pub(super) presentation: Arc<TextPresentation>,
    pub(super) inference_timeout: Duration,
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
                    TextPackage::open(&path)?,
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
        let prompt_tokens = input_ids.len() as u32;
        let prompt = input_ids.into_iter().map(u64::from).collect::<Vec<_>>();
        let job = self
            .text
            .render_job(&prompt, u64::from(max_tokens), &[])
            .map_err(|error| {
                BackendError::rejected(format!("Failed to prepare model input: {error:#}"))
            })?;
        Ok(PreparedGeneration {
            chat,
            prepared: self.work.generate(job)?,
            provenance: None,
            prompt_tokens,
            presentation: self.presentation.clone(),
            inference_timeout: self.inference_timeout,
        })
    }
}

impl PreparedGeneration {
    /// Absolute deadline for this generation's stream consumption.
    /// Computed at call time; covers the whole lifecycle from this point on.
    pub(super) fn deadline(&self) -> tokio::time::Instant {
        tokio::time::Instant::now() + self.inference_timeout
    }
}

#[cfg(test)]
mod tests;
