//! The text presentation: requests rendered locally into Compute text jobs.
use super::{TextOptions, WorkExecutionBackend};
use crate::ComputeEvent;
use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::routing::{MethodRouter, post};
use hellas_adaptors::anthropic::AnthropicMessagesAdaptor;
use hellas_adaptors::openai::{
    chat_completions::OpenAiChatCompletionsAdaptor, completions::OpenAiCompletionsAdaptor,
    responses::OpenAiResponsesAdaptor,
};
use hellas_adaptors::{
    BackendError, CanonicalExecution, ExecutionRequest as WireExecutionRequest, ResponseFormat,
    WireAdaptor,
};
use hellas_client::model::ModelPackage;
use hellas_presentation::TextPresentation;
use hellas_rpc::provenance::ExecutionProvenance;
use std::sync::Arc;
use tokio::time::Duration;

/// Reject controls the native executor cannot enforce before creating a job.
fn validate_native_text_request(canonical: &CanonicalExecution) -> Result<(), BackendError> {
    if !canonical.sampling.stop.is_empty() {
        return Err(BackendError::rejected(
            "custom stop sequences are not supported by native text execution",
        ));
    }
    // Native execution always takes the most likely token: temperature 0.
    if let Some(temperature) = canonical.sampling.temperature
        && temperature != 0.0
    {
        return Err(BackendError::rejected(format!(
            "`temperature` {temperature} is not supported: native text execution decodes greedily, as at temperature 0"
        )));
    }
    for (name, present) in [
        ("top_p", canonical.sampling.top_p.is_some()),
        ("top_logprobs", canonical.sampling.top_logprobs.is_some()),
        ("truncation", canonical.sampling.truncation.is_some()),
    ] {
        if present {
            return Err(BackendError::rejected(format!(
                "`{name}` is not supported by native text execution"
            )));
        }
    }
    if let Some(format) = &canonical.response_format {
        let unsupported = match format {
            ResponseFormat::Text => None,
            ResponseFormat::JsonObject => Some("json_object"),
            ResponseFormat::JsonSchema { .. } => Some("json_schema"),
            ResponseFormat::Raw(_) => Some("raw"),
        };
        if let Some(name) = unsupported {
            return Err(BackendError::rejected(format!(
                "response format `{name}` is not supported by native text execution"
            )));
        }
    }
    Ok(())
}

/// The paths the text presentation serves.
pub(super) const PATHS: [&str; 4] = [
    "/v1/chat/completions",
    "/v1/responses",
    ANTHROPIC_PATH,
    "/v1/completions",
];

/// The path served in the Anthropic Messages wire format.
pub(super) const ANTHROPIC_PATH: &str = "/v1/messages";

pub(super) fn router(state: Arc<TextState>) -> Router {
    Router::new()
        .route(
            PATHS[0],
            text(
                OpenAiChatCompletionsAdaptor,
                "OpenAI Chat Completions",
                "chatcmpl",
            ),
        )
        .route(
            PATHS[1],
            text(OpenAiResponsesAdaptor, "OpenAI Responses", "resp"),
        )
        .route(
            PATHS[2],
            text(AnthropicMessagesAdaptor, "Anthropic Messages", "msg"),
        )
        .route(
            PATHS[3],
            text(OpenAiCompletionsAdaptor, "OpenAI Completions", "cmpl"),
        )
        .with_state(state)
}

/// Serve `adaptor`'s wire format as a local text job on the loaded model.
fn text<A>(adaptor: A, surface: &'static str, id: &'static str) -> MethodRouter<Arc<TextState>>
where
    A: WireAdaptor + Copy + Send + Sync + 'static,
    A::ParsedRequest: Send + 'static,
    A::StreamState: Send + 'static,
{
    post(
        move |State(state): State<Arc<TextState>>, body: Bytes| async move {
            let backend = super::backend::GatewayBackend::new(state);
            let context = super::dispatch::render_context(id);
            super::dispatch::serve(adaptor, surface, context, backend, &body).await
        },
    )
}

pub(super) struct TextState {
    pub(super) inference_metrics: super::backend::telemetry::InferenceMetrics,
    default_max_tokens: u32,
    /// The most tokens one job may generate under the work source's terms.
    max_tokens: Option<u32>,
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
        let text = ModelPackage::open(
            &path,
            &work.evaluator().ok_or(crate::GatewayError::Presentation(
                "Compute models need a renderer (evaluator id)".into(),
            ))?,
        )
        .await
        .map_err(|error| crate::GatewayError::Presentation(error.into()))?;
        let presentation = tokio::task::spawn_blocking(move || TextPresentation::from_gguf(&path))
            .await
            .map_err(crate::GatewayError::Task)?
            .map_err(|error| crate::GatewayError::Presentation(error.into()))?;
        Ok(Self {
            inference_metrics: super::backend::telemetry::InferenceMetrics::new(),
            default_max_tokens: options.default_max_tokens,
            max_tokens: work
                .max_steps()
                .map(|steps| u32::try_from(steps).unwrap_or(u32::MAX)),
            inference_timeout: work.timeout(),
            presentation: Arc::new(presentation),
            text: Arc::new(text),
            work,
        })
    }

    pub(super) async fn prepare_wire_execution(
        &self,
        req: &WireExecutionRequest,
    ) -> Result<PreparedGeneration, BackendError> {
        let canonical = &req.canonical;
        validate_native_text_request(canonical)?;
        // A budget beyond the terms is cut to them; generation then ends
        // with the format's ordinary length stop.
        let max_tokens = canonical
            .sampling
            .max_output_tokens
            .unwrap_or(self.default_max_tokens)
            .min(self.max_tokens.unwrap_or(u32::MAX));
        let chat = self.presentation.prepare(canonical).map_err(|err| {
            BackendError::rejected(format!("Failed to prepare model input: {err:#}"))
        })?;
        self.prepare_ids(chat.input_ids, max_tokens, Some(chat.turn))
            .await
    }

    /// Render a prompt into a text job and start it on the work source.
    async fn prepare_ids(
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
            .await
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
