//! The text presentation: requests rendered locally into Compute text jobs.
use super::route::RouteExecution;
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
use hellas_presentation::{ChatTemplate, TextPresentation};
use hellas_rpc::provenance::ExecutionProvenance;
use std::sync::Arc;

/// Reject controls the native executor cannot enforce before creating a job.
fn validate_native_text_request(canonical: &CanonicalExecution) -> Result<(), BackendError> {
    if !canonical.sampling.stop.is_empty() {
        return Err(BackendError::rejected(
            "custom stop sequences are not supported by native text execution",
        ));
    }
    for (name, present) in [
        ("temperature", canonical.sampling.temperature.is_some()),
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
        move |State(state): State<Arc<TextState>>,
              axum::Extension(selection): axum::Extension<crate::routing::Selection>,
              body: Bytes| async move {
            let model = state.model_name.clone();
            let backend = super::backend::GatewayBackend::new(state, selection);
            let context = super::dispatch::render_context(id);
            super::dispatch::serve(adaptor, surface, context, backend, Some(&model), &body).await
        },
    )
}

pub(super) struct TextState {
    pub(super) inference_metrics: super::backend::telemetry::InferenceMetrics,
    default_max_tokens: u32,
    pub(super) model_name: String,
    presentation: Arc<TextPresentation>,
    execution: Arc<RouteExecution>,
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
}

impl TextState {
    pub(super) async fn open(
        path: std::path::PathBuf,
        model_name: String,
        default_max_tokens: u32,
        execution: Arc<RouteExecution>,
    ) -> crate::GatewayResult<Self> {
        if default_max_tokens == 0 {
            return Err(crate::GatewayConfigError::MaxTokens.into());
        }
        let presentation = tokio::task::spawn_blocking(move || {
            TextPresentation::from_gguf(&hellas_client::model::ModelPackage::gguf_path(&path))
                .map(|presentation| presentation.with_chat_template(Some(ChatTemplate::Qwen3)))
        })
        .await
        .map_err(crate::GatewayError::Task)?
        .map_err(|error| crate::GatewayError::Presentation(error.into()))?;
        Ok(Self {
            inference_metrics: super::backend::telemetry::InferenceMetrics::new(),
            default_max_tokens,
            model_name,
            presentation: Arc::new(presentation),
            execution,
        })
    }

    pub(super) async fn prepare_wire_execution(
        &self,
        req: &WireExecutionRequest,
        selection: &mut crate::routing::Selection,
    ) -> Result<PreparedGeneration, BackendError> {
        let canonical = &req.canonical;
        validate_native_text_request(canonical)?;
        let max_tokens = canonical
            .sampling
            .max_output_tokens
            .unwrap_or(self.default_max_tokens);
        let chat = self.presentation.prepare(canonical).map_err(|err| {
            BackendError::rejected(format!("Failed to prepare model input: {err:#}"))
        })?;
        self.prepare_ids(chat.input_ids, max_tokens, Some(chat.turn), selection)
            .await
    }

    /// Render a prompt into a text job and start it on the work source.
    async fn prepare_ids(
        &self,
        input_ids: Vec<u32>,
        max_tokens: u32,
        chat: Option<hellas_presentation::chat::ChatTurn>,
        selection: &mut crate::routing::Selection,
    ) -> Result<PreparedGeneration, BackendError> {
        let prompt_tokens = input_ids.len() as u32;
        let prompt = input_ids.into_iter().map(u64::from).collect::<Vec<_>>();
        let (_, prepared) = self
            .execution
            .compute(
                selection,
                &hellas_client::model::ModelRequest::Text {
                    prompt_ids: &prompt,
                    max_new: u64::from(max_tokens),
                    stops: &[],
                },
            )
            .await?;
        Ok(PreparedGeneration {
            chat,
            prepared,
            provenance: None,
            prompt_tokens,
            presentation: self.presentation.clone(),
        })
    }
}

impl PreparedGeneration {
    /// Wait for acceptance so its identity can head the response.
    pub(super) async fn accept(&mut self) -> Result<(), BackendError> {
        self.provenance = crate::accepted(&mut self.prepared).await;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
