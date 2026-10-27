use super::proxy::ResponsesProxy;
use super::{GatewayOptions, ResponsesBackend, json_error};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use hellas_adaptors::ExecutionRequest as WireExecutionRequest;
use hellas_presentation::TextPresentation;
use hellas_rpc::Retention;
use hellas_rpc::provenance::ExecutionProvenance;
use std::sync::Arc;
use tokio::time::Duration;
/// End-to-end deadline applied while consuming a prepared generation.
/// Covers paid proposal, execution and the entire decode stream.
pub(super) const DEFAULT_INFERENCE_TIMEOUT: Duration = Duration::from_secs(3600);

#[derive(Clone)]
pub(super) struct GatewayState {
    pub(super) output_cache: Option<Arc<super::cache::OutputCache>>,
    pub(super) inference_metrics: super::backend::telemetry::InferenceMetrics,
    default_max_tokens: u32,
    pub(super) model_name: String,
    pub(super) inference_timeout: Duration,
    presentation: Option<Arc<TextPresentation>>,
    pub(super) responses_proxy: Option<Arc<ResponsesProxy>>,
}

pub(super) struct PreparedGeneration {
    pub(super) chat: Option<hellas_presentation::chat::ChatTurn>,
    pub(super) prepared:
        futures::stream::BoxStream<'static, hellas_client::ClientResult<crate::ExecutionEvent>>,
    /// Pre-flight provenance the executor committed to. `None` for routes
    /// whose funded execution starts while the response is streaming;
    /// in that case headers can't be set and clients must rely on the
    /// in-band SSE `hellas-provenance` event.
    pub(super) provenance: Option<ExecutionProvenance>,
    pub(super) prompt_tokens: u32,
    pub(super) presentation: Arc<TextPresentation>,
    pub(super) inference_timeout: Duration,
}

#[derive(Debug)]
pub(super) struct HttpError {
    pub(super) status: StatusCode,
    pub(super) message: String,
}

impl GatewayState {
    pub(super) async fn from_options(options: &GatewayOptions) -> crate::GatewayResult<Self> {
        if options.default_max_tokens == 0 {
            return Err(crate::GatewayConfigError::MaxTokens.into());
        }
        let responses_proxy = match options.responses_backend {
            ResponsesBackend::Hellas => None,
            ResponsesBackend::Proxy => Some(Arc::new(ResponsesProxy::new(
                &options.responses_proxy_url,
                &options.responses_proxy_api_key_env,
            )?)),
            ResponsesBackend::Fetch => None,
        };

        let output_cache = super::cache::OutputCache::open(&options.output_cache)?;
        Ok(Self {
            output_cache,
            inference_metrics: super::backend::telemetry::InferenceMetrics::new(),
            default_max_tokens: options.default_max_tokens,
            model_name: options.model_name.clone(),
            inference_timeout: options
                .paid_work
                .as_ref()
                .map_or(DEFAULT_INFERENCE_TIMEOUT, |backend| backend.timeout()),
            presentation: None,
            responses_proxy,
        })
    }

    /// Resolve the gateway archive or collect and settle a paid Work result.
    async fn finalize_generation(
        &self,
        input_ids: Vec<u32>,
        max_tokens: u32,
        prepare_error: &str,
        _retention: Retention,
    ) -> Result<PreparedGeneration, HttpError> {
        let _ = (input_ids, max_tokens, prepare_error);
        Err(HttpError {
            status: StatusCode::NOT_FOUND,
            message: "this gateway exposes only Fetch".into(),
        })
    }

    pub(super) async fn prepare_wire_execution(
        &self,
        req: &WireExecutionRequest,
        retention: Retention,
    ) -> Result<PreparedGeneration, HttpError> {
        let max_tokens = req
            .canonical
            .sampling
            .max_output_tokens
            .unwrap_or(self.default_max_tokens);
        let presentation = self.presentation.as_ref().ok_or_else(|| HttpError {
            status: StatusCode::NOT_FOUND,
            message: "this gateway has no causal-LM presentation".into(),
        })?;
        let chat = presentation
            .prepare(&req.canonical)
            .map_err(|err| HttpError {
                status: StatusCode::BAD_REQUEST,
                message: format!("Failed to prepare model input: {err:#}"),
            })?;

        let mut generation = self
            .finalize_generation(
                chat.input_ids,
                max_tokens,
                "Failed to prepare model input",
                retention,
            )
            .await?;
        generation.chat = Some(chat.turn);
        Ok(generation)
    }

    pub(super) fn cached<B>(&self, backend: B) -> super::cache::CachedBackend<B> {
        super::cache::CachedBackend {
            backend,
            cache: self.output_cache.clone(),
        }
    }
}

impl PreparedGeneration {
    /// Absolute deadline for this generation's stream consumption.
    /// Computed at call time; covers the whole lifecycle from this point on.
    pub(super) fn deadline(&self) -> tokio::time::Instant {
        tokio::time::Instant::now() + self.inference_timeout
    }
}

impl IntoResponse for HttpError {
    fn into_response(self) -> Response {
        if self.status.is_server_error() {
            error!(
                status = %self.status,
                "gateway request failed"
            );
        } else {
            warn!(
                status = %self.status,
                "gateway request rejected"
            );
        }
        json_error(self.status, self.message)
    }
}

#[cfg(test)]
mod tests;
