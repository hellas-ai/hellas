use super::proxy::ResponsesProxy;
use super::{GatewayOptions, ResponsesBackend, json_error};
use crate::execution::CausalLmExecutionEnvironment;
use anyhow::Context;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use hellas_adaptors::ExecutionRequest as WireExecutionRequest;
use hellas_presentation::TextPresentation;
use hellas_rpc::Retention;
use hellas_rpc::provenance::ExecutionProvenance;
use std::{error::Error as StdError, sync::Arc};
use tokio::time::Duration;
/// End-to-end deadline applied while consuming a prepared generation.
/// Covers paid proposal, execution and the entire decode stream.
pub(super) const DEFAULT_INFERENCE_TIMEOUT: Duration = Duration::from_secs(3600);

#[derive(Clone)]
pub(super) struct GatewayState {
    pub(super) inference_metrics: super::backend::telemetry::InferenceMetrics,
    pub(super) output_cache: Option<Arc<super::cache::OutputCache>>,
    default_max_tokens: u32,
    pub(super) model_name: String,
    pub(super) causal_lm: Option<CausalLmExecutionEnvironment>,
    pub(super) inference_timeout: Duration,
    presentation: Option<Arc<TextPresentation>>,
    stop_token_ids: Vec<u32>,
    pub(super) responses_proxy: Option<Arc<ResponsesProxy>>,
    /// The one strategy every request runs, settled at startup by
    /// [`configured_strategy`]. The dial targets it was built from are
    /// deliberately not kept: there is no second place a route could be
    /// assembled, and so no place one could be assembled without an anchor.
    paid_work: Option<Arc<dyn super::WorkExecutionBackend>>,
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
    pub(super) async fn from_options(options: &GatewayOptions) -> anyhow::Result<Self> {
        let output_cache = super::cache::OutputCache::open(&options.output_cache)?;
        let replay_only = options.output_cache.policy == super::cache::CachePolicy::ReplayOnly;
        anyhow::ensure!(
            options.default_max_tokens > 0,
            "default maximum tokens must be greater than zero"
        );
        anyhow::ensure!(
            options.causal_lm.is_some() == options.tokenizer.is_some(),
            "causal-LM environment and tokenizer must be supplied together"
        );
        anyhow::ensure!(
            options.responses_backend != ResponsesBackend::Hellas || options.causal_lm.is_some(),
            "Hellas backend requires an environment and tokenizer"
        );
        let chat_template = options.chat_template;
        let presentation = if let Some(tokenizer) = options.tokenizer.clone() {
            Some(Arc::new(
                tokio::task::spawn_blocking(move || {
                    TextPresentation::load(&tokenizer)
                        .map(|presentation| presentation.with_chat_template(chat_template))
                })
                .await
                .context("tokenizer loader panicked")??,
            ))
        } else {
            None
        };
        let responses_proxy = match options.responses_backend {
            ResponsesBackend::Hellas => None,
            ResponsesBackend::Proxy => Some(Arc::new(ResponsesProxy::new(
                &options.responses_proxy_url,
                &options.responses_proxy_api_key_env,
            )?)),
            ResponsesBackend::Fetch => None,
        };

        if options.responses_backend == ResponsesBackend::Fetch
            || (!replay_only
                && options.paid_work.is_none()
                && (options.causal_lm.is_some()
                    || options.responses_backend == ResponsesBackend::Hellas))
        {
            return Err(hellas_client::ClientError::FundingRequired.into());
        }
        Ok(Self {
            inference_metrics: super::backend::telemetry::InferenceMetrics::new(),
            output_cache,
            default_max_tokens: options.default_max_tokens,
            model_name: options.model_name.clone(),
            causal_lm: options.causal_lm.clone(),
            inference_timeout: options
                .paid_work
                .as_ref()
                .map_or(DEFAULT_INFERENCE_TIMEOUT, |backend| backend.timeout()),
            presentation,
            stop_token_ids: options.stop_token_ids.clone(),
            responses_proxy,
            paid_work: if replay_only {
                None
            } else {
                options.paid_work.clone()
            },
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
        let prompt_tokens = input_ids.len() as u32;
        let causal_lm = self.causal_lm.clone().ok_or_else(|| HttpError {
            status: StatusCode::NOT_FOUND,
            message: "this gateway exposes only the Fetch-backed Responses route".to_string(),
        })?;
        use futures::StreamExt;
        use hellas_client::execution::{genesis_text_execution_id, prepare_evaluate_stream};
        let identity = genesis_text_execution_id(
            causal_lm.manifest_id(),
            &input_ids,
            max_tokens,
            &self.stop_token_ids,
        );
        let prepared = prepare_evaluate_stream(identity, self.output_cache.clone(), async {
            let backend = self
                .paid_work
                .as_ref()
                .ok_or(hellas_client::ClientError::FundingRequired)?;
            let payment = backend
                .execute(super::WorkExecutionRequest {
                    environment: causal_lm.environment().clone(),
                    input_ids,
                    max_new_tokens: max_tokens,
                    stop_token_ids: self.stop_token_ids.clone(),
                })
                .map_err(|error| hellas_client::ClientError::External(Box::new(error)))?;
            Ok((
                None,
                payment
                    .map(|result| {
                        result
                            .map_err(|error| hellas_client::ClientError::External(Box::new(error)))
                    })
                    .boxed(),
            ))
        })
        .await
        .map_err(|error| match error {
            hellas_client::ClientError::External(error) => HttpError {
                status: match error.downcast_ref::<super::WorkGatewayError>() {
                    Some(super::WorkGatewayError::Busy(_)) => StatusCode::SERVICE_UNAVAILABLE,
                    Some(super::WorkGatewayError::Denied(_)) => StatusCode::FORBIDDEN,
                    Some(super::WorkGatewayError::Quota(_)) => StatusCode::TOO_MANY_REQUESTS,
                    Some(super::WorkGatewayError::Rejected(_)) => StatusCode::BAD_REQUEST,
                    _ => StatusCode::BAD_GATEWAY,
                },
                message: error.to_string(),
            },
            error => HttpError {
                status: StatusCode::BAD_GATEWAY,
                message: format!("{prepare_error}: {}", format_error_causes(&error)),
            },
        })?;
        let provenance = prepared.provenance().cloned();
        Ok(PreparedGeneration {
            chat: None,
            prepared: prepared.stream(),
            provenance,
            prompt_tokens,
            presentation: self
                .presentation
                .clone()
                .expect("causal-LM presentation is loaded"),
            inference_timeout: self.inference_timeout,
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

fn format_error_causes(err: &(dyn StdError + 'static)) -> String {
    let mut parts = Vec::new();
    let mut current = err.source().unwrap_or(err);
    parts.push(current.to_string());
    while let Some(source) = current.source() {
        parts.push(source.to_string());
        current = source;
    }
    parts.join(": ")
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
