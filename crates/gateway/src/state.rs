use super::proxy::ResponsesProxy;
use super::{GatewayOptions, ResponsesBackend, json_error};
use crate::ExecutionEvent;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use futures::StreamExt;
use hellas_adaptors::ExecutionRequest as WireExecutionRequest;
use hellas_client::{ClientError, text::TextPackage};
use hellas_presentation::{ChatTemplate, TextPresentation};
use hellas_rpc::Retention;
use hellas_rpc::cache::{CacheKey, CacheKind};
use hellas_rpc::provenance::ExecutionProvenance;
use std::{error::Error as StdError, sync::Arc};
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
    text: Option<Arc<TextPackage>>,
    pub(super) responses_proxy: Option<Arc<ResponsesProxy>>,
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
        let (text, presentation) = match options.text_model.clone() {
            Some(path) => {
                let (text, presentation) = tokio::task::spawn_blocking(
                    move || -> Result<_, Box<dyn StdError + Send + Sync>> {
                        Ok((
                            TextPackage::open(&path)?,
                            TextPresentation::from_gguf(&path)?
                                .with_chat_template(Some(ChatTemplate::Qwen3)),
                        ))
                    },
                )
                .await
                .map_err(crate::GatewayError::Task)?
                .map_err(crate::GatewayError::Presentation)?;
                (Some(Arc::new(text)), Some(Arc::new(presentation)))
            }
            None => (None, None),
        };
        Ok(Self {
            inference_metrics: super::backend::telemetry::InferenceMetrics::new(),
            default_max_tokens: options.default_max_tokens,
            model_name: options.model_name.clone(),
            inference_timeout: options
                .paid_work
                .as_ref()
                .map_or(DEFAULT_INFERENCE_TIMEOUT, |backend| backend.timeout()),
            presentation,
            text,
            responses_proxy,
            paid_work: if output_cache
                .as_ref()
                .is_some_and(|cache| cache.policy == super::cache::CachePolicy::ReplayOnly)
            {
                None
            } else {
                options.paid_work.clone()
            },
            output_cache,
        })
    }

    /// Replay a recorded generation or collect and settle a paid Compute job.
    async fn finalize_generation(
        &self,
        input_ids: Vec<u32>,
        max_tokens: u32,
        prepare_error: &str,
        _retention: Retention,
    ) -> Result<PreparedGeneration, HttpError> {
        let (Some(text), Some(presentation)) = (&self.text, &self.presentation) else {
            return Err(HttpError {
                status: StatusCode::NOT_FOUND,
                message: "this gateway has no --text-model".into(),
            });
        };
        let prompt_tokens = input_ids.len() as u32;
        let prompt = input_ids.into_iter().map(u64::from).collect::<Vec<_>>();
        let job = text
            .render_job(&prompt, u64::from(max_tokens), &[])
            .map_err(|error| HttpError {
                status: StatusCode::BAD_REQUEST,
                message: format!("{prepare_error}: {error:#}"),
            })?;
        let (provenance, prepared) = self.text_stream(job).await.map_err(|error| match error {
            ClientError::External(error) => HttpError {
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
        Ok(PreparedGeneration {
            chat: None,
            prepared,
            provenance,
            prompt_tokens,
            presentation: presentation.clone(),
            inference_timeout: self.inference_timeout,
        })
    }

    /// The live job runs only after a permitted cache miss. Recording publishes
    /// only after its successful terminal and EOF.
    async fn text_stream(
        &self,
        job: hellas_client::text::TextJob,
    ) -> hellas_client::ClientResult<(
        Option<ExecutionProvenance>,
        futures::stream::BoxStream<'static, hellas_client::ClientResult<ExecutionEvent>>,
    )> {
        fn encode(error: impl std::fmt::Display) -> ClientError {
            ClientError::protocol(format!("text job: {error}"))
        }
        let key = CacheKey::hash(
            CacheKind::Text,
            &[
                &job.environment.canonical_bytes().map_err(encode)?,
                &job.plan.canonical_bytes().map_err(encode)?,
                &hellas_rpc::canonical_dag_cbor(&job.inputs).map_err(encode)?,
            ],
        );
        let guard = if let Some(cache) = &self.output_cache {
            if let Some(entry) = cache.read(key.clone()).await? {
                return Ok(replay(entry));
            }
            let guard = cache.acquire(&key).await?;
            if let Some(entry) = cache.read(key.clone()).await? {
                return Ok(replay(entry));
            }
            Some((cache.clone(), guard))
        } else {
            None
        };
        let external = |error| ClientError::External(Box::new(error));
        let events = self
            .paid_work
            .as_ref()
            .ok_or(ClientError::FundingRequired)?
            .generate(job)
            .map_err(external)?
            .map(move |event| event.map_err(external))
            .boxed();
        Ok(match guard {
            Some((cache, guard)) => (
                None,
                cache.record(key, None::<ExecutionProvenance>, events, guard),
            ),
            None => (None, events),
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

fn replay(
    entry: super::cache::Transcript<ExecutionEvent, ExecutionProvenance>,
) -> (
    Option<ExecutionProvenance>,
    futures::stream::BoxStream<'static, hellas_client::ClientResult<ExecutionEvent>>,
) {
    (
        entry.initial_provenance,
        futures::stream::iter(entry.events.into_iter().map(Ok)).boxed(),
    )
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
