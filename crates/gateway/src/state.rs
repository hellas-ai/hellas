use super::proxy::ResponsesProxy;
use super::{FetchGatewayOptions, GatewayOptions, ResponsesBackend, json_error};
use crate::execution::{
    CausalLmExecutionEnvironment, CliRuntime, ExecutionRequest, ExecutionRequestOptions,
    ExecutionStrategy,
};
use anyhow::Context;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use hellas_adaptors::ExecutionRequest as WireExecutionRequest;
use hellas_client::{ExecutionRoute, RemoteNodeTarget};
#[cfg(feature = "evaluate")]
use hellas_executor::{
    ArtifactStoreConfig, Executor, ExecutorMetrics, ExecutorSpawnConfig, FetchAccessPolicy,
    FetchRouteRegistry, FetchTranscriptStoreBackend, GpuConfig,
};
use hellas_presentation::TextPresentation;
use hellas_rpc::Retention;
#[cfg(feature = "evaluate")]
use hellas_rpc::policy::ExecutePolicy;
use hellas_rpc::provenance::ExecutionProvenance;
use iroh::EndpointId;
use std::error::Error as StdError;
use std::sync::Arc;
use tokio::time::Duration;

/// End-to-end deadline applied while consuming a prepared generation.
/// Covers preparation (quote / discovery) AND the entire decode stream.
pub(super) const DEFAULT_INFERENCE_TIMEOUT: Duration = Duration::from_secs(3600);

#[derive(Clone)]
pub(super) struct GatewayState {
    pub(super) output_cache: Option<Arc<super::cache::OutputCache>>,
    #[cfg(feature = "evaluate")]
    pub(super) local: bool,
    #[cfg(feature = "evaluate")]
    pub(super) verify_local: bool,
    pub(super) verify_node_id: Option<EndpointId>,
    default_max_tokens: u32,
    pub(super) model_name: String,
    pub(super) causal_lm: Option<CausalLmExecutionEnvironment>,
    pub(super) inference_timeout: Duration,
    runtime: CliRuntime,
    presentation: Option<Arc<TextPresentation>>,
    stop_token_ids: Vec<u32>,
    pub(super) responses_proxy: Option<Arc<ResponsesProxy>>,
    pub(super) responses_fetch: Option<Arc<super::fetch_backend::ResponsesFetchBackend>>,
    runner_key: Arc<hellas_rpc::ProducerSigningKey>,
    assurance: hellas_rpc::Assurance,
    /// The one strategy every request runs, settled at startup by
    /// [`configured_strategy`]. The dial targets it was built from are
    /// deliberately not kept: there is no second place a route could be
    /// assembled, and so no place one could be assembled without an anchor.
    strategy: Option<ExecutionStrategy>,
    paid_work: Option<Arc<dyn super::PaidExecutionBackend>>,
}

/// The execution strategy these options describe, or `None` when they
/// describe none.
///
/// A trust anchor is required exactly where one can be used. Every
/// remote constructor below — [`ExecutionRoute::remote`] and
/// [`RemoteNodeTarget::direct`] — takes a [`hellas_client::ProviderTrustAnchor`] by
/// value, so the `?` on the anchor is the only way past them: without
/// one there is no remote route to run, and a gateway with no route
/// refuses a request rather than dialling a provider it cannot verify.
/// Local execution answers to nobody remote and needs no anchor, so it
/// is built either way.
fn configured_strategy(options: &GatewayOptions) -> Option<ExecutionStrategy> {
    #[cfg(feature = "evaluate")]
    let primary = if options.local {
        ExecutionRoute::Local
    } else {
        ExecutionRoute::remote(
            options.node_id,
            options.node_addrs.clone(),
            options.retries,
            options.provider_trust.clone()?,
        )
    };
    #[cfg(not(feature = "evaluate"))]
    let primary = ExecutionRoute::remote(
        options.node_id,
        options.node_addrs.clone(),
        options.retries,
        options.provider_trust.clone()?,
    );

    #[cfg(feature = "evaluate")]
    if options.verify_local {
        return Some(ExecutionStrategy::Verify {
            primary,
            shadow: ExecutionRoute::Local,
        });
    }

    if let Some(node_id) = options.verify {
        return Some(ExecutionStrategy::Verify {
            primary,
            shadow: ExecutionRoute::RemoteDirect(RemoteNodeTarget::direct(
                node_id,
                options.provider_trust.clone()?,
            )),
        });
    }

    Some(ExecutionStrategy::Run(primary))
}

#[cfg(feature = "evaluate")]
fn local_runtime_needs_remote(options: &GatewayOptions) -> bool {
    options.verify_local
        || options.verify.is_some()
        || matches!(options.responses_backend, ResponsesBackend::Fetch)
}

pub(super) struct PreparedGeneration {
    pub(super) chat: Option<hellas_presentation::chat::ChatTurn>,
    pub(super) prepared:
        futures::stream::BoxStream<'static, hellas_client::ClientResult<crate::ExecutionEvent>>,
    /// Pre-flight provenance the executor committed to. `None` for routes
    /// that defer their quote until streaming starts (`RemoteDiscovery`);
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
        anyhow::ensure!(
            options.paid_work.is_none()
                || options.output_cache.policy == super::cache::CachePolicy::Off,
            "paid work requires live settlement; disable inference caching"
        );
        let output_cache = super::cache::OutputCache::open(&options.output_cache)?;
        let verification = options.verify.is_some();
        #[cfg(feature = "evaluate")]
        let verification = verification || options.verify_local;
        anyhow::ensure!(
            output_cache.is_none() || !verification,
            "verification requires live execution; disable inference caching"
        );
        let replay_only = options.output_cache.policy == super::cache::CachePolicy::ReplayOnly;
        anyhow::ensure!(
            options.default_max_tokens > 0,
            "default maximum tokens must be greater than zero"
        );
        let runner_key = Arc::new(options.producer_key.clone());
        anyhow::ensure!(
            options.causal_lm.is_some() == options.tokenizer.is_some(),
            "causal-LM environment and tokenizer must be supplied together"
        );
        anyhow::ensure!(
            options.responses_backend != ResponsesBackend::Hellas || options.causal_lm.is_some(),
            "Hellas backend requires an environment and tokenizer"
        );
        let presentation = if let Some(tokenizer) = options.tokenizer.clone() {
            let chat_template = options.chat_template;
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

        #[cfg(feature = "evaluate")]
        let runtime = if replay_only
            || (options.responses_backend == ResponsesBackend::Proxy
                && options.causal_lm.is_none()
                && !options.local
                && !options.verify_local)
        {
            CliRuntime::default()
        } else if options.local || options.verify_local {
            let content_store = options
                .local_content_store
                .clone()
                .context("local gateway execution requires a local content store")?;
            let handle = Executor::spawn_configured(ExecutorSpawnConfig {
                output_cache: options.output_cache.clone(),
                execute_policy: ExecutePolicy::Any,
                queue_capacity: options.queue_size,
                metrics: Arc::new(ExecutorMetrics::default()),
                producer_key: runner_key.clone(),
                provider_genesis: Arc::new(options.provider_genesis.clone()),
                assurance: options.assurance,
                fetch_access_policy: FetchAccessPolicy::trusted_callers([runner_key.public_key()]),
                fetch_routes: FetchRouteRegistry::default(),
                fetch_max_in_flight: hellas_rpc::DEFAULT_FETCH_MAX_IN_FLIGHT,
                fetch_queue_capacity: hellas_rpc::DEFAULT_FETCH_QUEUE_CAPACITY,
                fetch_replay_max_in_flight: hellas_rpc::DEFAULT_FETCH_REPLAY_MAX_IN_FLIGHT,
                fetch_store: FetchTranscriptStoreBackend::memory(),
                artifact_store: ArtifactStoreConfig::memory(),
                content_store,
                gpu_config: GpuConfig::default(),
            })
            .await
            .context("failed to initialize local Catena executor")?;
            let runtime = CliRuntime::local(handle);
            if local_runtime_needs_remote(options) {
                runtime.with_remote(options.secret_key.clone()).await?
            } else {
                runtime
            }
        } else if options.paid_work.is_some() {
            CliRuntime::default()
        } else {
            CliRuntime::remote(options.secret_key.clone()).await?
        };
        #[cfg(not(feature = "evaluate"))]
        let runtime = if replay_only
            || options.paid_work.is_some()
            || (options.responses_backend == ResponsesBackend::Proxy && options.causal_lm.is_none())
        {
            CliRuntime::default()
        } else {
            CliRuntime::remote(options.secret_key.clone()).await?
        };

        let responses_fetch = match options.responses_backend {
            ResponsesBackend::Fetch => {
                Some(Arc::new(super::fetch_backend::ResponsesFetchBackend::new(
                    runtime.clone(),
                    if replay_only {
                        None
                    } else {
                        Some(ExecutionRoute::remote(
                            options.node_id,
                            options.node_addrs.clone(),
                            options.retries,
                            // This backend dials a provider for every request
                            // it serves, so it is built only where the anchor
                            // that provider will be checked against exists.
                            options.provider_trust.clone().context(
                                "fetch responses backend requires a provider trust anchor",
                            )?,
                        ))
                    },
                    (
                        &options.responses_fetch_route_service,
                        &options.responses_fetch_route_method,
                        options
                            .responses_fetch_execution_environment
                            .ok_or_else(|| {
                                anyhow::anyhow!(
                                    "fetch responses backend requires an execution environment"
                                )
                            })?,
                    ),
                    runner_key.as_ref().clone(),
                    options.assurance,
                    options.responses_fetch_request_overrides.clone(),
                )))
            }
            ResponsesBackend::Hellas | ResponsesBackend::Proxy => None,
        };

        Ok(Self {
            output_cache,
            #[cfg(feature = "evaluate")]
            local: options.local,
            #[cfg(feature = "evaluate")]
            verify_local: options.verify_local,
            verify_node_id: options.verify,
            default_max_tokens: options.default_max_tokens,
            model_name: options.model_name.clone(),
            causal_lm: options.causal_lm.clone(),
            inference_timeout: DEFAULT_INFERENCE_TIMEOUT,
            runtime,
            presentation,
            stop_token_ids: options.stop_token_ids.clone(),
            responses_proxy,
            responses_fetch,
            runner_key,
            assurance: options.assurance,
            strategy: if replay_only {
                Some(ExecutionStrategy::Replay)
            } else {
                configured_strategy(options)
            },
            paid_work: options.paid_work.clone(),
        })
    }

    pub(super) async fn from_fetch_options(options: &FetchGatewayOptions) -> anyhow::Result<Self> {
        let runtime = CliRuntime::remote(options.secret_key.clone()).await?;
        let runner_key = Arc::new(options.caller_key.clone());
        let route = ExecutionRoute::remote(
            options.node_id,
            options.node_addrs.clone(),
            options.retries,
            options.provider_trust.clone(),
        );
        let responses_fetch = Arc::new(super::fetch_backend::ResponsesFetchBackend::new(
            runtime.clone(),
            Some(route),
            (
                &options.service,
                &options.method,
                options.execution_environment,
            ),
            options.caller_key.clone(),
            options.assurance,
            options.request_overrides.clone(),
        ));
        Ok(Self {
            output_cache: None,
            #[cfg(feature = "evaluate")]
            local: false,
            #[cfg(feature = "evaluate")]
            verify_local: false,
            verify_node_id: None,
            default_max_tokens: 1,
            model_name: String::new(),
            causal_lm: None,
            inference_timeout: DEFAULT_INFERENCE_TIMEOUT,
            runtime,
            presentation: None,
            stop_token_ids: Vec::new(),
            responses_proxy: None,
            responses_fetch: Some(responses_fetch),
            runner_key,
            assurance: options.assurance,
            strategy: None,
            paid_work: None,
        })
    }

    /// The strategy this request runs under, or the refusal of a gateway
    /// that was given no anchor and so holds no route to run it.
    fn execution_strategy(&self) -> Result<ExecutionStrategy, HttpError> {
        self.strategy.clone().ok_or_else(|| HttpError {
            status: StatusCode::SERVICE_UNAVAILABLE,
            message: "this gateway has no provider trust anchor, so it has no execution route; \
                      restart it with --provider <content-id>"
                .to_string(),
        })
    }

    /// Drive the executor quote step and assemble a `PreparedGeneration`
    /// from already-prepared wire-adaptor inputs.
    async fn finalize_generation(
        &self,
        input_ids: Vec<u32>,
        max_tokens: u32,
        prepare_error: &str,
        retention: Retention,
    ) -> Result<PreparedGeneration, HttpError> {
        let prompt_tokens = input_ids.len() as u32;
        let causal_lm = self.causal_lm.clone().ok_or_else(|| HttpError {
            status: StatusCode::NOT_FOUND,
            message: "this gateway exposes only the Fetch-backed Responses route".to_string(),
        })?;
        if let Some(backend) = self.paid_work.as_ref() {
            let payment = backend
                .execute(super::PaidExecutionRequest {
                    environment: causal_lm.environment().clone(),
                    input_ids,
                    max_new_tokens: max_tokens,
                    stop_token_ids: self.stop_token_ids.clone(),
                })
                .map_err(|err| HttpError {
                    status: StatusCode::BAD_REQUEST,
                    message: format!("Request does not match a paid provider policy: {err:#}"),
                })?;
            return Ok(PreparedGeneration {
                chat: None,
                prepared: Box::pin(futures::StreamExt::map(payment, |result| {
                    result.map_err(|error| {
                        hellas_client::ClientError::External(error.into_boxed_dyn_error())
                    })
                })),
                provenance: None,
                prompt_tokens,
                presentation: self
                    .presentation
                    .clone()
                    .expect("causal-LM presentation is loaded"),
                inference_timeout: self.inference_timeout,
            });
        }
        let request = ExecutionRequest::new(
            self.runtime.clone(),
            causal_lm,
            input_ids,
            self.stop_token_ids.clone(),
            ExecutionRequestOptions {
                max_new_tokens: max_tokens,
                assurance: self.assurance,
                retention,
            },
            self.execution_strategy()?,
            self.runner_key.as_ref().clone(),
        )
        .map_err(|err| HttpError {
            status: StatusCode::BAD_REQUEST,
            message: format!("Failed to build execution request: {err}"),
        })?;
        let cache = self.output_cache.clone();
        #[cfg(feature = "evaluate")]
        let cache = if self.local && !matches!(self.strategy, Some(ExecutionStrategy::Replay)) {
            None
        } else {
            cache
        };
        let prepared = request
            .with_cache(cache)
            .prepare()
            .await
            .map_err(|err| HttpError {
                status: StatusCode::BAD_GATEWAY,
                message: format!("{prepare_error}: {}", format_error_causes(&err)),
            })?;
        let provenance = prepared.provenance().cloned();

        Ok(PreparedGeneration {
            chat: None,
            presentation: self.presentation.clone().ok_or_else(|| HttpError {
                status: StatusCode::NOT_FOUND,
                message: "this gateway has no causal-LM presentation".to_string(),
            })?,
            prepared: prepared.stream(),
            provenance,
            prompt_tokens,
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
