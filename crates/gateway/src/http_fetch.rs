//! HTTP bytes over authenticated Fetch, without translating vendor schemas.
mod observation;
#[cfg(test)]
mod tests;

use anyhow::{Context, bail, ensure};
use axum::{
    Router,
    body::{Body, Bytes},
    extract::{Request, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use futures::StreamExt;
use hellas_client::{ExecutionRoute, cache::fetch_output_stream};
use hellas_rpc::{
    Assurance, FetchEnvironment, ProducerSigningKey, Retention,
    http_fetch::{HttpFetchRequest, HttpTls, HttpTrustRoots},
    output::{AdaptorEvent, HttpResponseEvent, OutputEvent, StopReason},
};
use serde::Deserialize;
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime},
};
use tokio::sync::Semaphore;
use tracing::Instrument;

use super::{GatewayHandle, GatewayOptions, access, execution::CliRuntime};

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpGatewayConfig {
    pub service: String,
    pub method: String,
    pub routes: Vec<HttpRoute>,
    #[serde(default = "default_concurrency")]
    pub max_in_flight: usize,
}

fn default_concurrency() -> usize {
    4
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpRoute {
    pub path: String,
    pub method: String,
    pub url: String,
    pub credential: String,
    #[serde(default)]
    pub headers: Vec<(String, String)>,
    /// Only these caller headers cross the gateway; credentials never do.
    #[serde(default)]
    pub forward_headers: Vec<String>,
}

struct Account {
    slots: Arc<Semaphore>,
    retry_at: Mutex<Instant>,
}

impl Account {
    fn delay(&self) -> Duration {
        self.retry_at
            .lock()
            .unwrap()
            .saturating_duration_since(Instant::now())
    }

    fn observe(&self, status: u16, headers: &HeaderMap) {
        if status == 429 || (status >= 500 && headers.contains_key("retry-after")) {
            let delay = retry_delay(headers).min(Duration::from_secs(u32::MAX as u64));
            let mut retry_at = self.retry_at.lock().unwrap();
            *retry_at = (*retry_at).max(Instant::now() + delay);
        }
    }
}

struct HttpState {
    config: HttpGatewayConfig,
    runtime: CliRuntime,
    route: ExecutionRoute,
    signer: Arc<ProducerSigningKey>,
    assurance: Assurance,
    accounts: BTreeMap<String, Arc<Account>>,
    metrics: observation::Metrics,
}

impl HttpGatewayConfig {
    fn validate(&self) -> anyhow::Result<()> {
        ensure!(
            !self.routes.is_empty(),
            "HTTP gateway needs at least one route"
        );
        ensure!(
            self.max_in_flight > 0 && self.max_in_flight <= 1024,
            "invalid HTTP concurrency limit"
        );
        let mut paths = std::collections::BTreeSet::new();
        for route in &self.routes {
            ensure!(
                route.path.starts_with('/') && !route.path.contains(['?', '#', '{', '}']),
                "HTTP routes must be exact paths"
            );
            ensure!(
                paths.insert((&route.path, &route.method)),
                "duplicate HTTP route"
            );
            ensure!(
                route.forward_headers.iter().all(|name| matches!(
                    name.as_str(),
                    "content-type"
                        | "accept"
                        | "anthropic-version"
                        | "anthropic-beta"
                        | "user-agent"
                )),
                "unsupported forwarded header"
            );
            ensure!(
                route.headers.iter().all(|(name, _)| !matches!(
                    name.as_str(),
                    "authorization" | "x-api-key" | "cookie"
                )),
                "use a provider credential alias for authentication"
            );
            route.request(Bytes::new(), &HeaderMap::new()).validate()?;
        }
        Ok(())
    }
}

impl HttpRoute {
    fn request(&self, body: Bytes, incoming: &HeaderMap) -> HttpFetchRequest {
        let mut headers = self.headers.clone();
        for name in &self.forward_headers {
            if !headers.iter().any(|(configured, _)| configured == name) {
                for value in incoming.get_all(name) {
                    if let Ok(value) = value.to_str() {
                        headers.push((name.clone(), value.into()));
                    }
                }
            }
        }
        HttpFetchRequest {
            url: self.url.clone(),
            method: self.method.clone(),
            headers,
            body_base64: STANDARD.encode(body),
            tls: HttpTls {
                roots: HttpTrustRoots::WebPki,
                spki_sha256: vec![],
            },
            credential: Some(self.credential.clone()),
            max_response_bytes: hellas_rpc::http_fetch::MAX_HTTP_RESPONSE_BYTES,
        }
    }
}

pub(super) async fn start(options: GatewayOptions) -> anyhow::Result<GatewayHandle> {
    let config = options
        .http_fetch
        .as_ref()
        .context("missing HTTP configuration")?
        .clone();
    config.validate()?;
    ensure!(
        options.paid_work.is_none(),
        "HTTP routes cannot use a token-native paid pool"
    );
    ensure!(
        options.output_cache.policy == hellas_rpc::cache::CachePolicy::Off,
        "HTTP routes archive exchanges; inference replay must be off"
    );
    if !options.archive.zdr {
        super::archive::prepare(&options.archive.directory)?;
    }
    let route = ExecutionRoute::remote(
        options.node_id,
        options.node_addrs.clone(),
        options.retries,
        options
            .provider_trust
            .clone()
            .context("HTTP Fetch requires a provider trust anchor")?,
    );
    let accounts = config
        .routes
        .iter()
        .map(|route| {
            (
                route.credential.clone(),
                Arc::new(Account {
                    slots: Arc::new(Semaphore::new(config.max_in_flight)),
                    retry_at: Mutex::new(Instant::now()),
                }),
            )
        })
        .collect();
    let state = Arc::new(HttpState {
        config,
        runtime: CliRuntime::remote(options.secret_key.clone()).await?,
        route,
        signer: Arc::new(options.producer_key.clone()),
        assurance: options.assurance,
        accounts,
        metrics: observation::Metrics::new(),
    });
    let bearer = Arc::new(match &options.bearer_token_file {
        Some(path) => access::Bearer::load_or_create(path)?,
        None => access::Bearer::generate(),
    });
    let mut app = Router::new();
    let paths: std::collections::BTreeSet<_> = state
        .config
        .routes
        .iter()
        .map(|route| route.path.as_str())
        .collect();
    for path in paths {
        app = app.route(path, axum::routing::any(handle));
    }
    let app = app
        .with_state(state)
        .layer(axum::middleware::from_fn_with_state(
            super::archive::Policy {
                options: options.archive.clone(),
                cache_enabled: false,
            },
            super::archive::record,
        ));
    #[cfg(feature = "otel")]
    let app = app.layer(axum::middleware::from_fn(
        hellas_rpc::telemetry::http::trace_request,
    ));
    let app = app.layer(access::BearerLayer::new(bearer.clone()));
    let listener = super::bind_gateway(
        &options.host,
        options.port,
        options.allow_remote && options.bearer_token_file.is_some(),
    )
    .await?;
    super::launch_gateway(
        app,
        listener,
        bearer,
        options.wrap.as_deref(),
        &options.wrap_args,
        None,
    )
    .await
}

fn error(status: StatusCode, message: &'static str) -> Response {
    (
        status,
        axum::Json(serde_json::json!({"error": {"message": message}})),
    )
        .into_response()
}

fn limited(status: StatusCode, seconds: u64) -> Response {
    let mut response = error(
        status,
        "provider temporarily unavailable; retry after the indicated delay",
    );
    response.headers_mut().insert(
        "retry-after",
        HeaderValue::from_str(&seconds.max(1).to_string()).unwrap(),
    );
    response
}

async fn handle(State(state): State<Arc<HttpState>>, request: Request) -> Response {
    let Some(route) = state.config.routes.iter().find(|route| {
        route.path == request.uri().path() && route.method == request.method().as_str()
    }) else {
        return error(StatusCode::NOT_FOUND, "no configured HTTP route");
    };
    if request.uri().query().is_some() {
        return error(
            StatusCode::BAD_REQUEST,
            "query parameters are not supported on this route",
        );
    }
    let mut observed = observation::Observation::new(&state.metrics, &route.path);
    let account = state.accounts[&route.credential].clone();
    let delay = account.delay();
    if !delay.is_zero() {
        observed.status(429);
        observed.complete();
        return limited(StatusCode::TOO_MANY_REQUESTS, delay.as_secs() + 1);
    }
    let Ok(permit) = account.slots.clone().try_acquire_owned() else {
        observed.status(503);
        observed.complete();
        return limited(StatusCode::SERVICE_UNAVAILABLE, 1);
    };
    let (parts, body) = request.into_parts();
    // Reserve space for URL, headers and JSON around the base64 body.
    let body_limit = (hellas_rpc::fetch::MAX_FETCH_REQUEST_BODY_BYTES - 64 * 1024) / 4 * 3;
    let body = match axum::body::to_bytes(body, body_limit).await {
        Ok(body) => body,
        Err(_) => {
            observed.status(413);
            observed.complete();
            return error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "HTTP request exceeds Fetch limit",
            );
        }
    };
    let upstream = route.request(body, &parts.headers);
    let payload = match serde_json::to_vec(&upstream) {
        Ok(payload) if upstream.validate().is_ok() => payload,
        _ => {
            observed.status(400);
            observed.complete();
            return error(StatusCode::BAD_REQUEST, "invalid HTTP request");
        }
    };
    let result = open(&state, &payload)
        .instrument(observed.span.clone())
        .await;
    let (status, headers, mut events) = match result {
        Ok(value) => value,
        Err(_) => {
            observed.status(502);
            return error(StatusCode::BAD_GATEWAY, "authenticated Fetch failed");
        }
    };
    observed.status(status);
    let headers = response_headers(headers);
    observed.content_type(
        headers
            .get("content-type")
            .and_then(|value| value.to_str().ok()),
    );
    account.observe(status, &headers);
    let stream = async_stream::try_stream! {
        let _permit = permit;
        let mut size = 0usize;
        while let Some(event) = events.next().instrument(observed.span.clone()).await {
            let event = event.map_err(|_| std::io::Error::other("Fetch stream verification failed"))?;
            match event {
                OutputEvent::Adaptor(AdaptorEvent::Http(HttpResponseEvent::Body { base64 })) => {
                    let bytes = hellas_rpc::http_fetch::decode_base64(&base64)
                        .map_err(|_| std::io::Error::other("invalid HTTP response encoding"))?;
                    size = size.saturating_add(bytes.len());
                    if bytes.is_empty() || size > upstream.max_response_bytes as usize {
                        Err(std::io::Error::other("HTTP response exceeds Fetch limit"))?;
                    }
                    observed.chunk(&bytes);
                    yield Bytes::from(bytes);
                }
                OutputEvent::Finished { stop_reason: StopReason::EndOfText, usage: None } => {
                    observed.complete();
                    return;
                }
                _ => Err(std::io::Error::other("unexpected HTTP Fetch event"))?,
            }
        }
        Err(std::io::Error::other("HTTP Fetch ended without verified completion"))?;
    };
    let stream: futures::stream::BoxStream<'static, Result<Bytes, std::io::Error>> =
        Box::pin(stream);
    let mut response = Response::new(Body::from_stream(stream));
    *response.status_mut() = StatusCode::from_u16(status).unwrap();
    *response.headers_mut() = headers;
    response
}

async fn open(
    state: &HttpState,
    payload: &[u8],
) -> anyhow::Result<(
    u16,
    Vec<(String, String)>,
    hellas_adaptors::OutputEventStream,
)> {
    let events = hellas_rpc::fetch::build_input_events_with_retention(
        &state.config.service,
        &state.config.method,
        payload,
        FetchEnvironment::Http.manifest_id(),
        state.assurance,
        state.signer.as_ref(),
        Retention::Ephemeral,
    )?;
    let request = hellas_rpc::pb::fetch::FetchRequest {
        input: events
            .iter()
            .map(hellas_rpc::stream::input_event_to_pb)
            .collect(),
    };
    let mut stream = fetch_output_stream(
        state.runtime.clone(),
        request,
        Some(state.route.clone()),
        state.signer.clone(),
        None,
    )
    .await?
    .events;
    match stream.next().await.transpose()? {
        Some(OutputEvent::Adaptor(AdaptorEvent::Http(HttpResponseEvent::Head {
            status,
            headers,
        }))) if (200..=599).contains(&status) => {
            hellas_rpc::http_fetch::check_headers(&headers, false)?;
            Ok((status, headers, stream))
        }
        _ => bail!("missing authenticated HTTP response head"),
    }
}

fn response_headers(headers: Vec<(String, String)>) -> HeaderMap {
    let mut result = HeaderMap::new();
    for (name, value) in headers {
        if matches!(
            name.as_str(),
            "content-type" | "content-encoding" | "retry-after" | "request-id" | "x-request-id"
        ) || name.starts_with("x-ratelimit-")
            || name.starts_with("ratelimit-")
            || name.starts_with("anthropic-ratelimit-")
        {
            if let (Ok(name), Ok(value)) = (
                name.parse::<axum::http::HeaderName>(),
                value.parse::<HeaderValue>(),
            ) {
                result.append(name, value);
            }
        }
    }
    result
}

fn retry_delay(headers: &HeaderMap) -> Duration {
    let value = headers
        .get("retry-after")
        .and_then(|value| value.to_str().ok());
    value
        .and_then(|value| {
            value
                .parse::<u64>()
                .ok()
                .map(Duration::from_secs)
                .or_else(|| {
                    httpdate::parse_http_date(value)
                        .ok()
                        .map(|date| date.duration_since(SystemTime::now()).unwrap_or_default())
                })
        })
        .unwrap_or(Duration::from_secs(1))
        .max(Duration::from_secs(1))
}
