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
    pub credential: Option<String>,
    #[serde(default = "public_tls")]
    pub tls: HttpTls,
    #[serde(default)]
    pub headers: Vec<(String, String)>,
}

fn public_tls() -> HttpTls {
    HttpTls {
        roots: HttpTrustRoots::WebPki,
        spki_sha256: vec![],
    }
}

struct Account {
    slots: Arc<Semaphore>,
    backoff: Mutex<Option<(Instant, u16)>>,
}

impl Account {
    fn cooldown(&self) -> Option<(u16, Duration)> {
        let (until, status) = (*self.backoff.lock().unwrap())?;
        let delay = until.saturating_duration_since(Instant::now());
        (!delay.is_zero()).then_some((status, delay))
    }

    fn observe(&self, status: u16, headers: &HeaderMap) {
        if status == 429 || (status >= 500 && headers.contains_key("retry-after")) {
            let delay = retry_delay(headers).min(Duration::from_secs(u32::MAX as u64));
            let until = Instant::now() + delay;
            let mut backoff = self.backoff.lock().unwrap();
            if backoff.is_none_or(|(previous, _)| until > previous) {
                *backoff = Some((until, status));
            }
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
                route.headers.iter().all(|(name, _)| !matches!(
                    name.as_str(),
                    "authorization" | "x-api-key" | "cookie"
                )),
                "use a provider credential alias for authentication"
            );
            route.request(Bytes::new(), &HeaderMap::new())?.validate()?;
        }
        Ok(())
    }
}

impl HttpRoute {
    fn account(&self) -> String {
        match &self.credential {
            Some(alias) => format!("credential:{alias}"),
            None => format!(
                "origin:{}",
                self.url
                    .parse::<reqwest::Url>()
                    .expect("validated URL")
                    .origin()
                    .ascii_serialization()
            ),
        }
    }

    fn request(&self, body: Bytes, incoming: &HeaderMap) -> anyhow::Result<HttpFetchRequest> {
        let mut headers = self.headers.clone();
        let connection = connection_headers(
            incoming
                .iter()
                .map(|(name, value)| (name.as_str(), value.to_str().unwrap_or_default())),
        );
        for (name, value) in incoming {
            let name = name.as_str();
            if !hop_header(name)
                && !connection.iter().any(|token| token == name)
                && !matches!(
                    name,
                    "host"
                        | "content-length"
                        | "authorization"
                        | "x-api-key"
                        | "api-key"
                        | "x-goog-api-key"
                        | "cookie"
                        | "forwarded"
                )
                && !name.starts_with("x-hellas-")
                && !name.starts_with("x-forwarded-")
                && !self
                    .headers
                    .iter()
                    .any(|(configured, _)| configured == name)
            {
                headers.push((name.into(), value.to_str()?.into()));
            }
        }
        Ok(HttpFetchRequest {
            url: self.url.clone(),
            method: self.method.clone(),
            headers,
            body_base64: STANDARD.encode(body),
            tls: self.tls.clone(),
            credential: self.credential.clone(),
            max_response_bytes: hellas_rpc::http_fetch::MAX_HTTP_RESPONSE_BYTES,
        })
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
                route.account(),
                Arc::new(Account {
                    slots: Arc::new(Semaphore::new(config.max_in_flight)),
                    backoff: Mutex::new(None),
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
    let mut observed = observation::Observation::new(&state.metrics, &route.path);
    let account = state.accounts[&route.account()].clone();
    if let Some((status, delay)) = account.cooldown() {
        observed.status(status);
        observed.complete();
        return limited(StatusCode::from_u16(status).unwrap(), delay.as_secs() + 1);
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
    let mut upstream = match route.request(body, &parts.headers) {
        Ok(upstream) => upstream,
        Err(_) => {
            observed.status(400);
            observed.complete();
            return error(StatusCode::BAD_REQUEST, "unsupported HTTP header encoding");
        }
    };
    if let Some(query) = parts.uri.query() {
        upstream
            .url
            .push(if upstream.url.contains('?') { '&' } else { '?' });
        upstream.url.push_str(query);
    }
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
    let representation_length = if parts.method == axum::http::Method::HEAD || status == 304 {
        headers
            .iter()
            .find(|(name, _)| name == "content-length")
            .and_then(|(_, value)| HeaderValue::from_str(value).ok())
    } else {
        None
    };
    let mut headers = response_headers(headers);
    if let Some(length) = representation_length {
        headers.insert("content-length", length);
    }
    observed.content_type(
        headers
            .get("content-type")
            .and_then(|value| value.to_str().ok()),
    );
    account.observe(status, &headers);
    if parts.method == axum::http::Method::HEAD || status == 204 || status == 304 {
        let end = events.next().instrument(observed.span.clone()).await;
        if !matches!(
            end,
            Some(Ok(OutputEvent::Finished {
                stop_reason: StopReason::EndOfText,
                usage: None
            }))
        ) {
            observed.status(502);
            return error(StatusCode::BAD_GATEWAY, "invalid bodyless HTTP completion");
        }
        observed.complete();
        let mut response = Response::new(Body::empty());
        *response.status_mut() = StatusCode::from_u16(status).unwrap();
        *response.headers_mut() = std::mem::take(&mut headers);
        return response;
    }
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
    let connection = connection_headers(
        headers
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str())),
    );
    for (name, value) in headers {
        if !hop_header(&name)
            && !connection.contains(&name)
            && !matches!(name.as_str(), "content-length" | "set-cookie")
            && !name.starts_with("x-hellas-")
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

fn hop_header(name: &str) -> bool {
    matches!(
        name,
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "proxy-connection"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

fn connection_headers<'a>(headers: impl Iterator<Item = (&'a str, &'a str)>) -> Vec<String> {
    headers
        .filter(|(name, _)| *name == "connection")
        .flat_map(|(_, value)| value.split(','))
        .map(|name| name.trim().to_ascii_lowercase())
        .collect()
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
