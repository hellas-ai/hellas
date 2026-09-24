use futures::StreamExt;
use hellas_adaptors::MAX_SSE_RESPONSE_BYTES;
use hellas_executor::{FetchProviderError, FetchProviderResponse, FetchProviderResponseHead};
use reqwest::Url;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};
use std::time::Duration;
use tracing::Instrument;

#[cfg_attr(feature = "otel", path = "responses_fetch/telemetry/otel.rs")]
#[cfg_attr(not(feature = "otel"), path = "responses_fetch/telemetry/noop.rs")]
pub(crate) mod telemetry;

/// A total request deadline bounds the whole call; this independent idle
/// deadline prevents a peer that stops producing SSE bytes from occupying a
/// Fetch execution slot for that entire window. Ordinary SSE keepalives count
/// as activity and reset it. Unsuccessful response bodies are never read or logged.
const FETCH_STREAM_IDLE_TIMEOUT: Duration = Duration::from_secs(90);

/// HTTP client for attested Fetch egress. Redirects are disabled because the
/// exact HTTPS destination is part of the quoted Fetch environment.
pub fn responses_http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(20 * 60))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("Fetch HTTP client configuration is valid")
}

pub async fn execute_responses_request(
    client: &reqwest::Client,
    endpoint: Url,
    bearer_token: &str,
    body: Vec<u8>,
    // Derived from the input transcript commitment, so a re-issued call for
    // the same ticket dedupes at the provider billing boundary where the
    // provider honors the header.
    idempotency_key: &str,
    label: &str,
) -> Result<FetchProviderResponse, FetchProviderError> {
    let mut telemetry = telemetry::Request::new(&endpoint);
    let request = client
        .post(endpoint)
        .header(CONTENT_TYPE, "application/json")
        .header(AUTHORIZATION, format!("Bearer {bearer_token}"))
        .header("Idempotency-Key", idempotency_key)
        .body(body);
    let upstream = telemetry
        .send(request)
        .instrument(telemetry.span.clone())
        .await
        .map_err(|source| {
            telemetry.fail("transport_error");
            FetchProviderError::failed(format!("{label} request failed: {source}"))
        })?;

    let status = upstream.status();
    telemetry.status(status.as_u16());
    if !status.is_success() {
        telemetry.fail("http_error");
        // Error bodies can echo customer input. Drop them without reading or
        // logging a prefix, even when the request itself is ephemeral.
        drop(upstream);
        tracing::warn!(
            provider = label,
            upstream_status = status.as_u16(),
            "upstream Fetch request failed"
        );
        return Err(FetchProviderError::failed(format!(
            "{label} upstream rejected the request (HTTP {})",
            status.as_u16()
        )));
    }

    let content_type = upstream
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(str::trim);
    if !content_type.is_some_and(|value| value.eq_ignore_ascii_case("text/event-stream")) {
        telemetry.fail("invalid_content_type");
        return Err(FetchProviderError::failed(format!(
            "{label} returned successful HTTP {status} without text/event-stream content"
        )));
    }

    let head = FetchProviderResponseHead {
        effective_model: effective_model_from_headers(upstream.headers())
            .inspect_err(|_| telemetry.fail("invalid_response_headers"))?,
        http: None,
    };
    Ok(FetchProviderResponse {
        head,
        stream: Box::pin(telemetry.stream(stream_response(upstream, label.to_string()))),
    })
}

/// Codex currently reads the standard `openai-model` response header. The
/// `x-openai-model` spelling is accepted as its compatibility fallback; the
/// standard spelling therefore wins when both are present. Repeated values of
/// either spelling are hostile unless they agree exactly.
fn effective_model_from_headers(
    headers: &reqwest::header::HeaderMap,
) -> Result<Option<String>, FetchProviderError> {
    let standard = unique_model_header(headers, "openai-model")?;
    let compatibility = unique_model_header(headers, "x-openai-model")?;
    Ok(standard.or(compatibility))
}

fn unique_model_header(
    headers: &reqwest::header::HeaderMap,
    name: &'static str,
) -> Result<Option<String>, FetchProviderError> {
    let mut value: Option<String> = None;
    for raw in headers.get_all(name) {
        let text = raw.to_str().map_err(|_| {
            FetchProviderError::failed(format!("{name} response header is not valid UTF-8"))
        })?;
        if text.is_empty() || text.len() > 256 {
            return Err(FetchProviderError::failed(format!(
                "{name} response header must contain 1..=256 UTF-8 bytes"
            )));
        }
        if value.as_deref().is_some_and(|existing| existing != text) {
            return Err(FetchProviderError::failed(format!(
                "conflicting duplicate {name} response headers"
            )));
        }
        value = Some(text.to_owned());
    }
    Ok(value)
}

fn stream_response(
    upstream: reqwest::Response,
    label: String,
) -> impl futures::Stream<Item = Result<Vec<u8>, FetchProviderError>> + Send + 'static {
    stream_response_with_idle_timeout(upstream, label, FETCH_STREAM_IDLE_TIMEOUT)
}

fn stream_response_with_idle_timeout(
    upstream: reqwest::Response,
    label: String,
    idle_timeout: Duration,
) -> impl futures::Stream<Item = Result<Vec<u8>, FetchProviderError>> + Send + 'static {
    async_stream::try_stream! {
        let mut chunks = upstream.bytes_stream();
        let mut received = 0_usize;

        loop {
            let next = tokio::time::timeout(idle_timeout, chunks.next())
                .await
                .map_err(|_| FetchProviderError::failed(format!(
                    "{label} stream produced no bytes for {} seconds",
                    idle_timeout.as_secs_f64()
                )))?;
            let Some(chunk) = next else {
                break;
            };
            let chunk = chunk.map_err(|source| {
                FetchProviderError::failed(format!("{label} stream failed: {source}"))
            })?;
            let next_received = received.checked_add(chunk.len()).ok_or_else(|| {
                FetchProviderError::failed(format!(
                    "{label} stream exceeded the {MAX_SSE_RESPONSE_BYTES}-byte limit"
                ))
            })?;
            if next_received > MAX_SSE_RESPONSE_BYTES {
                Err(FetchProviderError::failed(format!(
                    "{label} stream exceeded the {MAX_SSE_RESPONSE_BYTES}-byte limit"
                )))?;
            }
            received = next_received;
            yield chunk.to_vec();
        }
    }
}

#[cfg(test)]
mod tests;
