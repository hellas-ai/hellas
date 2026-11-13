use axum::body::Body;
use axum::http::{HeaderName, HeaderValue, StatusCode};
use axum::response::Response;
use axum::response::sse::Event;
use futures::StreamExt;
use hellas_adaptors::{
    AdaptorError, AdaptorResult, BackendError, BackendEvent, BackendRequest, BackendStream,
    ExecutionBackend, OutputEvent, Provenance, RawRequest, RenderContext, WireAdaptor, WireBody,
    WireEventData, WireResponse, WireStreamEvent,
};
use hellas_rpc::provenance::{ExecutionProvenance, parse_public_key};

use serde_json::Value as JsonValue;

use super::{json_error, next_id, now_unix, sse_data, sse_event_data, sse_response};

/// The response ids and creation time `prefix` names for one request.
pub(super) fn render_context(prefix: &str) -> RenderContext {
    RenderContext::new(next_id(prefix), next_id("msg"), now_unix())
}

/// Serve one wire-format request on `backend`: parse it, run it, render the
/// result in the same format, under the model the request names.
pub(super) async fn serve<A, B>(
    adaptor: A,
    surface: &'static str,
    context: RenderContext,
    backend: B,
    body: &[u8],
) -> Response
where
    A: WireAdaptor + Send + 'static,
    A::ParsedRequest: Send + 'static,
    A::StreamState: Send + 'static,
    B: ExecutionBackend,
{
    let (parsed, request) = match parse(&adaptor, body) {
        Ok(parsed) => parsed,
        Err(err) => return adaptor_error(&adaptor, surface, err),
    };
    let stream = request.raw.value().get("stream") == Some(&JsonValue::Bool(true));
    let backend_stream = match backend.stream(request).await {
        Ok(stream) => stream,
        Err(err) => return backend_error(&adaptor, surface, err),
    };
    if stream {
        stream_response(adaptor, parsed, backend_stream, context, surface).await
    } else {
        response(adaptor, parsed, backend_stream, context, surface).await
    }
}

fn parse<A: WireAdaptor>(
    adaptor: &A,
    body: &[u8],
) -> AdaptorResult<(A::ParsedRequest, BackendRequest)> {
    let raw = RawRequest::from_slice(body)?;
    let parsed = adaptor.parse(raw.clone())?;
    let execution = adaptor.to_execution_request(&parsed)?;
    Ok((parsed, BackendRequest::new(execution, raw)))
}

async fn response<A: WireAdaptor>(
    adaptor: A,
    parsed: A::ParsedRequest,
    backend_stream: BackendStream,
    context: RenderContext,
    surface: &'static str,
) -> Response {
    let result = match backend_stream.collect().await {
        Ok(result) => result,
        Err(err) => return backend_error(&adaptor, surface, err),
    };
    let provenance = result.provenance.clone();
    let wire = match adaptor.render_response(&parsed, result, context) {
        Ok(response) => response,
        Err(err) => return adaptor_error(&adaptor, surface, err),
    };
    let mut response = match wire_response(wire) {
        Ok(response) => response,
        Err(message) => {
            return error_response(&adaptor, StatusCode::INTERNAL_SERVER_ERROR, message);
        }
    };
    attach_wire_provenance(&mut response, provenance.as_ref());
    response
}

async fn stream_response<A>(
    adaptor: A,
    parsed: A::ParsedRequest,
    backend_stream: BackendStream,
    context: RenderContext,
    surface: &'static str,
) -> Response
where
    A: WireAdaptor + Send + 'static,
    A::ParsedRequest: Send + 'static,
    A::StreamState: Send + 'static,
{
    let header_provenance = backend_stream.initial_provenance.clone();
    let stream_provenance = backend_stream.initial_provenance;
    let mut output_events = backend_stream.events;
    // Admission is asynchronous. Preserve its HTTP refusal before committing
    // SSE headers; failures after the first output remain stream errors.
    let first = match output_events.next().await {
        Some(Ok(event)) => event,
        Some(Err(error)) => return backend_error(&adaptor, surface, error),
        None => {
            return backend_error(
                &adaptor,
                surface,
                BackendError::failed("backend returned no output"),
            );
        }
    };
    let mut output_events =
        futures::stream::once(std::future::ready(Ok(first))).chain(output_events);

    let mut response = sse_response(async_stream::stream! {
        let mut state = adaptor.initial_state(&parsed, context);

        if let Some(provenance) = stream_provenance {
            adaptor.attest(&mut state, provenance);
        }

        match render_events(&adaptor, adaptor.render_stream_start(&parsed, &mut state)) {
            Ok(events) => {
                for event in events {
                    yield Ok(event);
                }
            }
            Err(event) => {
                yield Ok(event);
                return;
            }
        }

        while let Some(event) = output_events.next().await {
            match event {
                Ok(BackendEvent::Provenance(provenance)) => adaptor.attest(&mut state, provenance),
                Ok(BackendEvent::Output(output)) => {
                    match render_events(&adaptor, adaptor.render_stream_event(&parsed, &mut state, output)) {
                        Ok(events) => {
                            for event in events {
                                yield Ok(event);
                            }
                        }
                        Err(event) => {
                            yield Ok(event);
                            return;
                        }
                    }
                }
                Err(err) => {
                    for event in render_error_events(&adaptor, &parsed, &mut state, &err) {
                        yield Ok(event);
                    }
                    return;
                }
            }
        }
    });
    attach_wire_provenance(&mut response, header_provenance.as_ref());
    response
}

fn adaptor_error<A: WireAdaptor>(adaptor: &A, surface: &str, error: AdaptorError) -> Response {
    let status = match error {
        AdaptorError::InvalidJson(_)
        | AdaptorError::InvalidRequest(_)
        | AdaptorError::Unsupported(_) => StatusCode::BAD_REQUEST,
        AdaptorError::InvalidResponse(_) => StatusCode::BAD_GATEWAY,
        AdaptorError::Render(_) => StatusCode::INTERNAL_SERVER_ERROR,
    };
    error_response(adaptor, status, format!("{surface}: {error}"))
}

fn backend_error<A: WireAdaptor>(adaptor: &A, surface: &str, error: BackendError) -> Response {
    let status = super::backend_status(&error);
    error_response(adaptor, status, format!("{surface}: {error}"))
}

fn error_response<A: WireAdaptor>(adaptor: &A, status: StatusCode, message: String) -> Response {
    wire_response(adaptor.render_error(status.as_u16(), message))
        .unwrap_or_else(|message| json_error(StatusCode::INTERNAL_SERVER_ERROR, message))
}

pub(super) fn wire_response(response: WireResponse) -> Result<Response, String> {
    let status = StatusCode::from_u16(response.status)
        .map_err(|err| format!("adaptor rendered invalid HTTP status: {err}"))?;
    let body = match response.body {
        WireBody::Json(value) => Body::from(
            serde_json::to_vec(&value)
                .map_err(|err| format!("failed to encode JSON response: {err}"))?,
        ),
        WireBody::Bytes(bytes) => Body::from(bytes),
    };

    let mut builder = Response::builder().status(status);
    for (name, value) in response.headers {
        let name = HeaderName::from_bytes(name.as_bytes())
            .map_err(|err| format!("adaptor rendered invalid header name `{name}`: {err}"))?;
        let value = HeaderValue::from_str(&value)
            .map_err(|err| format!("adaptor rendered invalid header value for `{name}`: {err}"))?;
        builder = builder.header(name, value);
    }

    builder
        .body(body)
        .map_err(|err| format!("failed to build HTTP response: {err}"))
}

fn sse_event(event: WireStreamEvent) -> Event {
    match (event.name, event.data) {
        (Some(name), WireEventData::Json(value)) => sse_event_data(&name, &value),
        (Some(name), WireEventData::Text(value)) => Event::default().event(name).data(value),
        (Some(name), WireEventData::Bytes(value)) => Event::default()
            .event(name)
            .data(String::from_utf8_lossy(&value)),
        (None, WireEventData::Json(value)) => sse_data(&value),
        (None, WireEventData::Text(value)) => Event::default().data(value),
        (None, WireEventData::Bytes(value)) => {
            Event::default().data(String::from_utf8_lossy(&value))
        }
    }
}

/// A stream failure with HTTP `status` as `adaptor`'s `error` event.
fn error_event<A: WireAdaptor>(adaptor: &A, status: StatusCode, message: String) -> Event {
    let data = match adaptor.render_error(status.as_u16(), message).body {
        WireBody::Json(value) => WireEventData::Json(value),
        WireBody::Bytes(bytes) => WireEventData::Bytes(bytes),
    };
    sse_event(WireStreamEvent {
        name: Some("error".into()),
        data,
    })
}

fn render_events<A: WireAdaptor>(
    adaptor: &A,
    events: Result<Vec<WireStreamEvent>, AdaptorError>,
) -> Result<Vec<Event>, Event> {
    events
        .map(|events| events.into_iter().map(sse_event).collect())
        .map_err(|error| {
            error_event(
                adaptor,
                StatusCode::INTERNAL_SERVER_ERROR,
                error.to_string(),
            )
        })
}

/// A backend failure after the stream began, classified as it would have
/// been before: the same status and error type.
fn render_error_events<A: WireAdaptor>(
    adaptor: &A,
    parsed: &A::ParsedRequest,
    state: &mut A::StreamState,
    error: &BackendError,
) -> Vec<Event> {
    let status = super::backend_status(error);
    let message = error.to_string();
    let events = adaptor.render_stream_event(
        parsed,
        state,
        OutputEvent::Error {
            message: message.clone(),
            code: adaptor.error_code(status.as_u16()),
        },
    );
    match render_events(adaptor, events) {
        Ok(events) if !events.is_empty() => events,
        Ok(_) => vec![error_event(adaptor, status, message)],
        Err(event) => vec![event],
    }
}

/// Hand the accepted job's identity to the provenance layer, which renders
/// it as response headers.
fn attach_wire_provenance(response: &mut Response, provenance: Option<&Provenance>) {
    let Some(provenance) = provenance else {
        return;
    };
    let commitment = provenance
        .commitment
        .as_deref()
        .and_then(|value| decode_hex_32("commitment", value));
    let provider = provenance.provider.as_deref().and_then(|value| {
        let key = parse_public_key(value);
        if key.is_none() {
            warn!("invalid provenance provider key");
        }
        key
    });
    if let (Some(commitment_id), Some(provider)) = (commitment, provider) {
        response.extensions_mut().insert(ExecutionProvenance {
            commitment_id,
            provider,
        });
    }
}

fn decode_hex_32(label: &'static str, value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 {
        warn!(
            label,
            len = value.len(),
            "invalid provenance commitment length"
        );
        return None;
    }
    hellas_auth::hex::parse(value)
        .map_err(|_| warn!(label, "invalid provenance commitment hex"))
        .ok()
}
