use axum::body::{Body, Bytes};
use axum::http::{HeaderName, HeaderValue, StatusCode};
use axum::response::Response;
use axum::response::sse::Event;
use futures::StreamExt;
use hellas_adaptors::{
    AdaptorError, BackendError, BackendRequest, ExecutionBackend, OutputEvent, Provenance,
    RawRequest, RenderContext, WireAdaptor, WireBody, WireEventData, WireResponse, WireStreamEvent,
};
use hellas_rpc::provenance::ExecutionProvenance;

use super::{json_error, sse_data, sse_event_data, sse_response};

pub(super) fn parse_backend_request<A: WireAdaptor>(
    adaptor: &A,
    body: &Bytes,
    surface: &str,
) -> Result<(A::ParsedRequest, BackendRequest), Box<Response>> {
    let raw = RawRequest::from_slice(body).map_err(|err| Box::new(adaptor_error(surface, err)))?;
    let parsed = adaptor
        .parse(raw.clone())
        .map_err(|err| Box::new(adaptor_error(surface, err)))?;
    let execution = adaptor
        .to_execution_request(&parsed)
        .map_err(|err| Box::new(adaptor_error(surface, err)))?;
    Ok((parsed, BackendRequest::new(execution, raw)))
}

pub(super) async fn backend_wire_response<A, B>(
    stream: bool,
    adaptor: A,
    parsed: A::ParsedRequest,
    backend: B,
    request: BackendRequest,
    context: RenderContext,
    surface: &'static str,
) -> Response
where
    A: WireAdaptor + Send + 'static,
    A::ParsedRequest: Send + 'static,
    A::StreamState: Send + 'static,
    B: ExecutionBackend,
{
    if stream {
        backend_stream_response(adaptor, parsed, backend, request, context, surface).await
    } else {
        backend_response(adaptor, parsed, backend, request, context, surface).await
    }
}

async fn backend_response<A, B>(
    adaptor: A,
    parsed: A::ParsedRequest,
    backend: B,
    request: BackendRequest,
    context: RenderContext,
    surface: &'static str,
) -> Response
where
    A: WireAdaptor,
    B: ExecutionBackend,
{
    let backend_stream = match backend.stream(request).await {
        Ok(stream) => stream,
        Err(err) => return backend_error(surface, err),
    };
    let result = match backend_stream.collect().await {
        Ok(result) => result,
        Err(err) => return backend_error(surface, err),
    };
    let provenance = result.provenance.clone();
    let wire = match adaptor.render_response(&parsed, result, context) {
        Ok(response) => response,
        Err(err) => return adaptor_error(surface, err),
    };
    let mut response = match wire_response(wire) {
        Ok(response) => response,
        Err(message) => return json_error(StatusCode::INTERNAL_SERVER_ERROR, message),
    };
    attach_wire_provenance(&mut response, provenance.as_ref());
    response
}

async fn backend_stream_response<A, B>(
    adaptor: A,
    parsed: A::ParsedRequest,
    backend: B,
    request: BackendRequest,
    context: RenderContext,
    surface: &'static str,
) -> Response
where
    A: WireAdaptor + Send + 'static,
    A::ParsedRequest: Send + 'static,
    A::StreamState: Send + 'static,
    B: ExecutionBackend,
{
    let backend_stream = match backend.stream(request).await {
        Ok(stream) => stream,
        Err(err) => return backend_error(surface, err),
    };
    let header_provenance = backend_stream.initial_provenance.clone();
    let stream_provenance = backend_stream.initial_provenance;
    let mut output_events = backend_stream.events;
    // Admission is asynchronous. Preserve its HTTP refusal before committing
    // SSE headers; failures after the first output remain stream errors.
    let first = match output_events.next().await {
        Some(Ok(event)) => event,
        Some(Err(error)) => return backend_error(surface, error),
        None => return backend_error(surface, BackendError::failed("backend returned no output")),
    };
    let mut output_events =
        futures::stream::once(std::future::ready(Ok(first))).chain(output_events);

    let mut response = sse_response(async_stream::stream! {
        let mut state = adaptor.initial_state(&parsed, context);

        if let Some(provenance) = stream_provenance {
            match render_events(adaptor.render_stream_event(
                &parsed,
                &mut state,
                OutputEvent::Provenance(provenance),
            )) {
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

        match render_events(adaptor.render_stream_start(&parsed, &mut state)) {
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
                Ok(output) => {
                    match render_events(adaptor.render_stream_event(&parsed, &mut state, output)) {
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
                    for event in render_error_events(&adaptor, &parsed, &mut state, err.to_string()) {
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

pub(super) fn adaptor_error(surface: &str, error: AdaptorError) -> Response {
    let status = match error {
        AdaptorError::InvalidJson(_)
        | AdaptorError::InvalidRequest(_)
        | AdaptorError::Unsupported(_) => StatusCode::BAD_REQUEST,
        AdaptorError::InvalidResponse(_) => StatusCode::BAD_GATEWAY,
        AdaptorError::Render(_) => StatusCode::INTERNAL_SERVER_ERROR,
    };
    json_error(status, format!("{surface}: {error}"))
}

fn backend_error(surface: &str, error: BackendError) -> Response {
    let status = match error {
        BackendError::Rejected(_) => StatusCode::BAD_REQUEST,
        BackendError::Denied(_) => StatusCode::FORBIDDEN,
        BackendError::Quota(_) => StatusCode::TOO_MANY_REQUESTS,
        BackendError::Busy(_) => StatusCode::SERVICE_UNAVAILABLE,
        BackendError::Failed(_) => StatusCode::INTERNAL_SERVER_ERROR,
    };
    json_error(status, format!("{surface}: {error}"))
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

pub(super) fn sse_event(event: WireStreamEvent) -> Event {
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

fn wire_error_event(error: AdaptorError) -> Event {
    output_error_event(error.to_string())
}

fn output_error_event(message: impl Into<String>) -> Event {
    sse_event_data(
        "error",
        &serde_json::json!({
            "error": { "message": message.into() }
        }),
    )
}

fn render_events(events: Result<Vec<WireStreamEvent>, AdaptorError>) -> Result<Vec<Event>, Event> {
    events
        .map(|events| events.into_iter().map(sse_event).collect())
        .map_err(wire_error_event)
}

fn render_error_events<A: WireAdaptor>(
    adaptor: &A,
    parsed: &A::ParsedRequest,
    state: &mut A::StreamState,
    message: String,
) -> Vec<Event> {
    match render_events(adaptor.render_stream_event(
        parsed,
        state,
        OutputEvent::Error {
            message: message.clone(),
            code: None,
        },
    )) {
        Ok(events) if !events.is_empty() => events,
        Ok(_) => vec![output_error_event(message)],
        Err(event) => vec![event],
    }
}

fn attach_wire_provenance(response: &mut Response, provenance: Option<&Provenance>) {
    let Some(provenance) = provenance else {
        return;
    };
    if let Some(call) = provenance
        .call_commitment
        .as_deref()
        .and_then(|value| decode_hex_32("call commitment", value))
    {
        response.extensions_mut().insert(ExecutionProvenance {
            commitment_id: call,
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
    let mut out = [0_u8; 32];
    let bytes = value.as_bytes();
    for (idx, byte) in out.iter_mut().enumerate() {
        let Some(hi) = hex_nibble(bytes[idx * 2]) else {
            warn!(label, "invalid provenance commitment hex");
            return None;
        };
        let Some(lo) = hex_nibble(bytes[idx * 2 + 1]) else {
            warn!(label, "invalid provenance commitment hex");
            return None;
        };
        *byte = (hi << 4) | lo;
    }
    Some(out)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}
