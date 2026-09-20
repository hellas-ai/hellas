//! RPC conventions v1.44.0 (Release Candidate), selected with the `otel` feature.
//! https://github.com/open-telemetry/semantic-conventions/blob/v1.44.0/docs/rpc/rpc-spans.md
//! Hellas uses the canonical 17 WireCode names as status/error strings. Only OK
//! is successful; no server-supplied status message is included in a span.

use hellas_wire::metadata::Metadata;
use tracing::Span;

/// Replace stale caller-supplied trace headers with the current client span.
pub fn inject_current(headers: &mut Metadata) {
    inject(&Span::current(), headers);
}

/// Inject one span's W3C context (also used for HTTP response correlation).
pub fn inject(span: &Span, headers: &mut Metadata) {
    use opentelemetry::propagation::Injector;
    use tracing_opentelemetry::OpenTelemetrySpanExt;
    struct Carrier<'a>(&'a mut Metadata);
    impl Injector for Carrier<'_> {
        fn set(&mut self, key: &str, value: String) {
            if matches!(key, "traceparent" | "tracestate") {
                self.0.remove(key);
                self.0.insert_text(key, value);
            }
        }
    }
    opentelemetry::global::get_text_map_propagator(|propagator| {
        propagator.inject_context(&span.context(), &mut Carrier(headers));
    });
}

/// Start a server span under the inbound remote context, never under an
/// unrelated accept-loop span. Invalid/missing context starts a fresh trace.
pub fn set_remote_parent(span: &Span, headers: &Metadata) {
    use opentelemetry::propagation::Extractor;
    use tracing_opentelemetry::OpenTelemetrySpanExt;
    struct Carrier<'a>(&'a Metadata);
    impl Extractor for Carrier<'_> {
        fn get(&self, key: &str) -> Option<&str> {
            matches!(key, "traceparent" | "tracestate")
                .then(|| self.0.get(key).and_then(|value| value.as_text()))
                .flatten()
        }
        fn keys(&self) -> Vec<&str> {
            vec!["traceparent", "tracestate"]
        }
    }
    let context = opentelemetry::global::get_text_map_propagator(|propagator| {
        propagator.extract_with_context(&opentelemetry::Context::new(), &Carrier(headers))
    });
    let _ = span.set_parent(context);
}

/// Build the RPC server span before entering it: entering can start the SDK
/// span, after which its remote parent cannot be changed.
pub(crate) fn server_span<M: hellas_wire::MethodMarker>(headers: &Metadata) -> Span {
    let method = method_name::<M>();
    let span = tracing::info_span!(
        target: "hellas_request",
        parent: None,
        "rpc.server",
        otel.name = %method,
        otel.kind = "server",
        rpc.system.name = "hellas",
        rpc.method = %method,
        rpc.response.status_code = tracing::field::Empty,
        error.type = tracing::field::Empty,
        otel.status_code = tracing::field::Empty,
    );
    set_remote_parent(&span, headers);
    span
}

/// Record only the protocol status code, never server-supplied error text.
pub(crate) fn record_status(span: &Span, code: hellas_wire::WireCode) {
    let status = status_name(code);
    span.record("rpc.response.status_code", status);
    if code != hellas_wire::WireCode::Ok {
        span.record("error.type", status);
        span.record("otel.status_code", "ERROR");
    }
}

/// Build a client span whose lifetime includes the streaming terminal trailer.
pub(crate) fn client_span<M: hellas_wire::MethodMarker>() -> Span {
    let method = method_name::<M>();
    tracing::info_span!(
        target: "hellas_request", "rpc.client",
        otel.name = %method,
        otel.kind = "client",
        rpc.system.name = "hellas",
        rpc.method = %method,
        rpc.response.status_code = tracing::field::Empty,
        error.type = tracing::field::Empty,
        otel.status_code = tracing::field::Empty,
    )
}

fn method_name<M: hellas_wire::MethodMarker>() -> String {
    format!(
        "{}/{}",
        <M::Service as hellas_wire::ServiceMarker>::NAME,
        M::NAME
    )
}

fn status_name(code: hellas_wire::WireCode) -> &'static str {
    use hellas_wire::WireCode;
    match code {
        WireCode::Ok => "OK",
        WireCode::Cancelled => "CANCELLED",
        WireCode::Unknown => "UNKNOWN",
        WireCode::InvalidArgument => "INVALID_ARGUMENT",
        WireCode::DeadlineExceeded => "DEADLINE_EXCEEDED",
        WireCode::NotFound => "NOT_FOUND",
        WireCode::AlreadyExists => "ALREADY_EXISTS",
        WireCode::PermissionDenied => "PERMISSION_DENIED",
        WireCode::ResourceExhausted => "RESOURCE_EXHAUSTED",
        WireCode::FailedPrecondition => "FAILED_PRECONDITION",
        WireCode::Aborted => "ABORTED",
        WireCode::OutOfRange => "OUT_OF_RANGE",
        WireCode::Unimplemented => "UNIMPLEMENTED",
        WireCode::Internal => "INTERNAL",
        WireCode::Unavailable => "UNAVAILABLE",
        WireCode::DataLoss => "DATA_LOSS",
        WireCode::Unauthenticated => "UNAUTHENTICATED",
    }
}
