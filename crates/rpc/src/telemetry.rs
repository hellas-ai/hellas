//! W3C trace context over the existing RPC metadata envelope.
//!
//! Only traceparent and tracestate cross this boundary. Request bodies,
//! authorization headers and baggage are never copied into telemetry.

#[doc(hidden)]
pub use tracing as __tracing;

/// Construct a request span only in builds with the `otel` feature.
/// Disabled builds do not evaluate any of the span's field expressions.
#[cfg(feature = "otel")]
#[macro_export]
macro_rules! request_span {
    ($($fields:tt)*) => {
        $crate::telemetry::__tracing::info_span!($($fields)*)
    };
}

/// No request instrumentation or field evaluation without the `otel` feature.
#[cfg(not(feature = "otel"))]
#[macro_export]
macro_rules! request_span {
    ($($fields:tt)*) => {
        $crate::telemetry::__tracing::Span::none()
    };
}

#[cfg_attr(feature = "otel", path = "telemetry/otel.rs")]
#[cfg_attr(not(feature = "otel"), path = "telemetry/noop.rs")]
mod implementation;

pub(crate) use implementation::{CallSpan, client_span, server_span};
pub use implementation::{inject, inject_current, set_remote_parent};

/// HTTP server spans including streamed response bodies.
#[cfg(all(feature = "otel", feature = "http-tracing"))]
pub mod http;

#[cfg(test)]
mod tests {
    #[test]
    fn injecting_absent_context_removes_stale_headers_only() {
        let mut headers = hellas_wire::Metadata::new();
        headers.insert_text("traceparent", "stale-parent");
        headers.insert_text("tracestate", "stale-state");
        headers.insert_text("authorization", "retained");
        super::inject(&tracing::Span::none(), &mut headers);
        assert!(headers.get("traceparent").is_none());
        assert!(headers.get("tracestate").is_none());
        assert_eq!(
            headers.get("authorization").unwrap().as_text(),
            Some("retained")
        );
    }

    #[cfg(not(feature = "otel"))]
    #[test]
    fn disabled_request_span_does_not_evaluate_fields() {
        let _span = crate::request_span!("unused", value = panic!("evaluated disabled span field"));
    }
}
