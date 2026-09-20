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

#[cfg(feature = "otel")]
#[path = "telemetry/otel.rs"]
mod implementation;
#[cfg(not(feature = "otel"))]
#[path = "telemetry/noop.rs"]
mod implementation;

pub(crate) use implementation::{client_span, record_status, server_span};
pub use implementation::{inject, inject_current, set_remote_parent};
