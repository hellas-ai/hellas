use hellas_wire::metadata::Metadata;
use tracing::Span;

/// Telemetry metadata is untouched when the feature is disabled.
pub fn inject_current(_headers: &mut Metadata) {}
/// Telemetry metadata is untouched when the feature is disabled.
pub fn inject(_span: &Span, _headers: &mut Metadata) {}
/// No remote trace context is installed when telemetry is disabled.
pub fn set_remote_parent(_span: &Span, _headers: &Metadata) {}

pub(crate) fn client_span<M: hellas_wire::MethodMarker>() -> Span {
    let _ = std::marker::PhantomData::<M>;
    Span::none()
}
pub(crate) fn server_span<M: hellas_wire::MethodMarker>(_headers: &Metadata) -> Span {
    let _ = std::marker::PhantomData::<M>;
    Span::none()
}
pub(crate) fn record_status(_span: &Span, _code: hellas_wire::WireCode) {}
