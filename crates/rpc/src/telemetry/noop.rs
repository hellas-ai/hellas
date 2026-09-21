use hellas_wire::metadata::Metadata;
use tracing::Span;

/// Disabled builds do not forward stale caller-supplied trace context.
pub fn inject_current(headers: &mut Metadata) {
    inject(&Span::none(), headers);
}
pub fn inject(_span: &Span, headers: &mut Metadata) {
    headers.remove("traceparent");
    headers.remove("tracestate");
}
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

#[derive(Clone)]
pub(crate) struct CallSpan(Span);
impl CallSpan {
    pub(crate) fn new(span: Span) -> Self {
        Self(span)
    }
    pub(crate) fn span(&self) -> &Span {
        &self.0
    }
    pub(crate) fn finish(&self, _code: hellas_wire::WireCode) {}
}
