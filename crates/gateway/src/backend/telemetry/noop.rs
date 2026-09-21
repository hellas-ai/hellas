use futures::Stream;
use hellas_adaptors::{BackendError, BackendRequest, OutputEvent};
use tracing::Span;

#[derive(Clone)]
pub(crate) struct InferenceMetrics;
impl InferenceMetrics {
    pub(crate) fn new() -> Self {
        Self
    }
}

pub(crate) struct Inference {
    pub(crate) span: Span,
}

impl Inference {
    pub(crate) fn new(_: &BackendRequest, _: &InferenceMetrics) -> Self {
        Self { span: Span::none() }
    }

    pub(crate) fn fail(&mut self, _: &BackendError) {}

    pub(crate) fn response_model(&mut self, _: &str) {}
    pub(crate) fn stream<S>(self, stream: S) -> S
    where
        S: Stream<Item = Result<OutputEvent, BackendError>> + Send + 'static,
    {
        stream
    }
}
