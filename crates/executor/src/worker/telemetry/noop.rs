use std::time::Instant;

use tracing::Span;

use super::StopReason;
use crate::ExecutorError;

pub(super) struct InferenceMetrics;

impl InferenceMetrics {
    pub(super) fn new() -> Self {
        Self
    }

    pub(super) fn start(
        &self,
        _parent: &Span,
        _accepted_at: Instant,
        _input_tokens: usize,
        _max_new_tokens: u32,
    ) -> InferenceTelemetry {
        InferenceTelemetry { span: Span::none() }
    }
}

pub(super) struct InferenceTelemetry {
    span: Span,
}

impl InferenceTelemetry {
    pub(super) fn span(&self) -> &Span {
        &self.span
    }

    pub(super) fn token_generated(&mut self) {}
    pub(super) fn cache_stats(&self, _reused_tokens: usize, _prefill_steps: usize) {}
    pub(super) fn succeeded(self, _stop_reason: StopReason, _output_tokens: usize) {}
    pub(super) fn failed(self, _error: &ExecutorError) {}
    pub(super) fn panicked(self) {}
}
