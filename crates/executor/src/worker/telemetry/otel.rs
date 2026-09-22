//! GenAI Development conventions, revision c88d504ab3d9879f8e50d3cc87e69775e11db234.
//! https://github.com/open-telemetry/semantic-conventions-genai/tree/c88d504ab3d9879f8e50d3cc87e69775e11db234/docs/gen-ai
//!
//! One inference span and terminal metric observation per worker invocation.
//! No model display name is available at this token-native boundary; a manifest
//! digest is not a model name. Never record tokens, prompts, outputs or errors' text.

use std::time::Instant;

use opentelemetry::metrics::{Histogram, Meter};
use opentelemetry::{Array, KeyValue, Value};
use tracing::Span;
use tracing_opentelemetry::OpenTelemetrySpanExt;

use super::StopReason;
use crate::{ExecutorError, StateError};

#[derive(Clone)]
pub(super) struct InferenceMetrics {
    duration: Histogram<f64>,
    first_token: Histogram<f64>,
    per_output_token: Histogram<f64>,
}

impl InferenceMetrics {
    pub(super) fn new() -> Self {
        Self::from_meter(opentelemetry::global::meter(env!("CARGO_PKG_NAME")))
    }

    pub(super) fn from_meter(meter: Meter) -> Self {
        Self {
            duration: meter
                .f64_histogram("gen_ai.server.request.duration")
                .with_unit("s")
                .with_description("Generative AI server request duration.")
                .with_boundaries(vec![
                    0.01, 0.02, 0.04, 0.08, 0.16, 0.32, 0.64, 1.28, 2.56, 5.12, 10.24, 20.48,
                    40.96, 81.92,
                ])
                .build(),
            first_token: meter
                .f64_histogram("gen_ai.server.time_to_first_token")
                .with_unit("s")
                .with_description("Time to generate the first token for successful responses.")
                .with_boundaries(vec![
                    0.001, 0.005, 0.01, 0.02, 0.04, 0.06, 0.08, 0.1, 0.25, 0.5, 0.75, 1.0, 2.5,
                    5.0, 7.5, 10.0,
                ])
                .build(),
            per_output_token: meter
                .f64_histogram("gen_ai.server.time_per_output_token")
                .with_unit("s")
                .with_description("Time per output token after the first for successful responses.")
                .with_boundaries(vec![
                    0.01, 0.025, 0.05, 0.075, 0.1, 0.15, 0.2, 0.3, 0.4, 0.5, 0.75, 1.0, 2.5,
                ])
                .build(),
        }
    }

    pub(super) fn start(
        &self,
        parent: &Span,
        accepted_at: Instant,
        input_tokens: usize,
        max_new_tokens: u32,
    ) -> InferenceTelemetry {
        let started_at = Instant::now();
        let span = tracing::info_span!(
            target: "hellas_request", parent: parent, "text_completion",
            otel.kind = "internal",
            gen_ai.operation.name = "text_completion",
            gen_ai.provider.name = "hellas",
            gen_ai.request.stream = true,
            gen_ai.request.max_tokens = i64::from(max_new_tokens),
            gen_ai.usage.input_tokens = i64::try_from(input_tokens).unwrap_or(i64::MAX),
            gen_ai.usage.output_tokens = tracing::field::Empty,
            gen_ai.usage.cache_read.input_tokens = tracing::field::Empty,
            gen_ai.response.time_to_first_chunk = tracing::field::Empty,
            error.type = tracing::field::Empty,
            otel.status_code = tracing::field::Empty,
            hellas.queue_wait_ms = started_at.duration_since(accepted_at).as_secs_f64() * 1_000.0,
            hellas.prefill_steps = tracing::field::Empty,
        );
        InferenceTelemetry {
            span,
            metrics: self.clone(),
            accepted_at,
            started_at,
            first_token_at: None,
            last_token_at: None,
        }
    }
}

pub(super) struct InferenceTelemetry {
    span: Span,
    metrics: InferenceMetrics,
    accepted_at: Instant,
    started_at: Instant,
    first_token_at: Option<Instant>,
    last_token_at: Option<Instant>,
}

impl InferenceTelemetry {
    pub(super) fn span(&self) -> &Span {
        &self.span
    }

    pub(super) fn token_generated(&mut self) {
        // Per-token work updates memory only. Attributes and metrics are recorded
        // once after the terminal result, never for partial/failed responses.
        let now = Instant::now();
        self.first_token_at.get_or_insert(now);
        self.last_token_at = Some(now);
    }

    pub(super) fn cache_stats(&self, reused_tokens: usize, prefill_steps: usize) {
        self.span.record(
            "gen_ai.usage.cache_read.input_tokens",
            i64::try_from(reused_tokens).unwrap_or(i64::MAX),
        );
        self.span.record(
            "hellas.prefill_steps",
            i64::try_from(prefill_steps).unwrap_or(i64::MAX),
        );
    }

    pub(super) fn succeeded(self, stop_reason: StopReason, output_tokens: usize) {
        let reason = match stop_reason {
            StopReason::StopToken(_) => "stop",
            StopReason::MaxNewTokens => "length",
        };
        self.span.record(
            "gen_ai.usage.output_tokens",
            i64::try_from(output_tokens).unwrap_or(i64::MAX),
        );
        self.finish_reason(reason);
        let attributes = metric_attributes();
        // Model-server latency includes time waiting for the worker, loading and
        // prefill. End at the final output token; exclude later artifact/payment
        // processing and runtime state release. A zero-token success ends here.
        let end = self.last_token_at.unwrap_or_else(Instant::now);
        self.metrics.duration.record(
            end.duration_since(self.accepted_at).as_secs_f64(),
            &attributes,
        );
        if let Some(first) = self.first_token_at {
            self.span.record(
                "gen_ai.response.time_to_first_chunk",
                first.duration_since(self.started_at).as_secs_f64(),
            );
            self.metrics.first_token.record(
                first.duration_since(self.accepted_at).as_secs_f64(),
                &attributes,
            );
            if output_tokens > 1 {
                let seconds = end.duration_since(first).as_secs_f64() / (output_tokens - 1) as f64;
                self.metrics.per_output_token.record(seconds, &attributes);
            }
        }
    }

    pub(super) fn failed(self, error: &ExecutorError) {
        self.failure(error_type(error));
    }

    pub(super) fn panicked(self) {
        self.failure("panic");
    }

    fn failure(self, error_type: &'static str) {
        self.span.record("error.type", error_type);
        self.span.record("otel.status_code", "ERROR");
        self.finish_reason("error");
        let mut attributes = metric_attributes().to_vec();
        attributes.push(KeyValue::new("error.type", error_type));
        self.metrics
            .duration
            .record(self.accepted_at.elapsed().as_secs_f64(), &attributes);
    }

    fn finish_reason(&self, reason: &'static str) {
        self.span.set_attribute(
            "gen_ai.response.finish_reasons",
            Value::Array(Array::String(vec![reason.into()])),
        );
    }
}

fn metric_attributes() -> [KeyValue; 2] {
    [
        KeyValue::new("gen_ai.operation.name", "text_completion"),
        KeyValue::new("gen_ai.provider.name", "hellas"),
    ]
}

// Bounded classes only. Never use Display: errors can include user-controlled
// content, paths, IDs, or device diagnostics. "panic" is handled separately.
fn error_type(error: &ExecutorError) -> &'static str {
    match error {
        ExecutorError::ChannelClosed => "channel_closed",
        ExecutorError::QueueFull { .. }
        | ExecutorError::ResourceExhausted(_)
        | ExecutorError::QuotaExceeded { .. } => "resource_exhausted",
        ExecutorError::InvalidQuoteRequest(_)
        | ExecutorError::InvalidTokenPayload(_)
        | ExecutorError::TokenBytes(_) => "invalid_request",
        ExecutorError::Execution(_) => "execution_error",
        ExecutorError::ArtifactNotFound(_) | ExecutorError::State(StateError::QuoteNotFound(_)) => {
            "not_found"
        }
        ExecutorError::ArtifactStore(_) => "artifact_store_error",
        ExecutorError::PolicyDenied(_) => "policy_denied",
        ExecutorError::State(StateError::QuoteExpired(_)) => "expired",
    }
}
