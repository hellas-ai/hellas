//! GenAI Development c88d504ab3d9879f8e50d3cc87e69775e11db234.
//! Client observations at the gateway's model-backend boundary.
//! Only operation metadata is recorded; model inputs and generated text stay
//! in the execution stream. Metrics describe this caller's complete operation,
//! including routing, inference and the payment acknowledgement.

use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Instant;

use futures::Stream;
use hellas_adaptors::{BackendError, BackendRequest, Input, OutputEvent, StopReason};
use tracing::Span;

use opentelemetry::{Array, KeyValue, Value};
use tracing_opentelemetry::OpenTelemetrySpanExt;

pub(crate) struct Inference {
    pub(crate) span: Span,
    started: Instant,
    terminal: bool,
    first_chunk: bool,
    streaming: bool,
    attributes: Vec<KeyValue>,
    duration: opentelemetry::metrics::Histogram<f64>,
    tokens: opentelemetry::metrics::Histogram<u64>,
    first_chunk_time: opentelemetry::metrics::Histogram<f64>,
}

impl Inference {
    pub(crate) fn new(request: &BackendRequest) -> Self {
        let canonical = &request.execution.canonical;
        let operation = match canonical.input {
            Input::Text(_) => "text_completion",
            _ => "chat",
        };
        let streaming = request
            .raw
            .value()
            .get("stream")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let model = &canonical.model.name;
        let span = tracing::info_span!(
            target: "hellas_request",
            "gen_ai.inference",
            otel.name = %format!("{operation} {model}"),
            otel.kind = "client",
            gen_ai.operation.name = operation,
            gen_ai.provider.name = "hellas",
            gen_ai.request.model = %model,
            gen_ai.response.model = tracing::field::Empty,
            gen_ai.response.id = tracing::field::Empty,
            gen_ai.usage.cache_read.input_tokens = tracing::field::Empty,
            gen_ai.request.stream = streaming,
            gen_ai.request.max_tokens = canonical.sampling.max_output_tokens.map(i64::from),
            gen_ai.request.temperature = canonical.sampling.temperature.map(f64::from),
            gen_ai.request.top_p = canonical.sampling.top_p.map(f64::from),
            gen_ai.usage.input_tokens = tracing::field::Empty,
            gen_ai.usage.output_tokens = tracing::field::Empty,
            gen_ai.response.time_to_first_chunk = tracing::field::Empty,
            error.type = tracing::field::Empty,
            otel.status_code = tracing::field::Empty,
        );
        let meter = opentelemetry::global::meter("hellas.gateway.gen_ai");
        let latency_buckets = vec![
            0.01, 0.02, 0.04, 0.08, 0.16, 0.32, 0.64, 1.28, 2.56, 5.12, 10.24, 20.48, 40.96, 81.92,
        ];
        Self {
            span,
            started: Instant::now(),
            terminal: false,
            first_chunk: true,
            streaming,
            attributes: vec![
                KeyValue::new("gen_ai.operation.name", operation),
                KeyValue::new("gen_ai.provider.name", "hellas"),
                KeyValue::new("gen_ai.request.model", model.clone()),
            ],
            duration: meter
                .f64_histogram("gen_ai.client.operation.duration")
                .with_unit("s")
                .with_description("GenAI operation duration.")
                .with_boundaries(latency_buckets.clone())
                .build(),
            tokens: meter
                .u64_histogram("gen_ai.client.token.usage")
                .with_unit("{token}")
                .with_description("Number of input and output tokens used.")
                .with_boundaries(vec![
                    1., 4., 16., 64., 256., 1024., 4096., 16384., 65536., 262144., 1048576.,
                    4194304., 16777216., 67108864.,
                ])
                .build(),
            first_chunk_time: meter
                .f64_histogram("gen_ai.client.operation.time_to_first_chunk")
                .with_unit("s")
                .with_description("Time from the generation request to its first response chunk.")
                .with_boundaries(latency_buckets)
                .build(),
        }
    }

    pub(crate) fn response_model(&mut self, model: &str) {
        self.span.record("gen_ai.response.model", model);
        self.attributes
            .retain(|a| a.key.as_str() != "gen_ai.response.model");
        self.attributes
            .push(KeyValue::new("gen_ai.response.model", model.to_owned()));
    }

    pub(crate) fn stream<S>(
        self,
        stream: S,
    ) -> impl Stream<Item = Result<OutputEvent, BackendError>> + Send
    where
        S: Stream<Item = Result<OutputEvent, BackendError>> + Send + 'static,
    {
        InferenceStream {
            inner: Box::pin(stream),
            inference: self,
        }
    }

    pub(crate) fn fail(&mut self, error: &BackendError) {
        self.finish(Some(match error {
            BackendError::Rejected(_) => "invalid_request",
            BackendError::Failed(_) => "backend_error",
        }));
        self.finish_reason("error");
    }

    fn finish_reason(&self, reason: &'static str) {
        self.span.set_attribute(
            "gen_ai.response.finish_reasons",
            Value::Array(Array::String(vec![reason.into()])),
        );
    }

    fn observe(&mut self, event: &OutputEvent) {
        if self.terminal {
            return;
        }
        if self.first_chunk {
            self.first_chunk = false;
            if self.streaming {
                let seconds = self.started.elapsed().as_secs_f64();
                self.span
                    .record("gen_ai.response.time_to_first_chunk", seconds);
                self.first_chunk_time.record(seconds, &self.attributes);
            }
        }
        match event {
            OutputEvent::Adaptor(hellas_rpc::output::AdaptorEvent::CodexResponses(
                hellas_rpc::output::CodexResponsesEvent::Completed(completed),
            )) => {
                self.span
                    .record("gen_ai.response.id", &completed.response_id);
                if let Some(model) = &completed.server_model {
                    self.response_model(model);
                }
                if let Some(details) = &completed.usage.input_tokens_details {
                    if let Ok(count) = i64::try_from(details.cached_tokens) {
                        self.span
                            .record("gen_ai.usage.cache_read.input_tokens", count);
                    }
                }
            }
            OutputEvent::Finished { stop_reason, usage } => {
                if let Some(usage) = usage {
                    for (attribute, kind, count) in [
                        ("gen_ai.usage.input_tokens", "input", usage.input_tokens),
                        ("gen_ai.usage.output_tokens", "output", usage.output_tokens),
                    ] {
                        if let Some(count) = count {
                            if let Ok(count) = i64::try_from(count) {
                                self.span.record(attribute, count);
                            }
                            {
                                let mut attributes = self.attributes.clone();
                                attributes.push(KeyValue::new("gen_ai.token.type", kind));
                                self.tokens.record(count, &attributes);
                            }
                        }
                    }
                }
                self.finish_reason(match stop_reason {
                    StopReason::EndOfText | StopReason::StopSequence => "stop",
                    StopReason::MaxOutputTokens => "length",
                    StopReason::ToolCall => "tool_calls",
                    StopReason::Cancelled => "error",
                });
                self.finish((*stop_reason == StopReason::Cancelled).then_some("cancelled"));
            }
            OutputEvent::Error { .. } => {
                self.finish_reason("error");
                self.finish(Some("backend_error"));
            }
            _ => {}
        }
    }

    fn finish(&mut self, error: Option<&'static str>) {
        if self.terminal {
            return;
        }
        self.terminal = true;
        if let Some(error) = error {
            self.span.record("error.type", error);
            self.span.record("otel.status_code", "ERROR");
            self.attributes.push(KeyValue::new("error.type", error));
        }
        self.duration
            .record(self.started.elapsed().as_secs_f64(), &self.attributes);
    }
}

impl Drop for Inference {
    fn drop(&mut self) {
        if !self.terminal {
            self.finish_reason("error");
            self.finish(Some("cancelled"));
        }
    }
}

struct InferenceStream<S> {
    inner: Pin<Box<S>>,
    inference: Inference,
}

impl<S> Stream for InferenceStream<S>
where
    S: Stream<Item = Result<OutputEvent, BackendError>>,
{
    type Item = Result<OutputEvent, BackendError>;
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        let span = this.inference.span.clone();
        let _entered = span.enter();
        let next = this.inner.as_mut().poll_next(cx);
        match &next {
            Poll::Ready(Some(Ok(event))) => this.inference.observe(event),
            Poll::Ready(Some(Err(error))) => this.inference.fail(error),
            Poll::Ready(None) if !this.inference.terminal => {
                this.inference.finish_reason("error");
                this.inference.finish(Some("incomplete_response"));
            }
            _ => {}
        }
        next
    }
}
