use serde_json::Value;
use std::time::Instant;

pub(super) struct Metrics {
    #[cfg(feature = "otel")]
    requests: opentelemetry::metrics::Counter<u64>,
    #[cfg(feature = "otel")]
    duration: opentelemetry::metrics::Histogram<f64>,
    #[cfg(feature = "otel")]
    first_byte: opentelemetry::metrics::Histogram<f64>,
    #[cfg(feature = "otel")]
    tokens: opentelemetry::metrics::Counter<u64>,
}

impl Metrics {
    pub(super) fn new() -> Self {
        #[cfg(feature = "otel")]
        let meter = opentelemetry::global::meter("hellas.gateway.http_fetch");
        Self {
            #[cfg(feature = "otel")]
            requests: meter.u64_counter("hellas.gateway.http.requests").build(),
            #[cfg(feature = "otel")]
            duration: meter
                .f64_histogram("hellas.gateway.http.duration")
                .with_unit("s")
                .with_boundaries(vec![
                    0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1., 2., 4., 8., 16., 32., 64.,
                    128., 300.,
                ])
                .build(),
            #[cfg(feature = "otel")]
            first_byte: meter
                .f64_histogram("hellas.gateway.http.time_to_first_byte")
                .with_unit("s")
                .with_boundaries(vec![
                    0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1., 2., 4., 8., 16., 32., 64.,
                ])
                .build(),
            #[cfg(feature = "otel")]
            tokens: meter
                .u64_counter("hellas.gateway.http.tokens")
                .with_unit("{token}")
                .build(),
        }
    }
}

pub(super) struct Observation {
    pub(super) span: tracing::Span,
    started: Instant,
    complete: bool,
    status: u16,
    bytes: u64,
    first_byte: Option<f64>,
    usage: Usage,
    #[cfg(feature = "otel")]
    route: String,
    #[cfg(feature = "otel")]
    metrics: Metrics,
}

impl Observation {
    pub(super) fn new(metrics: &Metrics, route: &str) -> Self {
        #[cfg(not(feature = "otel"))]
        let _ = (metrics, route);
        Self {
            span: hellas_rpc::request_span!(target: "hellas_request", "http.fetch",
                otel.kind = "client", http.route = route,
                http.response.status_code = tracing::field::Empty,
                http.response.body.size = tracing::field::Empty,
                gen_ai.usage.input_tokens = tracing::field::Empty,
                gen_ai.usage.output_tokens = tracing::field::Empty,
                gen_ai.usage.cache_read.input_tokens = tracing::field::Empty,
                hellas.response.time_to_first_byte = tracing::field::Empty,
                hellas.response.complete = tracing::field::Empty,
                error.type = tracing::field::Empty, otel.status_code = tracing::field::Empty),
            started: Instant::now(),
            complete: false,
            status: 0,
            bytes: 0,
            first_byte: None,
            usage: Usage::default(),
            #[cfg(feature = "otel")]
            route: route.into(),
            #[cfg(feature = "otel")]
            metrics: Metrics {
                requests: metrics.requests.clone(),
                duration: metrics.duration.clone(),
                first_byte: metrics.first_byte.clone(),
                tokens: metrics.tokens.clone(),
            },
        }
    }
    pub(super) fn status(&mut self, status: u16) {
        self.status = status;
        self.span.record("http.response.status_code", status);
    }
    pub(super) fn content_type(&mut self, value: Option<&str>) {
        self.usage.sse =
            value.is_some_and(|value| value.split(';').next() == Some("text/event-stream"));
    }
    pub(super) fn chunk(&mut self, bytes: &[u8]) {
        if self.first_byte.is_none() {
            self.first_byte = Some(self.started.elapsed().as_secs_f64());
        }
        self.bytes += bytes.len() as u64;
        self.usage.push(bytes);
    }
    pub(super) fn complete(&mut self) {
        self.usage.finish();
        self.complete = true;
    }
}

impl Drop for Observation {
    fn drop(&mut self) {
        self.span.record("http.response.body.size", self.bytes);
        self.span.record("hellas.response.complete", self.complete);
        if let Some(ttfb) = self.first_byte {
            self.span.record("hellas.response.time_to_first_byte", ttfb);
        }
        for (field, value) in [
            ("gen_ai.usage.input_tokens", self.usage.input),
            ("gen_ai.usage.output_tokens", self.usage.output),
            ("gen_ai.usage.cache_read.input_tokens", self.usage.cached),
        ] {
            if let Some(value) = value {
                self.span.record(field, value);
            }
        }
        if !self.complete || self.status >= 400 {
            self.span.record("otel.status_code", "ERROR");
            self.span.record(
                "error.type",
                if self.status == 429 {
                    "rate_limited"
                } else if !self.complete {
                    "incomplete"
                } else {
                    "http_error"
                },
            );
        }
        #[cfg(feature = "otel")]
        {
            use opentelemetry::KeyValue;
            let labels = [
                KeyValue::new("http.route", self.route.clone()),
                KeyValue::new("http.response.status_code", i64::from(self.status)),
                KeyValue::new("hellas.response.complete", self.complete),
            ];
            self.metrics.requests.add(1, &labels);
            self.metrics
                .duration
                .record(self.started.elapsed().as_secs_f64(), &labels);
            if let Some(ttfb) = self.first_byte {
                self.metrics.first_byte.record(ttfb, &labels);
            }
            for (kind, value) in [
                ("input", self.usage.input),
                ("output", self.usage.output),
                ("cache_read", self.usage.cached),
            ] {
                if let Some(value) = value {
                    let mut labels = labels.to_vec();
                    labels.push(KeyValue::new("gen_ai.token.type", kind));
                    self.metrics.tokens.add(value, &labels);
                }
            }
        }
    }
}

/// Observe standard usage fields without reserializing or delaying the wire body.
#[derive(Default)]
struct Usage {
    sse: bool,
    pending: Vec<u8>,
    input: Option<u64>,
    output: Option<u64>,
    cached: Option<u64>,
    overflow: bool,
}

impl Usage {
    fn push(&mut self, bytes: &[u8]) {
        if self.overflow {
            return;
        }
        self.pending.extend_from_slice(bytes);
        if !self.sse {
            return;
        }
        while let Some(end) = self.pending.iter().position(|byte| *byte == b'\n') {
            let line: Vec<_> = self.pending.drain(..=end).collect();
            if let Some(data) = line.strip_prefix(b"data:") {
                self.parse(data);
            }
        }
        if self.pending.len() > 512 * 1024 {
            self.pending.clear();
            self.overflow = true;
        }
    }
    fn finish(&mut self) {
        let pending = std::mem::take(&mut self.pending);
        self.parse(pending.strip_prefix(b"data:").unwrap_or(&pending));
    }
    fn parse(&mut self, bytes: &[u8]) {
        let Ok(value) = serde_json::from_slice::<Value>(bytes) else {
            return;
        };
        let Some(usage) = value.get("usage").or_else(|| {
            value
                .get("message")
                .and_then(|message| message.get("usage"))
        }) else {
            return;
        };
        fn update(target: &mut Option<u64>, value: Option<u64>) {
            if let Some(value) = value {
                *target = Some(target.unwrap_or_default().max(value));
            }
        }
        update(
            &mut self.input,
            usage
                .get("prompt_tokens")
                .or_else(|| usage.get("input_tokens"))
                .and_then(Value::as_u64),
        );
        update(
            &mut self.output,
            usage
                .get("completion_tokens")
                .or_else(|| usage.get("output_tokens"))
                .and_then(Value::as_u64),
        );
        update(
            &mut self.cached,
            usage
                .get("cache_read_input_tokens")
                .or_else(|| usage.pointer("/prompt_tokens_details/cached_tokens"))
                .and_then(Value::as_u64),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usage_survives_arbitrary_sse_boundaries_and_cumulative_updates() {
        let wire = b"event: message_start\r\ndata: {\"message\":{\"usage\":{\"input_tokens\":11,\"output_tokens\":1,\"cache_read_input_tokens\":7}}}\r\n\r\ndata: {\"usage\":{\"output_tokens\":5}}\n\ndata: {\"usage\":{\"output_tokens\":5}}\n\ndata: [DONE]\n\n";
        for size in 1..=wire.len() {
            let mut usage = Usage {
                sse: true,
                ..Default::default()
            };
            for chunk in wire.chunks(size) {
                usage.push(chunk);
            }
            usage.finish();
            assert_eq!(
                (usage.input, usage.output, usage.cached),
                (Some(11), Some(5), Some(7))
            );
        }
    }

    #[test]
    fn nonstreaming_usage_and_absent_usage_remain_distinct() {
        let mut usage = Usage::default();
        usage.push(b"{\n\"usage\":{\"prompt_tokens\":12,\"completion_tokens\":3,\"prompt_tokens_details\":{\"cached_tokens\":8}}\n}");
        usage.finish();
        assert_eq!(
            (usage.input, usage.output, usage.cached),
            (Some(12), Some(3), Some(8))
        );
        let mut absent = Usage::default();
        absent.push(b"{\"error\":\"private message\"}");
        absent.finish();
        assert_eq!(absent.input, None);
    }
}
