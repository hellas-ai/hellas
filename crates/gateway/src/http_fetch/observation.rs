use hellas_rpc::http_usage::UsageDecoder;
use std::time::Instant;
#[cfg(test)]
use {hellas_rpc::http_usage::Usage, std::io::Write};

#[derive(Clone)]
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
    usage: UsageDecoder,
    #[cfg(feature = "otel")]
    backend: Option<String>,
    #[cfg(feature = "otel")]
    model: Option<String>,
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
                hellas.backend = tracing::field::Empty,
                gen_ai.request.model = tracing::field::Empty,
                hellas.routing.affinity = tracing::field::Empty,
                http.response.status_code = tracing::field::Empty,
                http.response.body.size = tracing::field::Empty,
                gen_ai.usage.input_tokens = tracing::field::Empty,
                gen_ai.usage.output_tokens = tracing::field::Empty,
                gen_ai.usage.cache_read.input_tokens = tracing::field::Empty,
                gen_ai.usage.cache_creation.input_tokens = tracing::field::Empty,
                hellas.response.time_to_first_byte = tracing::field::Empty,
                hellas.response.complete = tracing::field::Empty,
                error.type = tracing::field::Empty, otel.status_code = tracing::field::Empty),
            started: Instant::now(),
            complete: false,
            status: 0,
            bytes: 0,
            first_byte: None,
            usage: UsageDecoder::default(),
            #[cfg(feature = "otel")]
            backend: None,
            #[cfg(feature = "otel")]
            model: None,
            #[cfg(feature = "otel")]
            route: route.into(),
            #[cfg(feature = "otel")]
            metrics: metrics.clone(),
        }
    }
    pub(super) fn backend(&mut self, name: &str, affinity: &'static str) {
        self.span.record("hellas.backend", name);
        self.span.record("hellas.routing.affinity", affinity);
        #[cfg(feature = "otel")]
        {
            self.backend = Some(name.into());
        }
    }
    pub(super) fn bind_response(&mut self, binding: Option<super::routing::ResponseBinding>) {
        self.usage.observe(binding.map(|binding| {
            std::sync::Arc::new(move |value: &serde_json::Value| binding.observe(value)) as _
        }));
    }
    pub(super) fn model(&mut self, model: Option<&str>) {
        if let Some(model) = model {
            self.span.record("gen_ai.request.model", model);
            #[cfg(feature = "otel")]
            {
                self.model = Some(model.into());
            }
        }
    }
    pub(super) fn status(&mut self, status: u16) {
        self.status = status;
        self.span.record("http.response.status_code", status);
    }
    pub(super) fn content(&mut self, value: Option<&str>, encoding: Option<&str>) {
        self.usage.content(value, encoding);
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
        let usage = &self.usage;
        self.span.record("http.response.body.size", self.bytes);
        self.span.record("hellas.response.complete", self.complete);
        if let Some(ttfb) = self.first_byte {
            self.span.record("hellas.response.time_to_first_byte", ttfb);
        }
        for (field, value) in [
            ("gen_ai.usage.input_tokens", usage.input),
            ("gen_ai.usage.output_tokens", usage.output),
            ("gen_ai.usage.cache_read.input_tokens", usage.cached),
            (
                "gen_ai.usage.cache_creation.input_tokens",
                usage.cache_write,
            ),
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
            let mut labels = vec![
                KeyValue::new("http.route", self.route.clone()),
                KeyValue::new("http.response.status_code", i64::from(self.status)),
                KeyValue::new("hellas.response.complete", self.complete),
            ];
            if let Some(backend) = &self.backend {
                labels.push(KeyValue::new("hellas.backend", backend.clone()));
            }
            if let Some(model) = &self.model {
                labels.push(KeyValue::new("gen_ai.request.model", model.clone()));
            }
            self.metrics.requests.add(1, &labels);
            self.metrics
                .duration
                .record(self.started.elapsed().as_secs_f64(), &labels);
            if let Some(ttfb) = self.first_byte {
                self.metrics.first_byte.record(ttfb, &labels);
            }
            for (kind, value) in [
                ("input", usage.input),
                ("output", usage.output),
                ("cache_read", usage.cached),
                ("cache_write", usage.cache_write),
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

#[cfg(test)]
mod tests {
    use super::*;

    fn gzip(bytes: &[u8]) -> Vec<u8> {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(bytes).unwrap();
        encoder.finish().unwrap()
    }

    #[test]
    fn compressed_usage_survives_fragmentation_without_changing_wire_accounting() {
        let wire = gzip(b"event: message_start\ndata: {\"message\":{\"usage\":{\"input_tokens\":2,\"cache_creation_input_tokens\":400,\"cache_read_input_tokens\":1244}}}\n\ndata: {\"usage\":{\"output_tokens\":99}}\n\n");
        for size in 1..=wire.len() {
            let mut observed = Observation::new(&Metrics::new(), "/v1/messages");
            observed.content(Some("text/event-stream; charset=utf-8"), Some("gzip"));
            for chunk in wire.chunks(size) {
                observed.chunk(chunk);
            }
            observed.complete();
            assert!(observed.complete);
            assert_eq!(observed.bytes, wire.len() as u64);
            assert_eq!(
                (
                    observed.usage.input,
                    observed.usage.output,
                    observed.usage.cached,
                    observed.usage.cache_write
                ),
                (Some(2), Some(99), Some(1244), Some(400))
            );
        }
    }

    #[test]
    fn bad_or_unsupported_compression_leaves_usage_unknown() {
        let wire = gzip(b"{\"usage\":{\"input_tokens\":10,\"output_tokens\":5}}");
        let mut corrupt = wire.clone();
        let crc = corrupt.len() - 8;
        corrupt[crc] ^= 1;
        for (bytes, encoding) in [
            (&wire[..wire.len() - 4], "gzip"),
            (corrupt.as_slice(), "gzip"),
            (wire.as_slice(), "br"),
        ] {
            let mut observed = Observation::new(&Metrics::new(), "/v1/responses");
            observed.content(Some("application/json"), Some(encoding));
            observed.chunk(bytes);
            observed.complete();
            assert!(observed.complete);
            assert_eq!(observed.bytes, bytes.len() as u64);
            assert_eq!((observed.usage.input, observed.usage.output), (None, None));
        }
    }

    #[test]
    fn compressed_observation_stops_at_its_budget() {
        let data = b": ping\n\n".repeat(32 * 1024 * 1024 / 8 + 1);
        let wire = gzip(&data);
        let mut observed = Observation::new(&Metrics::new(), "/v1/messages");
        observed.content(Some("text/event-stream"), Some("gzip"));
        observed.chunk(&wire);
        observed.complete();
        assert!(observed.usage.overflow);
        assert_eq!(observed.bytes, wire.len() as u64);
        assert_eq!(observed.usage.input, None);
    }

    #[test]
    fn usage_survives_arbitrary_sse_boundaries_and_cumulative_updates() {
        let wire = b"event: message_start\r\ndata: {\"message\":{\"usage\":{\"input_tokens\":11,\"output_tokens\":1,\"cache_read_input_tokens\":7,\"cache_creation_input_tokens\":13}}}\r\n\r\ndata: {\"usage\":{\"output_tokens\":5}}\n\ndata: {\"usage\":{\"output_tokens\":5}}\n\ndata: [DONE]\n\n";
        for size in 1..=wire.len() {
            let mut usage = Usage::default();
            usage.sse = true;
            for chunk in wire.chunks(size) {
                usage.push(chunk);
            }
            usage.finish();
            assert_eq!(
                (usage.input, usage.output, usage.cached),
                (Some(11), Some(5), Some(7))
            );
            assert_eq!(usage.cache_write, Some(13));
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

    #[test]
    fn responses_completed_usage_survives_fragmented_delivery() {
        let wire = b"event: response.completed\ndata: {\"response\":{\"usage\":{\"input_tokens\":12,\"output_tokens\":3,\"input_tokens_details\":{\"cached_tokens\":8,\"cache_write_tokens\":2}}}}\n\n";
        for size in 1..=wire.len() {
            // Live subscription Responses can omit Content-Type entirely.
            let mut usage = Usage::default();
            for chunk in wire.chunks(size) {
                usage.push(chunk);
            }
            usage.finish();
            assert_eq!(
                (usage.input, usage.output, usage.cached),
                (Some(12), Some(3), Some(8))
            );
            assert_eq!(usage.cache_write, Some(2));
        }
    }
}
