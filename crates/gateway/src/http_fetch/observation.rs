use serde_json::Value;
use std::{io::Write, time::Instant};

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
    compressed_usage: Option<flate2::write::GzDecoder<Usage>>,
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
            usage: Usage::default(),
            compressed_usage: None,
            #[cfg(feature = "otel")]
            backend: None,
            #[cfg(feature = "otel")]
            model: None,
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
    pub(super) fn backend(&mut self, name: &str, affinity: &'static str) {
        self.span.record("hellas.backend", name);
        self.span.record("hellas.routing.affinity", affinity);
        #[cfg(feature = "otel")]
        {
            self.backend = Some(name.into());
        }
    }
    pub(super) fn bind_response(&mut self, binding: Option<super::routing::ResponseBinding>) {
        self.usage.binding = binding;
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
        self.usage.sse =
            value.is_some_and(|value| value.split(';').next() == Some("text/event-stream"));
        match encoding.map(str::trim) {
            None | Some("") => {}
            Some(value) if value.eq_ignore_ascii_case("identity") => {}
            Some(value) if value.eq_ignore_ascii_case("gzip") => {
                self.compressed_usage = Some(flate2::write::GzDecoder::new(std::mem::take(
                    &mut self.usage,
                )));
            }
            Some(_) => self.usage.overflow = true,
        }
    }
    pub(super) fn chunk(&mut self, bytes: &[u8]) {
        if self.first_byte.is_none() {
            self.first_byte = Some(self.started.elapsed().as_secs_f64());
        }
        self.bytes += bytes.len() as u64;
        if let Some(decoder) = self.compressed_usage.as_mut() {
            if decoder.write_all(bytes).is_err() {
                self.compressed_usage = None;
                self.usage.overflow = true;
            }
        } else {
            self.usage.push(bytes);
        }
    }
    pub(super) fn complete(&mut self) {
        if let Some(decoder) = self.compressed_usage.take() {
            self.usage = decoder.finish().unwrap_or_else(|_| Usage {
                overflow: true,
                ..Default::default()
            });
        }
        self.usage.finish();
        self.complete = true;
    }
}

impl Drop for Observation {
    fn drop(&mut self) {
        let usage = self
            .compressed_usage
            .as_ref()
            .map(|decoder| decoder.get_ref())
            .unwrap_or(&self.usage);
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

/// Observe standard usage fields without reserializing or delaying the wire body.
#[derive(Default)]
struct Usage {
    binding: Option<super::routing::ResponseBinding>,
    sse: bool,
    pending: Vec<u8>,
    input: Option<u64>,
    output: Option<u64>,
    cached: Option<u64>,
    cache_write: Option<u64>,
    overflow: bool,
    decoded_bytes: usize,
}

impl std::io::Write for Usage {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        // Observation must not allow compressed data to consume unbounded CPU
        // or memory. Stopping this sink never changes the response sent onward.
        self.decoded_bytes = self.decoded_bytes.saturating_add(bytes.len());
        if self.overflow || self.decoded_bytes > 32 * 1024 * 1024 {
            return Err(std::io::Error::other("usage observation limit"));
        }
        self.push(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Usage {
    fn push(&mut self, bytes: &[u8]) {
        if self.overflow {
            return;
        }
        self.pending.extend_from_slice(bytes);
        // Some Responses endpoints omit Content-Type. Detect their SSE prelude
        // after enough bytes have arrived, without changing the forwarded body.
        self.sse |= self.pending.starts_with(b"event:")
            || self.pending.starts_with(b"data:")
            || self.pending.starts_with(b":");
        while self.sse
            && let Some(end) = self.pending.iter().position(|byte| *byte == b'\n')
        {
            let line: Vec<_> = self.pending.drain(..=end).collect();
            if let Some(data) = line.strip_prefix(b"data:") {
                self.parse(data);
            }
        }
        if self.pending.len() > 512 * 1024 {
            *self = Self {
                overflow: true,
                ..Default::default()
            };
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
        if let Some(binding) = &self.binding {
            binding.observe(&value);
        }
        let Some(usage) = value
            .get("usage")
            .or_else(|| value.pointer("/message/usage"))
            .or_else(|| value.pointer("/response/usage"))
        else {
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
                .or_else(|| usage.pointer("/input_tokens_details/cached_tokens"))
                .and_then(Value::as_u64),
        );
        update(
            &mut self.cache_write,
            usage
                .get("cache_creation_input_tokens")
                .or_else(|| usage.pointer("/input_tokens_details/cache_write_tokens"))
                .or_else(|| usage.pointer("/prompt_tokens_details/cache_write_tokens"))
                .and_then(Value::as_u64),
        );
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
