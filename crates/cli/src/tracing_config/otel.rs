use opentelemetry::trace::TracerProvider;
use tracing_subscriber::Layer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

/// Flushes the optional OTLP trace provider on shutdown.
pub struct TracerGuard {
    provider: Option<opentelemetry_sdk::trace::SdkTracerProvider>,
}

impl TracerGuard {
    pub fn shutdown(self) {
        if let Some(provider) = self.provider
            && let Err(err) = provider.shutdown()
        {
            eprintln!("warning: failed to flush traces: {err}");
        }
    }
}

pub(super) fn install_with_otel<S>(registry: S) -> TracerGuard
where
    S: tracing::Subscriber
        + Send
        + Sync
        + 'static
        + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    // Register W3C TraceContext propagator so trace IDs flow across RPC calls.
    opentelemetry::global::set_text_map_propagator(
        opentelemetry_sdk::propagation::TraceContextPropagator::new(),
    );

    let (otel_layer, provider) = build_otlp_layer::<S>(super::otlp_resource());
    registry.with(otel_layer).init();

    TracerGuard { provider }
}

fn build_otlp_layer<S>(
    resource: opentelemetry_sdk::Resource,
) -> (
    Option<impl Layer<S>>,
    Option<opentelemetry_sdk::trace::SdkTracerProvider>,
)
where
    S: tracing::Subscriber + for<'span> tracing_subscriber::registry::LookupSpan<'span>,
{
    if !otlp_signal_enabled("TRACES") {
        return (None, None);
    }

    let exporter = match opentelemetry_otlp::SpanExporter::builder()
        .with_http()
        .build()
    {
        Ok(e) => e,
        Err(_) => {
            // Exporter errors can contain configured URLs or header values.
            eprintln!("warning: failed to build OTLP trace exporter; check OTEL configuration");
            return (None, None);
        }
    };

    let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .with_resource(resource)
        .build();

    opentelemetry::global::set_tracer_provider(provider.clone());
    let tracer = provider.tracer(env!("CARGO_PKG_NAME"));

    // Request traces contain span metadata only. Log events can carry provider
    // errors or user content and stay in the independently configured log sink.
    let layer = tracing_opentelemetry::layer()
        .with_tracer(tracer)
        .with_filter(tracing_subscriber::filter::filter_fn(|metadata| {
            metadata.is_span()
                && (metadata.target() == "hellas_request"
                    || metadata.fields().field("otel.kind").is_some())
        }));
    (Some(layer), Some(provider))
}

pub(super) fn otlp_signal_enabled(signal: &str) -> bool {
    if std::env::var("OTEL_SDK_DISABLED").is_ok_and(|v| v.eq_ignore_ascii_case("true")) {
        return false;
    }
    let exporter = std::env::var(format!("OTEL_{signal}_EXPORTER")).ok();
    let has_endpoint = [
        "OTEL_EXPORTER_OTLP_ENDPOINT".to_string(),
        format!("OTEL_EXPORTER_OTLP_{signal}_ENDPOINT"),
    ]
    .iter()
    .any(|key| std::env::var(key).is_ok_and(|v| !v.trim().is_empty()));
    otlp_exporter_enabled(exporter.as_deref(), has_endpoint)
}

fn otlp_exporter_enabled(exporter: Option<&str>, has_endpoint: bool) -> bool {
    match exporter.map(str::trim).filter(|s| !s.is_empty()) {
        Some("otlp") => true,
        Some("none") => false,
        Some(_) => {
            eprintln!("warning: unsupported OTEL exporter; use otlp or none");
            false
        }
        None => has_endpoint,
    }
}

#[cfg(test)]
mod tests {
    use super::otlp_exporter_enabled;

    #[test]
    fn signal_export_selection_respects_opt_out_and_endpoint_defaults() {
        assert!(!otlp_exporter_enabled(None, false));
        assert!(otlp_exporter_enabled(None, true));
        assert!(otlp_exporter_enabled(Some(""), true));
        assert!(otlp_exporter_enabled(Some("otlp"), false));
        assert!(!otlp_exporter_enabled(Some("none"), true));
        assert!(!otlp_exporter_enabled(Some("unsupported"), true));
    }
}
