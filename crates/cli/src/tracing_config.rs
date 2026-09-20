use std::path::Path;
use std::sync::OnceLock;

#[cfg(feature = "otel")]
use opentelemetry::trace::TracerProvider;
#[cfg(feature = "otel")]
use opentelemetry_otlp::{WithExportConfig, WithHttpConfig};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::reload;
use tracing_subscriber::util::SubscriberInitExt;

type FilterHandle = reload::Handle<EnvFilter, tracing_subscriber::Registry>;

static LOG_FILTER: OnceLock<FilterHandle> = OnceLock::new();

fn base_env_filter() -> EnvFilter {
    EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("warn"))
        .add_directive("noq::connection=error".parse().unwrap())
        .add_directive("netlink_packet_route=error".parse().unwrap())
}

/// Holds the OTLP tracer provider (when the `otel` feature is on) so the CLI
/// can flush spans on shutdown. With the feature off this is a zero-sized type
/// and `shutdown()` is a no-op.
pub struct TracerGuard {
    #[cfg(feature = "otel")]
    provider: Option<opentelemetry_sdk::trace::SdkTracerProvider>,
}

impl TracerGuard {
    pub const fn noop() -> Self {
        Self {
            #[cfg(feature = "otel")]
            provider: None,
        }
    }

    pub fn shutdown(self) {
        #[cfg(feature = "otel")]
        if let Some(provider) = self.provider
            && let Err(err) = provider.shutdown()
        {
            eprintln!("warning: failed to flush traces: {err}");
        }
    }
}

/// Initialise the tracing subscriber.
///
/// When the `otel` feature is enabled and `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT`
/// is set (and non-empty), an OpenTelemetry OTLP layer is added that exports
/// traces over HTTP/protobuf. With the feature off, only the fmt + optional
/// file layers are registered.
///
/// Supported environment variables (all standard OTEL, only consulted when
/// `otel` is enabled):
///   OTEL_EXPORTER_OTLP_TRACES_ENDPOINT  — collector URL (e.g. https://collector.example.com/v1/traces)
///   OTEL_SERVICE_NAME                    — service name  (default: hellas-node)
///   OTEL_TRACES_SAMPLER_ARG             — sample rate 0.0–1.0 (default: 1.0)
///   OTEL_EXPORTER_OTLP_HEADERS          — extra headers as k=v,k=v
///                                          (use for CF-Access-Client-Id / CF-Access-Client-Secret)
pub fn init_tracing(log_file: Option<&Path>) -> TracerGuard {
    let (filter_layer, filter_handle) = reload::Layer::new(base_env_filter());
    let _ = LOG_FILTER.set(filter_handle);

    let fmt_layer = tracing_subscriber::fmt::layer().with_writer(std::io::stderr);
    let file_layer = log_file.and_then(|path| {
        // Open append-mode so successive runs accumulate; line-buffered
        // happens naturally per-event because the fmt layer flushes
        // after each record.
        match std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
        {
            Ok(f) => Some(
                tracing_subscriber::fmt::layer()
                    .with_writer(std::sync::Mutex::new(f))
                    .with_ansi(false),
            ),
            Err(err) => {
                eprintln!(
                    "warning: --log-file {} could not be opened: {err}",
                    path.display()
                );
                None
            }
        }
    });

    let registry = tracing_subscriber::registry()
        .with(filter_layer)
        .with(fmt_layer)
        .with(file_layer);

    install_with_otel(registry)
}

/// Suppress known one-shot transport tail logs after CLI execute has already finished.
pub fn suppress_execute_tail_logs() {
    let Some(handle) = LOG_FILTER.get() else {
        return;
    };

    let filter = base_env_filter()
        .add_directive("iroh::socket=off".parse().unwrap())
        .add_directive("noq::connection=off".parse().unwrap())
        .add_directive("noq_proto::connection=off".parse().unwrap())
        .add_directive("acto::tokio=off".parse().unwrap());

    let _ = handle.reload(filter);
}

#[cfg(feature = "otel")]
fn install_with_otel<S>(registry: S) -> TracerGuard
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

    let (otel_layer, provider) = build_otlp_layer::<S>();
    registry.with(otel_layer).init();

    TracerGuard { provider }
}

#[cfg(not(feature = "otel"))]
fn install_with_otel<S>(registry: S) -> TracerGuard
where
    S: tracing::Subscriber + Send + Sync + 'static,
{
    registry.init();
    TracerGuard {}
}

#[cfg(feature = "otel")]
fn build_otlp_layer<S>() -> (
    Option<tracing_opentelemetry::OpenTelemetryLayer<S, opentelemetry_sdk::trace::Tracer>>,
    Option<opentelemetry_sdk::trace::SdkTracerProvider>,
)
where
    S: tracing::Subscriber + for<'span> tracing_subscriber::registry::LookupSpan<'span>,
{
    let endpoint = match std::env::var("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT") {
        Ok(v) if !v.trim().is_empty() => v,
        _ => return (None, None),
    };

    let service_name = std::env::var("OTEL_SERVICE_NAME")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "hellas-node".to_string());

    let sample_rate: f64 = std::env::var("OTEL_TRACES_SAMPLER_ARG")
        .ok()
        .and_then(|s| s.parse().ok())
        .filter(|r: &f64| (0.0..=1.0).contains(r))
        .unwrap_or(1.0);

    let headers: std::collections::HashMap<String, String> =
        std::env::var("OTEL_EXPORTER_OTLP_HEADERS")
            .ok()
            .map(|raw| {
                raw.split(',')
                    .filter_map(|pair| {
                        let (k, v) = pair.split_once('=')?;
                        Some((k.trim().to_string(), v.trim().to_string()))
                    })
                    .collect()
            })
            .unwrap_or_default();

    let mut http = opentelemetry_otlp::SpanExporter::builder()
        .with_http()
        .with_endpoint(&endpoint);

    if !headers.is_empty() {
        http = http.with_headers(headers);
    }

    let exporter = match http.build() {
        Ok(e) => e,
        Err(err) => {
            eprintln!("warning: failed to build OTLP exporter: {err}");
            return (None, None);
        }
    };

    let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .with_sampler(opentelemetry_sdk::trace::Sampler::TraceIdRatioBased(
            sample_rate,
        ))
        .with_resource(
            opentelemetry_sdk::Resource::builder()
                .with_service_name(service_name.clone())
                .build(),
        )
        .build();

    opentelemetry::global::set_tracer_provider(provider.clone());
    let tracer = provider.tracer(service_name.clone());

    eprintln!("otlp: enabled endpoint={endpoint} service={service_name} sample_rate={sample_rate}");

    let layer = tracing_opentelemetry::layer().with_tracer(tracer);
    (Some(layer), Some(provider))
}
