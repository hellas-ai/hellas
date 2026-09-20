use std::path::Path;
use std::sync::OnceLock;

use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::reload;

#[cfg(feature = "otel")]
#[path = "tracing_config/otel.rs"]
mod telemetry;
#[cfg(not(feature = "otel"))]
#[path = "tracing_config/noop.rs"]
mod telemetry;

pub use telemetry::TracerGuard;
use telemetry::install_with_otel;

type FilterHandle = reload::Handle<EnvFilter, tracing_subscriber::Registry>;

static LOG_FILTER: OnceLock<FilterHandle> = OnceLock::new();

fn base_env_filter() -> EnvFilter {
    EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("warn"))
        .add_directive("hellas_request=info".parse().unwrap())
        .add_directive("noq::connection=error".parse().unwrap())
        .add_directive("netlink_packet_route=error".parse().unwrap())
}

/// Initialise the tracing subscriber.
///
/// With `otel`, a nonempty `OTEL_EXPORTER_OTLP_ENDPOINT` enables HTTP/protobuf
/// traces and metrics; signal-specific `OTEL_EXPORTER_OTLP_{TRACES,METRICS}_ENDPOINT`
/// enables only that signal and overrides the base URL. The SDK appends `/v1/traces`
/// or `/v1/metrics` to the base URL and uses signal-specific URLs verbatim.
/// `OTEL_{TRACES,METRICS}_EXPORTER=otlp` also enables that signal with the SDK's
/// default endpoint, while `none` disables it. `OTEL_SDK_DISABLED=true` disables both.
/// No endpoint or explicit exporter means no network telemetry by default.
///
/// The SDK handles common and signal-specific OTLP headers/timeouts,
/// `OTEL_SERVICE_NAME`, `OTEL_RESOURCE_ATTRIBUTES`, `OTEL_TRACES_SAMPLER` and
/// `OTEL_TRACES_SAMPLER_ARG`, and `OTEL_METRIC_EXPORT_INTERVAL`. Log events stay
/// in the local fmt/file sinks; only span metadata is exported as traces.
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
