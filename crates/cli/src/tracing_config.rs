use std::io::IsTerminal as _;
use std::path::Path;
use std::sync::OnceLock;

use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt::format::{FormatEvent, FormatFields, Writer};
use tracing_subscriber::fmt::time::FormatTime as _;
use tracing_subscriber::fmt::{FmtContext, time};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::registry::LookupSpan;
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
    with_default_directives(
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn")),
    )
}

fn with_default_directives(filter: EnvFilter) -> EnvFilter {
    filter
        .add_directive("hellas_request=info".parse().unwrap())
        .add_directive("noq::connection=error".parse().unwrap())
        .add_directive("netlink_packet_route=error".parse().unwrap())
        .add_directive("iroh::net_report=error".parse().unwrap())
        .add_directive("iroh::address_lookup=error".parse().unwrap())
}

/// Local logs contain event fields; request span attributes belong to traces.
/// The built-in compact formatter also appends ancestor span fields.
struct EventOnly;

impl<S, N> FormatEvent<S, N> for EventOnly
where
    S: tracing::Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        ctx: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &tracing::Event<'_>,
    ) -> std::fmt::Result {
        time::SystemTime.format_time(&mut writer)?;
        let metadata = event.metadata();
        write!(writer, " {} {}: ", metadata.level(), metadata.target())?;
        ctx.field_format().format_fields(writer.by_ref(), event)?;
        writeln!(writer)
    }
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

    let fmt_layer = tracing_subscriber::fmt::layer()
        .event_format(EventOnly)
        .with_ansi(std::io::stderr().is_terminal())
        .with_writer(std::io::stderr);
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
                    .event_format(EventOnly)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn journal_keeps_event_fields_and_transport_errors_without_span_or_warning_noise() {
        let output = tempfile::NamedTempFile::new().unwrap();
        let subscriber = tracing_subscriber::registry()
            .with(with_default_directives(EnvFilter::new("warn")))
            .with(
                tracing_subscriber::fmt::layer()
                    .event_format(EventOnly)
                    .with_ansi(false)
                    .with_writer(output.reopen().unwrap()),
            );
        tracing::subscriber::with_default(subscriber, || {
            let _request = tracing::info_span!(
                target: "hellas_request", "http.server",
                otel.kind = "server", http.route = "/v1/chat/completions",
            )
            .entered();
            let _payment = tracing::info_span!(
                target: "hellas_request", "paid.gateway",
                hellas.provider.id = "provider-span-only",
            )
            .entered();
            tracing::info!(target: "hellas_request", credited_cumulative = 17, "paid completion");
            tracing::warn!(target: "iroh::net_report::report", "routine address warning");
            tracing::warn!(target: "iroh::address_lookup::pkarr", "routine discovery warning");
            tracing::error!(target: "iroh::net_report::report", "report failed");
            tracing::error!(target: "iroh::address_lookup::pkarr", "lookup failed");
        });
        let output = std::fs::read_to_string(output.path()).unwrap();
        assert_eq!(output.lines().count(), 3, "{output}");
        assert!(output.contains("paid completion credited_cumulative=17"));
        assert!(output.contains("ERROR iroh::net_report::report: report failed"));
        assert!(output.contains("ERROR iroh::address_lookup::pkarr: lookup failed"));
        for absent in [
            "otel.kind",
            "http.route",
            "paid.gateway",
            "provider-span-only",
            "routine",
        ] {
            assert!(!output.contains(absent), "{output}");
        }
    }
}
