use prometheus::TextEncoder;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::info;

/// The OpenTelemetry pull registry and optional node endpoint.
#[derive(Default)]
pub struct MetricsBundle {
    pub registry: prometheus::Registry,
    #[cfg(feature = "otel")]
    iroh: Option<tokio::sync::watch::Receiver<Option<iroh::Endpoint>>>,
}

impl MetricsBundle {
    #[cfg(feature = "otel")]
    pub fn with_iroh(mut self, iroh: tokio::sync::watch::Receiver<Option<iroh::Endpoint>>) -> Self {
        self.iroh = Some(iroh);
        self
    }
}

pub async fn spawn_metrics_server(
    address: SocketAddr,
    bundle: MetricsBundle,
) -> std::io::Result<()> {
    let listener = tokio::net::TcpListener::bind(address).await?;
    let addr = listener.local_addr()?;
    let app = axum::Router::new()
        .route("/metrics", axum::routing::get(scrape))
        .with_state(Arc::new(bundle));
    info!("prometheus metrics server listening on http://{addr}/metrics");
    tokio::spawn(async move {
        if let Err(err) = axum::serve(listener, app).await {
            eprintln!("warning: metrics server failed: {err}");
        }
    });
    Ok(())
}

async fn scrape(
    axum::extract::State(bundle): axum::extract::State<Arc<MetricsBundle>>,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    // Pull readers also run observable callbacks; keep that synchronous work
    // off the async executor.
    match tokio::task::spawn_blocking(move || encode_metrics(&bundle)).await {
        Ok(Ok(body)) => (
            [(
                axum::http::header::CONTENT_TYPE,
                "text/plain; version=0.0.4; charset=utf-8",
            )],
            body,
        )
            .into_response(),
        _ => (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "failed to encode metrics",
        )
            .into_response(),
    }
}

fn encode_metrics(bundle: &MetricsBundle) -> anyhow::Result<String> {
    let mut buf = TextEncoder::new().encode_to_string(&bundle.registry.gather())?;
    append_iroh_metrics(&mut buf, bundle)?;
    Ok(buf)
}

#[cfg(feature = "otel")]
fn append_iroh_metrics(buf: &mut String, bundle: &MetricsBundle) -> std::fmt::Result {
    let Some(iroh) = bundle.iroh.as_ref() else {
        return Ok(());
    };
    let mut registry = iroh_metrics::Registry::default();
    if let Some(endpoint) = iroh.borrow().as_ref() {
        registry.register_all_prefixed(endpoint.metrics());
    }
    let mut encoded = String::new();
    registry.encode_openmetrics_to_writer(&mut encoded)?;
    // OpenMetrics counter metadata omits _total; Prometheus text metadata
    // names the sample including that suffix. The remaining iroh types share
    // the same text representation.
    let counters: std::collections::HashSet<_> = encoded
        .lines()
        .filter_map(|line| line.strip_prefix("# TYPE ")?.strip_suffix(" counter"))
        .filter(|name| !name.ends_with("_total"))
        .collect();
    for line in encoded.lines() {
        if let Some((kind, rest)) = line
            .strip_prefix("# ")
            .and_then(|line| line.split_once(' '))
            && matches!(kind, "HELP" | "TYPE")
            && let Some((name, value)) = rest.split_once(' ')
            && counters.contains(name)
        {
            use std::fmt::Write;
            writeln!(buf, "# {kind} {name}_total {value}")?;
        } else {
            buf.push_str(line);
            buf.push('\n');
        }
    }
    Ok(())
}

#[cfg(not(feature = "otel"))]
fn append_iroh_metrics(_buf: &mut String, _bundle: &MetricsBundle) -> std::fmt::Result {
    Ok(())
}
