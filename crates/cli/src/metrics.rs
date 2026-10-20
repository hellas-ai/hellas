use prometheus_client::encoding::text::encode;
use prometheus_client::registry::Registry;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::info;

/// Bundle of metric sources served by the prometheus HTTP endpoint.
///
/// The `prometheus` registry is the workspace's primary metrics surface
/// (executor counters, gateway counters, etc.). When the `otel` feature is on,
/// iroh's internal `EndpointMetrics` are appended to the same response.
pub struct MetricsBundle {
    pub prometheus: Arc<Registry>,
    #[cfg(feature = "otel")]
    pub iroh: Option<tokio::sync::watch::Receiver<Option<iroh::Endpoint>>>,
}

impl MetricsBundle {
    pub fn new(prometheus: Arc<Registry>) -> Self {
        Self {
            prometheus,
            #[cfg(feature = "otel")]
            iroh: None,
        }
    }

    /// Attach iroh's `EndpointMetrics` so they are emitted alongside the
    /// prometheus-client registry.
    #[cfg(feature = "otel")]
    pub fn with_iroh(mut self, iroh: tokio::sync::watch::Receiver<Option<iroh::Endpoint>>) -> Self {
        self.iroh = Some(iroh);
        self
    }
}

pub fn spawn_metrics_server(port: u16, bundle: MetricsBundle) {
    // Metrics carry provider activity and have no authentication. Keep the
    // default surface local; operators can publish it through their monitored
    // host rather than silently exposing it on every network interface.
    let addr = metrics_address(port);
    let bundle = Arc::new(bundle);

    tokio::spawn(async move {
        let listener = match tokio::net::TcpListener::bind(addr).await {
            Ok(l) => l,
            Err(err) => {
                eprintln!("warning: failed to bind metrics server on {addr}: {err}");
                return;
            }
        };

        let app = axum::Router::new()
            .route(
                "/metrics",
                axum::routing::get(
                    move |axum::extract::State(bundle): axum::extract::State<
                        Arc<MetricsBundle>,
                    >| async move {
                        encode_metrics(&bundle)
                            .map(|buf| (axum::http::StatusCode::OK, buf))
                            .unwrap_or((
                                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                                "failed to encode metrics".to_string(),
                            ))
                    },
                ),
            )
            .with_state(bundle);

        info!("prometheus metrics server listening on http://{addr}/metrics");

        if let Err(err) = axum::serve(listener, app).await {
            eprintln!("warning: metrics server failed: {err}");
        }
    });
}

fn metrics_address(port: u16) -> SocketAddr {
    ([127, 0, 0, 1], port).into()
}

fn encode_metrics(bundle: &MetricsBundle) -> Result<String, std::fmt::Error> {
    let mut buf = String::new();
    encode(&mut buf, &bundle.prometheus)?;
    // prometheus-client's `encode` terminates with `# EOF\n`; we strip it so
    // we can append iroh metrics in the same response. A single `# EOF\n` is
    // re-added at the end below.
    if let Some(pos) = buf.rfind("# EOF\n") {
        buf.truncate(pos);
    }
    append_iroh_metrics(&mut buf, bundle);
    if !buf.ends_with("# EOF\n") {
        buf.push_str("# EOF\n");
    }
    Ok(buf)
}

#[cfg(feature = "otel")]
fn append_iroh_metrics(buf: &mut String, bundle: &MetricsBundle) {
    use iroh_metrics::Registry as IrohRegistry;

    let Some(iroh) = bundle.iroh.as_ref() else {
        return;
    };

    let mut reg = IrohRegistry::default();
    if let Some(endpoint) = iroh.borrow().as_ref() {
        reg.register_all_prefixed(endpoint.metrics());
    }
    let _ = reg.encode_openmetrics_to_writer(buf);
}

#[cfg(not(feature = "otel"))]
fn append_iroh_metrics(_buf: &mut String, _bundle: &MetricsBundle) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unauthenticated_metrics_bind_only_to_loopback() {
        let address = metrics_address(9400);
        assert!(address.ip().is_loopback());
        assert_eq!(address.port(), 9400);
    }
}
