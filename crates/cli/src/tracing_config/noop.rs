use tracing_subscriber::util::SubscriberInitExt;

/// No telemetry providers are compiled without the `otel` feature.
pub struct TracerGuard;

impl TracerGuard {
    pub fn shutdown(self) {}
}

pub(super) fn install_with_otel<S>(registry: S) -> TracerGuard
where
    S: tracing::Subscriber + Send + Sync + 'static,
{
    registry.init();
    TracerGuard
}
