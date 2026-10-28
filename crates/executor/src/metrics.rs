//! Live executor counters.
//!
//! Counters are mutated inline at the event source (start/complete/fail),
//! so there is no polling step that copies internal state into a separate
//! prometheus registry. Detached metrics can be created with
//! [`ExecutorMetrics::default`] for tests and non-server callers.

use prometheus_client::encoding::EncodeLabelSet;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::registry::Registry;
use std::sync::atomic::AtomicU64;

type U64Counter = Counter<u64, AtomicU64>;

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct ExecutionLabel {
    pub scheme: String,
    pub name: String,
}

/// Single source of truth for executor counters. Each field is a prometheus
/// counter that can be both registered for scraping and read directly via
/// [`Counter::get`] (used by the GetStats RPC path).
#[derive(Default)]
pub struct ExecutorMetrics {
    pub(crate) by_execution_started: Family<ExecutionLabel, U64Counter>,
    pub(crate) by_execution_completed: Family<ExecutionLabel, U64Counter>,
    pub(crate) by_execution_failed: Family<ExecutionLabel, U64Counter>,
}

impl ExecutorMetrics {
    /// Register all counters with the supplied registry under the
    /// `hellas_execution_*` prefix. The
    /// counter handles are shared (`Arc` internally), so clones registered
    /// here observe the same updates as the executor's `Arc<Self>`.
    pub fn register_with(&self, registry: &mut Registry) {
        let sub = registry.sub_registry_with_prefix("hellas");
        let execution_sub = sub.sub_registry_with_prefix("execution");
        for (name, desc, fam) in [
            (
                "executions_started",
                "Executions started",
                &self.by_execution_started,
            ),
            (
                "executions_completed",
                "Executions completed",
                &self.by_execution_completed,
            ),
            (
                "executions_failed",
                "Executions failed",
                &self.by_execution_failed,
            ),
        ] {
            execution_sub.register(name, desc, fam.clone());
        }
    }

    pub(crate) fn record_execution_started(&self, name: &str) {
        self.by_execution_started
            .get_or_create(&ExecutionLabel {
                scheme: "invoke".into(),
                name: name.into(),
            })
            .inc();
    }
    pub(crate) fn record_execution_finished(&self, name: &str, succeeded: bool) {
        let family = if succeeded {
            &self.by_execution_completed
        } else {
            &self.by_execution_failed
        };
        family
            .get_or_create(&ExecutionLabel {
                scheme: "invoke".into(),
                name: name.into(),
            })
            .inc();
    }
}
