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
    pub(crate) evaluate_executions_started: U64Counter,
    pub(crate) evaluate_executions_completed: U64Counter,
    pub(crate) evaluate_executions_failed: U64Counter,
    pub(crate) evaluate_prompt_tokens: U64Counter,
    pub(crate) evaluate_prefill_tokens: U64Counter,
    pub(crate) evaluate_generated_tokens: U64Counter,

    pub(crate) by_execution_started: Family<ExecutionLabel, U64Counter>,
    pub(crate) by_execution_completed: Family<ExecutionLabel, U64Counter>,
    pub(crate) by_execution_failed: Family<ExecutionLabel, U64Counter>,
    pub(crate) by_execution_prompt_tokens: Family<ExecutionLabel, U64Counter>,
    pub(crate) by_execution_prefill_tokens: Family<ExecutionLabel, U64Counter>,
    pub(crate) by_execution_generated_tokens: Family<ExecutionLabel, U64Counter>,
}

impl ExecutorMetrics {
    /// Register all counters with the supplied registry under the
    /// `hellas_evaluate_*` and `hellas_execution_*` prefixes. The
    /// counter handles are shared (`Arc` internally), so clones registered
    /// here observe the same updates as the executor's `Arc<Self>`.
    pub fn register_with(&self, registry: &mut Registry) {
        let sub = registry.sub_registry_with_prefix("hellas");
        for (name, desc, ctr) in [
            (
                "evaluate_executions_started",
                "Catena evaluate executions started",
                &self.evaluate_executions_started,
            ),
            (
                "evaluate_executions_completed",
                "Catena evaluate executions completed",
                &self.evaluate_executions_completed,
            ),
            (
                "evaluate_executions_failed",
                "Catena evaluate executions failed",
                &self.evaluate_executions_failed,
            ),
            (
                "evaluate_prompt_tokens",
                "Catena evaluate prompt tokens",
                &self.evaluate_prompt_tokens,
            ),
            (
                "evaluate_prefill_tokens",
                "Catena evaluate prefill tokens computed",
                &self.evaluate_prefill_tokens,
            ),
            (
                "evaluate_generated_tokens",
                "Catena evaluate output tokens generated",
                &self.evaluate_generated_tokens,
            ),
        ] {
            sub.register(name, desc, ctr.clone());
        }
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
            (
                "prompt_tokens",
                "Total prompt tokens",
                &self.by_execution_prompt_tokens,
            ),
            (
                "prefill_tokens",
                "Prefill tokens computed",
                &self.by_execution_prefill_tokens,
            ),
            (
                "generated_tokens",
                "Output tokens generated",
                &self.by_execution_generated_tokens,
            ),
        ] {
            execution_sub.register(name, desc, fam.clone());
        }
    }

    #[cfg(feature = "evaluate")]
    fn execution_label(scheme: &str, name: &str) -> ExecutionLabel {
        ExecutionLabel {
            scheme: scheme.to_string(),
            name: name.to_string(),
        }
    }

    #[cfg(feature = "evaluate")]
    pub(crate) fn record_execution_started(
        &self,
        scheme: &str,
        name: &str,
        prompt: u64,
        prefill: u64,
    ) {
        let label = Self::execution_label(scheme, name);
        self.by_execution_started.get_or_create(&label).inc();
        if scheme == "evaluate" {
            self.evaluate_executions_started.inc();
            self.evaluate_prompt_tokens.inc_by(prompt);
            self.evaluate_prefill_tokens.inc_by(prefill);
            self.by_execution_prompt_tokens
                .get_or_create(&label)
                .inc_by(prompt);
            self.by_execution_prefill_tokens
                .get_or_create(&label)
                .inc_by(prefill);
        }
    }

    #[cfg(feature = "evaluate")]
    pub(crate) fn record_execution_completed(&self, scheme: &str, name: &str, generated: u64) {
        let label = Self::execution_label(scheme, name);
        self.by_execution_completed.get_or_create(&label).inc();
        if scheme == "evaluate" {
            self.evaluate_generated_tokens.inc_by(generated);
            self.evaluate_executions_completed.inc();
            self.by_execution_generated_tokens
                .get_or_create(&label)
                .inc_by(generated);
        }
    }

    #[cfg(feature = "evaluate")]
    pub(crate) fn record_execution_failed(&self, scheme: &str, name: &str, generated: u64) {
        let label = Self::execution_label(scheme, name);
        self.by_execution_failed.get_or_create(&label).inc();
        if scheme == "evaluate" {
            self.evaluate_generated_tokens.inc_by(generated);
            self.evaluate_executions_failed.inc();
            self.by_execution_generated_tokens
                .get_or_create(&label)
                .inc_by(generated);
        }
    }
}
