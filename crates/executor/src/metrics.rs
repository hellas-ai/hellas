//! Live executor counters recorded at the execution boundary.

use opentelemetry::{KeyValue, metrics::Counter};

pub struct ExecutorMetrics {
    started: Counter<u64>,
    completed: Counter<u64>,
    failed: Counter<u64>,
}

impl Default for ExecutorMetrics {
    fn default() -> Self {
        let meter = opentelemetry::global::meter("hellas.executor");
        Self {
            started: meter
                .u64_counter("hellas.execution.executions_started")
                .with_description("Executions started")
                .build(),
            completed: meter
                .u64_counter("hellas.execution.executions_completed")
                .with_description("Executions completed")
                .build(),
            failed: meter
                .u64_counter("hellas.execution.executions_failed")
                .with_description("Executions failed")
                .build(),
        }
    }
}

impl ExecutorMetrics {
    pub(crate) fn record_execution_started(&self, name: &str) {
        self.started.add(1, &labels(name));
    }

    pub(crate) fn record_execution_finished(&self, name: &str, succeeded: bool) {
        let counter = if succeeded {
            &self.completed
        } else {
            &self.failed
        };
        counter.add(1, &labels(name));
    }
}

fn labels(name: &str) -> [KeyValue; 2] {
    [
        KeyValue::new("scheme", "invoke"),
        KeyValue::new("name", name.to_owned()),
    ]
}
