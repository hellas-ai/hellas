pub(super) mod execution;
mod paid_fetch;
use super::{ExecutorCompletion, ExecutorHandle, ExecutorOwedRequest, ProviderContext};
#[cfg(feature = "evaluate")]
use crate::evaluate::{EvaluateEngine, EvaluateEngineConfig};
use crate::{ExecutorError, ExecutorMetrics, FetchRouteRegistry};
use hellas_rpc::{Assurance, ProducerSigningKey};
use std::{collections::VecDeque, sync::Arc};
use tokio::sync::mpsc;

pub(super) const EXECUTOR_OWED_MAILBOX_CAPACITY: usize = 64;

pub struct ExecutorSpawnConfig {
    pub queue_capacity: usize,
    pub metrics: Arc<ExecutorMetrics>,
    pub producer_key: Arc<ProducerSigningKey>,
    pub assurance: Assurance,
    pub fetch_routes: FetchRouteRegistry,
    pub fetch_max_in_flight: usize,
    pub fetch_queue_capacity: usize,
    #[cfg(feature = "evaluate")]
    pub content_store: hellas_store::ContentStore,
    #[cfg(feature = "evaluate")]
    pub gpu_config: crate::GpuConfig,
}
impl ExecutorSpawnConfig {
    pub fn fetch_only(
        producer_key: Arc<ProducerSigningKey>,
        assurance: Assurance,
        fetch_routes: FetchRouteRegistry,
    ) -> Self {
        Self {
            queue_capacity: hellas_rpc::DEFAULT_EXECUTION_QUEUE_CAPACITY,
            metrics: Arc::new(ExecutorMetrics::default()),
            producer_key,
            assurance,
            fetch_routes,
            fetch_max_in_flight: hellas_rpc::DEFAULT_FETCH_MAX_IN_FLIGHT,
            fetch_queue_capacity: hellas_rpc::DEFAULT_FETCH_QUEUE_CAPACITY,
            #[cfg(feature = "evaluate")]
            content_store: hellas_store::ContentStore::new(),
            #[cfg(feature = "evaluate")]
            gpu_config: crate::GpuConfig::default(),
        }
    }
}
pub struct Executor {
    owed_rx: mpsc::Receiver<ExecutorOwedRequest>,
    completion_rx: mpsc::Receiver<ExecutorCompletion>,
    pub(super) completion_tx: mpsc::Sender<ExecutorCompletion>,
    pub(super) provider: ProviderContext,
    pub(super) fetch_routes: FetchRouteRegistry,
    pending_paid_fetches: VecDeque<paid_fetch::PendingPaidFetch>,
    pub(super) fetch_max_in_flight: usize,
    fetch_queue_capacity: usize,
    pub(super) active_fetches: usize,
    #[cfg(feature = "evaluate")]
    evaluate: EvaluateEngine,
}
impl Executor {
    pub async fn spawn_configured(
        config: ExecutorSpawnConfig,
    ) -> Result<ExecutorHandle, ExecutorError> {
        if config.fetch_max_in_flight == 0 {
            return Err(ExecutorError::ResourceExhausted(
                "Fetch concurrency must be positive".into(),
            ));
        }
        let (owed_tx, owed_rx) = mpsc::channel(EXECUTOR_OWED_MAILBOX_CAPACITY);
        let permits =
            |active: usize, queue: usize| -> Result<Arc<tokio::sync::Semaphore>, ExecutorError> {
                let total = active
                    .checked_add(queue)
                    .filter(|n| *n <= tokio::sync::Semaphore::MAX_PERMITS)
                    .ok_or_else(|| {
                        ExecutorError::ResourceExhausted("executor capacity overflow".into())
                    })?;
                Ok(Arc::new(tokio::sync::Semaphore::new(total)))
            };
        let fetch_capacity = permits(config.fetch_max_in_flight, config.fetch_queue_capacity)?;
        let gpu_capacity = if cfg!(feature = "evaluate") {
            Some(permits(1, config.queue_capacity)?)
        } else {
            None
        };
        let capacity = config.fetch_max_in_flight.checked_add(1).ok_or_else(|| {
            ExecutorError::ResourceExhausted("completion capacity overflow".into())
        })?;
        let (completion_tx, completion_rx) = mpsc::channel(capacity);
        let provider = ProviderContext {
            producer_key: config.producer_key,
            assurance: config.assurance,
        };
        #[cfg(feature = "evaluate")]
        let evaluate = EvaluateEngine::new(EvaluateEngineConfig {
            content_store: config.content_store,
            gpu_config: config.gpu_config,
            queue_capacity: config.queue_capacity,
            metrics: config.metrics,
            provider: provider.clone(),
            completion_tx: completion_tx.clone(),
        })?;
        let executor = Self {
            owed_rx,
            completion_rx,
            completion_tx,
            provider,
            fetch_routes: config.fetch_routes,
            pending_paid_fetches: VecDeque::new(),
            fetch_max_in_flight: config.fetch_max_in_flight,
            fetch_queue_capacity: config.fetch_queue_capacity,
            active_fetches: 0,
            #[cfg(feature = "evaluate")]
            evaluate,
        };
        tokio::spawn(executor.run());
        Ok(ExecutorHandle {
            owed_tx,
            fetch_capacity,
            gpu_capacity,
        })
    }
    async fn run(mut self) {
        let mut ingress_open = true;
        loop {
            self.dispatch_paid_fetches();
            #[cfg(feature = "evaluate")]
            self.evaluate.dispatch_next_execution();
            let can_receive = self.active_fetches < self.fetch_max_in_flight
                || self.pending_paid_fetches.len() < self.fetch_queue_capacity;
            #[cfg(feature = "evaluate")]
            let can_receive = can_receive && self.evaluate.has_queue_capacity();
            let active = self.active_fetches > 0;
            #[cfg(feature = "evaluate")]
            let active = active || self.evaluate.has_work();
            if !ingress_open && !active && self.pending_paid_fetches.is_empty() {
                break;
            }
            tokio::select! {
                biased;
                Some(completion) = self.completion_rx.recv() => match completion {
                    ExecutorCompletion::PaidFetch { reply, result } => {
                        self.active_fetches -= 1;
                        let _ = reply.send(result);
                    }
                    #[cfg(feature = "evaluate")]
                    ExecutorCompletion::EvaluateFinished(completion) => self.evaluate.on_completion(*completion).await,
                },
                request = self.owed_rx.recv(), if ingress_open && can_receive => match request {
                    Some(ExecutorOwedRequest::RunPaidFetch { span, input, progress, reply }) => self.start_paid_fetch(*input, progress, reply, span),
                    Some(ExecutorOwedRequest::RunPaidEvaluate { span, input, reply }) => {
                        #[cfg(feature = "evaluate")]
                        {
                            use tracing::Instrument;
                            let result = self.evaluate.start_prepared_input(*input).instrument(span).await;
                            let _ = reply.send(result);
                        }
                        #[cfg(not(feature = "evaluate"))]
                        {
                            let _ = (span, input);
                            let _ = reply.send(Err(ExecutorError::PolicyDenied("Evaluate is unavailable on this node".into())));
                        }
                    }
                    None => ingress_open = false,
                },
            }
        }
    }
}
