//! The executor's execution path: run-ticket validation, backend
//! dispatch, and the signed event stream a job produces.
//!
//! # The terminal event commitment this file used to owe
//!
//! Paid, and the debt is closed. The cutover deleted the Receipt and
//! Settle handlers and took the private `terminal_commitment` helper
//! with them; the note that stood here recorded that, and named
//! `957162c` as where to read the old shape.
//!
//! It came back as `hellas_rpc::protocol::work::terminal_result`, and
//! deliberately not in the shape it left. The deleted helper answered
//! "what is the terminal commitment of my completed transcript for this
//! *request commitment*", by looking one up — Fetch's durable
//! `replay_completed` first, then Evaluate's replayed `WorkFinished`.
//! A lookup by request commitment is the wrong question for a paid job:
//! two accepted jobs can carry one request, and the second would be
//! answered out of the first one's transcript with nothing invoked. The
//! new function is handed the transcript one invocation produced and
//! checks it against the authorization that paid for it, so the three
//! refusals the old one made — no transcript, an empty one, a terminal
//! that does not decode — survive, and two it could not make are added.
//!
//! The Receipt type that owned its only caller is gone for good and did
//! not come back with it.

pub(in crate::executor) mod cache;

use crate::ExecutorError;
use crate::StateError;
use crate::executor::{
    ExecuteOutcome, ExecutorCompletion, FetchCompletion, FetchProviderFailure, FetchProviderRun,
    PendingFetch,
};
use crate::fetch::{FetchStateError, FetchStoreError, FetchTranscript, VerifiedFetchReplay};
use crate::fetch_policy::{FetchAccessError, FetchQuotaReservation, FetchRoute};
use crate::fetch_projection::{FetchProjector, ProjectedFetch};
use crate::fetch_provider::{FetchProvider, FetchProviderError, PreparedFetchRequest};
use crate::state::{QuoteKind, new_execution_id, validate_job_terms};
use futures_util::StreamExt;
use hellas_rpc::fetch::{
    FetchOutputTranscriptBuilder, MAX_FETCH_OUTPUT_EVENTS, MAX_FETCH_OUTPUT_PAYLOAD_BYTES,
    decode_fetch_terminal_payload,
};
use hellas_rpc::pb::execute::{
    RunTicketRequest, WorkChunk, WorkEvent, WorkFailed, WorkFinished, work_event,
};
use hellas_rpc::provenance::ExecutionProvenance;
use hellas_rpc::run_ticket::{VerifiedRunTicket, verify_run_ticket};
use hellas_rpc::stream::output_event_to_pb;
use hellas_rpc::{Digest, InputCommitment, OutputEventEnvelope, ProducerSigningKey};
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::{OwnedSemaphorePermit, mpsc};

use super::{
    DeferredFetchQuotaCancellation, DeferredFetchQuotaSettlement, Executor,
    FETCH_QUOTA_CANCELLATION_RETRIES_PER_TURN, FETCH_QUOTA_SETTLEMENT_RETRIES_PER_TURN,
    MAX_DEFERRED_FETCH_QUOTA_CANCELLATIONS,
};

/// Backpressure buffer for the per-execution event channel. The worker keeps
/// one slot reserved for the terminal frame and cancels a consumer that does
/// not drain the rest; it never blocks the sole execution thread.
const PER_EXECUTION_CHANNEL_CAPACITY: usize = 64;
const FETCH_STREAM_STALLED_ERROR: &str =
    "fetch stream consumer did not drain its bounded event channel";

#[derive(Debug, Default)]
struct FetchProjectionBudget {
    events: usize,
    signed_payload_bytes: usize,
}

impl FetchProjectionBudget {
    fn record_event(&mut self, payload_len: usize) -> Result<u64, FetchProviderError> {
        let streamed_event_limit = MAX_FETCH_OUTPUT_EVENTS
            .checked_sub(1)
            .expect("Fetch output limit includes one terminal event");
        self.record(payload_len, streamed_event_limit)
    }

    fn record_terminal(&mut self, payload_len: usize) -> Result<(), FetchProviderError> {
        self.record(payload_len, MAX_FETCH_OUTPUT_EVENTS)
            .map(|_| ())
    }

    fn record(
        &mut self,
        payload_len: usize,
        event_limit: usize,
    ) -> Result<u64, FetchProviderError> {
        let events = self.events.checked_add(1).ok_or_else(|| {
            FetchProviderError::failed(format!(
                "fetch projection exceeded the {event_limit}-event limit"
            ))
        })?;
        let signed_payload_bytes = self
            .signed_payload_bytes
            .checked_add(payload_len)
            .ok_or_else(|| {
                FetchProviderError::failed(format!(
                    "fetch projection exceeded the {MAX_FETCH_OUTPUT_PAYLOAD_BYTES}-byte signed payload limit"
                ))
            })?;
        if events > event_limit {
            return Err(FetchProviderError::failed(format!(
                "fetch projection exceeded the {event_limit}-event limit"
            )));
        }
        if signed_payload_bytes > MAX_FETCH_OUTPUT_PAYLOAD_BYTES {
            return Err(FetchProviderError::failed(format!(
                "fetch projection exceeded the {MAX_FETCH_OUTPUT_PAYLOAD_BYTES}-byte signed payload limit"
            )));
        }

        self.events = events;
        self.signed_payload_bytes = signed_payload_bytes;
        u64::try_from(payload_len)
            .map_err(|_| FetchProviderError::failed("fetch output position overflow"))
    }
}

impl Executor {
    pub(super) async fn handle_execute(
        &mut self,
        request: RunTicketRequest,
    ) -> Result<ExecuteOutcome, ExecutorError> {
        let verified_run = verify_run_ticket(&request).map_err(|err| {
            ExecutorError::InvalidQuoteRequest(format!("invalid run ticket: {err}"))
        })?;
        validate_job_terms(
            &verified_run.terms,
            self.provider.genesis.as_slice(),
            self.provider.assurance,
        )?;
        let request_commitment_id = *verified_run.terms.request.as_bytes();
        let request_commitment = request_commitment_id.to_vec();
        let input_commitment =
            InputCommitment::from_digest(Digest::from_bytes(request_commitment_id));
        if let Some(outcome) = self
            .replay_fetch_execution(input_commitment, request_commitment_id, &verified_run)
            .await?
        {
            return Ok(outcome);
        }
        #[cfg(feature = "evaluate")]
        if let Some(outcome) = self
            .evaluate
            .replay_completed(
                request_commitment_id,
                &verified_run.public_key,
                verified_run.terms.assurance,
            )
            .await?
        {
            info!(
                request_commitment = %format_request_commitment(&request_commitment),
                "replayed evaluate execution"
            );
            return Ok(outcome);
        }
        self.store.prune_expired_quotes(Instant::now());
        let quote = match self.store.get_quote(&request_commitment, Instant::now()) {
            Ok(quote) => quote.clone(),
            Err(err) => {
                // The quote store is transient; after a restart a caller
                // retrying a ticket whose run may have reached the provider
                // must hear "indeterminate", not "quote not found". If the
                // check itself fails, that store error is the truth — not
                // the quote-store miss.
                return Err(match self.fetch_state.is_indeterminate(input_commitment) {
                    Ok(true) => fetch_execute_error(FetchStateError::Indeterminate),
                    Ok(false) => err.into(),
                    Err(state_err) => fetch_execute_error(state_err),
                });
            }
        };
        if quote.terms != verified_run.terms {
            return Err(ExecutorError::InvalidQuoteRequest(
                "run ticket terms do not match quote".into(),
            ));
        }
        match &quote.kind {
            #[cfg(feature = "evaluate")]
            QuoteKind::Evaluate(job) => {
                if job.evaluate_request.assurance != verified_run.terms.assurance {
                    return Err(ExecutorError::InvalidQuoteRequest(
                        "evaluate request assurance does not match ticket terms".into(),
                    ));
                }
            }
            QuoteKind::Fetch { .. } => {
                let fetch_quote = self
                    .fetch_state
                    .quoted(input_commitment)
                    .map_err(fetch_execute_error)?;
                if fetch_quote.assurance != verified_run.terms.assurance {
                    return Err(ExecutorError::InvalidQuoteRequest(
                        "fetch request assurance does not match ticket terms".into(),
                    ));
                }
            }
        }
        ensure_authorized_runner(&quote.runner_public_key, &verified_run.public_key)?;
        let dispatched: Result<ExecuteOutcome, ExecutorError> = async {
            match quote.kind {
                #[cfg(feature = "evaluate")]
                QuoteKind::Evaluate(job) => {
                    let outcome =
                        self.evaluate
                            .start(*job, new_execution_id(), request_commitment_id)?;
                    let _ = self.store.remove_quote(&request_commitment);
                    Ok(outcome)
                }
                QuoteKind::Fetch { call } => {
                    self.retry_deferred_fetch_quota_settlements();
                    if !self.pending_fetch_quota_settlements.is_empty() {
                        return Err(ExecutorError::ArtifactStore(
                            "fetch quota settlement retries remain unresolved".to_string(),
                        ));
                    }
                    self.retry_deferred_fetch_quota_cancellations();
                    self.ensure_fetch_quota_cancellation_capacity()?;
                    let provenance = ExecutionProvenance {
                        commitment_id: request_commitment_id,
                    };
                    if self.active_fetches >= self.fetch_max_in_flight
                        && self.pending_fetches.len() >= self.fetch_queue_capacity
                    {
                        return Err(ExecutorError::QueueFull {
                            capacity: self.fetch_queue_capacity,
                        });
                    }
                    let route = FetchRoute::new(call.service.clone(), call.method.clone());
                    let entry = self
                        .fetch_routes
                        .entry(&route)
                        .cloned()
                        .ok_or_else(|| no_fetch_route_error(&route))?;
                    let adapted = entry
                        .adaptor_factory
                        .create(&call)
                        .map_err(|err| ExecutorError::InvalidQuoteRequest(err.to_string()))?;
                    let provider_request = adapted.provider_request;
                    let fetch_quote = self
                        .fetch_state
                        .quoted(input_commitment)
                        .map_err(fetch_execute_error)?;
                    let cache = self
                        .fetch_cache
                        .as_ref()
                        .map(|cache| {
                            hellas_rpc::cache::CacheKey::fetch_for_policy(
                                cache.policy(),
                                entry.execution_environment(),
                                &call.service,
                                &call.method,
                                call.body.as_bytes(),
                            )
                            .and_then(|key| {
                                key.map(|key| {
                                    cache::FetchCacheRequest::new(
                                        cache.clone(),
                                        key,
                                        fetch_quote.clone(),
                                    )
                                })
                                .transpose()
                            })
                        })
                        .transpose()
                        .map_err(|error| ExecutorError::PolicyDenied(error.to_string()))?
                        .flatten();
                    let execution_id = new_execution_id();
                    let admission = match self.fetch_access_policy.authorize_admission(
                        &fetch_quote.caller_key,
                        &adapted.request_view,
                        now_ms(),
                        execution_id.clone(),
                        input_commitment,
                        &entry.capabilities,
                    ) {
                        Ok(admission) => admission,
                        Err(error) => {
                            if let Some(reservation) = error.admission_reservation().cloned()
                                && let Err(cleanup) = self.cancel_or_defer_fetch_quota(
                                    Some(&reservation),
                                    None,
                                    false,
                                )
                            {
                                return Err(ExecutorError::ArtifactStore(format!(
                                    "{error}; failed to retain admission rollback: {cleanup}"
                                )));
                            }
                            return Err(fetch_access_error(error));
                        }
                    };
                    // Route-derived and operator-bounded. Never use the
                    // projected request's arbitrary model string as a
                    // Prometheus label or retain it in the metrics index.
                    let metric_name =
                        format!("{}/{}", provider_request.service, provider_request.method);
                    let (sender, receiver) = mpsc::channel(PER_EXECUTION_CHANNEL_CAPACITY);
                    let pending = PendingFetch {
                        cache,
                        request: provider_request,
                        provider: entry.provider,
                        input_commitment,
                        assurance: fetch_quote.assurance,
                        request_commitment_id,
                        quota_reservation: admission.reservation,
                        execution_id: execution_id.clone(),
                        metric_name: metric_name.clone(),
                        sender,
                        projector: adapted.projector,
                    };

                    let queued = if self.active_fetches < self.fetch_max_in_flight {
                        match self.fetch_state.start(input_commitment) {
                            Ok(_) => match self.start_fetch_execution(pending) {
                                Ok(()) => false,
                                Err(error) => {
                                    let (pending, activation_error) = *error;
                                    self.cancel_or_defer_fetch_quota(
                                        pending.quota_reservation.as_ref(),
                                        Some(pending.input_commitment),
                                        true,
                                    )?;
                                    return Err(fetch_access_error(activation_error));
                                }
                            },
                            Err(FetchStateError::AlreadyCompleted) => {
                                self.cancel_or_defer_fetch_quota(
                                    pending.quota_reservation.as_ref(),
                                    None,
                                    false,
                                )?;
                                if let Some(outcome) = self
                                    .replay_fetch_execution(
                                        input_commitment,
                                        request_commitment_id,
                                        &verified_run,
                                    )
                                    .await?
                                {
                                    return Ok(outcome);
                                }
                                return Err(fetch_execute_error(FetchStateError::AlreadyCompleted));
                            }
                            Err(err) => {
                                let abort_running =
                                    matches!(&err, FetchStateError::StartMarkerRollback { .. })
                                        .then_some(pending.input_commitment);
                                self.cancel_or_defer_fetch_quota(
                                    pending.quota_reservation.as_ref(),
                                    abort_running,
                                    false,
                                )?;
                                return Err(fetch_execute_error(err));
                            }
                        }
                    } else {
                        match self.fetch_state.queue(input_commitment) {
                            Ok(_) => {
                                self.pending_fetches.push_back(pending);
                                true
                            }
                            Err(FetchStateError::AlreadyCompleted) => {
                                self.cancel_or_defer_fetch_quota(
                                    pending.quota_reservation.as_ref(),
                                    None,
                                    false,
                                )?;
                                if let Some(outcome) = self
                                    .replay_fetch_execution(
                                        input_commitment,
                                        request_commitment_id,
                                        &verified_run,
                                    )
                                    .await?
                                {
                                    return Ok(outcome);
                                }
                                return Err(fetch_execute_error(FetchStateError::AlreadyCompleted));
                            }
                            Err(err) => {
                                self.cancel_or_defer_fetch_quota(
                                    pending.quota_reservation.as_ref(),
                                    None,
                                    false,
                                )?;
                                return Err(fetch_execute_error(err));
                            }
                        }
                    };

                    self.metrics.record_execution_started(
                        "fetch",
                        &metric_name,
                        /* prompt= */ 0,
                        /* prefill= */ 0,
                    );
                    let _ = self.store.remove_quote(&request_commitment);

                    info!(
                        %execution_id,
                        request_commitment = %format_request_commitment(&request_commitment),
                        queued,
                        active_fetches = self.active_fetches,
                        fetch_queue_len = self.pending_fetches.len(),
                        "accepted fetch execution"
                    );

                    Ok(ExecuteOutcome {
                        provenance,
                        events: receiver,
                    })
                }
            }
        }
        .await;
        dispatched
    }

    async fn replay_fetch_execution(
        &self,
        input_commitment: InputCommitment,
        request_commitment_id: [u8; 32],
        verified_run: &VerifiedRunTicket,
    ) -> Result<Option<ExecuteOutcome>, ExecutorError> {
        let producer_key = self.provider.producer_key.public_key();
        if !self
            .fetch_state
            .has_completed(input_commitment)
            .map_err(fetch_execute_error)?
        {
            return Ok(None);
        }
        let replay_permit = Arc::clone(&self.fetch_replay_slots)
            .try_acquire_owned()
            .map_err(|_| {
                ExecutorError::ResourceExhausted(
                    "fetch replay concurrency capacity is exhausted".to_string(),
                )
            })?;
        let VerifiedFetchReplay { transcript, input } = match self.fetch_state.replay_completed(
            input_commitment,
            &producer_key,
            &verified_run.public_key,
        ) {
            Ok(replay) => replay,
            Err(FetchStateError::NotFound | FetchStateError::NotCompleted) => return Ok(None),
            Err(error) => return Err(fetch_execute_error(error)),
        };
        if input.assurance != verified_run.terms.assurance {
            return Err(ExecutorError::InvalidQuoteRequest(
                "fetch request assurance does not match ticket terms".into(),
            ));
        }
        ensure_authorized_runner(&input.caller_key, &verified_run.public_key)?;
        let outcome =
            fetch_transcript_outcome(request_commitment_id, transcript, replay_permit).await?;
        info!(
            request_commitment = %format_request_commitment(input_commitment.as_bytes()),
            "replayed fetch execution"
        );
        Ok(Some(outcome))
    }

    /// Cross the durable quota barrier before the task that owns provider
    /// invocation can exist. Keeping activation inside this sole spawn helper
    /// makes a future call-site omission a type-visible `Result`, not a silent
    /// billing-boundary regression.
    fn start_fetch_execution(
        &mut self,
        pending: PendingFetch,
    ) -> Result<(), Box<(PendingFetch, FetchAccessError)>> {
        if let Err(error) = self
            .fetch_access_policy
            .activate_reservation(pending.quota_reservation.as_ref())
        {
            return Err(Box::new((pending, error)));
        }
        self.active_fetches = self.active_fetches.saturating_add(1);
        spawn_fetch_provider(
            self.completion_tx.clone(),
            Arc::clone(&self.provider.producer_key),
            pending,
        );
        Ok(())
    }

    fn finish_fetch_slot(&mut self) {
        self.active_fetches = self.active_fetches.saturating_sub(1);
        self.retry_deferred_fetch_quota_settlements();
        self.retry_deferred_fetch_quota_cancellations();
        self.dispatch_next_fetch();
    }

    fn ensure_fetch_quota_cancellation_capacity(&self) -> Result<(), ExecutorError> {
        let queued_reservations = self
            .pending_fetches
            .iter()
            .filter(|pending| pending.quota_reservation.is_some())
            .count();
        let liabilities = self
            .pending_fetch_quota_cancellations
            .len()
            .saturating_add(queued_reservations);
        if liabilities >= MAX_DEFERRED_FETCH_QUOTA_CANCELLATIONS {
            return Err(ExecutorError::ResourceExhausted(format!(
                "fetch quota cancellation retry capacity of {MAX_DEFERRED_FETCH_QUOTA_CANCELLATIONS} is exhausted"
            )));
        }
        Ok(())
    }

    fn cancel_or_defer_fetch_quota(
        &mut self,
        reservation: Option<&FetchQuotaReservation>,
        abort_running: Option<InputCommitment>,
        allow_dispatched: bool,
    ) -> Result<(), ExecutorError> {
        let Some(reservation) = reservation.cloned() else {
            if let Some(input) = abort_running {
                self.fetch_state
                    .abort_before_dispatch(input)
                    .map_err(fetch_execute_error)?;
            }
            return Ok(());
        };
        let mut cancellation = DeferredFetchQuotaCancellation {
            reservation,
            abort_running,
            allow_dispatched,
        };
        if let Err(error) = self.try_fetch_quota_cancellation(&mut cancellation) {
            if self.pending_fetch_quota_cancellations.len()
                >= MAX_DEFERRED_FETCH_QUOTA_CANCELLATIONS
            {
                tracing::error!(
                    reservation = %cancellation.reservation.id,
                    cancellation_error = %error,
                    "fetch quota cancellation retry capacity exhausted; refusing further quota-bearing work until restart recovery"
                );
                return Err(ExecutorError::ResourceExhausted(format!(
                    "fetch quota cancellation retry capacity of {MAX_DEFERRED_FETCH_QUOTA_CANCELLATIONS} is exhausted"
                )));
            }
            warn!(
                reservation = %cancellation.reservation.id,
                cancellation_error = %error,
                "deferring failed pre-dispatch Fetch quota cancellation"
            );
            self.pending_fetch_quota_cancellations
                .push_back(cancellation);
            if self.pending_fetch_quota_cancellations.len()
                == MAX_DEFERRED_FETCH_QUOTA_CANCELLATIONS
            {
                warn!(
                    capacity = MAX_DEFERRED_FETCH_QUOTA_CANCELLATIONS,
                    "fetch quota cancellation retry capacity reached; new quota-bearing work will be refused"
                );
            }
        }
        Ok(())
    }

    fn try_fetch_quota_cancellation(
        &mut self,
        cancellation: &mut DeferredFetchQuotaCancellation,
    ) -> Result<(), String> {
        if cancellation.allow_dispatched {
            self.fetch_access_policy
                .begin_reservation_cancellation(Some(&cancellation.reservation))
                .map_err(|error| format!("quota cancellation intent failed: {error}"))?;
        }
        if let Some(input) = cancellation.abort_running {
            self.fetch_state
                .abort_before_dispatch(input)
                .map_err(|error| format!("Fetch state rollback failed: {error}"))?;
            cancellation.abort_running = None;
        }
        let result = if cancellation.allow_dispatched {
            self.fetch_access_policy
                .finish_reservation_cancellation(Some(&cancellation.reservation))
        } else {
            self.fetch_access_policy
                .cancel_reservation(Some(&cancellation.reservation))
        };
        result.map_err(|error| error.to_string())
    }

    fn retry_deferred_fetch_quota_cancellations(&mut self) {
        let attempts = self
            .pending_fetch_quota_cancellations
            .len()
            .min(FETCH_QUOTA_CANCELLATION_RETRIES_PER_TURN);
        for _ in 0..attempts {
            let mut cancellation = self
                .pending_fetch_quota_cancellations
                .pop_front()
                .expect("retry count was bounded by queue length");
            match self.try_fetch_quota_cancellation(&mut cancellation) {
                Ok(()) => {
                    tracing::debug!(
                        reservation = %cancellation.reservation.id,
                        "retired deferred Fetch quota cancellation"
                    );
                }
                Err(error) => {
                    warn!(
                        reservation = %cancellation.reservation.id,
                        cancellation_error = %error,
                        "Fetch quota cancellation retry remains pending"
                    );
                    self.pending_fetch_quota_cancellations
                        .push_back(cancellation);
                }
            }
        }
    }

    fn reconcile_or_defer_fetch_reservation(
        &mut self,
        reservation: Option<&FetchQuotaReservation>,
        billable_units: u64,
    ) -> Result<(), FetchAccessError> {
        let Some(reservation) = reservation else {
            return Ok(());
        };
        match self.fetch_access_policy.reconcile_reservation(
            Some(reservation),
            billable_units,
            now_ms(),
        ) {
            Ok(()) => Ok(()),
            Err(error) => {
                // Once one settlement is unresolved, later admissions stop.
                // Only work already active or queued can add another record,
                // bounding this queue by the configured execution capacities.
                let capacity = self
                    .fetch_max_in_flight
                    .saturating_add(self.fetch_queue_capacity)
                    .max(1);
                if self.pending_fetch_quota_settlements.len() < capacity {
                    self.pending_fetch_quota_settlements
                        .push_back(DeferredFetchQuotaSettlement {
                            reservation: reservation.clone(),
                            billable_units,
                        });
                } else {
                    // The durable Dispatched entry remains the fail-closed
                    // authority and startup will settle it. Reaching this log
                    // means the actor's active+queued invariant was violated.
                    tracing::error!(
                        reservation = %reservation.id,
                        capacity,
                        "fetch quota settlement retry capacity exhausted"
                    );
                }
                Err(error)
            }
        }
    }

    fn retry_deferred_fetch_quota_settlements(&mut self) {
        let attempts = self
            .pending_fetch_quota_settlements
            .len()
            .min(FETCH_QUOTA_SETTLEMENT_RETRIES_PER_TURN);
        for _ in 0..attempts {
            let settlement = self
                .pending_fetch_quota_settlements
                .pop_front()
                .expect("retry count was bounded by queue length");
            if let Err(error) = self.fetch_access_policy.reconcile_reservation(
                Some(&settlement.reservation),
                settlement.billable_units,
                now_ms(),
            ) {
                warn!(
                    reservation = %settlement.reservation.id,
                    quota_error = %error,
                    "Fetch quota settlement retry remains pending"
                );
                self.pending_fetch_quota_settlements.push_back(settlement);
            } else {
                tracing::debug!(
                    reservation = %settlement.reservation.id,
                    "retired deferred Fetch quota settlement"
                );
            }
        }
    }

    /// A dispatched request may have been billed even when no trustworthy
    /// terminal usage survives. Charge the full reservation as actual spend
    /// at failure completion: it remains fail-closed for one spend window,
    /// then ages out like any other completed charge.
    fn reconcile_failed_fetch_reservation(
        &mut self,
        reservation: Option<&FetchQuotaReservation>,
        execution_id: &str,
    ) {
        let Some(reservation) = reservation else {
            return;
        };
        if let Err(err) =
            self.reconcile_or_defer_fetch_reservation(Some(reservation), reservation.reserved_units)
        {
            // Do not follow a failed reconciliation with cancellation or any
            // second ledger mutation: the original reservation remains the
            // fail-closed authority for operator recovery.
            warn!(
                %execution_id,
                reserved_units = reservation.reserved_units,
                quota_error = %err,
                "failed to reconcile fetch quota after failed provider dispatch; leaving reservation intact"
            );
        }
    }

    pub(super) fn handle_fetch_finished(&mut self, completion: FetchCompletion) {
        let FetchCompletion {
            input_commitment,
            request_commitment_id,
            quota_reservation,
            execution_id,
            metric_name,
            sender,
            result,
        } = completion;

        let run = match result {
            Ok(run) => run,
            Err(failure) => {
                let error = failure.error.to_string();
                let _ = self.fetch_state.fail(input_commitment, error.clone());
                self.reconcile_failed_fetch_reservation(quota_reservation.as_ref(), &execution_id);
                self.metrics
                    .record_execution_failed("fetch", &metric_name, 0);
                send_fetch_failed(&sender, failure.position, error);
                self.finish_fetch_slot();
                return;
            }
        };

        let (event, billable_units) = match fetch_finished_event(&run.output_events) {
            Ok(event) => event,
            Err(err) => {
                let error = err.to_string();
                let _ = self.fetch_state.fail(input_commitment, error.clone());
                self.reconcile_failed_fetch_reservation(quota_reservation.as_ref(), &execution_id);
                self.metrics
                    .record_execution_failed("fetch", &metric_name, 0);
                send_fetch_failed(&sender, run.position, error);
                self.finish_fetch_slot();
                return;
            }
        };
        // The accounting transition is the publication barrier. A caller must
        // never receive (or later replay) a successful retained transcript
        // while its known billable usage is still an immortal Dispatched
        // reservation. On failure the running marker and Dispatched entry stay
        // fail-closed; startup settles the latter at the full reservation.
        if let Err(err) =
            self.reconcile_or_defer_fetch_reservation(quota_reservation.as_ref(), billable_units)
        {
            let error = format!("fetch quota reconciliation failed: {err}");
            let _ = self.fetch_state.fail(input_commitment, error.clone());
            self.metrics
                .record_execution_failed("fetch", &metric_name, 0);
            send_fetch_failed(&sender, run.position, error);
            self.finish_fetch_slot();
            return;
        }
        if let Err(err) = self.fetch_state.complete_output(
            input_commitment,
            run.output_events,
            &self.provider.producer_key.public_key(),
        ) {
            let error = fetch_execute_error(err).to_string();
            let _ = self.fetch_state.fail(input_commitment, error.clone());
            self.metrics
                .record_execution_failed("fetch", &metric_name, 0);
            send_fetch_failed(&sender, run.position, error);
            self.finish_fetch_slot();
            return;
        }

        self.metrics
            .record_execution_completed("fetch", &metric_name, 0);
        // Completion runs on the sole actor. A stalled receiver must never
        // wedge every later quote and execution behind an awaited send.
        let _ = sender.try_send(Ok(event));

        info!(
            %execution_id,
            request_commitment = %format_request_commitment(&request_commitment_id),
            billable_units,
            "completed fetch execution"
        );
        self.finish_fetch_slot();
    }

    fn dispatch_next_fetch(&mut self) {
        while self.active_fetches < self.fetch_max_in_flight {
            let Some(pending) = self.pending_fetches.pop_front() else {
                return;
            };
            if pending.sender.is_closed() {
                if let Err(err) = self.fetch_state.cancel_queued(pending.input_commitment) {
                    warn!(
                        execution_id = %pending.execution_id,
                        state_error = %err,
                        "queued fetch was not cancellable; ticket state is inconsistent"
                    );
                }
                if let Err(err) = self.cancel_or_defer_fetch_quota(
                    pending.quota_reservation.as_ref(),
                    None,
                    false,
                ) {
                    tracing::error!(
                        execution_id = %pending.execution_id,
                        quota_error = %err,
                        "could not retain a quota cancellation for disconnected fetch"
                    );
                }
                debug!(
                    execution_id = %pending.execution_id,
                    "dropping queued fetch execution: consumer disconnected before dispatch"
                );
                continue;
            }
            match self.fetch_state.start(pending.input_commitment) {
                Ok(_) => match self.start_fetch_execution(pending) {
                    Ok(()) => return,
                    Err(error) => {
                        let (pending, activation_error) = *error;
                        let mut error = fetch_access_error(activation_error).to_string();
                        if let Err(cleanup_error) = self.cancel_or_defer_fetch_quota(
                            pending.quota_reservation.as_ref(),
                            Some(pending.input_commitment),
                            true,
                        ) {
                            error =
                                format!("{error}; pre-dispatch cleanup failed: {cleanup_error}");
                        }
                        let _ = pending.sender.try_send(Ok(WorkEvent {
                            kind: Some(work_event::Kind::Failed(WorkFailed { position: 0, error })),
                        }));
                    }
                },
                Err(err) => {
                    let abort_running = matches!(&err, FetchStateError::StartMarkerRollback { .. })
                        .then_some(pending.input_commitment);
                    if abort_running.is_none()
                        && !self.fetch_state.discard_queued(pending.input_commitment)
                    {
                        warn!(
                            execution_id = %pending.execution_id,
                            "failed to discard a queued fetch after dispatch refusal"
                        );
                    }
                    if let Err(error) = self.cancel_or_defer_fetch_quota(
                        pending.quota_reservation.as_ref(),
                        abort_running,
                        false,
                    ) {
                        tracing::error!(
                            execution_id = %pending.execution_id,
                            quota_error = %error,
                            "could not retain a quota cancellation after dispatch refusal"
                        );
                    }
                    let position = 0;
                    let error = fetch_execute_error(err).to_string();
                    let _ = pending.sender.try_send(Ok(WorkEvent {
                        kind: Some(work_event::Kind::Failed(WorkFailed { position, error })),
                    }));
                }
            }
        }
    }
}

fn ensure_authorized_runner(
    expected: &hellas_rpc::PublicKey,
    actual: &hellas_rpc::PublicKey,
) -> Result<(), ExecutorError> {
    if expected == actual {
        Ok(())
    } else {
        Err(ExecutorError::PolicyDenied(
            "run ticket signer is not authorized for this ticket".to_string(),
        ))
    }
}

fn format_request_commitment(bytes: &[u8]) -> String {
    Digest::from_slice(bytes)
        .map(|digest| digest.to_string())
        .unwrap_or_else(|_| format!("invalid:{}bytes", bytes.len()))
}

fn spawn_fetch_provider(
    completion_tx: mpsc::Sender<ExecutorCompletion>,
    producer_key: Arc<ProducerSigningKey>,
    pending: PendingFetch,
) {
    tokio::spawn(async move {
        let PendingFetch {
            cache,
            request,
            provider,
            projector,
            quota_reservation,
            input_commitment,
            assurance,
            request_commitment_id,
            execution_id,
            metric_name,
            sender,
        } = pending;
        let result = async {
            let _guard = if let Some(cache) = &cache {
                let (recording, guard) = cache.read().await?;
                if let Some(recording) = recording {
                    return cache::replay(
                        recording,
                        input_commitment,
                        assurance,
                        &producer_key,
                        &sender,
                    )
                    .await;
                }
                Some(guard)
            } else {
                None
            };
            let run = run_fetch_provider(
                provider,
                request,
                projector,
                input_commitment,
                assurance,
                &producer_key,
                sender.clone(),
            )
            .await?;
            if let Some(cache) = &cache {
                cache.record(&run).await.map_err(|mut error| {
                    error.position = run.position;
                    error
                })?;
            }
            Ok(run)
        }
        .await;
        let _ = completion_tx
            .send(ExecutorCompletion::FetchFinished(Box::new(
                FetchCompletion {
                    input_commitment,
                    request_commitment_id,
                    quota_reservation,
                    execution_id,
                    metric_name,
                    sender,
                    result,
                },
            )))
            .await;
    });
}

async fn run_fetch_provider(
    provider: Arc<dyn FetchProvider>,
    request: PreparedFetchRequest,
    mut projector: Box<dyn FetchProjector>,
    input_commitment: InputCommitment,
    assurance: hellas_rpc::Assurance,
    producer_key: &ProducerSigningKey,
    sender: mpsc::Sender<Result<WorkEvent, hellas_wire::WireStatus>>,
) -> Result<FetchProviderRun, FetchProviderFailure> {
    let mut builder = FetchOutputTranscriptBuilder::new(input_commitment, assurance, producer_key);
    let mut position = 0_u64;
    let mut terminal = None;
    let mut projection_budget = FetchProjectionBudget::default();
    let response = provider
        .run(request)
        .await
        .map_err(|error| FetchProviderFailure { position, error })?;
    let projected = projector
        .begin(response.head)
        .map_err(|err| FetchProviderFailure {
            position,
            error: FetchProviderError::failed(format!("fetch projection failed: {err}")),
        })?;
    process_projected_fetch(
        projected,
        &mut builder,
        &mut terminal,
        &mut projection_budget,
        &mut position,
        &sender,
    )
    .await?;
    let mut stream = response.stream;

    while let Some(next) = stream.next().await {
        let chunk = next.map_err(|error| FetchProviderFailure { position, error })?;
        let projected = projector
            .project(&chunk)
            .map_err(|err| FetchProviderFailure {
                position,
                error: FetchProviderError::failed(format!("fetch projection failed: {err}")),
            })?;
        let reached_terminal = process_projected_fetch(
            projected,
            &mut builder,
            &mut terminal,
            &mut projection_budget,
            &mut position,
            &sender,
        )
        .await?;
        if reached_terminal {
            // A terminal projection is the trusted end of the operation. Do
            // not let an upstream keep this task, connection, or credential
            // alive after it has supplied the complete result.
            drop(stream);
            break;
        }
    }

    if terminal.is_none() {
        let projected = projector.finish().map_err(|err| FetchProviderFailure {
            position,
            error: FetchProviderError::failed(format!("fetch projection failed: {err}")),
        })?;
        process_projected_fetch(
            projected,
            &mut builder,
            &mut terminal,
            &mut projection_budget,
            &mut position,
            &sender,
        )
        .await?;
    }
    let terminal_payload = terminal.ok_or_else(|| FetchProviderFailure {
        position,
        error: FetchProviderError::failed(
            "fetch provider ended without terminal event".to_string(),
        ),
    })?;
    let output_events = builder
        .finish(terminal_payload)
        .map_err(|err| FetchProviderFailure {
            position,
            error: FetchProviderError::failed(format!("fetch output transcript failed: {err}")),
        })?;
    Ok(FetchProviderRun {
        output_events,
        position,
    })
}

async fn process_projected_fetch(
    projected: Vec<ProjectedFetch>,
    builder: &mut FetchOutputTranscriptBuilder<'_>,
    terminal: &mut Option<Vec<u8>>,
    projection_budget: &mut FetchProjectionBudget,
    position: &mut u64,
    sender: &mpsc::Sender<Result<WorkEvent, hellas_wire::WireStatus>>,
) -> Result<bool, FetchProviderFailure> {
    for item in projected {
        match item {
            ProjectedFetch::Event(payload) => {
                if terminal.is_some() {
                    return Err(FetchProviderFailure {
                        position: *position,
                        error: FetchProviderError::failed(
                            "fetch projection emitted an event after terminal".to_string(),
                        ),
                    });
                }
                // The actor needs one guaranteed permit for WorkFinished or
                // WorkFailed. Fail before signing another chunk when only that
                // permit remains; never await a slow consumer here.
                if sender.capacity() <= 1 {
                    return Err(FetchProviderFailure {
                        position: *position,
                        error: FetchProviderError::failed(FETCH_STREAM_STALLED_ERROR),
                    });
                }
                let payload_len =
                    projection_budget
                        .record_event(payload.len())
                        .map_err(|error| FetchProviderFailure {
                            position: *position,
                            error,
                        })?;
                let next_position =
                    position
                        .checked_add(payload_len)
                        .ok_or_else(|| FetchProviderFailure {
                            position: *position,
                            error: FetchProviderError::failed("fetch output position overflow"),
                        })?;
                let output_event =
                    builder
                        .push_event(payload)
                        .map_err(|err| FetchProviderFailure {
                            position: *position,
                            error: FetchProviderError::failed(format!(
                                "fetch output event transcript failed: {err}"
                            )),
                        })?;
                match sender.try_send(Ok(WorkEvent {
                    kind: Some(work_event::Kind::Chunk(WorkChunk {
                        output_event: Some(output_event_to_pb(&output_event)),
                    })),
                })) {
                    Ok(()) => {
                        *position = next_position;
                        // Give the just-returned RPC receiver a scheduling
                        // opportunity before classifying a full burst as a
                        // stalled consumer.
                        tokio::task::yield_now().await;
                    }
                    Err(mpsc::error::TrySendError::Full(_)) => {
                        return Err(FetchProviderFailure {
                            position: *position,
                            error: FetchProviderError::failed(FETCH_STREAM_STALLED_ERROR),
                        });
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => {
                        return Err(FetchProviderFailure {
                            position: *position,
                            error: FetchProviderError::failed("fetch stream consumer disconnected"),
                        });
                    }
                }
            }
            ProjectedFetch::Terminal(payload) => {
                if terminal.is_some() {
                    return Err(FetchProviderFailure {
                        position: *position,
                        error: FetchProviderError::failed(
                            "fetch projection emitted multiple terminal events".to_string(),
                        ),
                    });
                }
                projection_budget
                    .record_terminal(payload.len())
                    .map_err(|error| FetchProviderFailure {
                        position: *position,
                        error,
                    })?;
                *terminal = Some(payload);
            }
        }
    }
    Ok(terminal.is_some())
}

fn send_fetch_failed(
    sender: &mpsc::Sender<Result<WorkEvent, hellas_wire::WireStatus>>,
    position: u64,
    error: impl Into<String>,
) {
    let _ = sender.try_send(Ok(WorkEvent {
        kind: Some(work_event::Kind::Failed(WorkFailed {
            position,
            error: error.into(),
        })),
    }));
}

async fn fetch_transcript_outcome(
    request_commitment_id: [u8; 32],
    transcript: FetchTranscript,
    replay_permit: OwnedSemaphorePermit,
) -> Result<ExecuteOutcome, ExecutorError> {
    fetch_finished_outcome_inner(
        ExecutionProvenance {
            commitment_id: request_commitment_id,
        },
        transcript.into_output_events(),
        Some(replay_permit),
    )
    .await
}

#[cfg(test)]
async fn fetch_finished_outcome(
    provenance: ExecutionProvenance,
    output_events: &[OutputEventEnvelope],
) -> Result<ExecuteOutcome, ExecutorError> {
    fetch_finished_outcome_inner(provenance, output_events.to_vec(), None).await
}

async fn fetch_finished_outcome_inner(
    provenance: ExecutionProvenance,
    mut output_events: Vec<OutputEventEnvelope>,
    replay_permit: Option<OwnedSemaphorePermit>,
) -> Result<ExecuteOutcome, ExecutorError> {
    let (finished, _) = fetch_finished_event(&output_events)?;
    output_events
        .pop()
        .ok_or_else(|| ExecutorError::InvalidQuoteRequest("empty fetch transcript".to_string()))?;
    let streamed_prefix = output_events;
    let (sender, receiver) = mpsc::channel(PER_EXECUTION_CHANNEL_CAPACITY);
    tokio::spawn(async move {
        async {
            for output_event in streamed_prefix {
                let event = WorkEvent {
                    kind: Some(work_event::Kind::Chunk(WorkChunk {
                        output_event: Some(output_event_to_pb(&output_event)),
                    })),
                };
                if sender.send(Ok(event)).await.is_err() {
                    return;
                }
            }
            let _ = sender.send(Ok(finished)).await;
        }
        .await;

        // A replay slot represents a live consumer, not merely a producer
        // task. Reserving the channel's entire capacity can succeed only
        // after every buffered event has been consumed, or fail when the
        // receiver is dropped. Keep the owned semaphore permit across that
        // rendezvous so an undrained terminal frame still occupies its slot.
        if let Some(_replay_permit) = replay_permit {
            let _drained_or_dropped = sender.reserve_many(PER_EXECUTION_CHANNEL_CAPACITY).await;
        }
    });

    Ok(ExecuteOutcome {
        provenance,
        events: receiver,
    })
}

fn fetch_finished_event(
    output_events: &[OutputEventEnvelope],
) -> Result<(WorkEvent, u64), ExecutorError> {
    let terminal = output_events
        .last()
        .ok_or_else(|| ExecutorError::InvalidQuoteRequest("empty fetch transcript".to_string()))?;
    let billable_units = decode_fetch_terminal_payload(terminal.payload())
        .map_err(|err| ExecutorError::InvalidQuoteRequest(err.to_string()))?
        .billable_units();
    Ok((
        WorkEvent {
            kind: Some(work_event::Kind::Finished(WorkFinished {
                terminal_output_event: Some(output_event_to_pb(terminal)),
                assurance_evidence: Vec::new(),
            })),
        },
        billable_units,
    ))
}

pub(super) fn fetch_execute_error(err: FetchStateError) -> ExecutorError {
    match err {
        FetchStateError::NotFound => {
            ExecutorError::State(StateError::QuoteNotFound(err.to_string()))
        }
        FetchStateError::AlreadyExists
        | FetchStateError::AlreadyQueued
        | FetchStateError::AlreadyRunning
        | FetchStateError::NotRunning
        | FetchStateError::NotCompleted
        | FetchStateError::AlreadyCompleted
        | FetchStateError::Indeterminate => {
            ExecutorError::State(StateError::QuoteExpired(err.to_string()))
        }
        FetchStateError::Store(err @ FetchStoreError::Capacity { .. }) => {
            ExecutorError::ResourceExhausted(err.to_string())
        }
        FetchStateError::Store(err) => {
            ExecutorError::ArtifactStore(format!("fetch transcript store error: {err}"))
        }
        FetchStateError::StartMarkerRollback { .. } => {
            ExecutorError::ArtifactStore(err.to_string())
        }
        FetchStateError::TicketCapacity { capacity } => ExecutorError::QueueFull { capacity },
        FetchStateError::InputCapacity { .. } => ExecutorError::ResourceExhausted(err.to_string()),
        FetchStateError::UnauthorizedRunner => ExecutorError::PolicyDenied(err.to_string()),
        FetchStateError::QuoteMismatch
        | FetchStateError::UnauthorizedCaller
        | FetchStateError::InputLengthOverflow
        | FetchStateError::Verify(_)
        | FetchStateError::Input(_) => {
            ExecutorError::InvalidQuoteRequest(format!("fetch transcript rejected: {err}"))
        }
    }
}

pub(super) fn no_fetch_route_error(route: &FetchRoute) -> ExecutorError {
    ExecutorError::PolicyDenied(format!(
        "no fetch route configured for {}/{}",
        route.service, route.method
    ))
}

fn fetch_access_error(err: FetchAccessError) -> ExecutorError {
    match err {
        FetchAccessError::Denied(message) => ExecutorError::PolicyDenied(message),
        FetchAccessError::QuotaExceeded {
            retry_after_ms,
            message,
        } => ExecutorError::QuotaExceeded {
            retry_after_ms,
            message,
        },
        error @ (FetchAccessError::BillableUnitsExceedReservation { .. }
        | FetchAccessError::MissingReservation(_)
        | FetchAccessError::InvalidReservationLifecycle { .. }) => {
            ExecutorError::Execution(error.to_string())
        }
        error @ FetchAccessError::AdmissionReservationIndeterminate { .. } => {
            ExecutorError::ArtifactStore(error.to_string())
        }
        FetchAccessError::Store(message) => {
            ExecutorError::ArtifactStore(format!("fetch quota store error: {message}"))
        }
        FetchAccessError::Io(err) => {
            ExecutorError::ArtifactStore(format!("fetch quota store I/O error: {err}"))
        }
    }
}

pub(super) fn now_ms() -> u64 {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    u64::try_from(elapsed).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests;
