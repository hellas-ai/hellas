use std::collections::{BTreeSet, HashMap};
use std::fs::{self, OpenOptions, TryLockError};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use hellas_rpc::peers::TokenBucket;
use hellas_rpc::{
    Digest, InputCommitment, ProducerId, PublicKey, canonical_dag_cbor, decode_dag_cbor,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::fetch_projection::FetchRequestView;

/// A spend window is also a bounded accounting structure. This cap prevents
/// tiny successful requests from turning each admission into an ever-growing
/// scan and rewrite.
const MAX_FETCH_SPEND_LEDGER_ENTRIES: usize = 4_096;
/// 4,096 runtime UUID reservations encode well below this ceiling. Keeping a
/// separate byte bound makes corrupt legacy state an I/O error before it can
/// allocate without limit.
const MAX_FETCH_SPEND_LEDGER_BYTES: usize = 4 * 1024 * 1024;

#[derive(Clone, Debug)]
pub struct FetchAccessPolicy {
    callers: HashMap<ProducerId, CallerAccess>,
    rate_buckets: HashMap<ProducerId, TokenBucket>,
    quota_store: FetchQuotaStoreBackend,
}

impl FetchAccessPolicy {
    pub fn new(callers: impl IntoIterator<Item = CallerAccess>) -> Self {
        Self::with_quota_store(callers, FetchQuotaStoreBackend::memory())
    }

    pub fn with_quota_store(
        callers: impl IntoIterator<Item = CallerAccess>,
        quota_store: FetchQuotaStoreBackend,
    ) -> Self {
        Self {
            callers: callers
                .into_iter()
                .map(|access| (ProducerId::from_public_key(&access.public_key), access))
                .collect(),
            rate_buckets: HashMap::new(),
            quota_store,
        }
    }

    pub fn trusted_callers(keys: impl IntoIterator<Item = PublicKey>) -> Self {
        Self::new(keys.into_iter().map(CallerAccess::allow_all))
    }

    pub fn caller_keys(&self) -> Vec<PublicKey> {
        self.callers
            .values()
            .map(|access| access.public_key)
            .collect()
    }

    pub fn with_store(mut self, quota_store: FetchQuotaStoreBackend) -> Self {
        self.quota_store = quota_store;
        self
    }

    pub(crate) fn init_store(&self) -> Result<(), FetchAccessError> {
        self.quota_store.init()
    }

    pub fn authorize_admission(
        &mut self,
        caller_key: &PublicKey,
        request: &FetchRequestView,
        now_ms: u64,
        reservation_id: String,
        input_commitment: InputCommitment,
        capabilities: &FetchRoutePolicy,
    ) -> Result<FetchAdmission, FetchAccessError> {
        let caller_id = ProducerId::from_public_key(caller_key);
        let caller = self.callers.get(&caller_id).ok_or_else(|| {
            FetchAccessError::Denied("fetch caller is not authorized".to_string())
        })?;
        if caller.public_key != *caller_key {
            return Err(FetchAccessError::Denied(
                "fetch caller key does not match authorized key".to_string(),
            ));
        }
        let route = FetchRoute::new(request.service.clone(), request.method.clone());
        let route_policy = caller.routes.policy_for(&route).ok_or_else(|| {
            FetchAccessError::Denied(format!(
                "fetch caller is not authorized for {}/{}",
                request.service, request.method
            ))
        })?;
        let effective = capabilities.intersect(route_policy);
        effective.validate(request)?;

        if let Some(rate) = caller.request_rate {
            let bucket = self
                .rate_buckets
                .entry(caller_id)
                .or_insert_with(|| TokenBucket::new(now_ms, rate.capacity));
            bucket
                .try_take(now_ms, rate.capacity, rate.refill_per_sec)
                .map_err(|retry_after_ms| FetchAccessError::QuotaExceeded {
                    retry_after_ms,
                    message: "fetch request rate quota exceeded".to_string(),
                })?;
        }

        let reservation = match caller.spend {
            Some(spend) => {
                let reserved_units = reserved_units(request, &effective)?;
                self.reserve_spend(
                    caller_id,
                    reservation_id,
                    input_commitment,
                    now_ms,
                    reserved_units,
                    spend,
                )?
            }
            None => None,
        };

        Ok(FetchAdmission { reservation })
    }

    pub fn cancel_reservation(
        &mut self,
        reservation: Option<&FetchQuotaReservation>,
    ) -> Result<(), FetchAccessError> {
        self.remove_pending_reservation(reservation)
    }

    fn remove_pending_reservation(
        &mut self,
        reservation: Option<&FetchQuotaReservation>,
    ) -> Result<(), FetchAccessError> {
        let Some(reservation) = reservation else {
            return Ok(());
        };
        let Some(caller) = self.callers.get(&reservation.caller_id) else {
            return Ok(());
        };
        if caller.spend.is_none() {
            return Ok(());
        }
        let mut ledger = self.quota_store.load(reservation.caller_id)?;
        let Some(index) = ledger
            .entries
            .iter()
            .position(|entry| entry.id == reservation.id)
        else {
            // Cancellation is idempotent so a retry after an ambiguous store
            // acknowledgement can retire without manufacturing an error.
            return Ok(());
        };
        let lifecycle = ledger.entries[index].lifecycle();
        if lifecycle != SpendLifecycle::Pending {
            return Err(FetchAccessError::InvalidReservationLifecycle {
                id: reservation.id.clone(),
                expected: "pending",
                actual: lifecycle.to_string(),
            });
        }
        ledger.entries.remove(index);
        self.quota_store.put(reservation.caller_id, &ledger)?;
        Ok(())
    }

    /// Persist the authority to undo an activation that returned an error
    /// before any provider task could be spawned. Marker rollback may begin
    /// only after this transition is durably acknowledged. Rewriting an
    /// already-Cancelling ledger is intentional: it closes the ambiguity of a
    /// previous post-write error before the caller removes durable evidence.
    pub(crate) fn begin_reservation_cancellation(
        &mut self,
        reservation: Option<&FetchQuotaReservation>,
    ) -> Result<(), FetchAccessError> {
        let Some(reservation) = reservation else {
            return Ok(());
        };
        let Some(caller) = self.callers.get(&reservation.caller_id) else {
            return Ok(());
        };
        if caller.spend.is_none() {
            return Ok(());
        }
        let mut ledger = self.quota_store.load(reservation.caller_id)?;
        let Some(entry) = ledger
            .entries
            .iter_mut()
            .find(|entry| entry.id == reservation.id)
        else {
            return Ok(());
        };
        match entry.lifecycle() {
            SpendLifecycle::Pending | SpendLifecycle::Dispatched => entry.mark_cancelling(),
            SpendLifecycle::Cancelling => {}
            actual @ SpendLifecycle::Spent => {
                return Err(FetchAccessError::InvalidReservationLifecycle {
                    id: reservation.id.clone(),
                    expected: "pending, dispatched, or cancelling",
                    actual: actual.to_string(),
                });
            }
        }
        self.quota_store.put(reservation.caller_id, &ledger)
    }

    /// Delete a cancellation only after its running marker has been durably
    /// removed. Missing is success so a retry can retire an ambiguous store
    /// acknowledgement without recreating liability.
    pub(crate) fn finish_reservation_cancellation(
        &mut self,
        reservation: Option<&FetchQuotaReservation>,
    ) -> Result<(), FetchAccessError> {
        let Some(reservation) = reservation else {
            return Ok(());
        };
        let Some(caller) = self.callers.get(&reservation.caller_id) else {
            return Ok(());
        };
        if caller.spend.is_none() {
            return Ok(());
        }
        let mut ledger = self.quota_store.load(reservation.caller_id)?;
        let Some(index) = ledger
            .entries
            .iter()
            .position(|entry| entry.id == reservation.id)
        else {
            return Ok(());
        };
        let lifecycle = ledger.entries[index].lifecycle();
        if lifecycle != SpendLifecycle::Cancelling {
            return Err(FetchAccessError::InvalidReservationLifecycle {
                id: reservation.id.clone(),
                expected: "cancelling",
                actual: lifecycle.to_string(),
            });
        }
        ledger.entries.remove(index);
        self.quota_store.put(reservation.caller_id, &ledger)
    }

    /// Durably cross the billing boundary immediately before a provider task
    /// can be spawned. A Dispatched reservation never ages automatically: after
    /// this acknowledgement, a crash cannot prove whether the upstream was
    /// reached.
    pub fn activate_reservation(
        &mut self,
        reservation: Option<&FetchQuotaReservation>,
    ) -> Result<(), FetchAccessError> {
        let Some(reservation) = reservation else {
            return Ok(());
        };
        let Some(caller) = self.callers.get(&reservation.caller_id) else {
            return Ok(());
        };
        if caller.spend.is_none() {
            return Ok(());
        }
        let mut ledger = self.quota_store.load(reservation.caller_id)?;
        let entry = ledger
            .entries
            .iter_mut()
            .find(|entry| entry.id == reservation.id)
            .ok_or_else(|| FetchAccessError::MissingReservation(reservation.id.clone()))?;
        match entry.lifecycle() {
            SpendLifecycle::Pending => entry.mark_dispatched(),
            SpendLifecycle::Dispatched => return Ok(()),
            actual @ (SpendLifecycle::Cancelling | SpendLifecycle::Spent) => {
                return Err(FetchAccessError::InvalidReservationLifecycle {
                    id: reservation.id.clone(),
                    expected: "pending",
                    actual: actual.to_string(),
                });
            }
        }
        self.quota_store.put(reservation.caller_id, &ledger)
    }

    pub fn reconcile_reservation(
        &mut self,
        reservation: Option<&FetchQuotaReservation>,
        billable_units: u64,
        now_ms: u64,
    ) -> Result<(), FetchAccessError> {
        let Some(reservation) = reservation else {
            return Ok(());
        };
        if billable_units > reservation.reserved_units {
            return Err(FetchAccessError::BillableUnitsExceedReservation {
                billable_units,
                reserved_units: reservation.reserved_units,
            });
        }
        let Some(caller) = self.callers.get(&reservation.caller_id) else {
            return Ok(());
        };
        if caller.spend.is_none() {
            return Ok(());
        }
        let mut ledger = self.quota_store.load(reservation.caller_id)?;
        let Some(index) = ledger
            .entries
            .iter()
            .position(|entry| entry.id == reservation.id)
        else {
            return if billable_units == 0 {
                Ok(())
            } else {
                Err(FetchAccessError::MissingReservation(reservation.id.clone()))
            };
        };
        let lifecycle = ledger.entries[index].lifecycle();
        if lifecycle == SpendLifecycle::Spent && ledger.entries[index].units == billable_units {
            return Ok(());
        }
        if lifecycle != SpendLifecycle::Dispatched {
            return Err(FetchAccessError::InvalidReservationLifecycle {
                id: reservation.id.clone(),
                expected: "dispatched",
                actual: lifecycle.to_string(),
            });
        }
        if billable_units == 0 {
            ledger.entries.remove(index);
        } else {
            ledger.entries[index].mark_spent(billable_units, now_ms);
        }
        self.quota_store.put(reservation.caller_id, &ledger)?;
        Ok(())
    }

    /// Recover reservations that belonged to a previous process incarnation.
    ///
    /// The quota root is single-owner. At executor startup there can be no live
    /// queued work, so Pending and Cancelling entries are safe to remove after
    /// their running marker. A Dispatched entry may have reached the upstream,
    /// so it becomes worst-case Spent for one fresh window instead of either
    /// vanishing or consuming quota forever. The actual legacy format had no
    /// lifecycle bit; it receives the same conservative fresh-window charge.
    pub(crate) fn recover_reservations(
        &mut self,
        now_ms: u64,
        mut remove_running_marker: impl FnMut(InputCommitment) -> Result<(), String>,
    ) -> Result<usize, FetchAccessError> {
        let caller_ids = self
            .callers
            .iter()
            .filter_map(|(caller_id, caller)| caller.spend.map(|_| *caller_id))
            .collect::<Vec<_>>();
        let mut recovered = 0_usize;
        for caller_id in caller_ids {
            let mut ledger = self.quota_store.load(caller_id)?;
            let mut reclaim = Vec::new();
            let mut changed = false;
            for entry in &mut ledger.entries {
                if entry.lifecycle.is_none() {
                    entry.mark_spent(entry.units, now_ms);
                    recovered = recovered.checked_add(1).ok_or_else(|| {
                        FetchAccessError::Store(
                            "recovered fetch quota reservation count overflowed".to_string(),
                        )
                    })?;
                    changed = true;
                    continue;
                }
                match entry.lifecycle() {
                    SpendLifecycle::Pending | SpendLifecycle::Cancelling => {
                        let input = entry.input_commitment.ok_or_else(|| {
                            FetchAccessError::Store(format!(
                                "recoverable fetch quota reservation `{}` has no input commitment",
                                entry.id
                            ))
                        })?;
                        reclaim.push(input);
                    }
                    SpendLifecycle::Dispatched => {
                        entry.mark_spent(entry.units, now_ms);
                        recovered = recovered.checked_add(1).ok_or_else(|| {
                            FetchAccessError::Store(
                                "recovered fetch quota reservation count overflowed".to_string(),
                            )
                        })?;
                        changed = true;
                    }
                    SpendLifecycle::Spent => {}
                }
            }
            if reclaim.is_empty() && !changed {
                continue;
            }
            for input in reclaim.iter().copied() {
                remove_running_marker(InputCommitment::from_digest(Digest::from_bytes(input)))
                    .map_err(|error| {
                        FetchAccessError::Store(format!(
                            "failed to remove a pre-dispatch Fetch running marker: {error}"
                        ))
                    })?;
            }
            ledger.entries.retain(|entry| {
                !matches!(
                    entry.lifecycle(),
                    SpendLifecycle::Pending | SpendLifecycle::Cancelling
                )
            });
            self.quota_store.put(caller_id, &ledger)?;
            recovered = recovered.checked_add(reclaim.len()).ok_or_else(|| {
                FetchAccessError::Store(
                    "recovered fetch quota reservation count overflowed".to_string(),
                )
            })?;
        }
        Ok(recovered)
    }

    fn reserve_spend(
        &mut self,
        caller_id: ProducerId,
        reservation_id: String,
        input_commitment: InputCommitment,
        now_ms: u64,
        reserved_units: u64,
        spend: SpendLimit,
    ) -> Result<Option<FetchQuotaReservation>, FetchAccessError> {
        if reserved_units == 0 {
            return Ok(None);
        }
        let mut ledger = self.quota_store.load(caller_id)?;
        prune_ledger(&mut ledger, now_ms, spend.window);
        if ledger.entries.len() >= MAX_FETCH_SPEND_LEDGER_ENTRIES {
            return Err(FetchAccessError::QuotaExceeded {
                retry_after_ms: spend_retry_after_ms(&ledger, now_ms, spend.window),
                message: format!(
                    "fetch spend ledger reached its {MAX_FETCH_SPEND_LEDGER_ENTRIES}-entry limit"
                ),
            });
        }
        let used = ledger
            .entries
            .iter()
            .fold(0_u64, |acc, entry| acc.saturating_add(entry.units));
        if used.saturating_add(reserved_units) > spend.max_units {
            return Err(FetchAccessError::QuotaExceeded {
                retry_after_ms: spend_retry_after_ms(&ledger, now_ms, spend.window),
                message: "fetch token spend quota exceeded".to_string(),
            });
        }
        let reservation = FetchQuotaReservation {
            caller_id,
            id: reservation_id.clone(),
            reserved_units,
        };
        ledger.entries.push(SpendEntry::pending(
            reservation_id,
            input_commitment,
            reserved_units,
        ));
        if let Err(error) = self.quota_store.put(caller_id, &ledger) {
            return Err(FetchAccessError::AdmissionReservationIndeterminate {
                authority: AdmissionRollbackAuthority(reservation),
                message: error.to_string(),
            });
        }
        Ok(Some(reservation))
    }
}

fn reserved_units(
    request: &FetchRequestView,
    route_policy: &FetchRoutePolicy,
) -> Result<u64, FetchAccessError> {
    let requested = request.max_output_units.ok_or_else(|| {
        FetchAccessError::Denied(
            "fetch request must set max output units for quota-controlled routes".to_string(),
        )
    })?;
    Ok(match route_policy.max_output_units {
        Some(limit) => requested.min(limit),
        None => requested,
    })
}

fn prune_ledger(ledger: &mut SpendLedger, now_ms: u64, window: Duration) {
    let window_ms = u64::try_from(window.as_millis()).unwrap_or(u64::MAX);
    ledger.entries.retain(|entry| {
        entry.units != 0
            && (entry.lifecycle() != SpendLifecycle::Spent
                || now_ms.saturating_sub(entry.at_ms) < window_ms)
    });
}

fn spend_retry_after_ms(ledger: &SpendLedger, now_ms: u64, window: Duration) -> Option<u64> {
    if ledger
        .entries
        .iter()
        .any(|entry| entry.lifecycle() != SpendLifecycle::Spent)
    {
        return None;
    }
    let window_ms = u64::try_from(window.as_millis()).unwrap_or(u64::MAX);
    ledger
        .entries
        .iter()
        .map(|entry| entry.at_ms.saturating_add(window_ms).saturating_sub(now_ms))
        .filter(|retry| *retry > 0)
        .min()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FetchAdmission {
    pub reservation: Option<FetchQuotaReservation>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FetchQuotaReservation {
    pub caller_id: ProducerId,
    pub id: String,
    pub reserved_units: u64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CallerAccess {
    pub public_key: PublicKey,
    pub routes: RouteSet,
    pub request_rate: Option<RequestRateLimit>,
    pub spend: Option<SpendLimit>,
}

impl CallerAccess {
    pub fn allow_all(public_key: PublicKey) -> Self {
        Self {
            public_key,
            routes: RouteSet::All(FetchRoutePolicy::default()),
            request_rate: None,
            spend: None,
        }
    }

    pub fn explicit(
        public_key: PublicKey,
        routes: impl IntoIterator<Item = FetchRouteGrant>,
    ) -> Self {
        Self {
            public_key,
            routes: RouteSet::explicit(routes),
            request_rate: None,
            spend: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RouteSet {
    All(FetchRoutePolicy),
    Explicit(HashMap<FetchRoute, FetchRoutePolicy>),
}

impl RouteSet {
    pub fn explicit(routes: impl IntoIterator<Item = FetchRouteGrant>) -> Self {
        Self::Explicit(
            routes
                .into_iter()
                .map(|grant| (grant.route, grant.policy))
                .collect(),
        )
    }

    fn policy_for(&self, route: &FetchRoute) -> Option<&FetchRoutePolicy> {
        match self {
            Self::All(policy) => Some(policy),
            Self::Explicit(routes) => routes.get(route),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FetchRoute {
    pub service: String,
    pub method: String,
}

impl FetchRoute {
    pub fn new(service: impl Into<String>, method: impl Into<String>) -> Self {
        Self {
            service: service.into(),
            method: method.into(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FetchRouteGrant {
    pub route: FetchRoute,
    pub policy: FetchRoutePolicy,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FetchRoutePolicy {
    pub allowed_models: Option<BTreeSet<String>>,
    pub max_output_units: Option<u64>,
}

impl FetchRoutePolicy {
    /// The policy admitting exactly what both `self` and `other` admit:
    /// model allowlists intersect when both are set (otherwise the one that
    /// is set applies), and output limits take the minimum.
    pub fn intersect(&self, other: &Self) -> Self {
        Self {
            allowed_models: match (&self.allowed_models, &other.allowed_models) {
                (Some(a), Some(b)) => Some(a.intersection(b).cloned().collect()),
                (Some(a), None) => Some(a.clone()),
                (None, b) => b.clone(),
            },
            max_output_units: match (self.max_output_units, other.max_output_units) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (a, b) => a.or(b),
            },
        }
    }

    pub(crate) fn validate(&self, request: &FetchRequestView) -> Result<(), FetchAccessError> {
        if let Some(models) = &self.allowed_models {
            let Some(model) = &request.model else {
                return Err(FetchAccessError::Denied(
                    "fetch request model is required for this route".to_string(),
                ));
            };
            if !models.contains(model) {
                return Err(FetchAccessError::Denied(format!(
                    "fetch model {model} is not authorized for this route"
                )));
            }
        }
        if let Some(max_output_units) = self.max_output_units {
            let requested = request.max_output_units.ok_or_else(|| {
                FetchAccessError::Denied(
                    "fetch request must set max output units for this route".to_string(),
                )
            })?;
            if requested > max_output_units {
                return Err(FetchAccessError::Denied(format!(
                    "fetch request max output units {requested} exceed route limit {max_output_units}"
                )));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct RequestRateLimit {
    pub capacity: f64,
    pub refill_per_sec: f64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SpendLimit {
    pub max_units: u64,
    pub window: Duration,
}

#[derive(Clone, Debug)]
pub enum FetchQuotaStoreBackend {
    Memory(MemoryFetchQuotaStore),
    Fs(FsFetchQuotaStore),
}

impl FetchQuotaStoreBackend {
    pub fn memory() -> Self {
        Self::Memory(MemoryFetchQuotaStore::default())
    }

    pub fn fs(root: impl Into<PathBuf>) -> Self {
        Self::Fs(FsFetchQuotaStore::new(root))
    }

    fn init(&self) -> Result<(), FetchAccessError> {
        match self {
            Self::Memory(_) => Ok(()),
            Self::Fs(store) => {
                let store = store.clone();
                crate::private_fs::run_blocking_io(move || store.init())
                    .map_err(FetchAccessError::Io)?
            }
        }
    }

    fn load(&self, caller_id: ProducerId) -> Result<SpendLedger, FetchAccessError> {
        match self {
            Self::Memory(store) => store.load(caller_id),
            Self::Fs(store) => {
                let store = store.clone();
                crate::private_fs::run_blocking_io(move || store.load(caller_id))
                    .map_err(FetchAccessError::Io)?
            }
        }
    }

    fn put(&self, caller_id: ProducerId, ledger: &SpendLedger) -> Result<(), FetchAccessError> {
        match self {
            Self::Memory(store) => store.put(caller_id, ledger),
            Self::Fs(store) => {
                let store = store.clone();
                let ledger = ledger.clone();
                crate::private_fs::run_blocking_io(move || store.put(caller_id, &ledger))
                    .map_err(FetchAccessError::Io)?
            }
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct MemoryFetchQuotaStore {
    ledgers: std::sync::Arc<std::sync::Mutex<HashMap<ProducerId, SpendLedger>>>,
    #[cfg(test)]
    faults: std::sync::Arc<MemoryFetchQuotaStoreFaults>,
}

#[cfg(test)]
#[derive(Debug, Default)]
struct MemoryFetchQuotaStoreFaults {
    puts: std::sync::atomic::AtomicUsize,
    fail_put_before: std::sync::atomic::AtomicUsize,
    fail_put_after: std::sync::atomic::AtomicUsize,
}

impl MemoryFetchQuotaStore {
    #[cfg(test)]
    pub(crate) fn fail_put_number(&self, put: usize) {
        assert!(put > 0, "fault injection uses one-based put numbers");
        self.faults
            .fail_put_before
            .store(put, std::sync::atomic::Ordering::SeqCst);
    }

    #[cfg(test)]
    pub(crate) fn fail_put_after_write_number(&self, put: usize) {
        assert!(put > 0, "fault injection uses one-based put numbers");
        self.faults
            .fail_put_after
            .store(put, std::sync::atomic::Ordering::SeqCst);
    }

    #[cfg(test)]
    pub(crate) fn puts(&self) -> usize {
        self.faults.puts.load(std::sync::atomic::Ordering::SeqCst)
    }

    #[cfg(test)]
    pub(crate) fn entry_count(&self, caller_id: ProducerId) -> usize {
        self.load(caller_id)
            .expect("fetch quota memory store should remain readable")
            .entries
            .len()
    }

    fn load(&self, caller_id: ProducerId) -> Result<SpendLedger, FetchAccessError> {
        let ledgers = self.ledgers.lock().map_err(|_| {
            FetchAccessError::Store("fetch quota memory store lock is poisoned".to_string())
        })?;
        Ok(ledgers.get(&caller_id).cloned().unwrap_or_default())
    }

    fn put(&self, caller_id: ProducerId, ledger: &SpendLedger) -> Result<(), FetchAccessError> {
        #[cfg(test)]
        let put = self
            .faults
            .puts
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
            + 1;
        #[cfg(test)]
        if self
            .faults
            .fail_put_before
            .compare_exchange(
                put,
                0,
                std::sync::atomic::Ordering::SeqCst,
                std::sync::atomic::Ordering::SeqCst,
            )
            .is_ok()
        {
            return Err(FetchAccessError::Io(io::Error::other(format!(
                "injected fetch quota put failure {put}"
            ))));
        }
        let mut ledgers = self.ledgers.lock().map_err(|_| {
            FetchAccessError::Store("fetch quota memory store lock is poisoned".to_string())
        })?;
        ledgers.insert(caller_id, ledger.clone());
        #[cfg(test)]
        if self
            .faults
            .fail_put_after
            .compare_exchange(
                put,
                0,
                std::sync::atomic::Ordering::SeqCst,
                std::sync::atomic::Ordering::SeqCst,
            )
            .is_ok()
        {
            return Err(FetchAccessError::Io(io::Error::other(format!(
                "injected fetch quota post-write failure {put}"
            ))));
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct FsFetchQuotaStore {
    root: PathBuf,
    /// Every clone belongs to one cooperating executor ownership claim. A
    /// separately constructed store has a separate claim and must fail while
    /// this root directory inode is locked, including when the competing
    /// executable has no Evaluate feature.
    owner: std::sync::Arc<std::sync::Mutex<Option<fs::File>>>,
}

impl FsFetchQuotaStore {
    /// Opens a quota root owned by one cooperating executor process.
    ///
    /// Atomic replacement provides crash-safe persistence, not multi-process
    /// transactions. The process-lifetime root lock below is what makes each
    /// load/modify/replace sequence part of one serialized executor instead of
    /// two cooperating processes' lost update. It is advisory and requires a
    /// stable path beneath trusted ancestors; same-user malicious code can
    /// ignore it or replace names used by later path-based access.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            owner: std::sync::Arc::new(std::sync::Mutex::new(None)),
        }
    }

    fn init(&self) -> Result<(), FetchAccessError> {
        self.ensure_owned()
    }

    fn ensure_owned(&self) -> Result<(), FetchAccessError> {
        let mut owner = self.owner.lock().map_err(|_| {
            FetchAccessError::Store("fetch quota owner lock is poisoned".to_string())
        })?;
        if owner.is_some() {
            return Ok(());
        }

        crate::private_fs::create_private_dir_all(&self.root).map_err(FetchAccessError::Io)?;
        let root_directory =
            crate::private_fs::open_directory(&self.root).map_err(FetchAccessError::Io)?;
        match root_directory.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => {
                return Err(FetchAccessError::Io(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    format!(
                        "fetch quota store at {} is already open by another executor",
                        self.root.display()
                    ),
                )));
            }
            Err(TryLockError::Error(error)) => return Err(FetchAccessError::Io(error)),
        }
        crate::private_fs::make_directory_private(&root_directory).map_err(FetchAccessError::Io)?;
        *owner = Some(root_directory);
        Ok(())
    }

    fn path(&self, caller_id: ProducerId) -> PathBuf {
        self.root.join(format!("{}.dagcbor", caller_id.digest()))
    }

    fn load(&self, caller_id: ProducerId) -> Result<SpendLedger, FetchAccessError> {
        self.ensure_owned()?;
        let path = self.path(caller_id);
        let bytes =
            match crate::private_fs::read_bounded_regular_file(&path, MAX_FETCH_SPEND_LEDGER_BYTES)
            {
                Ok(bytes) => bytes,
                Err(err) if err.kind() == io::ErrorKind::NotFound => {
                    return Ok(SpendLedger::default());
                }
                Err(err) => return Err(FetchAccessError::Io(err)),
            };
        decode_dag_cbor(&bytes).map_err(|err| {
            FetchAccessError::Store(format!("fetch quota ledger decode failed: {err}"))
        })
    }

    fn put(&self, caller_id: ProducerId, ledger: &SpendLedger) -> Result<(), FetchAccessError> {
        self.ensure_owned()?;
        let bytes = canonical_dag_cbor(ledger).map_err(|err| {
            FetchAccessError::Store(format!("fetch quota ledger encode failed: {err}"))
        })?;
        if bytes.len() > MAX_FETCH_SPEND_LEDGER_BYTES {
            return Err(FetchAccessError::Store(format!(
                "fetch quota ledger is {} bytes, over the {MAX_FETCH_SPEND_LEDGER_BYTES}-byte limit",
                bytes.len()
            )));
        }
        atomic_replace(&self.path(caller_id), &bytes)
    }
}

fn atomic_replace(path: &Path, bytes: &[u8]) -> Result<(), FetchAccessError> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("quota");
    let tmp = parent.join(format!(
        ".{file_name}.{}.{}.tmp",
        std::process::id(),
        Uuid::new_v4().simple()
    ));

    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)
            .map_err(FetchAccessError::Io)?;
        file.write_all(bytes).map_err(FetchAccessError::Io)?;
        file.sync_all().map_err(FetchAccessError::Io)?;
        drop(file);
        fs::rename(&tmp, path).map_err(FetchAccessError::Io)?;
        #[cfg(unix)]
        hellas_private::sync_directory(parent).map_err(FetchAccessError::Io)?;
        Ok(())
    })();

    let _ = fs::remove_file(&tmp);
    result
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
struct SpendLedger {
    entries: Vec<SpendEntry>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SpendLifecycle {
    Pending,
    Dispatched,
    Cancelling,
    Spent,
}

impl std::fmt::Display for SpendLifecycle {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => formatter.write_str("pending"),
            Self::Dispatched => formatter.write_str("dispatched"),
            Self::Cancelling => formatter.write_str("cancelling"),
            Self::Spent => formatter.write_str("spent"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct SpendEntry {
    id: String,
    at_ms: u64,
    units: u64,
    /// Mirrors lifecycle for compatibility with the short-lived intermediate
    /// schema that learned `reserved`; the actual predecessor ignores it and
    /// is protected by unresolved entries' `at_ms = u64::MAX`.
    #[serde(default)]
    reserved: bool,
    /// Absent in the actual legacy format, whose entries are conservatively
    /// recovered as a full fresh window because their state is unknowable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    lifecycle: Option<SpendLifecycle>,
    /// Required for new Pending entries so startup recovery can remove a marker
    /// created immediately before a crash at the activation boundary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    input_commitment: Option<[u8; 32]>,
}

impl SpendEntry {
    fn pending(id: String, input_commitment: InputCommitment, units: u64) -> Self {
        Self {
            id,
            // The actual predecessor schema sees only id/at_ms/units. MAX
            // therefore makes old readers retain unresolved work forever
            // instead of silently aging it during a downgrade.
            at_ms: u64::MAX,
            units,
            reserved: true,
            lifecycle: Some(SpendLifecycle::Pending),
            input_commitment: Some(*input_commitment.as_bytes()),
        }
    }

    fn lifecycle(&self) -> SpendLifecycle {
        // The real legacy format had no `reserved` or `lifecycle` field, so an
        // absent lifecycle cannot distinguish in-flight from completed spend.
        // Stay fail-closed until startup recovery charges one fresh window.
        self.lifecycle.unwrap_or(SpendLifecycle::Dispatched)
    }

    fn mark_dispatched(&mut self) {
        self.at_ms = u64::MAX;
        self.reserved = true;
        self.lifecycle = Some(SpendLifecycle::Dispatched);
    }

    fn mark_cancelling(&mut self) {
        self.at_ms = u64::MAX;
        self.reserved = true;
        self.lifecycle = Some(SpendLifecycle::Cancelling);
    }

    fn mark_spent(&mut self, units: u64, at_ms: u64) {
        self.at_ms = at_ms;
        self.units = units;
        self.reserved = false;
        self.lifecycle = Some(SpendLifecycle::Spent);
    }
}

#[derive(Debug, thiserror::Error)]
pub enum FetchAccessError {
    #[error("fetch access denied: {0}")]
    Denied(String),
    #[error("{message}")]
    QuotaExceeded {
        retry_after_ms: Option<u64>,
        message: String,
    },
    #[error(
        "fetch completion reported {billable_units} billable units, exceeding its {reserved_units}-unit reservation"
    )]
    BillableUnitsExceedReservation {
        billable_units: u64,
        reserved_units: u64,
    },
    #[error("fetch quota reservation `{0}` disappeared before reconciliation")]
    MissingReservation(String),
    #[error("{message}")]
    AdmissionReservationIndeterminate {
        #[doc(hidden)]
        authority: AdmissionRollbackAuthority,
        message: String,
    },
    #[error(
        "fetch quota reservation `{id}` is {actual}, but this operation requires it to be {expected}"
    )]
    InvalidReservationLifecycle {
        id: String,
        expected: &'static str,
        actual: String,
    },
    #[error("fetch quota store error: {0}")]
    Store(String),
    #[error("fetch quota store I/O error: {0}")]
    Io(#[source] io::Error),
}

/// Opaque outside this crate: external callers may propagate the public error,
/// but cannot manufacture rollback authority for an arbitrary reservation.
#[doc(hidden)]
#[derive(Debug)]
pub struct AdmissionRollbackAuthority(FetchQuotaReservation);

impl FetchAccessError {
    /// The actor must retain this authority until it has cancelled a Pending
    /// reservation whose admission write returned an ambiguous error.
    pub(crate) const fn admission_reservation(&self) -> Option<&FetchQuotaReservation> {
        match self {
            Self::AdmissionReservationIndeterminate { authority, .. } => Some(&authority.0),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests;
