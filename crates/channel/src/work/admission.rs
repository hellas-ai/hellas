//! Capacity follows an invocation from queue admission through worker teardown.
use super::BackendFault;
use std::{future::Future, time::Instant};
use tokio::sync::OwnedSemaphorePermit;
mod cancellation;
pub(crate) use cancellation::{CancelOnFailure, Cancellation};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapacityDomain {
    Gpu,
    Fetch,
}

#[derive(Debug, thiserror::Error)]
pub enum AdmissionError {
    #[error("{0:?} execution is unavailable")]
    Unsupported(CapacityDomain),
    #[error("executor capacity is exhausted")]
    Capacity,
    #[error("executor is closed")]
    Closed,
    #[error("reserved {actual:?} capacity for {expected:?} work")]
    WrongDomain {
        expected: CapacityDomain,
        actual: CapacityDomain,
    },
    #[error("grant execution deadline passed")]
    Deadline,
    #[error("execution authority was cancelled")]
    Cancelled,
}

#[derive(Debug)]
pub struct WorkPermit {
    domain: CapacityDomain,
    _permit: OwnedSemaphorePermit,
}
impl WorkPermit {
    pub fn new(domain: CapacityDomain, permit: OwnedSemaphorePermit) -> Self {
        Self {
            domain,
            _permit: permit,
        }
    }
    pub fn domain(&self) -> CapacityDomain {
        self.domain
    }
}

type Dispatch = futures::future::BoxFuture<'static, Result<(), BackendFault>>;

/// Payment obligations wait for capacity; grants reserve it before acceptance.
#[derive(Debug)]
pub struct WorkAdmission(Authorization);

#[derive(Debug)]
enum Authorization {
    Payment,
    Grant(AdmittedWork),
}

impl WorkAdmission {
    pub(crate) fn payment() -> Self {
        Self(Authorization::Payment)
    }

    pub(crate) fn grant(
        permit: WorkPermit,
        deadline: Instant,
        cancellation: Cancellation,
        dispatch: impl Future<Output = Result<(), BackendFault>> + Send + 'static,
    ) -> Self {
        Self(Authorization::Grant(AdmittedWork {
            permit,
            funding: Funding::Grant {
                deadline,
                cancellation,
                dispatch: Box::pin(dispatch),
            },
        }))
    }

    /// Convert authorized work into queued work with capacity in the right domain.
    /// The payment reservation is polled only for payment-funded work.
    pub async fn reserve(
        self,
        domain: CapacityDomain,
        payment: impl Future<Output = Result<WorkPermit, BackendFault>>,
    ) -> Result<AdmittedWork, BackendFault> {
        let admitted = match self.0 {
            Authorization::Payment => AdmittedWork::payment(payment.await?),
            Authorization::Grant(admitted) => admitted,
        };
        if admitted.permit.domain != domain {
            return Err(AdmissionError::WrongDomain {
                expected: domain,
                actual: admitted.permit.domain,
            }
            .into());
        }
        Ok(admitted)
    }
}

/// Only admitted work can be dispatched. Its permit cannot be detached.
pub struct AdmittedWork {
    permit: WorkPermit,
    funding: Funding,
}
enum Funding {
    Payment,
    Grant {
        deadline: Instant,
        cancellation: Cancellation,
        dispatch: Dispatch,
    },
}
impl std::fmt::Debug for AdmittedWork {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdmittedWork")
            .field("permit", &self.permit)
            .field("is_owed", &self.is_owed())
            .finish_non_exhaustive()
    }
}
impl AdmittedWork {
    pub fn payment(permit: WorkPermit) -> Self {
        Self {
            permit,
            funding: Funding::Payment,
        }
    }
    pub fn is_owed(&self) -> bool {
        matches!(self.funding, Funding::Payment)
    }

    /// Durably authorize dispatch before any backend preparation or execution.
    pub async fn dispatch(self) -> Result<RunningWork, BackendFault> {
        let started = Instant::now();
        let (deadline, cancellation) = match self.funding {
            Funding::Payment => (None, None),
            Funding::Grant {
                deadline,
                cancellation,
                dispatch,
            } => {
                if cancellation.is_cancelled() {
                    return Err(AdmissionError::Cancelled.into());
                }
                if started >= deadline {
                    return Err(AdmissionError::Deadline.into());
                }
                dispatch.await?;
                if cancellation.is_cancelled() {
                    return Err(AdmissionError::Cancelled.into());
                }
                if Instant::now() >= deadline {
                    return Err(AdmissionError::Deadline.into());
                }
                (Some(deadline), Some(cancellation))
            }
        };
        Ok(RunningWork {
            _permit: self.permit,
            started,
            deadline,
            cancellation,
        })
    }
}

/// Owned by the physical invocation until worker teardown has finished.
#[derive(Debug)]
pub struct RunningWork {
    _permit: WorkPermit,
    started: Instant,
    deadline: Option<Instant>,
    cancellation: Option<Cancellation>,
}
impl RunningWork {
    pub fn deadline(&self) -> Option<Instant> {
        self.deadline
    }
    /// The signed grant deadline; work funded without one stops after `fallback`.
    pub fn deadline_or(&self, fallback: std::time::Duration) -> Instant {
        self.deadline.unwrap_or(self.started + fallback)
    }
    pub fn elapsed_millis(&self) -> u64 {
        self.started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64
    }
    /// Wait for authority cancellation without releasing physical ownership.
    /// Paid work retains its settlement duty and has no grant cancellation signal.
    pub async fn cancelled(&self) {
        match &self.cancellation {
            Some(cancellation) => cancellation.cancelled().await,
            None => std::future::pending().await,
        }
    }
    pub fn check_active(&self) -> Result<(), BackendFault> {
        if self
            .cancellation
            .as_ref()
            .is_some_and(Cancellation::is_cancelled)
        {
            return Err(AdmissionError::Cancelled.into());
        }
        if self
            .deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
        {
            Err(AdmissionError::Deadline.into())
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        error::Error,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        task::Poll,
        time::Duration,
    };
    use tokio::sync::Semaphore;

    fn permit(capacity: &Arc<Semaphore>, domain: CapacityDomain) -> WorkPermit {
        WorkPermit::new(domain, capacity.clone().try_acquire_owned().unwrap())
    }

    #[tokio::test]
    async fn payment_waits_for_capacity_and_holds_it_until_execution_ends() {
        let capacity = Arc::new(Semaphore::new(0));
        let mut waiting = std::pin::pin!(WorkAdmission::payment().reserve(
            CapacityDomain::Fetch,
            async {
                Ok(WorkPermit::new(
                    CapacityDomain::Fetch,
                    capacity.clone().acquire_owned().await.unwrap(),
                ))
            }
        ));
        assert!(matches!(futures::poll!(&mut waiting), Poll::Pending));
        capacity.add_permits(1);
        let admitted = waiting.await.unwrap();
        assert_eq!(capacity.available_permits(), 0);
        let running = admitted.dispatch().await.unwrap();
        assert_eq!(capacity.available_permits(), 0);
        drop(running);
        assert_eq!(capacity.available_permits(), 1);
    }

    #[tokio::test]
    async fn grants_keep_the_acceptance_reservation_and_dispatch_before_execution() {
        for cancel in [true, false] {
            let capacity = Arc::new(Semaphore::new(1));
            let dispatched = Arc::new(AtomicBool::new(false));
            let observed = dispatched.clone();
            let (commit, committed) = tokio::sync::oneshot::channel();
            let admission = WorkAdmission::grant(
                permit(&capacity, CapacityDomain::Fetch),
                Instant::now() + Duration::from_secs(10),
                Cancellation::new(),
                async move {
                    committed.await.unwrap();
                    observed.store(true, Ordering::SeqCst);
                    Ok(())
                },
            );
            let admitted = admission
                .reserve(CapacityDomain::Fetch, async {
                    panic!("grant reserved payment capacity")
                })
                .await
                .unwrap();
            assert!(!dispatched.load(Ordering::SeqCst));
            let mut dispatch = Box::pin(admitted.dispatch());
            assert!(futures::poll!(&mut dispatch).is_pending());
            assert_eq!(capacity.available_permits(), 0);
            assert!(!dispatched.load(Ordering::SeqCst));
            if cancel {
                drop(dispatch);
                assert!(commit.send(()).is_err());
                assert!(!dispatched.load(Ordering::SeqCst));
                assert_eq!(capacity.available_permits(), 1);
                continue;
            }
            commit.send(()).unwrap();
            let running = dispatch.await.unwrap();
            assert!(dispatched.load(Ordering::SeqCst));
            assert_eq!(capacity.available_permits(), 0);
            drop(running);
            assert_eq!(capacity.available_permits(), 1);
        }
    }

    #[tokio::test]
    async fn signed_grant_deadlines_are_not_clamped_to_the_payment_fallback() {
        let capacity = Arc::new(Semaphore::new(2));
        let fallback = Duration::from_secs(90);
        let signed = Instant::now() + Duration::from_secs(20 * 60);
        let running = WorkAdmission::grant(
            permit(&capacity, CapacityDomain::Fetch),
            signed,
            Cancellation::new(),
            async { Ok(()) },
        )
        .reserve(CapacityDomain::Fetch, async { panic!("reserved twice") })
        .await
        .unwrap()
        .dispatch()
        .await
        .unwrap();
        assert_eq!(running.deadline_or(fallback), signed);
        let paid = AdmittedWork::payment(permit(&capacity, CapacityDomain::Fetch))
            .dispatch()
            .await
            .unwrap();
        assert!(paid.deadline_or(fallback) <= Instant::now() + fallback);
    }

    #[tokio::test]
    async fn expired_grants_release_capacity_without_dispatching() {
        let capacity = Arc::new(Semaphore::new(1));
        let admission = WorkAdmission::grant(
            permit(&capacity, CapacityDomain::Gpu),
            Instant::now(),
            Cancellation::new(),
            async { panic!("expired grant dispatched") },
        );
        let admitted = admission
            .reserve(CapacityDomain::Gpu, async { panic!("reserved twice") })
            .await
            .unwrap();
        let error = admitted.dispatch().await.unwrap_err();
        assert!(matches!(
            error.source().unwrap().downcast_ref::<AdmissionError>(),
            Some(AdmissionError::Deadline)
        ));
        assert_eq!(capacity.available_permits(), 1);

        // A write can finish after the grant expires. It must not return an
        // execution permit even though its dispatch record is now durable.
        let deadline = Instant::now() + Duration::from_secs(1);
        let completed = Arc::new(AtomicBool::new(false));
        let observed = completed.clone();
        let admitted = WorkAdmission::grant(
            permit(&capacity, CapacityDomain::Gpu),
            deadline,
            Cancellation::new(),
            async move {
                tokio::time::sleep_until(deadline.into()).await;
                observed.store(true, Ordering::SeqCst);
                Ok(())
            },
        )
        .reserve(CapacityDomain::Gpu, async { panic!("reserved twice") })
        .await
        .unwrap();
        let error = admitted.dispatch().await.unwrap_err();
        assert!(completed.load(Ordering::SeqCst));
        assert!(matches!(
            error.source().unwrap().downcast_ref::<AdmissionError>(),
            Some(AdmissionError::Deadline)
        ));
        assert_eq!(capacity.available_permits(), 1);
    }

    #[tokio::test]
    async fn cancellation_survives_dispatch_and_keeps_capacity_until_teardown() {
        for at in ["queued", "committing", "running"] {
            let capacity = Arc::new(Semaphore::new(1));
            let cancellation = Cancellation::new();
            let (commit, committed) = tokio::sync::oneshot::channel();
            let admitted = WorkAdmission::grant(
                permit(&capacity, CapacityDomain::Fetch),
                Instant::now() + Duration::from_secs(30),
                cancellation.clone(),
                async {
                    committed.await.unwrap();
                    Ok(())
                },
            )
            .reserve(CapacityDomain::Fetch, async { panic!("reserved twice") })
            .await
            .unwrap();
            if at == "queued" {
                cancellation.cancel();
                assert!(admitted.dispatch().await.is_err());
            } else {
                let mut dispatch = Box::pin(admitted.dispatch());
                assert!(futures::poll!(&mut dispatch).is_pending());
                if at == "committing" {
                    cancellation.cancel();
                    assert!(futures::poll!(&mut dispatch).is_pending());
                    assert_eq!(capacity.available_permits(), 0);
                    commit.send(()).unwrap();
                    assert!(dispatch.await.is_err());
                } else {
                    commit.send(()).unwrap();
                    let running = dispatch.await.unwrap();
                    assert!(running.check_active().is_ok());
                    let mut waiting = Box::pin(running.cancelled());
                    assert!(futures::poll!(&mut waiting).is_pending());
                    cancellation.cancel();
                    waiting.await;
                    assert!(running.check_active().is_err());
                    assert_eq!(capacity.available_permits(), 0);
                    drop(running);
                }
            }
            assert_eq!(capacity.available_permits(), 1);
        }
    }

    #[tokio::test]
    async fn the_wrong_capacity_domain_is_refused_and_released() {
        let capacity = Arc::new(Semaphore::new(1));
        let error = WorkAdmission::payment()
            .reserve(CapacityDomain::Gpu, async {
                Ok(permit(&capacity, CapacityDomain::Fetch))
            })
            .await
            .unwrap_err();
        assert!(matches!(
            error.source().unwrap().downcast_ref::<AdmissionError>(),
            Some(AdmissionError::WrongDomain { .. })
        ));
        assert_eq!(capacity.available_permits(), 1);
    }
}
