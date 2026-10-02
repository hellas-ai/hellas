//! Capacity follows an invocation from queue admission through worker teardown.
use super::BackendFault;
use std::{future::Future, time::Instant};
use tokio::sync::OwnedSemaphorePermit;

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

type Dispatch = Box<dyn FnOnce() -> Result<(), BackendFault> + Send>;

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

    pub(crate) fn grant(permit: WorkPermit, deadline: Instant, dispatch: Dispatch) -> Self {
        Self(Authorization::Grant(AdmittedWork {
            permit,
            funding: Funding::Grant { deadline, dispatch },
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
    pub fn dispatch(self) -> Result<RunningWork, BackendFault> {
        let started = Instant::now();
        let deadline = match self.funding {
            Funding::Payment => None,
            Funding::Grant { deadline, dispatch } => {
                if started >= deadline {
                    return Err(AdmissionError::Deadline.into());
                }
                dispatch()?;
                Some(deadline)
            }
        };
        Ok(RunningWork {
            _permit: self.permit,
            started,
            deadline,
        })
    }
}

/// Owned by the physical invocation until worker teardown has finished.
#[derive(Debug)]
pub struct RunningWork {
    _permit: WorkPermit,
    started: Instant,
    deadline: Option<Instant>,
}
impl RunningWork {
    pub fn deadline(&self) -> Option<Instant> {
        self.deadline
    }
    pub fn deadline_with(&self, maximum: std::time::Duration) -> Instant {
        let provider = self.started + maximum;
        self.deadline
            .map_or(provider, |deadline| deadline.min(provider))
    }
    pub fn elapsed_millis(&self) -> u64 {
        self.started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64
    }
    pub fn check_deadline(&self) -> Result<(), BackendFault> {
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
        let running = admitted.dispatch().unwrap();
        assert_eq!(capacity.available_permits(), 0);
        drop(running);
        assert_eq!(capacity.available_permits(), 1);
    }

    #[tokio::test]
    async fn grants_keep_the_acceptance_reservation_and_dispatch_before_execution() {
        let capacity = Arc::new(Semaphore::new(1));
        let dispatched = Arc::new(AtomicBool::new(false));
        let observed = dispatched.clone();
        let admission = WorkAdmission::grant(
            permit(&capacity, CapacityDomain::Fetch),
            Instant::now() + Duration::from_secs(10),
            Box::new(move || {
                observed.store(true, Ordering::SeqCst);
                Ok(())
            }),
        );
        let admitted = admission
            .reserve(CapacityDomain::Fetch, async {
                panic!("grant reserved payment capacity")
            })
            .await
            .unwrap();
        assert!(!dispatched.load(Ordering::SeqCst));
        let running = admitted.dispatch().unwrap();
        assert!(dispatched.load(Ordering::SeqCst));
        assert_eq!(capacity.available_permits(), 0);
        drop(running);
        assert_eq!(capacity.available_permits(), 1);
    }

    #[tokio::test]
    async fn expired_grants_release_capacity_without_dispatching() {
        let capacity = Arc::new(Semaphore::new(1));
        let admission = WorkAdmission::grant(
            permit(&capacity, CapacityDomain::Gpu),
            Instant::now(),
            Box::new(|| panic!("expired grant dispatched")),
        );
        let admitted = admission
            .reserve(CapacityDomain::Gpu, async { panic!("reserved twice") })
            .await
            .unwrap();
        let error = admitted.dispatch().unwrap_err();
        assert!(matches!(
            error.source().unwrap().downcast_ref::<AdmissionError>(),
            Some(AdmissionError::Deadline)
        ));
        assert_eq!(capacity.available_permits(), 1);
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
