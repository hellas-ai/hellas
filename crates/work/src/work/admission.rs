//! Executor capacity is shared across funding models. A grant receives a
//! non-cloneable queue permit before acceptance; only dispatch consumes its
//! journal callback. The physical invocation owns the permit through teardown.
use super::BackendFault;
use hellas_rpc::protocol::work_grant::records::GrantClass;
use std::time::Instant;
use tokio::sync::OwnedSemaphorePermit;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapacityDomain {
    Gpu,
    Fetch,
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
pub struct WorkAdmission {
    permit: Option<WorkPermit>,
    grant: Option<GrantDispatch>,
}
struct GrantDispatch {
    class: GrantClass,
    deadline: Instant,
    dispatch: Dispatch,
}
impl std::fmt::Debug for WorkAdmission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WorkAdmission")
            .field("permit", &self.permit)
            .field("grant_class", &self.grant.as_ref().map(|g| g.class))
            .field("deadline", &self.deadline())
            .finish_non_exhaustive()
    }
}
impl WorkAdmission {
    pub(crate) fn payment() -> Self {
        Self {
            permit: None,
            grant: None,
        }
    }
    pub(crate) fn grant(
        permit: WorkPermit,
        class: GrantClass,
        deadline: Instant,
        dispatch: Dispatch,
    ) -> Self {
        Self {
            permit: Some(permit),
            grant: Some(GrantDispatch {
                class,
                deadline,
                dispatch,
            }),
        }
    }
    pub fn is_owed(&self) -> bool {
        self.grant.is_none()
    }
    pub fn deadline(&self) -> Option<Instant> {
        self.grant.as_ref().map(|g| g.deadline)
    }
    pub fn needs_permit(&self) -> bool {
        self.permit.is_none()
    }
    pub fn attach_payment_permit(&mut self, permit: WorkPermit) -> Result<(), BackendFault> {
        if self.grant.is_some() || self.permit.is_some() {
            return Err(BackendFault::new("capacity already reserved"));
        }
        self.permit = Some(permit);
        Ok(())
    }
    /// Call once, only when this capacity domain can start the invocation.
    /// Failure drops its queue reservation without authorizing backend work.
    pub fn dispatch(self) -> Result<RunningWork, BackendFault> {
        let started = Instant::now();
        let deadline = self.deadline();
        if let Some(grant) = self.grant {
            if started >= grant.deadline {
                return Err(BackendFault::new("grant dispatch deadline passed"));
            }
            (grant.dispatch)()?;
        }
        Ok(RunningWork {
            _permit: self.permit,
            started,
            deadline,
        })
    }
}
/// Moved into the actual worker; a dropped client future never frees this slot.
#[derive(Debug)]
pub struct RunningWork {
    _permit: Option<WorkPermit>,
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
            Err(BackendFault::new("grant execution deadline passed"))
        } else {
            Ok(())
        }
    }
}
