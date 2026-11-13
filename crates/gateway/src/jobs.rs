//! Live requests, their reservations, cancellation and owned execution tasks.
use crate::{WorkGatewayBusy, WorkShutdownError};
use hellas_channel::work::admission::Cancellation;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio::sync::broadcast;
mod limits;
pub use limits::RequestLimit;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Origin {
    Http { credential: String },
    Iroh { peer: String },
    Local,
}

#[derive(Clone, Debug)]
pub struct Request {
    pub origin: Origin,
    pub method: String,
    pub path: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Completed,
    Failed,
    Rejected,
    Cancelled,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    Admitted,
    Running,
    Accepted,
    Cancelling,
    Finished,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Info {
    pub id: u64,
    pub origin: Origin,
    pub backend: Option<String>,
    pub state: State,
    pub outcome: Option<Outcome>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Event {
    Revision {
        revision: hellas_auth::authority::Revision,
    },
    Backend {
        id: String,
        down: bool,
        reason: String,
    },
    Job {
        job: Info,
    },
}

#[derive(Debug, thiserror::Error)]
#[error("{message}")]
pub struct Refusal {
    pub status: axum::http::StatusCode,
    pub message: String,
}
impl From<WorkGatewayBusy> for Refusal {
    fn from(_: WorkGatewayBusy) -> Self {
        Self {
            status: axum::http::StatusCode::SERVICE_UNAVAILABLE,
            message: "daemon is draining".into(),
        }
    }
}

pub struct Jobs {
    limit: Arc<RequestLimit>,
    state: Mutex<Table>,
    draining: tokio::sync::Mutex<()>,
    events: broadcast::Sender<Event>,
}
#[derive(Default)]
struct Table {
    closed: bool,
    next: u64,
    jobs: BTreeMap<u64, Entry>,
    failure: Option<Arc<tokio::task::JoinError>>,
}
struct Entry {
    job: Weak<Job>,
    info: Info,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}
impl Table {
    fn poll(&mut self, cx: &mut std::task::Context<'_>, finished_only: bool) {
        use std::{future::Future as _, pin::Pin, task::Poll};
        self.jobs.retain(|_, entry| {
            entry.tasks.retain_mut(|task| {
                if finished_only && !task.is_finished() {
                    return true;
                }
                match Pin::new(task).poll(cx) {
                    Poll::Pending => true,
                    Poll::Ready(Ok(())) => false,
                    Poll::Ready(Err(error)) => {
                        self.failure.get_or_insert_with(|| Arc::new(error));
                        false
                    }
                }
            });
            !entry.tasks.is_empty() || entry.job.strong_count() > 0
        });
    }
}
impl Default for Jobs {
    fn default() -> Self {
        Self::new(Arc::new(RequestLimit::default()))
    }
}
impl Jobs {
    pub fn new(limit: Arc<RequestLimit>) -> Self {
        Self {
            limit,
            state: Mutex::default(),
            draining: Default::default(),
            events: broadcast::channel(1024).0,
        }
    }

    /// Register work whose acceptance was recovered from a journal.
    pub fn recover(self: &Arc<Self>, request: &Request) -> Result<Arc<Job>, Refusal> {
        let job = self.register(request, None)?;
        job.accepted();
        Ok(job)
    }

    pub fn admit(self: &Arc<Self>, request: &Request) -> Result<Arc<Job>, Refusal> {
        self.register(request, Some(self.limit.admit()?))
    }

    fn register(
        self: &Arc<Self>,
        request: &Request,
        mut reservation: Option<limits::Hold>,
    ) -> Result<Arc<Job>, Refusal> {
        let admitted = (|| {
            let mut state = self.state.lock().map_err(|_| WorkGatewayBusy)?;
            if state.closed {
                return Err(WorkGatewayBusy);
            }
            state.next = state.next.checked_add(1).ok_or(WorkGatewayBusy)?;
            let id = state.next;
            state.poll(
                &mut std::task::Context::from_waker(futures::task::noop_waker_ref()),
                true,
            );
            let job = Arc::new(Job {
                id,
                jobs: self.clone(),
                stop: Cancellation::new(),
                accepted: AtomicBool::new(false),
                proposed: Arc::new(AtomicBool::new(false)),
                binding: Default::default(),
                reservation: Mutex::new(reservation.take()),
            });
            let info = Info {
                id,
                origin: request.origin.clone(),
                backend: None,
                state: State::Admitted,
                outcome: None,
            };
            let _ = self.events.send(Event::Job { job: info.clone() });
            state.jobs.insert(
                id,
                Entry {
                    job: Arc::downgrade(&job),
                    info,
                    tasks: vec![],
                },
            );
            Ok(job)
        })();
        if let Some(reservation) = reservation {
            reservation.finish(Outcome::Rejected);
        }
        admitted.map_err(Into::into)
    }

    /// Read the initial snapshot and subscribe under the same event lock.
    pub fn watch<T>(&self, read: impl FnOnce(Vec<Info>) -> T) -> (T, broadcast::Receiver<Event>) {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let jobs = state
            .jobs
            .values()
            .filter(|entry| entry.info.state != State::Finished)
            .map(|entry| entry.info.clone())
            .collect();
        (read(jobs), self.events.subscribe())
    }

    /// A snapshot or backend state change and its event have one ordering point.
    pub fn change(&self, change: impl FnOnce() -> Option<Event>) {
        let _state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(event) = change() {
            let _ = self.events.send(event);
        }
    }

    pub fn cancel(&self, id: u64) -> bool {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let Some(entry) = state.jobs.get_mut(&id) else {
            return false;
        };
        if entry.info.state == State::Finished {
            return false;
        }
        let Some(job) = entry.job.upgrade() else {
            return false;
        };
        job.stop.cancel();
        entry.info.state = State::Cancelling;
        let _ = self.events.send(Event::Job {
            job: entry.info.clone(),
        });
        // Drop outside the table lock: the last job reference finishes reservations.
        drop(state);
        drop(job);
        true
    }

    pub fn is_closed(&self) -> bool {
        self.state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .closed
    }

    pub fn close(&self) {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).closed = true;
    }

    /// Poll handles in place; cancelling a drain never detaches accepted work.
    pub async fn drain(&self) -> Result<(), WorkShutdownError> {
        self.close();
        let _draining = self.draining.lock().await;
        std::future::poll_fn(|cx| {
            let (mut state, poisoned) = match self.state.lock() {
                Ok(state) => (state, false),
                Err(error) => (error.into_inner(), true),
            };
            state.poll(cx, false);
            if state.jobs.values().any(|entry| !entry.tasks.is_empty()) {
                return std::task::Poll::Pending;
            }
            std::task::Poll::Ready(if let Some(error) = &state.failure {
                Err(WorkShutdownError::Task(error.clone()))
            } else if poisoned {
                Err(WorkShutdownError::Poisoned)
            } else {
                Ok(())
            })
        })
        .await
    }
}

pub struct Job {
    id: u64,
    jobs: Arc<Jobs>,
    stop: Cancellation,
    accepted: AtomicBool,
    proposed: Arc<AtomicBool>,
    pub(crate) binding: Mutex<Option<crate::routing::Pending>>,
    reservation: Mutex<Option<limits::Hold>>,
}
impl Job {
    pub fn proposal(&self) -> Arc<AtomicBool> {
        self.proposed.clone()
    }
    pub fn id(&self) -> u64 {
        self.id
    }
    pub fn is_cancelled(&self) -> bool {
        self.stop.is_cancelled()
    }
    pub async fn cancelled(&self) {
        self.stop.cancelled().await;
    }
    pub fn cancellation(&self) -> Cancellation {
        self.stop.clone()
    }
    pub fn running(&self, backend: &str) {
        self.update(|info| {
            info.backend = Some(backend.into());
            if info.state != State::Cancelling {
                info.state = State::Running;
            }
        });
    }
    pub fn pre_proposal_failure(&self) {
        self.update(|info| {
            info.state = State::Admitted;
            info.backend = None;
        });
    }
    pub fn accepted(&self) {
        self.proposed.store(true, Ordering::Release);
        self.accepted.store(true, Ordering::Release);
        self.update(|info| {
            if info.state != State::Cancelling {
                info.state = State::Accepted;
            }
        });
    }
    /// Cancellation after acceptance cannot certify that no work was done.
    pub fn stopped(&self) {
        self.finish(if self.accepted.load(Ordering::Acquire) {
            Outcome::Failed
        } else {
            Outcome::Cancelled
        });
    }
    fn update(&self, update: impl FnOnce(&mut Info)) {
        let mut state = self.jobs.state.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(entry) = state.jobs.get_mut(&self.id) {
            update(&mut entry.info);
            let _ = self.jobs.events.send(Event::Job {
                job: entry.info.clone(),
            });
        }
    }
    pub fn spawn(
        &self,
        backend: &str,
        future: impl std::future::Future<Output = ()> + Send + 'static,
    ) -> Result<(), WorkGatewayBusy> {
        let mut state = self.jobs.state.lock().map_err(|_| WorkGatewayBusy)?;
        if state.closed || self.is_cancelled() {
            return Err(WorkGatewayBusy);
        }
        let entry = state.jobs.get_mut(&self.id).ok_or(WorkGatewayBusy)?;
        if entry.info.state == State::Finished {
            return Err(WorkGatewayBusy);
        }
        entry.info.backend = Some(backend.into());
        entry.info.state = State::Running;
        let _ = self.jobs.events.send(Event::Job {
            job: entry.info.clone(),
        });
        entry.tasks.push(tokio::spawn(future));
        Ok(())
    }
    pub fn finish(&self, outcome: Outcome) {
        let reservation = self
            .reservation
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        if let Some(reservation) = reservation {
            self.update(|info| {
                info.state = State::Finished;
                info.outcome = Some(outcome);
            });
            reservation.finish(outcome);
        }
    }
}
impl Drop for Job {
    fn drop(&mut self) {
        let started = self
            .jobs
            .state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .jobs
            .get(&self.id)
            .is_some_and(|entry| entry.info.backend.is_some());
        self.finish(if started {
            Outcome::Failed
        } else if self.is_cancelled() {
            Outcome::Cancelled
        } else {
            Outcome::Rejected
        });
    }
}

#[cfg(test)]
mod tests;
