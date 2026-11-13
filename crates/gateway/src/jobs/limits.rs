//! Request quota using the same admission accounting as Work resources.
use super::{Outcome, Refusal};
use hellas_admission::{Ask, Book, Charge, HoldId, Key, Limit, Meter, Spec, Usage, Window};
use std::{
    num::NonZeroU64,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

pub struct RequestLimit {
    next: AtomicU64,
    book: Arc<Mutex<Book>>,
}

impl Default for RequestLimit {
    fn default() -> Self {
        let limit = Self {
            next: AtomicU64::new(0),
            book: Default::default(),
        };
        limit.configure(None);
        limit
    }
}

impl RequestLimit {
    /// Called at the snapshot commit point. Existing holds retain their charge.
    pub fn configure(&self, requests_per_minute: Option<NonZeroU64>) {
        let rate = requests_per_minute.map_or(0, NonZeroU64::get);
        let limits = if rate == 0 {
            vec![]
        } else {
            vec![Limit {
                meter: Meter::Requests,
                window: Window::Bucket {
                    every: 60_000u64.div_ceil(rate),
                },
                amount: rate,
                reserve: 0,
                pace: None,
            }]
        };
        self.book
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .configure(
                Key::Machine,
                Some(Spec {
                    limits,
                    ..Default::default()
                }),
            )
            .expect("valid request quota");
    }
}

fn now() -> u64 {
    hellas_auth::authority::UnixMillis::now()
        .unwrap_or_default()
        .0
}
fn unavailable() -> Refusal {
    Refusal {
        status: axum::http::StatusCode::SERVICE_UNAVAILABLE,
        message: "request accounting unavailable".into(),
    }
}

impl RequestLimit {
    pub(super) fn admit(&self) -> Result<Hold, Refusal> {
        let mut book = self.book.lock().map_err(|_| unavailable())?;
        let mut bytes = [0; 32];
        let sequence = self
            .next
            .try_update(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_add(1))
            .map_err(|_| unavailable())?;
        bytes[..8].copy_from_slice(&sequence.to_be_bytes());
        let id = HoldId(bytes);
        book.admit(
            &Ask {
                id,
                leaf: Key::Machine,
                charge: Charge([1, 0, 0, 0, 0]),
                wait: false,
                deadline: None,
            },
            now(),
        )
        .map_err(|_| Refusal {
            status: axum::http::StatusCode::TOO_MANY_REQUESTS,
            message: "request quota exhausted".into(),
        })?;
        Ok(Hold {
            id,
            book: self.book.clone(),
        })
    }
}

pub(super) struct Hold {
    id: HoldId,
    book: Arc<Mutex<Book>>,
}
impl Hold {
    pub(super) fn finish(self, outcome: Outcome) {
        let mut book = self.book.lock().unwrap_or_else(|e| e.into_inner());
        match outcome {
            Outcome::Rejected | Outcome::Cancelled => {
                book.release(self.id);
            }
            Outcome::Completed | Outcome::Failed => {
                book.charge(self.id, Usage::Unknown, now());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cancellation_refunds_only_work_that_was_never_accepted() {
        use super::super::{Jobs, Origin, Request};
        for accepted in [false, true] {
            let limit = Arc::new(RequestLimit::default());
            limit.configure(NonZeroU64::new(1));
            let jobs = Arc::new(Jobs::new(limit.clone()));
            let request = Request {
                origin: Origin::Local,
                method: "POST".into(),
                path: "/test".into(),
            };
            let job = jobs.admit(&request).unwrap();
            if accepted {
                job.accepted();
            }
            assert!(jobs.cancel(job.id()));
            job.stopped();
            drop(job);
            assert_eq!(limit.book.lock().unwrap().holds().count(), 0);
            assert_eq!(jobs.admit(&request).is_err(), accepted);
        }
    }
    #[test]
    fn limit_changes_retain_reservations_and_rejected_work_releases_once() {
        let limit = RequestLimit::default();
        limit.configure(NonZeroU64::new(2));
        let first = limit.admit().unwrap();
        let second = limit.admit().unwrap();
        assert!(limit.admit().is_err());
        limit.configure(NonZeroU64::new(1));
        assert!(limit.admit().is_err());
        assert_eq!(limit.book.lock().unwrap().holds().count(), 2);
        first.finish(Outcome::Rejected);
        let replacement = limit.admit().unwrap();
        assert_eq!(limit.book.lock().unwrap().holds().count(), 2);
        second.finish(Outcome::Completed);
        assert!(limit.admit().is_err());
        replacement.finish(Outcome::Rejected);
        limit.admit().unwrap().finish(Outcome::Completed);
        assert!(limit.admit().is_err());
    }
}
