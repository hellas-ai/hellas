//! Request quota using the same admission accounting as Work resources.
use super::{Hook, Outcome, Refusal, Request, Reservation};
use hellas_admission::{Ask, Book, Charge, HoldId, Key, Limit, Meter, Spec, Usage, Window};
use std::{
    num::NonZeroU64,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

#[derive(Default)]
pub struct RequestLimit {
    rate: AtomicU64,
    next: AtomicU64,
    book: Arc<Mutex<Book>>,
}

impl RequestLimit {
    /// Called at the snapshot commit point. Existing holds retain their charge.
    pub fn configure(&self, requests_per_minute: Option<NonZeroU64>) {
        self.rate.store(
            requests_per_minute.map_or(0, NonZeroU64::get),
            Ordering::Release,
        );
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

impl Hook for RequestLimit {
    fn admit(&self, _: &Request) -> Result<Box<dyn Reservation>, Refusal> {
        let mut book = self.book.lock().map_err(|_| unavailable())?;
        let rate = self.rate.load(Ordering::Acquire);
        let mut bytes = [0; 32];
        let sequence = self
            .next
            .try_update(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_add(1))
            .map_err(|_| unavailable())?;
        bytes[..8].copy_from_slice(&sequence.to_be_bytes());
        let id = HoldId(bytes);
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
        book.configure(
            Key::Machine,
            Some(Spec {
                limits,
                ..Default::default()
            }),
        )
        .map_err(|_| unavailable())?;
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
        Ok(Box::new(Hold {
            id,
            book: self.book.clone(),
        }))
    }
}

struct Hold {
    id: HoldId,
    book: Arc<Mutex<Book>>,
}
impl Reservation for Hold {
    fn finish(self: Box<Self>, outcome: Outcome) {
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
        use super::super::{Jobs, Origin};
        for accepted in [false, true] {
            let limit = Arc::new(RequestLimit::default());
            limit.configure(NonZeroU64::new(1));
            let jobs = Arc::new(Jobs::new(vec![limit.clone()]));
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
        let request = super::super::Request {
            origin: super::super::Origin::Local,
            method: "POST".into(),
            path: "/test".into(),
        };
        limit.configure(NonZeroU64::new(2));
        let first = limit.admit(&request).unwrap();
        let second = limit.admit(&request).unwrap();
        assert!(limit.admit(&request).is_err());
        limit.configure(NonZeroU64::new(1));
        assert!(limit.admit(&request).is_err());
        assert_eq!(limit.book.lock().unwrap().holds().count(), 2);
        first.finish(Outcome::Rejected);
        let replacement = limit.admit(&request).unwrap();
        assert_eq!(limit.book.lock().unwrap().holds().count(), 2);
        second.finish(Outcome::Completed);
        assert!(limit.admit(&request).is_err());
        replacement.finish(Outcome::Rejected);
        limit.admit(&request).unwrap().finish(Outcome::Completed);
        assert!(limit.admit(&request).is_err());
    }
}
