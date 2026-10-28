//! Revocable output bodies and a body-free commitment to accepted progress.
use super::*;
use hellas_channel::work::admission::Cancellation;

pub(crate) struct ResultCache {
    body: Mutex<Body>,
    cancellation: Cancellation,
    changed: Arc<Notify>,
    delivery_changed: Arc<Notify>,
}
pub(super) struct Body {
    pub(super) retained: bool,
    pub(super) events: Vec<OutputEventEnvelope>,
    pub(super) bytes: usize,
    expires: UnixMillis,
}
impl Body {
    fn discard(&mut self) {
        self.retained = false;
        self.events = Vec::new();
        self.bytes = 0;
    }
}
impl ResultCache {
    pub(super) fn new(expires: UnixMillis, delivery_changed: Arc<Notify>) -> Arc<Self> {
        Arc::new_cyclic(|weak: &std::sync::Weak<Self>| {
            let weak = weak.clone();
            Self {
                body: Mutex::new(Body {
                    retained: true,
                    events: Vec::new(),
                    bytes: 0,
                    expires,
                }),
                cancellation: Cancellation::with_cleanup(move || {
                    if let Some(cache) = weak.upgrade() {
                        // Poisoned bodies cannot be served; still release their allocation.
                        let mut body = match cache.body.lock() {
                            Ok(body) => body,
                            Err(poisoned) => poisoned.into_inner(),
                        };
                        body.discard();
                        drop(body);
                        cache.delivery_changed.notify_waiters();
                        cache.changed.notify_waiters();
                    }
                }),
                changed: Arc::new(Notify::new()),
                delivery_changed,
            }
        })
    }
    pub(crate) fn cancellation(&self) -> Cancellation {
        self.cancellation.clone()
    }
    pub(crate) fn retained(&self) -> bool {
        !self.cancellation.is_cancelled() && self.body.lock().is_ok_and(|body| body.retained)
    }
    pub(crate) fn retained_at(&self, now: UnixMillis) -> bool {
        let retained = !self.cancellation.is_cancelled()
            && self
                .body
                .lock()
                .is_ok_and(|body| body.retained && now < body.expires);
        if !retained {
            self.cancel();
        }
        retained
    }
    pub(crate) fn set_deadline(&self, expires: UnixMillis) -> bool {
        let Ok(mut body) = self.body.lock() else {
            return false;
        };
        if !body.retained || self.cancellation.is_cancelled() {
            return false;
        }
        if body.expires != expires {
            body.expires = expires;
            self.changed.notify_waiters();
        }
        true
    }
    pub(super) fn lock(&self) -> Result<std::sync::MutexGuard<'_, Body>, NodeStoreError> {
        self.body.lock().map_err(|_| NodeStoreError::WriterPoisoned)
    }
    pub(super) fn bytes(&self) -> usize {
        self.body.lock().map_or(usize::MAX, |body| body.bytes)
    }
    pub(super) fn cancel(&self) {
        self.cancellation.cancel();
    }

    /// A weak timer never owns the node writer, service, body or execution across
    /// a wait. Cache drop wakes it; deadline changes are installed by the writer.
    pub(super) fn monitor(self: &Arc<Self>, clock: GrantClock) {
        let weak = Arc::downgrade(self);
        let changed = self.changed.clone();
        let cancellation = self.cancellation.clone();
        tokio::spawn(async move {
            loop {
                let notified = changed.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                let now = clock();
                let expires = {
                    let Some(cache) = weak.upgrade() else {
                        return;
                    };
                    match cache.body.lock() {
                        Ok(body) if body.retained && now < body.expires => Some(body.expires),
                        Ok(mut body) => {
                            body.discard();
                            None
                        }
                        Err(_) => None,
                    }
                };
                let Some(expires) = expires else {
                    cancellation.cancel();
                    return;
                };
                let remaining = Duration::from_millis(expires.0.saturating_sub(now.0).max(1));
                tokio::select! {
                    () = cancellation.cancelled() => return,
                    () = notified => {},
                    () = tokio::time::sleep(remaining) => {},
                }
            }
        });
    }
}
impl Drop for ResultCache {
    fn drop(&mut self) {
        self.changed.notify_waiters();
        self.delivery_changed.notify_waiters();
    }
}

pub(super) struct Prefix {
    count: usize,
    digest: Digest,
}
impl Default for Prefix {
    fn default() -> Self {
        Self {
            count: 0,
            digest: Digest::hash(b"hellas.work.grant.prefix.v1"),
        }
    }
}
impl Prefix {
    pub(super) fn push(
        &mut self,
        event: &OutputEventEnvelope,
    ) -> Result<(), hellas_channel::model::work::PaidWorkError> {
        let encoded = encode_transcript(std::slice::from_ref(event))?;
        self.digest = hellas_auth::hash_tuple(
            "hellas.work.grant.prefix.v1",
            &[self.digest.as_bytes(), &encoded],
        );
        self.count = self.count.saturating_add(1);
        Ok(())
    }
    pub(super) fn matches(
        &self,
        events: &[OutputEventEnvelope],
    ) -> Result<bool, hellas_channel::model::work::PaidWorkError> {
        let Some(events) = events.get(..self.count) else {
            return Ok(false);
        };
        let mut prefix = Self::default();
        for event in events {
            prefix.push(event)?;
        }
        Ok(prefix.digest == self.digest)
    }
}
