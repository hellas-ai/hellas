//! One response's live authority, serialized with each carrier write.
use super::*;
use crate::endpoint_lock::OwnedEndpointGuard;
use crate::work::admission::Cancellation;
use std::{io, task::Context};

pub(crate) struct Delivery {
    pub(super) id: Digest,
    pub(super) authorization: GrantJobAuthorizationV1,
    access: Access,
    cancellation: Cancellation,
    cache: Option<std::sync::Weak<ResultCache>>,
}
impl Delivery {
    pub(super) fn verify(
        store: &NodeStore,
        access: &Access,
        request: &DeliverResultRequest,
        now: UnixMillis,
    ) -> Result<Self, WorkRefused> {
        let id = digest(&request.work_id)?;
        let channel = ChannelId(digest(
            &request
                .route
                .as_ref()
                .ok_or_else(|| refused(GrantRefusalCode::Unauthorized))?
                .channel_id,
        )?);
        authorize_route(channel, request.route.as_ref())?;
        access.authorize_channel(store, channel, now)?;
        let book = store
            .state()
            .channel(channel)
            .ok_or_else(|| refused(GrantRefusalCode::Unauthorized))?
            .job_book();
        let authorization = book
            .job_by_id(id)
            .map(|j| *j.authorization())
            .or_else(|| book.terminal_by_id(id).map(|t| t.outcome.authorization))
            .ok_or_else(|| refused(GrantRefusalCode::OutputUnavailable))?;
        let delivery = Self {
            id,
            authorization,
            access: access.clone(),
            cancellation: Cancellation::new(),
            cache: None,
        };
        let def = store
            .state()
            .grant(authorization.grant_id)
            .ok_or_else(|| refused(GrantRefusalCode::Unauthorized))?;
        delivery.current(store, now)?;
        def.admit().map_err(NodeStoreError::from)?;
        Ok(delivery)
    }
    fn current(&self, store: &NodeStore, now: UnixMillis) -> Result<UnixMillis, WorkRefused> {
        let a = &self.authorization;
        store.state().check_resource(a)?;
        let expires = self.access.authorize_channel(store, a.channel_id, now)?;
        let book = store
            .state()
            .channel(a.channel_id)
            .ok_or_else(|| refused(GrantRefusalCode::Unauthorized))?
            .job_book();
        let retained = book
            .job_by_id(self.id)
            .map(|j| j.authorization())
            .or_else(|| {
                book.terminal_by_id(self.id)
                    .map(|t| &t.outcome.authorization)
            });
        if retained != Some(a) {
            return Err(refused(GrantRefusalCode::OutputUnavailable));
        }
        let expires = expires.min(UnixMillis(a.delivery_deadline_ms.0.saturating_add(1)));
        if now >= expires {
            return Err(refused(GrantRefusalCode::Expired));
        }
        Ok(expires)
    }

    /// A committed loss of rights ends this response even if rights are later
    /// restored. Revisions that retain its exact permission do not invalidate it.
    pub(crate) fn refresh(
        &self,
        store: &NodeStore,
        now: UnixMillis,
    ) -> Result<UnixMillis, WorkRefused> {
        let current = self.current(store, now);
        if current.is_err() {
            self.cancellation.cancel();
        }
        let result =
            current.and_then(|expires| {
                if self.cancellation.is_cancelled() {
                    Err(refused(GrantRefusalCode::Revoked))
                } else if self.cache.as_ref().is_some_and(|cache| {
                    cache.upgrade().is_none_or(|cache| !cache.retained_at(now))
                }) {
                    self.cancellation.cancel();
                    Err(refused(GrantRefusalCode::OutputUnavailable))
                } else {
                    Ok(expires)
                }
            });
        if result.is_err() {
            let mut decision = self.access.decision("work.delivery.refresh");
            self.access.observe(&mut decision, store, now);
            decision.finish_work(result)
        } else {
            result
        }
    }
    pub(crate) fn cancellation(&self) -> &Cancellation {
        &self.cancellation
    }
}

impl GrantService {
    pub(super) async fn bind_delivery(
        &self,
        access: &Access,
        request: &DeliverResultRequest,
    ) -> Result<Arc<Delivery>, WorkRefused> {
        let mut decision = access.decision("work.delivery");
        let result = async {
            let mut store = self.node.writer().await?;
            access.observe(&mut decision, &store, self.node.observed_time(&store));
            self.inner
                .lock()
                .map_err(|_| refused(GrantRefusalCode::StorageUnavailable))?
                .status
                .check()?;
            let now = self.node.observed_time(&store);
            let mut delivery = Delivery::verify(&store, access, request, now)?;
            delivery.cache = self
                .inner
                .lock()
                .map_err(|_| refused(GrantRefusalCode::StorageUnavailable))?
                .live
                .get(&delivery.id)
                .filter(|live| live.cache.retained_at(now))
                .map(|live| Arc::downgrade(&live.cache));
            store
                .register_delivery(delivery, now)
                .map_err(WorkRefused::from)
        }
        .await;
        decision.finish_work(result)
    }
    pub(super) fn delivery_authority(
        &self,
        delivery: Arc<Delivery>,
    ) -> hellas_wire::WriteAuthority {
        hellas_wire::WriteAuthority::new(DeliveryWriter {
            service: self.clone(),
            cancelled: {
                let delivery = delivery.clone();
                Box::pin(async move { delivery.cancellation.cancelled().await })
            },
            delivery,
            pending: None,
            changed: Box::pin(self.node.changed.clone().notified_owned()),
            timer: None,
            denied: false,
        })
    }
}

struct DeliveryWriter {
    service: GrantService,
    delivery: Arc<Delivery>,
    pending: Option<BoxFuture<'static, Result<OwnedEndpointGuard<NodeStore>, ()>>>,
    changed: BoxFuture<'static, ()>,
    cancelled: BoxFuture<'static, ()>,
    timer: Option<Pin<Box<tokio::time::Sleep>>>,
    denied: bool,
}
fn denied() -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, "delivery authority ended")
}
impl hellas_wire::WriteAuthorization for DeliveryWriter {
    fn poll_write(
        &mut self,
        cx: &mut Context<'_>,
        write: &mut dyn FnMut(&mut Context<'_>) -> Poll<io::Result<usize>>,
    ) -> Poll<io::Result<usize>> {
        if self.denied || self.cancelled.as_mut().poll(cx).is_ready() {
            self.denied = true;
            self.pending = None;
            return Poll::Ready(Err(denied()));
        }
        while self.changed.as_mut().poll(cx).is_ready() {
            self.changed = Box::pin(self.service.node.changed.clone().notified_owned());
        }
        let pending = self.pending.get_or_insert_with(|| {
            let store = self.service.node.store.clone();
            Box::pin(async move { store.lock_owned().await })
        });
        let store = std::task::ready!(pending.as_mut().poll(cx));
        self.pending = None;
        let Ok(store) = store else {
            self.denied = true;
            return Poll::Ready(Err(denied()));
        };
        let now = self.service.node.observed_time(&store);
        let current = self
            .service
            .inner
            .lock()
            .ok()
            .and_then(|held| held.status.check().ok())
            .and_then(|()| self.delivery.refresh(&store, now).ok());
        let Some(expires) = current else {
            self.denied = true;
            return Poll::Ready(Err(denied()));
        };
        let remaining = Duration::from_millis(expires.0.saturating_sub(now.0).max(1));
        let timer = self
            .timer
            .get_or_insert_with(|| Box::pin(tokio::time::sleep(remaining)));
        timer
            .as_mut()
            .reset(tokio::time::Instant::now() + remaining);
        let _ = timer.as_mut().poll(cx);
        // The store guard stays local through this one nonblocking handoff.
        // Pending releases it and the next carrier attempt checks current state.
        let result = write(cx);
        drop(store);
        result
    }
}
