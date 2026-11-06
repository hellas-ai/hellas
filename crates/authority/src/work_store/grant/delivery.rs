//! Live response generations; weak entries never retain abandoned output.
use super::{NodeStore, NodeStoreError};
use crate::content::ContentBinding;
use crate::grant_service::Delivery;
use crate::model::grant::records::GrantError;
use hellas_auth::authority::UnixMillis;
use hellas_channel::work::admission::Cancellation;
use std::sync::{Arc, Weak};

pub(super) enum DeliveryEntry {
    Work(Weak<Delivery>),
    Content(Weak<ContentBinding>),
}
impl DeliveryEntry {
    pub(super) fn cancellation(&self) -> Option<Cancellation> {
        match self {
            Self::Work(w) => w.upgrade().map(|d| d.cancellation().clone()),
            Self::Content(w) => w.upgrade().map(|d| d.cancellation.clone()),
        }
    }
    fn refresh(&self, store: &NodeStore, now: UnixMillis) {
        match self {
            Self::Work(w) => {
                if let Some(d) = w.upgrade() {
                    let _ = d.refresh(store, now);
                }
            }
            Self::Content(w) => {
                if let Some(d) = w.upgrade() {
                    let _ = d.refresh(store, now);
                }
            }
        }
    }
}

const MAX_DELIVERIES: usize = 1024;

impl NodeStore {
    pub(crate) fn register_delivery(
        &mut self,
        delivery: Delivery,
        now: UnixMillis,
    ) -> Result<Arc<Delivery>, NodeStoreError> {
        // Expired, unpolled responses must not occupy capacity indefinitely.
        self.refresh_deliveries(now);
        if self.deliveries.len() >= MAX_DELIVERIES {
            return Err(GrantError::StateCapacity.into());
        }
        let delivery = Arc::new(delivery);
        self.deliveries
            .push(DeliveryEntry::Work(Arc::downgrade(&delivery)));
        Ok(delivery)
    }

    pub(crate) fn register_content(
        &mut self,
        binding: ContentBinding,
        now: UnixMillis,
    ) -> Result<Arc<ContentBinding>, NodeStoreError> {
        self.refresh_deliveries(now);
        if self.deliveries.len() >= MAX_DELIVERIES {
            return Err(GrantError::StateCapacity.into());
        }
        let binding = Arc::new(binding);
        self.deliveries
            .push(DeliveryEntry::Content(Arc::downgrade(&binding)));
        Ok(binding)
    }

    pub(super) fn refresh_deliveries(&mut self, now: UnixMillis) {
        for delivery in &self.deliveries {
            delivery.refresh(self, now);
        }
        self.prune_deliveries();
    }

    fn prune_deliveries(&mut self) {
        self.deliveries
            .retain(|weak| weak.cancellation().is_some_and(|c| !c.is_cancelled()));
    }
}
