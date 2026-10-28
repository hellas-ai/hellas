//! Live response generations; weak entries never retain abandoned output.
use super::{NodeStore, NodeStoreError};
use crate::grant_service::Delivery;
use crate::model::grant::records::GrantError;
use hellas_auth::authority::UnixMillis;
use std::sync::Arc;

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
        self.deliveries.push(Arc::downgrade(&delivery));
        Ok(delivery)
    }

    pub(super) fn refresh_deliveries(&mut self, now: UnixMillis) {
        for delivery in self.deliveries.iter().filter_map(std::sync::Weak::upgrade) {
            let _ = delivery.refresh(self, now);
        }
        self.prune_deliveries();
    }

    fn prune_deliveries(&mut self) {
        self.deliveries.retain(|weak| {
            weak.upgrade()
                .is_some_and(|delivery| !delivery.cancellation().is_cancelled())
        });
    }
}
