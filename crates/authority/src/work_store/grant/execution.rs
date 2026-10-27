//! Ephemeral cancellation handles; durable admission remains in the job journal.
use super::{NodeStore, NodeStoreError};
use crate::grant_service::{Access, ResultCache};
use crate::model::grant::{GrantJobAuthorizationV1, records::GrantError};
use hellas_auth::{Digest, authority::UnixMillis};
use hellas_channel::work::admission::{CancelOnFailure, Cancellation};

pub(super) struct ActiveExecution {
    authorization: GrantJobAuthorizationV1,
    access: Access,
    cancellation: Cancellation,
    cache: std::sync::Weak<ResultCache>,
}

impl NodeStore {
    /// Called under the writer after acceptance, before releasing it to mutation.
    pub(crate) fn register_execution(
        &mut self,
        id: Digest,
        authorization: GrantJobAuthorizationV1,
        access: Access,
        cache: &std::sync::Arc<ResultCache>,
        now: UnixMillis,
    ) -> Cancellation {
        let cancellation = cache.cancellation();
        self.executions.insert(
            id,
            ActiveExecution {
                authorization,
                access,
                cancellation: cancellation.clone(),
                cache: std::sync::Arc::downgrade(cache),
            },
        );
        self.refresh_execution(id, now);
        cancellation
    }

    pub(crate) fn refresh_execution(&self, id: Digest, now: UnixMillis) -> Option<UnixMillis> {
        let execution = self.executions.get(&id)?;
        if execution.cancellation.is_cancelled() {
            return None;
        }
        let Some(cache) = execution.cache.upgrade() else {
            execution.cancellation.cancel();
            return None;
        };
        match execution.expires(self, now) {
            Ok(expires) if cache.set_deadline(expires) => Some(expires),
            _ => {
                execution.cancellation.cancel();
                None
            }
        }
    }

    pub(super) fn refresh_executions(&mut self, now: UnixMillis) {
        for id in self.executions.keys() {
            self.refresh_execution(*id, now);
        }
        self.executions.retain(|_, execution| {
            execution
                .cache
                .upgrade()
                .is_some_and(|cache| cache.retained())
        });
    }

    pub(super) fn cancel_on_failure(&self) -> CancelOnFailure {
        CancelOnFailure(
            self.executions
                .values()
                .map(|e| e.cancellation.clone())
                .chain(
                    self.deliveries
                        .iter()
                        .filter_map(std::sync::Weak::upgrade)
                        .map(|delivery| delivery.cancellation().clone()),
                )
                .collect(),
        )
    }
}

impl ActiveExecution {
    fn expires(&self, store: &NodeStore, now: UnixMillis) -> Result<UnixMillis, NodeStoreError> {
        let a = &self.authorization;
        store.state().check_resource(a)?;
        let mut expires = self.access.authorize_channel(store, a.channel_id, now)?;
        let book = store
            .state()
            .channel(a.channel_id)
            .ok_or(GrantError::Unauthorized)?
            .job_book();
        let id = crate::model::grant::grant_work_id(store.state().network(), a);
        let phase = if let Some(job) = book.job_by_id(id) {
            expires = expires.min(a.terminal_deadline_ms);
            Some(job.phase())
        } else if book
            .terminal_by_id(id)
            .is_some_and(|t| &t.outcome.authorization == a)
        {
            expires = expires.min(UnixMillis(a.delivery_deadline_ms.0.saturating_add(1)));
            None
        } else {
            return Err(GrantError::Unauthorized.into());
        };
        let allowance = store
            .state()
            .grant(a.grant_id)
            .ok_or(GrantError::Unauthorized)?;
        if phase == Some(hellas_channel::work_store::JobPhase::Accepted) {
            allowance.admit()?;
        }
        if now >= expires {
            return Err(GrantError::Expired.into());
        }
        Ok(expires)
    }
}
