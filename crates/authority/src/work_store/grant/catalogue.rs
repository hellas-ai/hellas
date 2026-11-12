//! Stable resource ownership and current policy; accepted policies stay in grant history.
use super::{NodeStoreError, State};
use crate::model::grant::{
    GrantJobAuthorizationV1,
    budget::BudgetNode,
    records::{GrantDef, GrantError, GrantPolicy},
};
use hellas_auth::authority::{ResourceId, Revision};

impl State {
    pub fn catalogue(&self) -> impl Iterator<Item = &GrantPolicy> {
        self.catalogue.values()
    }

    pub fn resource(&self, id: ResourceId) -> Option<&GrantPolicy> {
        self.catalogue.get(&id)
    }

    pub(super) fn configure_resource(&mut self, policy: GrantPolicy) -> Result<(), NodeStoreError> {
        policy.validate()?;
        if self
            .ledger
            .node(BudgetNode::Account(policy.account).key())
            .is_none()
            || self
                .catalogue
                .values()
                .any(|p| p.resource != policy.resource && p.name == policy.name)
        {
            return Err(GrantError::OutOfScope.into());
        }
        if let Some(old) = self.resource(policy.resource) {
            if old.account != policy.account {
                return Err(GrantError::OutOfScope.into());
            }
            if old.pricing != policy.pricing
                && !policy.pricing.revision.follows(Some(old.pricing.revision))
            {
                return Err(GrantError::Revision(old.pricing.revision).into());
            }
            if !policy.revision.follows(Some(old.revision)) {
                return Err(GrantError::Revision(old.revision).into());
            }
        } else if policy.revision != Revision(1)
            || policy.pricing.revision != Revision(1)
            || self.catalogue.len() >= super::state::MAX_RESOURCES
        {
            return Err(GrantError::StateCapacity.into());
        }
        self.resources.entry(policy.resource).or_default();
        self.catalogue.insert(policy.resource, policy);
        Ok(())
    }

    pub(super) fn check_resources(
        &self,
        grant: &GrantDef,
        current: bool,
    ) -> Result<(), NodeStoreError> {
        let BudgetNode::Subject { pool, .. } = grant.budget else {
            return Err(GrantError::OutOfScope.into());
        };
        let pool = super::ledger::definition(&self.ledger, BudgetNode::Pool(pool))
            .ok_or(GrantError::OutOfScope)?;
        for policy in &grant.policies {
            let configured = self
                .resource(policy.resource)
                .ok_or(GrantError::OutOfScope)?;
            if pool.parent != Some(BudgetNode::Account(policy.account))
                || policy.account != configured.account
                || policy.revision > configured.revision
                || policy.pricing.revision > configured.pricing.revision
                || (policy.pricing.revision == configured.pricing.revision
                    && policy.pricing != configured.pricing)
                || ((current || policy.revision == configured.revision) && policy != configured)
            {
                return Err(GrantError::OutOfScope.into());
            }
        }
        Ok(())
    }

    /// New proposals require the current policy. Admitted work may retain its
    /// recorded terms; grant authority, deadlines and health are checked separately.
    pub(crate) fn check_resource(&self, a: &GrantJobAuthorizationV1) -> Result<(), NodeStoreError> {
        if self
            .resources
            .get(&a.resource_id)
            .is_some_and(|health| health.quarantined)
        {
            return Err(GrantError::Quarantined.into());
        }
        let accepted = self.policy_for(a)?;
        let current = self.resource(a.resource_id).ok_or(GrantError::OutOfScope)?;
        let work = crate::model::grant::grant_work_id(self.network, a);
        let admitted = self.admission(a.channel_id, work).is_some();
        if admitted
            && current.config_change == crate::model::grant::records::ConfigChange::Keep
            && self
                .grant(a.grant_id)
                .is_some_and(|g| g.policies.iter().any(|p| p.resource == a.resource_id))
        {
            return Ok(());
        }
        if current != accepted
            || self
                .grant(a.grant_id)
                .is_none_or(|g| !g.policies.contains(accepted))
        {
            return Err(GrantError::OutOfScope.into());
        }
        Ok(())
    }
}
