//! What a node's own configuration owns: the budget tree down to accounts and
//! the resource catalogue. Pools, subjects, allowances and grants stay
//! owner-administered runtime state.
use super::{
    budget::{BudgetDef, BudgetNode, Limit},
    records::{GrantError, GrantPolicy, MAX_WORK_POLICIES},
};
use hellas_auth::authority::{ResourceId, Revision};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, num::NonZeroU16};

/// Concurrency and meter limits of a configuration-owned budget node.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfiguredBudget {
    pub max_in_flight: NonZeroU16,
    pub limits: Vec<Limit>,
}

/// A validated node configuration. Serving resources requires a machine
/// budget; every resource's account is declared, and every declared account is
/// used. The default serves nothing and configures no budgets.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeConfiguration {
    machine: Option<ConfiguredBudget>,
    accounts: Vec<(ResourceId, ConfiguredBudget)>,
    resources: Vec<GrantPolicy>,
}

/// The daemon's redacted document, committed with its authority configuration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigurationDocument {
    pub revision: Revision,
    pub document: String,
    /// Private restart data. Control replies return only `document`.
    pub secrets: ConfigurationSecrets,
}

#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigurationSecrets(pub BTreeMap<String, BTreeMap<String, String>>);

impl std::fmt::Debug for ConfigurationSecrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<redacted>")
    }
}

impl NodeConfiguration {
    pub fn new(
        machine: Option<ConfiguredBudget>,
        accounts: BTreeMap<ResourceId, ConfiguredBudget>,
        resources: Vec<GrantPolicy>,
    ) -> Result<Self, GrantError> {
        let configuration = Self {
            machine,
            accounts: accounts.into_iter().collect(),
            resources,
        };
        configuration.validate()?;
        Ok(configuration)
    }

    pub fn validate(&self) -> Result<(), GrantError> {
        let Self {
            machine,
            accounts,
            resources,
        } = self;
        let mut names = std::collections::BTreeSet::new();
        let mut ids = std::collections::BTreeSet::new();
        if resources.len() > MAX_WORK_POLICIES
            || accounts.len() > MAX_WORK_POLICIES
            || resources
                .iter()
                .any(|p| !names.insert(&p.name) || !ids.insert(p.resource))
            || (machine.is_none() && !resources.is_empty())
            || accounts
                .iter()
                .map(|(id, _)| id)
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != accounts.len()
            || resources
                .iter()
                .any(|p| !accounts.iter().any(|(id, _)| *id == p.account))
            || accounts
                .iter()
                .any(|(account, _)| !resources.iter().any(|p| p.account == *account))
        {
            return Err(GrantError::Limits);
        }
        for policy in resources {
            policy.validate()?;
        }
        Ok(())
    }

    pub fn machine(&self) -> Option<&ConfiguredBudget> {
        self.machine.as_ref()
    }

    pub fn accounts(&self) -> impl Iterator<Item = &(ResourceId, ConfiguredBudget)> {
        self.accounts.iter()
    }

    pub fn resources(&self) -> &[GrantPolicy] {
        &self.resources
    }

    pub fn resource(&self, name: &str) -> Option<&GrantPolicy> {
        self.resources.iter().find(|p| p.name == name)
    }

    /// The account definitions to apply, given each account's current one.
    pub fn account_changes(
        &self,
        current: impl Fn(BudgetNode) -> Option<BudgetDef>,
    ) -> Result<Vec<BudgetDef>, GrantError> {
        let mut changes = Vec::new();
        for (account, budget) in &self.accounts {
            let node = BudgetNode::Account(*account);
            let revision = match current(node) {
                None => Revision(1),
                Some(old)
                    if old.limits == budget.limits && old.max_in_flight == budget.max_in_flight =>
                {
                    continue;
                }
                Some(old) => old.revision.next().ok_or(GrantError::Limits)?,
            };
            changes.push(BudgetDef {
                node,
                parent: Some(BudgetNode::Machine),
                revision,
                limits: budget.limits.clone(),
                max_in_flight: budget.max_in_flight,
            });
        }
        Ok(changes)
    }
}
