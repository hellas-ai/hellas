//! Owner-approved application admission and common per-job bounds.
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

use super::{bound, compute, domain_is, encode, error, fetch::FetchAdmission};
use crate::protocol::value::{CanonicalDecodeError, decode_canonical_dag_cbor};
use crate::{Application, ContentId, ProgramManifest, Retention};

const DOMAIN: &str = "hellas.invocation.policy.v2";
pub const MAX_POLICY_BYTES: usize = 64 * 1024;
pub const MAX_ADMISSIONS: usize = 64;
pub const MAX_COMPUTE_PROGRAMS: usize = 64;

/// A Hub model repository at its root, without a revision or file selector.
pub fn valid_hub_repo(id: &str) -> bool {
    let component = |s: &str| {
        !matches!(s, "" | "." | "..")
            && s.bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"-_.".contains(&c))
    };
    id.len() <= 256
        && id
            .split_once('/')
            .is_some_and(|(org, repo)| component(org) && component(repo))
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Match {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evaluator: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub program: Option<ContentId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<ContentId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub repos: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub pure_setup_entries: BTreeSet<String>,
}

impl Match {
    /// A caller selecting candidates can defer the receipt check. Provider admission
    /// supplies a set for every distinct asset in the manifest's verified model.
    pub fn matches(
        &self,
        manifest: &ProgramManifest,
        receipts: Option<&[BTreeSet<String>]>,
    ) -> bool {
        manifest.application().adaptor() == compute::ADAPTOR
            && manifest.model().is_some()
            && self
                .evaluator
                .as_deref()
                .is_none_or(|e| e == manifest.application().evaluator())
            && self.program.is_none_or(|p| p == manifest.content_id())
            && self.model.is_none_or(|m| Some(m) == manifest.model())
            && (self.repos.is_empty()
                || receipts.is_none_or(|assets| {
                    !assets.is_empty()
                        && assets
                            .iter()
                            .all(|sources| self.repos.iter().any(|repo| sources.contains(repo)))
                }))
    }
    fn validate(&self) -> Result<(), CanonicalDecodeError> {
        if let Some(evaluator) = &self.evaluator {
            Application::new(evaluator.clone(), compute::ADAPTOR)
                .map_err(|e| error(e.to_string()))?;
        }
        if self.repos.len() > MAX_COMPUTE_PROGRAMS
            || self.repos.iter().any(|id| !valid_hub_repo(id))
            || self.repos.windows(2).any(|w| w[0] >= w[1])
        {
            return Err(error(
                "match repositories must be bounded, unique and sorted",
            ));
        }
        if self.model.is_none() && self.program.is_none() && !self.pure_setup_entries.is_empty() {
            return Err(error(
                "setup cache permission requires an exact program or model",
            ));
        }
        for entry in &self.pure_setup_entries {
            super::label(entry)?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    pub max_upload_bytes: u64,
    pub max_output_bytes: u64,
    pub max_steps: u64,
    pub execution_timeout_ms: u64,
}
impl Limits {
    /// The most steps a Compute job emitting one 8-byte value per step, with
    /// no other outputs, may take: [`compute::Plan::validate_bounds`] bounds
    /// its steps and its output bytes.
    pub fn step_bound(&self) -> u64 {
        self.max_steps.min(
            self.max_output_bytes
                .min(super::MAX_INVOCATION_BYTES as u64)
                / 8,
        )
    }
    pub fn validate(&self) -> Result<(), CanonicalDecodeError> {
        if self.max_upload_bytes == 0
            || self.max_output_bytes == 0
            || self.max_steps == 0
            || self.execution_timeout_ms == 0
        {
            return Err(error("invocation resource bounds must be positive"));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapacityDomain {
    Gpu,
    Fetch,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Admission {
    Compute(Match),
    Fetch { admission: FetchAdmission },
}
impl Admission {
    /// Admit one exact executable and its approved setup entries.
    pub fn exact(
        manifest: &ProgramManifest,
        entries: &[&str],
    ) -> Result<Self, CanonicalDecodeError> {
        if manifest.application().adaptor() != compute::ADAPTOR || manifest.model().is_none() {
            return Err(error("exact Compute rule requires a model manifest"));
        }
        Ok(Self::Compute(Match {
            evaluator: Some(manifest.application().evaluator().into()),
            program: Some(manifest.content_id()),
            pure_setup_entries: entries.iter().map(|s| (*s).to_owned()).collect(),
            ..Default::default()
        }))
    }

    pub fn evaluator(evaluator: String) -> Self {
        Self::Compute(Match {
            evaluator: Some(evaluator),
            ..Default::default()
        })
    }
    pub const fn capacity_domain(&self) -> CapacityDomain {
        match self {
            Self::Compute(_) => CapacityDomain::Gpu,
            Self::Fetch { .. } => CapacityDomain::Fetch,
        }
    }
    /// Compute bytes/results are durable. Paid Fetch admits ephemeral requests
    /// and keeps their bodies in memory.
    pub const fn retention(&self) -> Retention {
        match self {
            Self::Compute(_) => Retention::Retain,
            Self::Fetch { .. } => Retention::Ephemeral,
        }
    }
    pub fn candidate(&self, manifest: &ProgramManifest) -> bool {
        match self {
            Self::Compute(rule) => rule.matches(manifest, None),
            Self::Fetch { admission } => manifest == &admission.contract.manifest(),
        }
    }
    pub fn validate(&self) -> Result<(), CanonicalDecodeError> {
        match self {
            Self::Compute(rule) => rule.validate(),
            Self::Fetch { admission } => admission.validate(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvocationPolicy {
    pub admissions: Vec<Admission>,
    pub limits: Limits,
}
impl InvocationPolicy {
    /// All Compute rules in this policy, in their signed order.
    pub fn compute_rules(&self) -> impl Iterator<Item = &Match> {
        self.admissions
            .iter()
            .filter_map(|admission| match admission {
                Admission::Compute(rule) => Some(rule),
                Admission::Fetch { .. } => None,
            })
    }

    /// Whether this policy permits arbitrary source programs for a matching model.
    pub fn admits_any_program(&self) -> bool {
        self.compute_rules().any(|rule| rule.program.is_none())
    }
    pub fn validate(&self) -> Result<(), CanonicalDecodeError> {
        self.limits.validate()?;
        let compute = self.compute_rules().count();
        let fetch = self.admissions.len() - compute;
        if self.admissions.is_empty()
            || fetch + compute.div_ceil(MAX_COMPUTE_PROGRAMS) > MAX_ADMISSIONS
        {
            return Err(error(
                "invocation policy requires bounded application admissions",
            ));
        }
        let mut seen = BTreeSet::new();
        for admission in &self.admissions {
            admission.validate()?;
            if !seen.insert(encode(admission)?) {
                return Err(error("duplicate invocation admission"));
            }
        }
        Ok(())
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, CanonicalDecodeError> {
        self.validate()?;
        let bytes = encode(&(DOMAIN, self))?;
        bound(&bytes, MAX_POLICY_BYTES)?;
        Ok(bytes)
    }
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CanonicalDecodeError> {
        bound(bytes, MAX_POLICY_BYTES)?;
        let (domain, policy): (String, Self) = decode_canonical_dag_cbor(bytes)?;
        domain_is(&domain, DOMAIN)?;
        policy.validate()?;
        Ok(policy)
    }
    pub fn content_id(&self) -> Result<ContentId, CanonicalDecodeError> {
        Ok(ContentId::hash(&self.canonical_bytes()?))
    }
    /// Union the setup permissions of rules actually satisfied by this model.
    pub fn admitted_setup(
        &self,
        manifest: &ProgramManifest,
        receipts: &[BTreeSet<String>],
    ) -> Option<BTreeSet<String>> {
        if manifest.application().adaptor() != compute::ADAPTOR {
            return self
                .candidates_for(manifest)
                .next()
                .map(|_| BTreeSet::new());
        }
        let mut rules = self
            .compute_rules()
            .filter(|r| r.matches(manifest, Some(receipts)))
            .peekable();
        rules.peek()?;
        Some(
            rules
                .flat_map(|r| r.pure_setup_entries.iter().cloned())
                .collect(),
        )
    }

    /// More than one route can admit the same Fetch manifest. Callers check the
    /// application's input against a matching admission rather than choosing
    /// the first manifest match and silently ignoring the remaining routes.
    pub fn candidates_for<'a>(
        &'a self,
        manifest: &ProgramManifest,
    ) -> impl Iterator<Item = &'a Admission> {
        self.admissions
            .iter()
            .filter(move |a| a.candidate(manifest))
    }
}
