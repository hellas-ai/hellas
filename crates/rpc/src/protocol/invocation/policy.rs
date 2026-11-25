//! Owner-approved application admission and common per-job bounds.
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

use super::{bound, compute, domain_is, encode, error, fetch::FetchAdmission};
use crate::protocol::value::{CanonicalDecodeError, decode_canonical_dag_cbor};
use crate::{Application, ContentId, ProgramManifest, Retention};

const DOMAIN: &str = "hellas.invocation.policy.v2";
pub const MAX_POLICY_BYTES: usize = 64 * 1024;
pub const MAX_ADMISSIONS: usize = 64;
pub const MAX_COMPUTE_PROGRAMS: usize = 64;

/// A Hub model repository, with neither revision nor path.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct HubRepo(String);

impl TryFrom<String> for HubRepo {
    type Error = CanonicalDecodeError;
    fn try_from(id: String) -> Result<Self, Self::Error> {
        let valid = |part: &str| {
            !matches!(part, "" | "." | "..")
                && part
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"-_.".contains(&c))
        };
        if id.len() > 256
            || !id
                .split_once('/')
                .is_some_and(|(org, repo)| valid(org) && valid(repo))
        {
            return Err(error("invalid Hub repository name"));
        }
        Ok(Self(id))
    }
}
impl From<HubRepo> for String {
    fn from(repo: HubRepo) -> String {
        repo.0
    }
}
impl HubRepo {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One entry per distinct model asset. Missing origins are explicitly unproven.
pub struct ModelOrigins {
    model: ContentId,
    assets: Vec<BTreeSet<HubRepo>>,
}
impl ModelOrigins {
    pub fn new(
        model: &compute::Model,
        files: &BTreeMap<crate::ContentRef, BTreeSet<HubRepo>>,
    ) -> Result<Self, CanonicalDecodeError> {
        Ok(Self {
            model: model.content_id()?,
            assets: model
                .assets
                .iter()
                .map(|asset| files.get(&asset.object).cloned().unwrap_or_default())
                .collect(),
        })
    }
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
    pub repos: Vec<HubRepo>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub pure_setup_entries: BTreeSet<String>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Accept,
    Reject,
    NeedsOrigins,
}

impl Match {
    pub fn evaluate(&self, manifest: &ProgramManifest, origins: Option<&ModelOrigins>) -> Decision {
        if manifest.application().adaptor() != compute::ADAPTOR
            || manifest.model().is_none()
            || self
                .evaluator
                .as_ref()
                .is_some_and(|e| e != manifest.application().evaluator())
            || self.program.is_some_and(|p| p != manifest.content_id())
            || self.model.is_some_and(|m| Some(m) != manifest.model())
        {
            return Decision::Reject;
        }
        if self.repos.is_empty() {
            return Decision::Accept;
        }
        let Some(origins) = origins else {
            return Decision::NeedsOrigins;
        };
        if Some(origins.model) == manifest.model()
            && !origins.assets.is_empty()
            && origins
                .assets
                .iter()
                .all(|repos| self.repos.iter().any(|repo| repos.contains(repo)))
        {
            Decision::Accept
        } else {
            Decision::Reject
        }
    }
    fn validate(&self) -> Result<(), CanonicalDecodeError> {
        if let Some(evaluator) = &self.evaluator {
            Application::new(evaluator.clone(), compute::ADAPTOR)
                .map_err(|e| error(e.to_string()))?;
        }
        if self.repos.len() > MAX_COMPUTE_PROGRAMS || self.repos.windows(2).any(|w| w[0] >= w[1]) {
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
    Compute { rules: Vec<Match> },
    Fetch { admission: FetchAdmission },
}
impl Admission {
    /// Admit exact Compute manifests for one evaluator with the owner's pure setup entries.
    pub fn compute_only(
        programs: &[ProgramManifest],
        entries: &[&str],
    ) -> Result<Self, CanonicalDecodeError> {
        let [first, ..] = programs else {
            return Err(error("compute admission requires a nonempty program list"));
        };
        let application = first.application();
        if application.adaptor() != compute::ADAPTOR
            || programs.iter().any(|p| p.application() != application)
        {
            return Err(error("admitted programs must share one Compute evaluator"));
        }
        let entries: BTreeSet<_> = entries.iter().map(|s| (*s).to_owned()).collect();
        Ok(Self::Compute {
            rules: programs
                .iter()
                .map(|manifest| Match {
                    evaluator: Some(application.evaluator().into()),
                    program: Some(manifest.content_id()),
                    pure_setup_entries: entries.clone(),
                    ..Default::default()
                })
                .collect(),
        })
    }

    pub fn evaluator(evaluator: String) -> Self {
        Self::Compute {
            rules: vec![Match {
                evaluator: Some(evaluator),
                ..Default::default()
            }],
        }
    }
    pub const fn capacity_domain(&self) -> CapacityDomain {
        match self {
            Self::Compute { .. } => CapacityDomain::Gpu,
            Self::Fetch { .. } => CapacityDomain::Fetch,
        }
    }
    /// Compute bytes/results are durable. Paid Fetch admits ephemeral requests
    /// and keeps their bodies in memory.
    pub const fn retention(&self) -> Retention {
        match self {
            Self::Compute { .. } => Retention::Retain,
            Self::Fetch { .. } => Retention::Ephemeral,
        }
    }
    pub fn evaluate(&self, manifest: &ProgramManifest, origins: Option<&ModelOrigins>) -> Decision {
        match self {
            Self::Compute { rules } => {
                let mut decision = Decision::Reject;
                for rule in rules {
                    match rule.evaluate(manifest, origins) {
                        Decision::Accept => return Decision::Accept,
                        Decision::NeedsOrigins => decision = Decision::NeedsOrigins,
                        Decision::Reject => {}
                    }
                }
                decision
            }
            Self::Fetch { admission } if manifest == &admission.contract.manifest() => {
                Decision::Accept
            }
            Self::Fetch { .. } => Decision::Reject,
        }
    }
    pub fn validate(&self) -> Result<(), CanonicalDecodeError> {
        match self {
            Self::Compute { rules } => {
                if rules.is_empty() || rules.len() > MAX_COMPUTE_PROGRAMS {
                    return Err(error("require a bounded nonempty list of Compute rules"));
                }
                let mut seen = BTreeSet::new();
                for rule in rules {
                    rule.validate()?;
                    if !seen.insert(encode(rule)?) {
                        return Err(error("duplicate Compute rule"));
                    }
                }
                Ok(())
            }
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
            .flat_map(|admission| match admission {
                Admission::Compute { rules } => rules.as_slice(),
                Admission::Fetch { .. } => &[],
            })
    }

    /// Whether this policy permits arbitrary source programs for a matching model.
    pub fn admits_any_program(&self) -> bool {
        self.compute_rules().any(|rule| rule.program.is_none())
    }
    pub fn validate(&self) -> Result<(), CanonicalDecodeError> {
        self.limits.validate()?;
        if self.admissions.is_empty() || self.admissions.len() > MAX_ADMISSIONS {
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
    /// Whether any otherwise matching rule requires verified asset provenance.
    pub fn needs_model_origins(&self, manifest: &ProgramManifest) -> bool {
        self.compute_rules()
            .any(|rule| rule.evaluate(manifest, None) == Decision::NeedsOrigins)
    }
    pub fn pure_setup_entries(
        &self,
        manifest: &ProgramManifest,
        origins: Option<&ModelOrigins>,
    ) -> BTreeSet<String> {
        self.compute_rules()
            .filter(|r| r.evaluate(manifest, origins) == Decision::Accept)
            .flat_map(|r| r.pure_setup_entries.iter().cloned())
            .collect()
    }

    pub fn admits_manifest(
        &self,
        manifest: &ProgramManifest,
        origins: Option<&ModelOrigins>,
    ) -> bool {
        self.admissions
            .iter()
            .any(|a| a.evaluate(manifest, origins) == Decision::Accept)
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
            .filter(move |a| a.evaluate(manifest, None) != Decision::Reject)
    }
}
