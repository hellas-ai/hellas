//! Owner-approved application admission and common per-job bounds.
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

use super::{bound, compute, domain_is, encode, error, fetch::FetchAdmission};
use crate::protocol::value::{CanonicalDecodeError, decode_canonical_dag_cbor};
use crate::{Application, ContentId, ProgramManifest, Retention};

const DOMAIN: &str = "hellas.invocation.policy.v1";
pub const MAX_POLICY_BYTES: usize = 64 * 1024;
pub const MAX_ADMISSIONS: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    pub max_upload_bytes: u64,
    pub max_output_bytes: u64,
    pub max_steps: u64,
    pub execution_timeout_ms: u64,
}
impl Limits {
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
    Compute { evaluator: String },
    Fetch { admission: FetchAdmission },
}
impl Admission {
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
    pub fn admits_manifest(&self, manifest: &ProgramManifest) -> bool {
        match self {
            Self::Compute { evaluator } => {
                evaluator == compute::EVALUATOR
                    && manifest.application().evaluator() == evaluator
                    && manifest.application().adaptor() == compute::ADAPTOR
            }
            Self::Fetch { admission } => manifest == &admission.contract.manifest(),
        }
    }
    pub fn validate(&self) -> Result<(), CanonicalDecodeError> {
        match self {
            Self::Compute { evaluator } => {
                Application::new(evaluator.clone(), compute::ADAPTOR)
                    .map_err(|e| error(e.to_string()))?;
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
    /// More than one route can admit the same Fetch manifest. Callers check the
    /// application's input against a matching admission rather than choosing
    /// the first manifest match and silently ignoring the remaining routes.
    pub fn admissions_for<'a>(
        &'a self,
        manifest: &'a ProgramManifest,
    ) -> impl Iterator<Item = &'a Admission> {
        self.admissions
            .iter()
            .filter(move |a| a.admits_manifest(manifest))
    }
}
