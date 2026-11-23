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

/// Explicit owner choice between general Compute and exact program manifests.
/// A manifest commits the rendered sources and asset identities, while request
/// inputs and plans remain variable within the invocation limits.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "kebab-case", deny_unknown_fields)]
pub enum ComputePrograms {
    Any {},
    Only {
        manifests: Vec<ContentId>,
        /// Fully initializing, pure weight preparation entries approved by the owner.
        #[serde(
            default,
            skip_serializing_if = "BTreeMap::is_empty",
            with = "setup_entries_by_id"
        )]
        pure_setup_entries: BTreeMap<ContentId, BTreeSet<String>>,
    },
}

// Signed policies use lowercase Xet text for map keys in every encoding, including DAG-CBOR.
mod setup_entries_by_id {
    use super::*;
    use serde::{Deserializer, Serializer, de::IntoDeserializer};

    pub(super) fn serialize<S: Serializer>(
        map: &BTreeMap<ContentId, BTreeSet<String>>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.collect_map(map.iter().map(|(id, entries)| (id.to_string(), entries)))
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<BTreeMap<ContentId, BTreeSet<String>>, D::Error> {
        BTreeMap::<String, BTreeSet<String>>::deserialize(deserializer)?
            .into_iter()
            .map(|(key, entries)| Ok((ContentId::deserialize(key.into_deserializer())?, entries)))
            .collect()
    }
}

impl ComputePrograms {
    pub fn validate(&self) -> Result<(), CanonicalDecodeError> {
        if let Self::Only {
            manifests,
            pure_setup_entries,
        } = self
        {
            if manifests.is_empty() || manifests.len() > MAX_COMPUTE_PROGRAMS {
                return Err(error(
                    "compute admission requires a bounded, nonempty manifest list",
                ));
            }
            for (manifest, entries) in pure_setup_entries {
                if !manifests.contains(manifest) || entries.is_empty() {
                    return Err(error("setup entries must belong to an admitted manifest"));
                }
                for entry in entries {
                    super::label(entry)?;
                }
            }
            if manifests.iter().collect::<BTreeSet<_>>().len() != manifests.len() {
                return Err(error("duplicate compute manifest"));
            }
        }
        Ok(())
    }
    fn admits(&self, manifest: &ProgramManifest) -> bool {
        match self {
            Self::Any {} => true,
            Self::Only { manifests, .. } => manifests.contains(&manifest.content_id()),
        }
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
    Compute {
        evaluator: String,
        programs: ComputePrograms,
    },
    Fetch {
        admission: FetchAdmission,
    },
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
        let manifests: Vec<_> = programs.iter().map(ProgramManifest::content_id).collect();
        let mut pure_setup_entries = BTreeMap::new();
        if !entries.is_empty() {
            let entries: BTreeSet<_> = entries.iter().map(|s| (*s).to_owned()).collect();
            pure_setup_entries.extend(manifests.iter().map(|&id| (id, entries.clone())));
        }
        Ok(Self::Compute {
            evaluator: application.evaluator().into(),
            programs: ComputePrograms::Only {
                manifests,
                pure_setup_entries,
            },
        })
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
    pub fn admits_manifest(&self, manifest: &ProgramManifest) -> bool {
        match self {
            Self::Compute {
                evaluator,
                programs,
            } => {
                manifest.application().evaluator() == evaluator
                    && manifest.application().adaptor() == compute::ADAPTOR
                    && programs.admits(manifest)
            }
            Self::Fetch { admission } => manifest == &admission.contract.manifest(),
        }
    }
    pub fn validate(&self) -> Result<(), CanonicalDecodeError> {
        match self {
            Self::Compute {
                evaluator,
                programs,
            } => {
                Application::new(evaluator.clone(), compute::ADAPTOR)
                    .map_err(|e| error(e.to_string()))?;
                programs.validate()
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
    /// Whether this policy admits Compute programs nobody configured.
    pub fn admits_any_program(&self) -> bool {
        self.admissions.iter().any(|admission| {
            matches!(
                admission,
                Admission::Compute {
                    programs: ComputePrograms::Any {},
                    ..
                }
            )
        })
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
    /// Compute the cache permission from this owner's exact program admissions.
    pub fn pure_setup_entries(&self, manifest: &ProgramManifest) -> BTreeSet<String> {
        self.admissions_for(manifest)
            .filter_map(|admission| match admission {
                Admission::Compute {
                    programs:
                        ComputePrograms::Only {
                            pure_setup_entries, ..
                        },
                    ..
                } => pure_setup_entries.get(&manifest.content_id()),
                _ => None,
            })
            .flatten()
            .cloned()
            .collect()
    }
    /// More than one route can admit the same Fetch manifest. Callers check the
    /// application's input against a matching admission rather than choosing
    /// the first manifest match and silently ignoring the remaining routes.
    pub fn admissions_for<'a>(
        &'a self,
        manifest: &ProgramManifest,
    ) -> impl Iterator<Item = &'a Admission> {
        self.admissions
            .iter()
            .filter(move |a| a.admits_manifest(manifest))
    }
}
