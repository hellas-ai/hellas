//! Caller-owned provider approvals. Offers and execution requests select an ID;
//! only an explicit local configuration operation writes approval state.
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

use hellas_auth::authority::UnixMillis;
use hellas_rpc::protocol::value::all_distinct;

use hellas_client::{AppleAppAttestTrust, ProviderTrustAnchor};
use hellas_rpc::{Assurance, ContentId};
use serde::{Deserialize, Serialize};
use std::{io, path::PathBuf, sync::Arc};

const MAX_FILE: usize = 64 * 1024;
const MAX_POLICIES: usize = 256;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppleApproval {
    pub app_id: String,
    #[serde(with = "cd_hashes")]
    pub cd_hashes: Vec<[u8; 32]>,
}

mod cd_hashes {
    use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};

    pub fn serialize<S: Serializer>(values: &[[u8; 32]], serializer: S) -> Result<S::Ok, S::Error> {
        values
            .iter()
            .map(hex::encode)
            .collect::<Vec<_>>()
            .serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<[u8; 32]>, D::Error> {
        let values = Vec::<String>::deserialize(deserializer)?;
        if values.len() > 32 {
            return Err(D::Error::custom("too many CDHash pins"));
        }
        values
            .into_iter()
            .map(|value| {
                let mut hash = [0; 32];
                hex::decode_to_slice(value, &mut hash)
                    .map_err(|_| D::Error::custom("CDHash requires 32 hex bytes"))?;
                Ok(hash)
            })
            .collect()
    }
}

/// Exact independent enrollment, assurance, software and execution pins.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustPolicy {
    pub provider_genesis: ContentId,
    pub assurance: Assurance,
    pub apple: Option<AppleApproval>,
}

impl TrustPolicy {
    pub fn check(&self) -> io::Result<()> {
        if self.assurance == Assurance::AppleAppAttest && self.apple.is_none() {
            return Err(invalid(
                "Apple assurance requires independent software approval",
            ));
        }
        if let Some(apple) = &self.apple
            && (apple.app_id.len() > 255
                || !apple
                    .app_id
                    .split_once('.')
                    .is_some_and(|(team, bundle)| !team.is_empty() && !bundle.is_empty())
                || !apple
                    .app_id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b".-".contains(&b))
                || apple.cd_hashes.is_empty()
                || apple.cd_hashes.len() > 32
                || !all_distinct(&apple.cd_hashes))
        {
            return Err(invalid("invalid Apple application identity or CDHash pins"));
        }
        Ok(())
    }

    fn commitment(&self) -> io::Result<ContentId> {
        Ok(ContentId::hash(&serde_json::to_vec(self)?))
    }
}

/// Latest local-owner approval, atomically published with its pins. Previous
/// commitment and revision identify the replaced policy; this is not a history log.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalRecord {
    pub id: String,
    pub revision: u64,
    pub approved_at: u64,
    pub previous: Option<ContentId>,
    pub reason: String,
    pub policy: TrustPolicy,
}

impl ApprovalRecord {
    fn check(&self, id: &str) -> io::Result<()> {
        self.policy.check()?;
        if self.id != id
            || self.revision == 0
            || (self.revision == 1) != self.previous.is_none()
            || self.reason.trim().is_empty()
            || self.reason.len() > 256
        {
            return Err(invalid("invalid trust approval record"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct TrustPolicyStore {
    directory: PathBuf,
}

impl TrustPolicyStore {
    /// Hosts choose this native private location; it never comes from an offer.
    pub fn new(directory: impl Into<PathBuf>) -> Self {
        Self {
            directory: directory.into(),
        }
    }

    pub fn load(&self, id: &str) -> io::Result<ApprovalRecord> {
        let path = self.path(id, ".json")?;
        let file = hellas_private::open_regular_file_nofollow(&path)?;
        if !hellas_private::is_private(&file)? {
            return Err(invalid("trust approval must be a private file"));
        }
        let bytes = hellas_private::read_bounded(file, MAX_FILE)?;
        let record: ApprovalRecord = serde_json::from_slice(&bytes)?;
        record.check(id)?;
        Ok(record)
    }

    /// Every approved policy, sorted by ID. Each record is loaded and checked
    /// exactly as `load` does; one invalid record fails the whole listing.
    pub fn list(&self) -> io::Result<Vec<ApprovalRecord>> {
        let entries = match std::fs::read_dir(&self.directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error),
        };
        let mut ids = Vec::new();
        for entry in entries {
            let name = entry?.file_name();
            // Locks, pending writes and counter state never match `<id>.json`.
            let Some(id) = name.to_str().and_then(|name| name.strip_suffix(".json")) else {
                continue;
            };
            if self.path(id, "").is_err() {
                continue;
            }
            if ids.len() == MAX_POLICIES {
                return Err(invalid("trust policies exceed their bound"));
            }
            ids.push(id.to_owned());
        }
        ids.sort_unstable();
        ids.iter().map(|id| self.load(id)).collect()
    }

    /// Approval is a local-owner configuration action, never a connection side
    /// effect. Expected revision zero creates; replacement requires the current
    /// revision. The stable per-ID lock serializes concurrent native processes.
    pub fn approve(
        &self,
        id: &str,
        expected_revision: u64,
        policy: TrustPolicy,
        reason: String,
    ) -> io::Result<ApprovalRecord> {
        let path = self.path(id, ".json")?;
        policy.check()?;
        if reason.trim().is_empty() || reason.len() > 256 {
            return Err(invalid("approval reason must contain 1..=256 bytes"));
        }
        hellas_private::create_dir_all_durable(&self.directory)?;
        hellas_private::restrict_directory(&self.directory)?;
        let lock = hellas_private::open_lock_beside(&self.path(id, "")?)?;
        if !hellas_private::is_private(&lock)? {
            return Err(invalid("trust lock must be private"));
        }
        lock.lock()?;
        let previous = match self.load(id) {
            Ok(record) => Some(record),
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => return Err(error),
        };
        if previous.as_ref().map_or(0, |record| record.revision) != expected_revision {
            return Err(invalid("trust approval revision changed"));
        }
        let revision = expected_revision
            .checked_add(1)
            .ok_or_else(|| invalid("trust revision exhausted"))?;
        let now = UnixMillis::now()
            .map_err(|_| invalid("approval clock precedes Unix epoch"))?
            .0
            / 1_000;
        let record = ApprovalRecord {
            id: id.into(),
            revision,
            approved_at: previous
                .as_ref()
                .map_or(now, |record| now.max(record.approved_at)),
            previous: previous
                .map(|record| record.policy.commitment())
                .transpose()?,
            reason,
            policy,
        };
        let bytes = serde_json::to_vec(&record)?;
        if bytes.len() > MAX_FILE {
            return Err(invalid("trust approval exceeds its bound"));
        }
        hellas_private::write_atomically(&path, ".pending", &bytes)?;
        Ok(record)
    }

    /// Resolve before opening/funding a connection. Missing policy or assurance
    /// mismatch denies; each job must also pass the anchor's environment check.
    /// Hosts inject their existing persistent counter owner so adopting or
    /// replacing a policy cannot reset assertion high-water marks.
    pub fn resolve(
        &self,
        id: &str,
        assurance: Assurance,
        counters: Arc<dyn hellas_attestation::AssertionCounterStore + Send + Sync>,
    ) -> io::Result<ProviderTrustAnchor> {
        let policy = self.load(id)?.policy;
        if policy.assurance != assurance {
            return Err(invalid("execution is outside the approved trust policy"));
        }
        Ok(ProviderTrustAnchor {
            expected_genesis: policy.provider_genesis,
            required_assurance: policy.assurance,
            apple_app_attest: policy
                .apple
                .map(|apple| AppleAppAttestTrust::new(apple.app_id, apple.cd_hashes, counters)),
        })
    }

    fn path(&self, id: &str, suffix: &str) -> io::Result<PathBuf> {
        if id.is_empty()
            || id.len() > 64
            || !id
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"-_".contains(&b))
        {
            return Err(invalid(
                "trust policy ID requires 1..=64 lowercase letters, digits, hyphens or underscores",
            ));
        }
        Ok(self.directory.join(format!("{id}{suffix}")))
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests;
