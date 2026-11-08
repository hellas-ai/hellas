//! Caller purchase/report state. This contains identifiers only, never input or output.
use super::super::job::Job;
use hellas_auth::Digest;
use hellas_auth::authority::PrincipalId;
use hellas_kernel::EdgeId;
use hellas_private::Durability;
use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    path::{Path, PathBuf},
};

/// A paid attempt location bound to one selected chain before any record opens.
#[derive(Clone, Debug)]
pub struct PaidAttemptPath {
    path: PathBuf,
    durability: Durability,
    state_key: String,
}

impl PaidAttemptPath {
    pub fn new(
        chain: &hellas_chain::chain_dir::ChainDir,
        provider: hellas_client::ProviderAddress,
        owner: PrincipalId,
        job: Digest,
    ) -> Self {
        let client = chain.client();
        Self {
            path: client
                .join("purchases")
                .join(provider.to_string())
                .join(hex::encode(owner.as_bytes()))
                .join(format!("{job}.json")),
            durability: client.durability(),
            state_key: chain.state_key(),
        }
    }

    pub fn with_nonce(&self, nonce: [u8; 16]) -> Self {
        let mut path = self.path.clone();
        path.set_file_name(format!(
            "{}.{}.json",
            path.file_stem().unwrap().to_string_lossy(),
            hex::encode(nonce)
        ));
        Self {
            path,
            durability: self.durability,
            state_key: self.state_key.clone(),
        }
    }

    pub fn as_path(&self) -> &Path {
        &self.path
    }

    /// The selected store's policy for this attempt's records.
    pub fn durability(&self) -> Durability {
        self.durability
    }

    pub(crate) fn state_key(&self) -> &str {
        &self.state_key
    }
}

#[cfg(test)]
impl PaidAttemptPath {
    fn test(path: PathBuf) -> Self {
        Self {
            path,
            durability: Durability::default(),
            state_key: String::new(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PurchaseError {
    #[error(
        "unfinished purchase {work} cannot resume: {reason}. No new charge. Resume or settle the original channel."
    )]
    Unfinished { work: String, reason: &'static str },
    #[error("another command holds this job's purchase lock")]
    Busy,
    #[error("purchase marker does not describe this job")]
    Identity,
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}
type Result<T> = std::result::Result<T, PurchaseError>;

/// A record's state is which facts it holds: a target before funding, a
/// proposal before the request leaves, and an outcome once work is terminal.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    job: [u8; 32],
    price: u64,
    attempt_nonce: [u8; 32],
    #[serde(default, skip_serializing_if = "Option::is_none")]
    target: Option<PurchaseTarget>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    proposal: Option<Proposal>,
}

/// Written once, before the proposal can leave the process, so recovery reuses
/// this exact nonce and attaches only an acceptance of this exact request.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Proposal {
    channel: [u8; 32],
    bond: [u8; 32],
    nonce: u64,
    request_commitment: [u8; 32],
    #[serde(default, skip_serializing_if = "Option::is_none")]
    outcome: Option<Outcome>,
}

/// Terminal work, kept so a paid attempt whose result was lost is refused
/// offline and the completion receipt can be bound to its work.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Outcome {
    work: [u8; 32],
    paid: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct PurchaseTarget {
    pub network: String,
    pub provider: hellas_client::ProviderAddress,
}

struct PurchaseLock(File);

impl Drop for PurchaseLock {
    fn drop(&mut self) {
        // A concurrently forked child can retain the open file description
        // after this one closes, so release the lock itself.
        let _ = self.0.unlock();
    }
}

/// Held from before channel funding until output has been successfully reported.
/// The lock serializes invocations of the same job, including --buy-again.
pub struct Purchase {
    path: PathBuf,
    durability: Durability,
    state_key: String,
    _lock: PurchaseLock,
    record: Record,
}
impl Purchase {
    pub(crate) fn bound_channel(&self) -> Option<(Digest, EdgeId)> {
        self.record.proposal.as_ref().map(|proposal| {
            (
                Digest::from_bytes(proposal.channel),
                EdgeId::from_bytes(proposal.bond),
            )
        })
    }
    /// Open a caller-owned attempt without clearing a terminal record.
    pub(crate) fn open_tracked(path: &PaidAttemptPath, job: &Job) -> Result<Self> {
        Self::open_tracked_inner(path, job, true)
    }

    pub(crate) fn open_existing_tracked(path: &PaidAttemptPath, job: &Job) -> Result<Self> {
        Self::open_tracked_inner(path, job, false)
    }

    fn open_tracked_inner(path: &PaidAttemptPath, job: &Job, create: bool) -> Result<Self> {
        let state_key = path.state_key().to_owned();
        let durability = path.durability();
        let path = path.as_path();
        let parent = path.parent().ok_or(PurchaseError::Identity)?;
        durability.create_dir_all(parent)?;
        let lock = hellas_private::open_lock_beside(path)?;
        lock.try_lock().map_err(|_| PurchaseError::Busy)?;
        let lock = PurchaseLock(lock);
        let (record, created) = match hellas_private::read_bounded_regular_file(path, 4096) {
            Ok(bytes) => (serde_json::from_slice::<Record>(&bytes)?, false),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound && create => (
                Record {
                    job: *job.digest().as_bytes(),
                    price: job.price(),
                    attempt_nonce: rand::random(),
                    target: None,
                    proposal: None,
                },
                true,
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(PurchaseError::Identity);
            }
            Err(error) => return Err(error.into()),
        };
        if record.job != *job.digest().as_bytes() || record.price != job.price() {
            return Err(PurchaseError::Identity);
        }
        let purchase = Self {
            path: path.to_owned(),
            durability,
            state_key,
            _lock: lock,
            record,
        };
        if created {
            purchase.persist()?;
        }
        Ok(purchase)
    }

    pub(crate) fn ensure_state_key(&self, state_key: &str) -> Result<()> {
        if self.state_key != state_key {
            return Err(PurchaseError::Identity);
        }
        Ok(())
    }

    pub(crate) fn ensure_chain(&self, session: &crate::paid_client::PaidWorkSession) -> Result<()> {
        self.ensure_state_key(&session.state_key())
    }

    /// Bind a target before funding. Returns true only when this handle wrote
    /// a new binding; an existing binding never authorizes fresh funding.
    pub(crate) fn bind_target(&mut self, target: PurchaseTarget) -> Result<bool> {
        match &self.record.target {
            None => {
                self.record.target = Some(target);
                self.persist()?;
                Ok(true)
            }
            Some(held) if *held == target => Ok(false),
            Some(_) => Err(PurchaseError::Identity),
        }
    }

    pub(crate) fn has_target(&self) -> bool {
        self.record.target.is_some()
    }
    pub(crate) fn matches_target(&self, target: &PurchaseTarget) -> bool {
        self.record.target.as_ref() == Some(target)
    }
    pub(crate) fn work_id(&self) -> Option<Digest> {
        self.outcome().map(|(work, _)| work)
    }
    /// Terminal work and whether it was paid.
    pub(crate) fn outcome(&self) -> Option<(Digest, bool)> {
        self.record
            .proposal
            .as_ref()
            .and_then(|proposal| proposal.outcome)
            .map(|outcome| (Digest::from_bytes(outcome.work), outcome.paid))
    }

    /// Recover the accepted identity from the channel journal, which is
    /// committed before the caller marker records an outcome. Channel replay
    /// has checked both signatures. The request commitment distinguishes this
    /// intent from a later attempt that reused a nonce never proposed here.
    pub(crate) fn accepted_work(
        &self,
        state: &hellas_channel::work_store::Channel,
    ) -> Result<Option<Digest>> {
        let Some(proposal) = &self.record.proposal else {
            return Ok(None);
        };
        let channel = state.channel().id();
        if proposal.channel != *channel.as_bytes() {
            return Err(PurchaseError::Identity);
        }
        let Some(job) = state
            .jobs()
            .find(|job| job.authorization().proposal_nonce == proposal.nonce)
        else {
            return if proposal.nonce <= state.proposal_nonce_high_water() {
                Err(self.unfinished(
                    "the proposal nonce was consumed but no active request-bound acceptance remains",
                ))
            } else {
                Ok(None)
            };
        };
        let authorization = job.authorization();
        if authorization.channel_id != channel || authorization.price != self.record.price {
            return Err(PurchaseError::Identity);
        }
        if job.provider_signature().is_none() {
            return Ok(None);
        }
        if proposal.request_commitment != *authorization.request_commitment.digest().as_bytes() {
            return Err(PurchaseError::Identity);
        }
        // Retained input additionally checks this job and attempt's request
        // nonce. The durable commitment carries that binding through replay.
        if !job.prepared_input().is_empty() {
            use hellas_rpc::protocol::invocation::{MAX_INVOCATION_BYTES, PreparedInvocation};
            let prepared = PreparedInvocation::from_canonical_bytes(
                job.prepared_input(),
                MAX_INVOCATION_BYTES,
            )
            .map_err(|_| PurchaseError::Identity)?;
            if prepared.request.nonce != self.request_nonce(channel, proposal.nonce) {
                return Err(PurchaseError::Identity);
            }
        }
        Ok(Some(job.work_id()))
    }

    /// A recorded proposal is an irrevocable intent for tracked attempts.
    pub(crate) fn has_proposal_intent(&self) -> bool {
        self.record.proposal.is_some()
    }

    pub(super) fn request_nonce(&self, channel: Digest, nonce: u64) -> [u8; 32] {
        crate::job::purchase_nonce(
            Digest::from_bytes(self.record.job),
            channel,
            nonce,
            Some(&self.record.attempt_nonce),
        )
    }

    /// Check a session's channel against the target and any recorded proposal.
    /// Before a proposal, any retained channel to the target may serve it.
    pub(crate) fn ensure_channel(&self, channel: Digest, bond: EdgeId) -> Result<()> {
        if self.record.target.is_none()
            || self.record.proposal.as_ref().is_some_and(|proposal| {
                proposal.channel != *channel.as_bytes() || proposal.bond != bond.to_bytes()
            })
        {
            return Err(PurchaseError::Identity);
        }
        Ok(())
    }

    fn unfinished(&self, reason: &'static str) -> PurchaseError {
        PurchaseError::Unfinished {
            work: self
                .work_id()
                .map_or_else(|| "not yet accepted".into(), |id| id.to_string()),
            reason,
        }
    }

    pub(super) fn nonce(&self, channel: Digest) -> Result<Option<u64>> {
        match &self.record.proposal {
            Some(proposal) if proposal.channel == *channel.as_bytes() => Ok(Some(proposal.nonce)),
            Some(_) => Err(self.unfinished("the original channel is unavailable")),
            None => Ok(None),
        }
    }
    /// Channel, bond, nonce and its exact request binding must survive
    /// together, before any proposal can leave the process.
    pub(super) fn begin(
        &mut self,
        channel: Digest,
        bond: EdgeId,
        nonce: u64,
        request_commitment: Digest,
    ) -> Result<()> {
        if self.record.target.is_none() {
            return Err(PurchaseError::Identity);
        }
        let proposal = Proposal {
            channel: *channel.as_bytes(),
            bond: bond.to_bytes(),
            nonce,
            request_commitment: *request_commitment.as_bytes(),
            outcome: None,
        };
        match &self.record.proposal {
            None => {
                self.record.proposal = Some(proposal);
                self.persist()
            }
            Some(held) if *held == proposal => Ok(()),
            Some(_) => Err(PurchaseError::Identity),
        }
    }
    /// Record only after the channel journal holds this work's payment.
    pub(crate) fn paid(&mut self, work: Digest) -> Result<()> {
        self.finish(work, true)
    }
    /// Record only after the channel journal durably retires this unpaid result.
    pub(crate) fn unpaid(&mut self, work: Digest) -> Result<()> {
        self.finish(work, false)
    }
    fn finish(&mut self, work: Digest, paid: bool) -> Result<()> {
        let proposal = self
            .record
            .proposal
            .as_mut()
            .ok_or(PurchaseError::Identity)?;
        let outcome = Outcome {
            work: *work.as_bytes(),
            paid,
        };
        match proposal.outcome {
            None => proposal.outcome = Some(outcome),
            Some(held) if held == outcome => return Ok(()),
            Some(_) => return Err(PurchaseError::Identity),
        }
        self.persist()
    }

    /// The selected store's policy, shared by this attempt's sidecars.
    pub(crate) fn durability(&self) -> Durability {
        self.durability
    }

    fn persist(&self) -> Result<()> {
        self.durability.write_atomically(
            &self.path,
            ".writing",
            &serde_json::to_vec(&self.record)?,
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tracked(path: &Path) -> PaidAttemptPath {
        PaidAttemptPath::test(path.to_owned())
    }

    fn target() -> PurchaseTarget {
        PurchaseTarget {
            network: "fixture".into(),
            provider: hellas_client::ProviderAddress {
                enrollment: hellas_rpc::ContentId::hash(b"provider"),
                node: iroh::SecretKey::from_bytes(&[1; 32]).public(),
            },
        }
    }

    #[test]
    fn tracked_outcomes_survive_reopen_and_cannot_change() {
        let root = tempfile::tempdir().unwrap();
        let job = job();
        let channel = Digest::from_bytes([1; 32]);
        let bond = EdgeId::from_bytes([2; 32]);
        let work = Digest::from_bytes([7; 32]);
        for paid in [false, true] {
            let path = root.path().join(if paid { "paid" } else { "rejected" });
            {
                let mut purchase = Purchase::open_tracked(&tracked(&path), &job).unwrap();
                purchase.bind_target(target()).unwrap();
                purchase
                    .begin(channel, bond, 3, Digest::from_bytes([4; 32]))
                    .unwrap();
                if paid {
                    purchase.paid(work).unwrap();
                    purchase.paid(work).unwrap();
                    assert!(purchase.unpaid(work).is_err());
                } else {
                    purchase.unpaid(work).unwrap();
                }
            }
            // The marker holds identifiers only, never the job's input.
            assert!(
                !std::fs::read_to_string(&path)
                    .unwrap()
                    .contains("private-input-sentinel")
            );
            let recovered = Purchase::open_existing_tracked(&tracked(&path), &job).unwrap();
            assert_eq!(recovered.bound_channel(), Some((channel, bond)));
            assert_eq!(recovered.outcome(), Some((work, paid)));
            assert!(recovered.has_proposal_intent());
        }
    }

    #[test]
    fn tracked_target_and_proposal_bindings_cannot_change() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("purchase");
        let job = job();
        let channel = Digest::from_bytes([1; 32]);
        let bond = EdgeId::from_bytes([2; 32]);
        {
            let mut attempt = Purchase::open_tracked(&tracked(&path), &job).unwrap();
            assert!(attempt.bind_target(target()).unwrap());
            assert!(!attempt.bind_target(target()).unwrap());
            let mut other = target();
            other.network = "other".into();
            assert!(attempt.bind_target(other).is_err());
        }
        let mut attempt = Purchase::open_tracked(&tracked(&path), &job).unwrap();
        assert!(!attempt.bind_target(target()).unwrap());
        assert_eq!(attempt.nonce(channel).unwrap(), None);
        attempt
            .begin(channel, bond, 3, Digest::from_bytes([4; 32]))
            .unwrap();
        assert_eq!(attempt.nonce(channel).unwrap(), Some(3));
        attempt.ensure_channel(channel, bond).unwrap();
        assert!(
            attempt
                .ensure_channel(Digest::from_bytes([8; 32]), bond)
                .is_err()
        );
        let before = std::fs::read(&path).unwrap();
        assert!(
            attempt
                .begin(channel, bond, 3, Digest::from_bytes([5; 32]))
                .is_err()
        );
        assert_eq!(std::fs::read(&path).unwrap(), before);
        drop(attempt);
        assert!(
            Purchase::open_tracked(&tracked(&path), &job)
                .unwrap()
                .has_proposal_intent()
        );
    }

    #[test]
    fn tracked_request_nonces_are_stable_and_distinguish_identical_attempts() {
        let root = tempfile::tempdir().unwrap();
        let job = job();
        let channel = Digest::from_bytes([1; 32]);
        let path = root.path().join("first");
        let first = Purchase::open_tracked(&tracked(&path), &job).unwrap();
        let nonce = first.request_nonce(channel, 1);
        drop(first);
        let reopened = Purchase::open_existing_tracked(&tracked(&path), &job).unwrap();
        assert_eq!(reopened.request_nonce(channel, 1), nonce);
        let second = Purchase::open_tracked(&tracked(&root.path().join("second")), &job).unwrap();
        assert_ne!(second.request_nonce(channel, 1), nonce);
    }

    #[test]
    fn markers_follow_the_selected_store_durability() {
        let passkey = hellas_kernel::SoftPasskey::from_secret_scalar([1; 32]).unwrap();
        let owner = PrincipalId::from_public_key(hellas_auth::PublicKey::P256(
            passkey.party_key().to_bytes(),
        ))
        .unwrap();
        let provider = hellas_client::ProviderAddress {
            enrollment: hellas_rpc::ContentId::hash(b"provider"),
            node: iroh::SecretKey::from_bytes(&[1; 32]).public(),
        };
        let job = job();
        for durability in [Durability::Crash, Durability::Power] {
            let root = tempfile::tempdir().unwrap();
            let chain = hellas_chain::chain_dir::ChainDir::open(
                &hellas_private::StoreLocation::from_home(root.path(), durability),
                &hellas_chain::genesis::ChainProfile::known(hellas_chain::genesis::Chain::Devnet),
            )
            .unwrap();
            let path =
                PaidAttemptPath::new(&chain, provider, owner, job.digest()).with_nonce([1; 16]);
            let purchase = Purchase::open_tracked(&path, &job).unwrap();
            assert_eq!(purchase.durability(), durability);
            assert!(path.as_path().is_file());
        }
    }

    fn job() -> Job {
        Job::fetch(20, hellas_rpc::FetchContract::http().unwrap(), "http".into(), "request".into(), br#"{"url":"https://example.test/private-input-sentinel","method":"GET","tls":{"roots":{"mode":"web_pki"}},"max_response_bytes":4096}"#.to_vec(), hellas_rpc::Assurance::ProducerSigned).unwrap()
    }
}
