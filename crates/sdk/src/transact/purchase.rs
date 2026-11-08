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
        "already paid (work {work}, price {price}), result lost. No new charge. Use --buy-again to deliberately purchase again, or transact --settle to close the channel."
    )]
    ResultLost { work: Digest, price: u64 },
    #[error("this tracked purchase was already reported; create a new attempt to buy again")]
    AlreadyReported,
    #[error(
        "this tracked purchase was rejected without payment; create a new attempt to try again"
    )]
    Rejected,
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

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
enum Phase {
    InputBound,
    TargetBound,
    ChannelBound,
    Running,
    Paying,
    Paid,
    Reported,
    Rejected,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    job: [u8; 32],
    price: u64,
    channel: [u8; 32],
    bond: [u8; 32],
    nonce: u64,
    work: Option<[u8; 32]>,
    phase: Phase,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    target: Option<PurchaseTarget>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    request_commitment: Option<[u8; 32]>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    attempt_nonce: Option<[u8; 32]>,
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
    job: [u8; 32],
    price: u64,
    record: Option<Record>,
}
impl Purchase {
    pub(crate) fn bound_channel(&self) -> Option<(Digest, EdgeId)> {
        self.record
            .as_ref()
            .filter(|record| !matches!(record.phase, Phase::InputBound | Phase::TargetBound))
            .map(|record| {
                (
                    Digest::from_bytes(record.channel),
                    EdgeId::from_bytes(record.bond),
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
        let mut purchase = Self::open_identity(path, job.digest(), job.price())?;
        if let Some(record) = &purchase.record
            && (record.attempt_nonce.is_none()
                || (record.nonce != 0 && record.request_commitment.is_none()))
        {
            return Err(PurchaseError::Identity);
        }
        if purchase.record.is_none() {
            if !create {
                return Err(PurchaseError::Identity);
            }
            purchase.record = Some(Record {
                job: purchase.job,
                price: purchase.price,
                channel: [0; 32],
                bond: [0; 32],
                nonce: 0,
                work: None,
                phase: Phase::InputBound,
                target: None,
                request_commitment: None,
                attempt_nonce: Some(rand::random()),
            });
            purchase.persist()?;
        }
        Ok(purchase)
    }

    fn open_identity(path: &PaidAttemptPath, job: Digest, price: u64) -> Result<Self> {
        let state_key = path.state_key().to_owned();
        let durability = path.durability();
        let path = path.as_path();
        let parent = path.parent().ok_or(PurchaseError::Identity)?;
        durability.create_dir_all(parent)?;
        let lock = hellas_private::open_lock_beside(path)?;
        lock.try_lock().map_err(|_| PurchaseError::Busy)?;
        let lock = PurchaseLock(lock);
        let record: Option<Record> = match hellas_private::read_bounded_regular_file(path, 4096) {
            Ok(bytes) => Some(serde_json::from_slice(&bytes)?),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(error.into()),
        };
        if let Some(record) = &record
            && (record.job != *job.as_bytes()
                || record.price != price
                || (record.nonce == 0
                    && !matches!(
                        record.phase,
                        Phase::InputBound | Phase::TargetBound | Phase::ChannelBound
                    ))
                || (matches!(
                    record.phase,
                    Phase::Paying | Phase::Paid | Phase::Reported | Phase::Rejected
                ) && record.work.is_none()))
        {
            return Err(PurchaseError::Identity);
        }
        Ok(Self {
            path: path.to_owned(),
            durability,
            state_key,
            _lock: lock,
            job: *job.as_bytes(),
            price,
            record,
        })
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

    pub(super) fn ensure_executable(&self) -> Result<()> {
        match self.record.as_ref() {
            Some(record) if record.phase == Phase::Reported => Err(PurchaseError::AlreadyReported),
            Some(record) if record.phase == Phase::Rejected => Err(PurchaseError::Rejected),
            Some(record) if record.phase == Phase::Paid => Err(PurchaseError::ResultLost {
                work: Digest::from_bytes(record.work.ok_or(PurchaseError::Identity)?),
                price: record.price,
            }),
            _ => Ok(()),
        }
    }

    /// Bind a target before funding. Returns true only when this handle wrote
    /// a new binding; an existing binding never authorizes fresh funding.
    pub(crate) fn bind_target(&mut self, target: PurchaseTarget) -> Result<bool> {
        let record = self.record.as_mut().ok_or(PurchaseError::Identity)?;
        if record.phase == Phase::InputBound && record.target.is_none() {
            record.target = Some(target);
            record.phase = Phase::TargetBound;
            self.persist()?;
            return Ok(true);
        }
        if record.target.as_ref() == Some(&target) {
            Ok(false)
        } else {
            Err(PurchaseError::Identity)
        }
    }

    pub(crate) fn has_target(&self) -> bool {
        self.record
            .as_ref()
            .is_some_and(|record| record.target.is_some())
    }
    pub(crate) fn matches_target(&self, target: &PurchaseTarget) -> bool {
        self.record
            .as_ref()
            .and_then(|record| record.target.as_ref())
            == Some(target)
    }
    pub(crate) fn work_id(&self) -> Option<Digest> {
        self.record
            .as_ref()
            .and_then(|record| record.work)
            .map(Digest::from_bytes)
    }

    /// Recover the accepted identity after the channel journal was committed
    /// but before the caller marker's work ID was saved. Channel replay has
    /// checked both signatures. The request commitment distinguishes this
    /// intent from a later attempt that reused a nonce never proposed here.
    pub(crate) fn accepted_work(
        &self,
        state: &hellas_channel::work_store::Channel,
    ) -> Result<Option<Digest>> {
        let Some(record) = &self.record else {
            return Ok(None);
        };
        if record.nonce == 0 {
            return Ok(None);
        }
        let channel = state.channel().id();
        if record.channel != *channel.as_bytes() {
            return Err(PurchaseError::Identity);
        }
        let Some(job) = state
            .jobs()
            .find(|job| job.authorization().proposal_nonce == record.nonce)
        else {
            return if record.nonce <= state.proposal_nonce_high_water() {
                Err(self.unfinished(
                    "the proposal nonce was consumed but no active request-bound acceptance remains",
                ))
            } else {
                Ok(None)
            };
        };
        let authorization = job.authorization();
        if authorization.channel_id != channel || authorization.price != record.price {
            return Err(PurchaseError::Identity);
        }
        if job.provider_signature().is_none() {
            return Ok(None);
        }
        if record.attempt_nonce.is_none()
            || record.request_commitment
                != Some(*authorization.request_commitment.digest().as_bytes())
        {
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
            if prepared.request.nonce != self.request_nonce(channel, record.nonce) {
                return Err(PurchaseError::Identity);
            }
        }
        Ok(Some(job.work_id()))
    }

    /// A recorded nonce is an irrevocable proposal intent for tracked attempts.
    pub(crate) fn has_proposal_intent(&self) -> bool {
        self.record.as_ref().is_some_and(|record| record.nonce != 0)
    }

    pub(super) fn request_nonce(&self, channel: Digest, nonce: u64) -> [u8; 32] {
        crate::job::purchase_nonce(
            Digest::from_bytes(self.job),
            channel,
            nonce,
            self.record
                .as_ref()
                .and_then(|record| record.attempt_nonce.as_ref()),
        )
    }

    pub(crate) fn bind_channel(&mut self, channel: Digest, bond: EdgeId) -> Result<()> {
        let record = self.record.as_mut().ok_or(PurchaseError::Identity)?;
        if record.target.is_none() {
            return Err(PurchaseError::Identity);
        }
        if record.phase == Phase::TargetBound {
            record.channel = *channel.as_bytes();
            record.bond = bond.to_bytes();
            record.phase = Phase::ChannelBound;
            self.persist()?;
        } else if record.channel != *channel.as_bytes() || record.bond != bond.to_bytes() {
            return Err(PurchaseError::Identity);
        }
        Ok(())
    }

    fn unfinished(&self, reason: &'static str) -> PurchaseError {
        PurchaseError::Unfinished {
            work: self
                .record
                .as_ref()
                .and_then(|r| r.work)
                .map(Digest::from_bytes)
                .map_or_else(|| "not yet accepted".into(), |id| id.to_string()),
            reason,
        }
    }

    pub(super) fn nonce(&self, channel: Digest) -> Result<Option<u64>> {
        match &self.record {
            Some(record)
                if record.channel == *channel.as_bytes() && record.phase == Phase::ChannelBound =>
            {
                Ok(None)
            }
            Some(record) if record.channel == *channel.as_bytes() => Ok(Some(record.nonce)),
            Some(_) => Err(self.unfinished("the original channel is unavailable")),
            None => Ok(None),
        }
    }
    pub(super) fn begin(
        &mut self,
        channel: Digest,
        bond: EdgeId,
        nonce: u64,
        request_commitment: Digest,
    ) -> Result<()> {
        let request_commitment = *request_commitment.as_bytes();
        let record = self.record.as_mut().ok_or(PurchaseError::Identity)?;
        if record.channel != *channel.as_bytes()
            || record.bond != bond.to_bytes()
            || (record.phase != Phase::ChannelBound && record.nonce != nonce)
            || record
                .request_commitment
                .is_some_and(|held| held != request_commitment)
        {
            return Err(PurchaseError::Identity);
        }
        if record.phase == Phase::ChannelBound || record.request_commitment.is_none() {
            if record.phase == Phase::ChannelBound {
                record.nonce = nonce;
                record.phase = Phase::Running;
            }
            // Nonce and its exact request binding must survive together,
            // before any proposal can leave the process.
            record.request_commitment = Some(request_commitment);
            self.persist()?;
        }
        Ok(())
    }
    pub(crate) fn accepting(&mut self, work: Digest) -> Result<()> {
        self.advance(work, Phase::Running)
    }
    pub(crate) fn paying(&mut self, work: Digest) -> Result<()> {
        self.advance(work, Phase::Paying)
    }
    pub(crate) fn paid(&mut self, work: Digest) -> Result<()> {
        self.advance(work, Phase::Paid)
    }
    /// Clear only after the channel journal durably retires this unpaid result.
    pub(crate) fn unpaid(&mut self, work: Digest) -> Result<()> {
        let record = self.record.as_ref().ok_or(PurchaseError::Identity)?;
        if record.work != Some(*work.as_bytes())
            || matches!(record.phase, Phase::Paid | Phase::Reported)
        {
            return Err(PurchaseError::Identity);
        }
        self.record.as_mut().ok_or(PurchaseError::Identity)?.phase = Phase::Rejected;
        self.persist()
    }
    /// Call only after all selected output writes and the result report succeed.
    pub fn reported(&mut self) -> Result<()> {
        let record = self.record.as_mut().ok_or(PurchaseError::Identity)?;
        if record.phase == Phase::Reported {
            return Ok(());
        }
        if record.phase != Phase::Paid {
            return Err(PurchaseError::Identity);
        }
        record.phase = Phase::Reported;
        self.persist()
    }
    fn advance(&mut self, work: Digest, phase: Phase) -> Result<()> {
        let record = self.record.as_mut().ok_or(PurchaseError::Identity)?;
        if record.work.is_some_and(|id| id != *work.as_bytes()) {
            return Err(PurchaseError::Identity);
        }
        record.work = Some(*work.as_bytes());
        record.phase = phase;
        self.persist()
    }
    pub(crate) fn status(&self) -> Result<PurchaseStatus> {
        let Some(record) = &self.record else {
            return Ok(PurchaseStatus::Absent);
        };
        let work = record.work.map(Digest::from_bytes);
        Ok(match record.phase {
            Phase::InputBound => PurchaseStatus::InputBound,
            Phase::TargetBound => PurchaseStatus::TargetBound,
            Phase::ChannelBound => PurchaseStatus::ChannelBound,
            Phase::Running => PurchaseStatus::Running { work },
            Phase::Paying => PurchaseStatus::Paying {
                work: work.ok_or(PurchaseError::Identity)?,
            },
            Phase::Paid | Phase::Reported => PurchaseStatus::Paid {
                work: work.ok_or(PurchaseError::Identity)?,
                reported: record.phase == Phase::Reported,
            },
            Phase::Rejected => PurchaseStatus::Rejected {
                work: work.ok_or(PurchaseError::Identity)?,
            },
        })
    }

    /// The selected store's policy, shared by this attempt's sidecars.
    pub(crate) fn durability(&self) -> Durability {
        self.durability
    }

    fn persist(&self) -> Result<()> {
        self.durability.write_atomically(
            &self.path,
            ".writing",
            &serde_json::to_vec(self.record.as_ref().ok_or(PurchaseError::Identity)?)?,
        )?;
        Ok(())
    }
}

/// Local purchase facts. An absent marker cannot establish whether an older
/// application attempt existed before its metadata was retained.
#[derive(Debug, PartialEq, Eq)]
pub enum PurchaseStatus {
    Absent,
    InputBound,
    TargetBound,
    ChannelBound,
    Running { work: Option<Digest> },
    Paying { work: Digest },
    Paid { work: Digest, reported: bool },
    Rejected { work: Digest },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tracked(path: &Path) -> PaidAttemptPath {
        PaidAttemptPath::test(path.to_owned())
    }

    #[test]
    fn tracked_open_requires_attempt_and_proposed_request_bindings() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("attempt");
        let job = job();
        drop(Purchase::open_tracked(&tracked(&path), &job).unwrap());
        let initial: Record = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        for phase in [
            Phase::InputBound,
            Phase::TargetBound,
            Phase::ChannelBound,
            Phase::Running,
        ] {
            for work in [None, Some([7; 32])] {
                let mut record = initial.clone();
                record.phase = phase;
                record.work = work;
                if phase == Phase::Running {
                    record.nonce = 1;
                    record.request_commitment = Some([4; 32]);
                }
                for field in ["attempt_nonce", "request_commitment"] {
                    if field == "request_commitment" && record.nonce == 0 {
                        continue;
                    }
                    let mut missing = record.clone();
                    if field == "attempt_nonce" {
                        missing.attempt_nonce = None;
                    } else {
                        missing.request_commitment = None;
                    }
                    let bytes = serde_json::to_vec(&missing).unwrap();
                    hellas_private::write_atomically(&path, ".writing", &bytes).unwrap();
                    assert!(
                        matches!(
                            Purchase::open_existing_tracked(&tracked(&path), &job),
                            Err(PurchaseError::Identity)
                        ),
                        "{phase:?} {field}, known work: {}",
                        work.is_some()
                    );
                    assert_eq!(std::fs::read(&path).unwrap(), bytes);
                }
            }
        }
        // An unproposed current attempt has an attempt identity but no request yet.
        for phase in [Phase::InputBound, Phase::TargetBound, Phase::ChannelBound] {
            let mut record = initial.clone();
            record.phase = phase;
            hellas_private::write_atomically(
                &path,
                ".writing",
                &serde_json::to_vec(&record).unwrap(),
            )
            .unwrap();
            drop(Purchase::open_existing_tracked(&tracked(&path), &job).unwrap());
        }
    }

    #[test]
    fn tracked_terminal_records_survive_reopen_and_cannot_execute_again() {
        let root = tempfile::tempdir().unwrap();
        let job = job();
        let channel = Digest::from_bytes([1; 32]);
        let work = Digest::from_bytes([7; 32]);
        for reported in [false, true] {
            let path = root
                .path()
                .join(if reported { "reported" } else { "rejected" });
            {
                let mut purchase = Purchase::open_tracked(&tracked(&path), &job).unwrap();
                purchase
                    .bind_target(PurchaseTarget {
                        network: "fixture".into(),
                        provider: hellas_client::ProviderAddress {
                            enrollment: hellas_rpc::ContentId::hash(b"provider"),
                            node: iroh::SecretKey::from_bytes(&[1; 32]).public(),
                        },
                    })
                    .unwrap();
                purchase
                    .bind_channel(channel, EdgeId::from_bytes([2; 32]))
                    .unwrap();
                purchase
                    .begin(
                        channel,
                        EdgeId::from_bytes([2; 32]),
                        3,
                        Digest::from_bytes([4; 32]),
                    )
                    .unwrap();
                purchase.accepting(work).unwrap();
                if reported {
                    purchase.paid(work).unwrap();
                    purchase.reported().unwrap();
                    purchase.reported().unwrap();
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
            assert_eq!(
                recovered.bound_channel().map(|(found, _)| found),
                Some(channel)
            );
            assert_eq!(
                recovered.status().unwrap(),
                if reported {
                    PurchaseStatus::Paid {
                        work,
                        reported: true,
                    }
                } else {
                    PurchaseStatus::Rejected { work }
                }
            );
            drop(recovered);
            let purchase = Purchase::open_tracked(&tracked(&path), &job).unwrap();
            assert!(matches!(
                purchase.ensure_executable(),
                Err(PurchaseError::AlreadyReported | PurchaseError::Rejected)
            ));
        }
    }

    #[test]
    fn tracked_target_and_channel_bindings_cannot_change() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("purchase");
        let job = job();
        let target = PurchaseTarget {
            network: "fixture".into(),
            provider: hellas_client::ProviderAddress {
                enrollment: hellas_rpc::ContentId::hash(b"provider"),
                node: iroh::SecretKey::from_bytes(&[1; 32]).public(),
            },
        };
        let channel = Digest::from_bytes([1; 32]);
        let bond = EdgeId::from_bytes([2; 32]);
        {
            let mut attempt = Purchase::open_tracked(&tracked(&path), &job).unwrap();
            assert!(attempt.bind_target(target.clone()).unwrap());
            assert!(!attempt.bind_target(target.clone()).unwrap());
            let mut other = target.clone();
            other.network = "other".into();
            assert!(attempt.bind_target(other).is_err());
            attempt.bind_channel(channel, bond).unwrap();
            attempt.bind_channel(channel, bond).unwrap();
            assert!(
                attempt
                    .bind_channel(Digest::from_bytes([8; 32]), bond)
                    .is_err()
            );
        }
        let mut attempt = Purchase::open_tracked(&tracked(&path), &job).unwrap();
        assert!(!attempt.bind_target(target).unwrap());
        assert_eq!(attempt.nonce(channel).unwrap(), None);
        attempt
            .begin(channel, bond, 3, Digest::from_bytes([4; 32]))
            .unwrap();
        assert_eq!(attempt.nonce(channel).unwrap(), Some(3));
        let before = std::fs::read(&path).unwrap();
        assert!(
            attempt
                .begin(channel, bond, 3, Digest::from_bytes([5; 32]))
                .is_err()
        );
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert!(attempt.has_proposal_intent());
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
