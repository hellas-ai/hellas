//! Caller purchase/report state. This contains identifiers only, never input or output.
use super::super::{job::Job, paid_client::PaidWorkOptions};
use hellas_auth::Digest;
use hellas_channel::work_store::{ChannelRecord, ChannelStore, Role, SetupStore, TerminalOutcome};
use hellas_kernel::{EdgeId, Secp256k1Verifier};
use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    path::{Path, PathBuf},
};

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
    #[error(transparent)]
    Store(#[from] hellas_channel::work_store::WorkStoreError),
    #[error(transparent)]
    Setup(#[from] hellas_channel::model::setup::WorkSetupError),
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
    _lock: PurchaseLock,
    job: [u8; 32],
    price: u64,
    record: Option<Record>,
    buy_again: bool,
    tracked: bool,
}
impl Purchase {
    pub fn open(path: &Path, job: &Job, buy_again: bool) -> Result<Self> {
        let mut purchase = Self::open_identity(path, job.digest(), job.price(), false)?;
        purchase.buy_again = buy_again;
        if let Some(record) = &purchase.record
            && !buy_again
            && record.phase == Phase::Paid
        {
            return Err(PurchaseError::ResultLost {
                work: Digest::from_bytes(record.work.ok_or(PurchaseError::Identity)?),
                price: record.price,
            });
        }
        purchase.record = purchase.record.filter(|record| {
            !matches!(record.phase, Phase::Reported | Phase::Rejected)
                && !(buy_again && record.phase == Phase::Paid)
        });
        Ok(purchase)
    }

    /// Open a caller-owned attempt without clearing a terminal record.
    pub fn open_tracked(path: &Path, job: &Job) -> Result<Self> {
        Self::open_tracked_inner(path, job, true)
    }

    pub(crate) fn open_existing_tracked(path: &Path, job: &Job) -> Result<Self> {
        Self::open_tracked_inner(path, job, false)
    }

    fn open_tracked_inner(path: &Path, job: &Job, create: bool) -> Result<Self> {
        let mut purchase = Self::open_identity(path, job.digest(), job.price(), true)?;
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
            });
            purchase.persist()?;
        }
        Ok(purchase)
    }

    fn open_identity(path: &Path, job: Digest, price: u64, tracked: bool) -> Result<Self> {
        let parent = path.parent().ok_or(PurchaseError::Identity)?;
        hellas_private::create_dir_all_durable(parent)?;
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
            _lock: lock,
            job: *job.as_bytes(),
            price,
            record,
            buy_again: false,
            tracked,
        })
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
        if !self.tracked {
            return Err(PurchaseError::Identity);
        }
        if let Some(record) = &self.record {
            if record.phase == Phase::InputBound && record.target.is_none() {
                let record = self.record.as_mut().ok_or(PurchaseError::Identity)?;
                record.target = Some(target);
                record.phase = Phase::TargetBound;
                self.persist()?;
                return Ok(true);
            }
            return if record.target.as_ref() == Some(&target) {
                Ok(false)
            } else {
                Err(PurchaseError::Identity)
            };
        }
        self.record = Some(Record {
            job: self.job,
            price: self.price,
            channel: [0; 32],
            bond: [0; 32],
            nonce: 0,
            work: None,
            phase: Phase::TargetBound,
            target: Some(target),
        });
        self.persist()?;
        Ok(true)
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

    /// A recorded nonce is an irrevocable proposal intent for tracked attempts.
    pub(crate) fn has_proposal_intent(&self) -> bool {
        self.record.as_ref().is_some_and(|record| record.nonce != 0)
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

    pub fn is_pending(&self) -> bool {
        self.record.is_some()
    }
    pub(super) fn buys_again(&self) -> bool {
        self.buy_again && self.record.is_none()
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

    /// Resolve the crash window between payment intent and payment completion
    /// from the existing signed channel journal, even after channel settlement.
    pub async fn reconcile(&mut self, options: &PaidWorkOptions) -> Result<()> {
        let Some(record) = self.record.clone() else {
            return Ok(());
        };
        if matches!(
            record.phase,
            Phase::InputBound | Phase::TargetBound | Phase::ChannelBound
        ) {
            return Err(self.unfinished("target or channel binding is incomplete"));
        }
        if self.tracked
            && matches!(
                record.phase,
                Phase::Paid | Phase::Reported | Phase::Rejected
            )
        {
            return Ok(());
        }
        if !options.journal_root.exists() {
            return Err(self.unfinished("channel journal is missing"));
        }
        let found = hellas_channel::work_store::discover_setups(
            &options.journal_root,
            options.config.chain.network,
        )
        .await?;
        if !found.unidentified.is_empty()
            || !found.setups.iter().any(|setup| {
                setup.role == Role::Client && setup.bond_edge.to_bytes() == record.bond
            })
        {
            return Err(self.unfinished("its setup journal is unavailable"));
        }
        let setup = SetupStore::open(
            &options.journal_root,
            options.config.chain.network,
            EdgeId::from_bytes(record.bond),
            Role::Client,
            &Secp256k1Verifier::new(),
        )
        .await?;
        let descriptor = setup
            .state()
            .close_descriptor()
            .ok_or_else(|| self.unfinished("channel descriptor is missing"))?;
        if descriptor.channel().id().as_bytes() != &record.channel {
            return Err(PurchaseError::Identity);
        }
        let origin = setup
            .state()
            .origin()
            .ok_or_else(|| self.unfinished("channel origin is missing"))?;
        let channel = descriptor.channel().clone();
        let settlement = descriptor.expected_settlement()?;
        let mut store = ChannelStore::open(
            &options.journal_root,
            channel,
            settlement,
            Role::Client,
            origin,
            hellas_store::ContentStore::new(),
            &Secp256k1Verifier::new(),
        )
        .await?;
        if let Some(work) = record.work.map(Digest::from_bytes)
            && let Some((result, _)) = store.state().job_by_id(work).and_then(|job| job.result())
            && result.outcome == hellas_channel::model::work::ResultOutcome::Failed
        {
            let outcome = TerminalOutcome::Rejected {
                result_digest: hellas_channel::model::work::result_digest(
                    store.state().channel(),
                    result,
                ),
                evidence_digest: result.transcript_content.id().digest(),
            };
            store
                .commit(
                    ChannelRecord::JobTerminated {
                        work_id: work,
                        outcome,
                    },
                    &Secp256k1Verifier::new(),
                )
                .await?;
        }
        if let Some(work) = record.work.map(Digest::from_bytes)
            && store.state().terminal_by_id(work).is_some_and(|terminal| {
                matches!(
                    terminal.outcome,
                    TerminalOutcome::Rejected { .. } | TerminalOutcome::Expired { .. }
                )
            })
        {
            return self.unpaid(work);
        }
        if let Some(work) = record.work.map(Digest::from_bytes)
            && store.state().terminal_by_id(work).is_some_and(|terminal| {
                matches!(terminal.outcome, TerminalOutcome::Certified { .. })
            })
        {
            self.record.as_mut().ok_or(PurchaseError::Identity)?.phase = Phase::Paid;
            self.persist()?;
            if self.buy_again {
                self.record = None;
                return Ok(());
            }
            return Err(PurchaseError::ResultLost {
                work,
                price: self.price,
            });
        }
        if let Some(job) = store
            .state()
            .jobs()
            .find(|job| job.authorization().proposal_nonce == record.nonce)
        {
            if job.authorization().payment_deadline < store.state().cursor().0
                || (job.phase() == hellas_channel::work_store::JobPhase::HalfSigned
                    && job.authorization().acceptance_deadline < store.state().cursor().0)
            {
                return Err(self.unfinished("its authorization expired"));
            }
            if record
                .work
                .is_some_and(|id| id != *job.work_id().as_bytes())
            {
                return Err(PurchaseError::Identity);
            }
            return Ok(());
        }
        if record.work.is_none()
            && record.nonce == store.state().proposal_nonce_high_water().saturating_add(1)
            && !store.state().is_closing()
        {
            return Ok(());
        }
        Err(self.unfinished("no unfinished authorized work remains"))
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
    pub(super) fn begin(&mut self, channel: Digest, bond: EdgeId, nonce: u64) -> Result<()> {
        if let Some(record) = &mut self.record {
            if record.phase == Phase::ChannelBound
                && record.channel == *channel.as_bytes()
                && record.bond == bond.to_bytes()
            {
                record.nonce = nonce;
                record.phase = Phase::Running;
                self.persist()?;
            } else if record.channel != *channel.as_bytes() || record.nonce != nonce {
                return Err(PurchaseError::Identity);
            }
        } else {
            self.record = Some(Record {
                job: self.job,
                price: self.price,
                channel: *channel.as_bytes(),
                bond: bond.to_bytes(),
                nonce,
                work: None,
                phase: Phase::Running,
                target: None,
            });
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
        if self.tracked {
            self.record.as_mut().ok_or(PurchaseError::Identity)?.phase = Phase::Rejected;
            return self.persist();
        }
        match std::fs::remove_file(&self.path) {
            Ok(()) => (),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(error) => return Err(error.into()),
        }
        hellas_private::sync_directory(self.path.parent().ok_or(PurchaseError::Identity)?)?;
        self.record = None;
        Ok(())
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

    fn persist(&self) -> Result<()> {
        hellas_private::write_atomically(
            &self.path,
            ".writing",
            &serde_json::to_vec(self.record.as_ref().ok_or(PurchaseError::Identity)?)?,
        )?;
        Ok(())
    }
}

/// An exclusively locked, recovery-only view of a purchase marker. It never
/// opens a channel, allocates a proposal, or needs the original payload.
pub struct PurchaseRecovery(Purchase);

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

impl PurchaseRecovery {
    pub fn open(path: &Path, job: Digest, price: u64) -> Result<Self> {
        Purchase::open_identity(path, job, price, true).map(Self)
    }

    pub fn channel(&self) -> Option<Digest> {
        self.0
            .record
            .as_ref()
            .filter(|record| !matches!(record.phase, Phase::InputBound | Phase::TargetBound))
            .map(|record| Digest::from_bytes(record.channel))
    }

    pub fn inspect(&self) -> Result<PurchaseStatus> {
        self.0.status()
    }

    pub async fn reconcile(&mut self, options: &PaidWorkOptions) -> Result<PurchaseStatus> {
        match self.0.reconcile(options).await {
            Ok(()) | Err(PurchaseError::ResultLost { .. }) => (),
            Err(error) => return Err(error),
        }
        self.inspect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_purchase_records_decode() {
        for (bytes, phase) in [
            (
                include_bytes!("../../tests/fixtures/legacy-purchase/running.json").as_slice(),
                Phase::Running,
            ),
            (
                include_bytes!("../../tests/fixtures/legacy-purchase/paying.json").as_slice(),
                Phase::Paying,
            ),
            (
                include_bytes!("../../tests/fixtures/legacy-purchase/paid.json").as_slice(),
                Phase::Paid,
            ),
            (
                include_bytes!("../../tests/fixtures/legacy-purchase/reported.json").as_slice(),
                Phase::Reported,
            ),
        ] {
            let record: Record = serde_json::from_slice(bytes).unwrap();
            assert_eq!(record.phase, phase);
            assert_eq!(record.price, 20);
            assert_eq!(record.nonce, 3);
            assert_eq!(record.work, (phase != Phase::Running).then_some([7; 32]));
            assert_eq!(serde_json::to_vec(&record).unwrap(), bytes);
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
                let mut purchase = Purchase::open_tracked(&path, &job).unwrap();
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
                    .begin(channel, EdgeId::from_bytes([2; 32]), 3)
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
            let recovered = PurchaseRecovery::open(&path, job.digest(), job.price()).unwrap();
            assert_eq!(recovered.channel(), Some(channel));
            assert_eq!(
                recovered.inspect().unwrap(),
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
            let purchase = Purchase::open_tracked(&path, &job).unwrap();
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
            let mut attempt = Purchase::open_tracked(&path, &job).unwrap();
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
        let mut attempt = Purchase::open_tracked(&path, &job).unwrap();
        assert!(!attempt.bind_target(target).unwrap());
        assert_eq!(attempt.nonce(channel).unwrap(), None);
        attempt.begin(channel, bond, 3).unwrap();
        assert_eq!(attempt.nonce(channel).unwrap(), Some(3));
        assert!(attempt.has_proposal_intent());
        drop(attempt);
        assert!(
            Purchase::open_tracked(&path, &job)
                .unwrap()
                .has_proposal_intent()
        );
    }

    #[test]
    fn recovery_reads_legacy_phases_without_the_original_payload() {
        let root = tempfile::tempdir().unwrap();
        let job = job();
        for (bytes, expected) in [
            (
                include_bytes!("../../tests/fixtures/legacy-purchase/running.json").as_slice(),
                PurchaseStatus::Running { work: None },
            ),
            (
                include_bytes!("../../tests/fixtures/legacy-purchase/paying.json").as_slice(),
                PurchaseStatus::Paying {
                    work: Digest::from_bytes([7; 32]),
                },
            ),
            (
                include_bytes!("../../tests/fixtures/legacy-purchase/paid.json").as_slice(),
                PurchaseStatus::Paid {
                    work: Digest::from_bytes([7; 32]),
                    reported: false,
                },
            ),
            (
                include_bytes!("../../tests/fixtures/legacy-purchase/reported.json").as_slice(),
                PurchaseStatus::Paid {
                    work: Digest::from_bytes([7; 32]),
                    reported: true,
                },
            ),
        ] {
            let path = root.path().join("purchase");
            hellas_private::write_atomically(&path, ".writing", bytes).unwrap();
            let recovery = PurchaseRecovery::open(&path, job.digest(), job.price()).unwrap();
            assert_eq!(recovery.inspect().unwrap(), expected);
        }
        let absent =
            PurchaseRecovery::open(&root.path().join("missing"), job.digest(), job.price())
                .unwrap();
        assert_eq!(absent.inspect().unwrap(), PurchaseStatus::Absent);
    }

    fn job() -> Job {
        Job::fetch(20, hellas_rpc::FetchContract::http().unwrap(), "http".into(), "request".into(), br#"{"url":"https://example.test/private-input-sentinel","method":"GET","tls":{"roots":{"mode":"web_pki"}},"max_response_bytes":4096}"#.to_vec(), hellas_rpc::Assurance::ProducerSigned).unwrap()
    }
    #[test]
    fn paid_but_unreported_marker_refuses_a_charge_and_retains_no_payload() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("purchase.json");
        let job = job();
        let work = Digest::from_bytes([7; 32]);
        {
            let mut purchase = Purchase::open(&path, &job, false).unwrap();
            assert!(
                matches!(Purchase::open(&path, &job, true), Err(PurchaseError::Busy)),
                "buy-again cannot bypass the live command lock"
            );
            purchase
                .begin(Digest::from_bytes([1; 32]), EdgeId::from_bytes([2; 32]), 1)
                .unwrap();
            purchase.accepting(work).unwrap();
            purchase.paying(work).unwrap();
            purchase.paid(work).unwrap();
        }
        assert!(
            matches!(Purchase::open(&path, &job, false), Err(PurchaseError::ResultLost { work: id, price: 20 }) if id == work)
        );
        let marker = std::fs::read_to_string(&path).unwrap();
        assert!(!marker.contains("private-input-sentinel"));
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&marker)
                .unwrap()
                .as_object()
                .unwrap()
                .keys()
                .cloned()
                .collect::<std::collections::BTreeSet<_>>(),
            ["job", "price", "channel", "bond", "nonce", "work", "phase"]
                .into_iter()
                .map(str::to_owned)
                .collect()
        );
        let purchase = Purchase::open(&path, &job, true).unwrap();
        assert!(purchase.buys_again());
        assert!(!purchase.is_pending());
    }
    #[test]
    fn reporting_finishes_the_purchase_and_reopening_preserves_unfinished_nonce() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("purchase.json");
        let job = job();
        let channel = Digest::from_bytes([1; 32]);
        {
            let mut purchase = Purchase::open(&path, &job, false).unwrap();
            purchase
                .begin(channel, EdgeId::from_bytes([2; 32]), 3)
                .unwrap();
        }
        {
            let mut purchase = Purchase::open(&path, &job, true).unwrap();
            assert_eq!(purchase.nonce(channel).unwrap(), Some(3));
            assert!(!purchase.buys_again());
            assert!(purchase.nonce(Digest::from_bytes([9; 32])).is_err());
            purchase.paid(Digest::from_bytes([7; 32])).unwrap();
            purchase.reported().unwrap();
        }
        let purchase = Purchase::open(&path, &job, false).unwrap();
        assert!(!purchase.is_pending());
        assert_eq!(purchase.nonce(channel).unwrap(), None);
    }
}
