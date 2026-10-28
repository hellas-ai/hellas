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
    Running,
    Paying,
    Paid,
    Reported,
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
}
impl Purchase {
    pub fn open(path: &Path, job: &Job, buy_again: bool) -> Result<Self> {
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
        if let Some(record) = &record {
            if record.job != *job.digest().as_bytes()
                || record.price != job.price()
                || record.nonce == 0
                || (matches!(record.phase, Phase::Paying | Phase::Paid | Phase::Reported)
                    && record.work.is_none())
            {
                return Err(PurchaseError::Identity);
            }
            if !buy_again && record.phase == Phase::Paid {
                return Err(PurchaseError::ResultLost {
                    work: Digest::from_bytes(record.work.ok_or(PurchaseError::Identity)?),
                    price: record.price,
                });
            }
        }
        let record = record.filter(|record| {
            record.phase != Phase::Reported && !(buy_again && record.phase == Phase::Paid)
        });
        Ok(Self {
            path: path.to_owned(),
            _lock: lock,
            job: *job.digest().as_bytes(),
            price: job.price(),
            record,
            buy_again,
        })
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
                matches!(terminal.outcome, TerminalOutcome::Rejected { .. })
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
            Some(record) if record.channel == *channel.as_bytes() => Ok(Some(record.nonce)),
            Some(_) => Err(self.unfinished("the original channel is unavailable")),
            None => Ok(None),
        }
    }
    pub(super) fn begin(&mut self, channel: Digest, bond: EdgeId, nonce: u64) -> Result<()> {
        if let Some(record) = &self.record {
            if record.channel != *channel.as_bytes() || record.nonce != nonce {
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
    fn persist(&self) -> Result<()> {
        hellas_private::write_atomically(
            &self.path,
            ".writing",
            &serde_json::to_vec(self.record.as_ref().ok_or(PurchaseError::Identity)?)?,
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
