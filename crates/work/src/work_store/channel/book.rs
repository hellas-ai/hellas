//! Funding-independent job identity, phases and nonce ordering.
use super::funding::{Clock, JobAuthorization, JobOutcome};
use super::*;

/// Job lifecycle shared by all supported funding models. Mutations are private
/// to the journal implementation; signatures and funding are checked before
/// the journal can publish a transition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JobBook<F: Funding> {
    pub(in crate::work_store) pending_proposal: Option<Digest>,
    pub(in crate::work_store) jobs: BTreeMap<Digest, JobState<F>>,
    pub(in crate::work_store) terminals: BTreeMap<Digest, JobTerminal<F>>,
    pub(in crate::work_store) proposal_nonce_high_water: u64,
    pub(in crate::work_store) indeterminate: BTreeSet<Digest>,
}

impl<F: Funding> Default for JobBook<F> {
    fn default() -> Self {
        Self {
            pending_proposal: None,
            jobs: BTreeMap::new(),
            terminals: BTreeMap::new(),
            proposal_nonce_high_water: 0,
            indeterminate: BTreeSet::new(),
        }
    }
}

impl<F: Funding> JobBook<F> {
    /// All jobs that have not reached a terminal.
    pub fn jobs(&self) -> impl ExactSizeIterator<Item = &JobState<F>> {
        self.jobs.values()
    }
    /// One open job, selected only within this book.
    pub fn job_by_id(&self, id: Digest) -> Option<&JobState<F>> {
        self.jobs.get(&id)
    }
    /// A retained terminal, for idempotent replay and recovery.
    pub fn terminal_by_id(&self, id: Digest) -> Option<&JobTerminal<F>> {
        self.terminals.get(&id)
    }
    /// All retained terminal outcomes.
    pub fn terminals(&self) -> impl ExactSizeIterator<Item = &JobTerminal<F>> {
        self.terminals.values()
    }
    /// Highest nonce ever proposed, including jobs that have ended.
    pub const fn proposal_nonce_high_water(&self) -> u64 {
        self.proposal_nonce_high_water
    }

    /// Proposal whose reply is still uncertain. Retrying preserves its exact bytes.
    pub const fn pending_proposal(&self) -> Option<Digest> {
        self.pending_proposal
    }

    pub(in crate::work_store) fn proposal_exchange(
        &mut self,
        id: Digest,
        pending: bool,
    ) -> Result<Applied, ChannelStateError> {
        let job = self.open_job(id, "recording proposal exchange")?;
        if job.phase != JobPhase::HalfSigned {
            return Err(ChannelStateError::WrongPhase {
                step: "recording proposal exchange",
                phase: job.phase.name(),
            });
        }
        if self.pending_proposal.is_some_and(|held| held != id) {
            return Err(ChannelStateError::Conflict {
                what: "unanswered proposal",
            });
        }
        let next = pending.then_some(id);
        if self.pending_proposal == next {
            return Ok(Applied::Redundant);
        }
        self.pending_proposal = next;
        Ok(Applied::Changed)
    }

    pub(in crate::work_store) fn revalidate_exchange(
        &self,
        role: Role,
    ) -> Result<(), ChannelStateError> {
        if let Some(id) = self.pending_proposal {
            if role != Role::Client {
                return Err(ChannelStateError::WrongRole {
                    step: "pending proposal",
                    expected: "client",
                });
            }
            let job = self.open_job(id, "replaying pending proposal")?;
            if job.phase != JobPhase::HalfSigned {
                return Err(ChannelStateError::WrongPhase {
                    step: "replaying pending proposal",
                    phase: job.phase.name(),
                });
            }
        }
        Ok(())
    }

    pub(in crate::work_store) fn open_job(
        &self,
        id: Digest,
        step: &'static str,
    ) -> Result<JobState<F>, ChannelStateError> {
        if let Some(job) = self.jobs.get(&id) {
            return Ok(job.clone());
        }
        self.refuse_if_terminated(id, step)?;
        Err(ChannelStateError::WrongPhase {
            step,
            phase: "none",
        })
    }
    fn open_job_mut(
        &mut self,
        id: Digest,
        step: &'static str,
    ) -> Result<&mut JobState<F>, ChannelStateError> {
        if let Some(job) = self.jobs.get_mut(&id) {
            return Ok(job);
        }
        match self.terminals.get(&id) {
            Some(t) => Err(ChannelStateError::Terminated {
                step,
                outcome: t.outcome.name(),
            }),
            None => Err(ChannelStateError::WrongPhase {
                step,
                phase: "none",
            }),
        }
    }
    pub(in crate::work_store) fn refuse_if_terminated(
        &self,
        id: Digest,
        step: &'static str,
    ) -> Result<(), ChannelStateError> {
        match self.terminals.get(&id) {
            Some(t) => Err(ChannelStateError::Terminated {
                step,
                outcome: t.outcome.name(),
            }),
            None => Ok(()),
        }
    }
    pub(in crate::work_store) fn propose(
        &mut self,
        job: JobState<F>,
        role: Role,
    ) -> Result<Applied, ChannelStateError> {
        if let Some(held) = self.jobs.get(&job.work_id) {
            return if held == &job {
                Ok(Applied::Redundant)
            } else {
                Err(ChannelStateError::Conflict {
                    what: "job proposal",
                })
            };
        }
        self.refuse_if_terminated(job.work_id, "proposing a job")?;
        let nonce = job.authorization.proposal_nonce();
        if nonce <= self.proposal_nonce_high_water {
            return Err(ChannelStateError::WrongChannel {
                field: "proposal_nonce",
            });
        }
        if role == Role::Client {
            if self.pending_proposal.is_some() {
                return Err(ChannelStateError::Conflict {
                    what: "unanswered proposal",
                });
            }
            self.pending_proposal = Some(job.work_id);
        }
        self.jobs.insert(job.work_id, job);
        self.proposal_nonce_high_water = nonce;
        Ok(Applied::Changed)
    }
    pub(in crate::work_store) fn accept(
        &mut self,
        id: Digest,
        signature: F::Signature,
        now: F::Clock,
        role: Role,
    ) -> Result<Applied, ChannelStateError> {
        let job = self.open_job_mut(id, "co-signing a job")?;
        if job.provider_signature == Some(signature) {
            return Ok(Applied::Redundant);
        }
        if job.phase != JobPhase::HalfSigned {
            return Err(ChannelStateError::WrongPhase {
                step: "co-signing a job",
                phase: job.phase.name(),
            });
        }
        if role == Role::Provider && now > job.authorization.acceptance_deadline() {
            return Err(ChannelStateError::AcceptanceLate {
                now: now.diagnostic(),
                deadline: job.authorization.acceptance_deadline().diagnostic(),
            });
        }
        job.provider_signature = Some(signature);
        job.phase = JobPhase::Accepted;
        if self.pending_proposal == Some(id) {
            self.pending_proposal = None;
        }
        Ok(Applied::Changed)
    }
    pub(in crate::work_store) fn run(
        &mut self,
        id: Digest,
        now: F::Clock,
    ) -> Result<Applied, ChannelStateError> {
        let job = self.open_job_mut(id, "a running marker")?;
        match job.phase {
            JobPhase::Running | JobPhase::Streaming => return Ok(Applied::Redundant),
            JobPhase::Accepted => {}
            phase => {
                return Err(ChannelStateError::WrongPhase {
                    step: "a running marker",
                    phase: phase.name(),
                });
            }
        }
        if now > job.authorization.terminal_deadline() {
            return Err(ChannelStateError::DispatchLate {
                now: now.diagnostic(),
                deadline: job.authorization.terminal_deadline().diagnostic(),
            });
        }
        job.phase = JobPhase::Running;
        Ok(Applied::Changed)
    }
    pub(in crate::work_store) fn record_result(
        &mut self,
        id: Digest,
        result: F::Result,
        signature: F::Signature,
        transcript: Vec<u8>,
    ) -> Result<Applied, ChannelStateError> {
        if self.indeterminate.contains(&id) {
            return Err(ChannelStateError::Indeterminate);
        }
        let job = self.open_job_mut(id, "recording a result")?;
        if !matches!(
            job.phase,
            JobPhase::Accepted | JobPhase::Running | JobPhase::Streaming
        ) {
            return Err(ChannelStateError::WrongPhase {
                step: "recording a result",
                phase: job.phase.name(),
            });
        }
        job.result = Some((result, signature));
        job.transcript = transcript;
        job.phase = if job.phase == JobPhase::Streaming {
            JobPhase::Delivered
        } else {
            JobPhase::Ready
        };
        Ok(Applied::Changed)
    }
    pub(in crate::work_store) fn mark_matched(
        &mut self,
        id: Digest,
    ) -> Result<Applied, ChannelStateError> {
        let job = self.open_job_mut(id, "recording a reproduction match")?;
        match job.phase {
            JobPhase::Matched => return Ok(Applied::Redundant),
            JobPhase::Ready => {}
            phase => {
                return Err(ChannelStateError::WrongPhase {
                    step: "recording a reproduction match",
                    phase: phase.name(),
                });
            }
        }
        job.phase = JobPhase::Matched;
        Ok(Applied::Changed)
    }
    pub(in crate::work_store) fn release(
        &mut self,
        id: Digest,
    ) -> Result<Applied, ChannelStateError> {
        let job = self.open_job_mut(id, "releasing plaintext")?;
        if job.phase.delivered() {
            return Ok(Applied::Redundant);
        }
        job.phase = match job.phase {
            JobPhase::Running => JobPhase::Streaming,
            JobPhase::Ready => JobPhase::Delivered,
            phase => {
                return Err(ChannelStateError::WrongPhase {
                    step: "releasing plaintext",
                    phase: phase.name(),
                });
            }
        };
        Ok(Applied::Changed)
    }
    pub(in crate::work_store) fn rest_at(&mut self, terminal: JobTerminal<F>) {
        if self.pending_proposal == Some(terminal.work_id) {
            self.pending_proposal = None;
        }
        self.jobs.remove(&terminal.work_id);
        self.indeterminate.remove(&terminal.work_id);
        self.terminals.insert(terminal.work_id, terminal);
    }
}
