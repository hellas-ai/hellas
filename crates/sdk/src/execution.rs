//! Native work execution and caller-owned attempt tracking.
use crate::job::{Job, JobInput};
use crate::paid_client::{PaidWorkOptions, PaidWorkResult, PaidWorkSession};
use crate::transact::{Purchase, PurchaseTarget};
use hellas_auth::{Digest, ProducerSigningKey, authority::ResourceId};
use hellas_channel::model::grant::ChannelId;
use hellas_channel::model::work::PrivateRecord;
use hellas_channel::work::PaidProgress;
use hellas_kernel::NetworkId;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExecutionTerms {
    Paid { price: u64 },
    Grant { resource: ResourceId },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExecutionTarget {
    pub network: NetworkId,
    pub provider: hellas_client::ProviderAddress,
}

#[derive(Debug, thiserror::Error)]
pub enum ExecutionError {
    #[error("attempt identity or funding mode does not match")]
    Identity,
    #[error("the original attempt is unresolved; recover it without proposing new work")]
    RecoveryRequired,
    #[error(transparent)]
    Purchase(#[from] crate::transact::PurchaseError),
    #[error(transparent)]
    Job(#[from] crate::job::JobError),
    #[error(transparent)]
    Paid(#[from] crate::paid_client::PaidClientError),
    #[error(transparent)]
    Transaction(#[from] crate::transact::TransactError),
    #[error(transparent)]
    Grant(#[from] crate::grant_client::GrantClientError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}
type Result<T> = std::result::Result<T, ExecutionError>;

/// Prepare an admitted grant input using the current signed provider policy.
pub(crate) fn prepare_grant_input(
    input: &JobInput,
    policy: &hellas_authority::model::grant::records::GrantPolicy,
    offer: &hellas_authority::model::grant::records::SignedOffer,
    signer: &ProducerSigningKey,
) -> Result<hellas_rpc::protocol::invocation::PreparedInvocation> {
    input.admits(&policy.invocation_policy, false)?;
    let runner = hellas_auth::PublicKey::Secp256k1(
        hellas_authority::model::grant::records::grant_producer(&offer.offer().provider)
            .map_err(crate::grant_client::GrantClientError::from)?
            .to_bytes(),
    );
    Ok(input.prepare(
        &input.manifest()?,
        signer,
        rand::random(),
        runner,
        &policy.invocation_policy,
        false,
    )?)
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GrantRecord {
    format: String,
    input: [u8; 32],
    resource: ResourceId,
    target: Option<GrantTarget>,
    channel: Option<ChannelId>,
    authorization: Option<Vec<u8>>,
    work: Option<[u8; 32]>,
    #[serde(default)]
    rejected: bool,
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct GrantTarget {
    network: String,
    provider: hellas_client::ProviderAddress,
}

pub(crate) struct GrantAttempt {
    path: PathBuf,
    _lock: std::fs::File,
    record: GrantRecord,
}
impl Drop for GrantAttempt {
    fn drop(&mut self) {
        let _ = self._lock.unlock();
    }
}
impl GrantAttempt {
    fn persist(&self) -> Result<()> {
        hellas_private::write_atomically(
            &self.path,
            ".writing",
            &serde_json::to_vec(&self.record)?,
        )?;
        Ok(())
    }
    fn bind_channel(&mut self, channel: ChannelId) -> Result<()> {
        if self.record.target.is_none() {
            return Err(ExecutionError::Identity);
        }
        match self.record.channel {
            Some(existing) if existing != channel => Err(ExecutionError::Identity),
            Some(_) => Ok(()),
            None => {
                self.record.channel = Some(channel);
                self.persist()
            }
        }
    }
    pub(crate) fn bind_proposal(
        &mut self,
        authorization: &hellas_channel::model::grant::GrantJobAuthorizationV1,
        work: Digest,
    ) -> Result<()> {
        if self.record.channel != Some(authorization.channel_id)
            || self.record.resource != authorization.resource_id
            || self.record.work.is_some()
        {
            return Err(ExecutionError::RecoveryRequired);
        }
        self.record.authorization = Some(authorization.encode());
        self.record.work = Some(*work.as_bytes());
        self.persist()
    }
    pub(crate) fn mark_rejected(&mut self, work: Digest) -> Result<()> {
        if self.record.work != Some(*work.as_bytes()) {
            return Err(ExecutionError::Identity);
        }
        if !self.record.rejected {
            self.record.rejected = true;
            self.persist()?;
        }
        Ok(())
    }
}

enum AttemptRecord {
    Paid(Purchase),
    Grant(GrantAttempt),
}
/// Exclusive handle to a caller-chosen private attempt. Paid attempts use the
/// same file and lock as Purchase; grant attempts contain identifiers only.
pub struct ExecutionAttempt {
    path: PathBuf,
    input: Digest,
    terms: ExecutionTerms,
    record: AttemptRecord,
    newly_bound: bool,
    retain_results: bool,
}
impl ExecutionAttempt {
    pub fn open(path: &Path, input: &JobInput, terms: ExecutionTerms) -> Result<Self> {
        Self::open_inner(path, input, terms, true)
    }

    /// Open only an existing attempt, failing closed if its record was lost.
    pub fn open_existing(path: &Path, input: &JobInput, terms: ExecutionTerms) -> Result<Self> {
        Self::open_inner(path, input, terms, false)
    }

    fn open_inner(
        path: &Path,
        input: &JobInput,
        terms: ExecutionTerms,
        create: bool,
    ) -> Result<Self> {
        // Keep caller records out of the reserved completion namespace so one
        // attempt cannot overwrite another attempt's payload or receipt.
        if path.components().any(|component| {
            matches!(component,
            std::path::Component::Normal(name) if name == ".hellas-execution")
        }) {
            return Err(ExecutionError::Identity);
        }
        let digest = input.tracking_digest();
        let record = match terms {
            ExecutionTerms::Paid { price } => {
                let job = Job::from_input(price, input.clone())?;
                AttemptRecord::Paid(if create {
                    Purchase::open_tracked(path, &job)?
                } else {
                    Purchase::open_existing_tracked(path, &job)?
                })
            }
            ExecutionTerms::Grant { resource } => {
                let parent = path.parent().ok_or(ExecutionError::Identity)?;
                hellas_private::create_dir_all_durable(parent)?;
                let lock = hellas_private::open_lock_beside(path)?;
                lock.try_lock()
                    .map_err(|_| crate::transact::PurchaseError::Busy)?;
                let (record, created) = match hellas_private::read_bounded_regular_file(path, 4096)
                {
                    Ok(bytes) => (serde_json::from_slice::<GrantRecord>(&bytes)?, false),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound && create => (
                        GrantRecord {
                            format: "hellas.grant-attempt.v1".into(),
                            input: *digest.as_bytes(),
                            resource,
                            target: None,
                            channel: None,
                            authorization: None,
                            work: None,
                            rejected: false,
                        },
                        true,
                    ),
                    Err(error) => return Err(error.into()),
                };
                if record.format != "hellas.grant-attempt.v1"
                    || record.input != *digest.as_bytes()
                    || record.resource != resource
                    || record.authorization.is_some() != record.work.is_some()
                    || (record.rejected && record.work.is_none())
                {
                    return Err(ExecutionError::Identity);
                }
                if let Some(encoded) = &record.authorization {
                    let authorization =
                        hellas_channel::model::grant::GrantJobAuthorizationV1::decode(encoded)
                            .map_err(|_| ExecutionError::Identity)?;
                    let target = record.target.as_ref().ok_or(ExecutionError::Identity)?;
                    let network =
                        NetworkId::new(&target.network).ok_or(ExecutionError::Identity)?;
                    if record.channel != Some(authorization.channel_id)
                        || record.resource != authorization.resource_id
                        || record.work
                            != Some(
                                *hellas_channel::model::grant::grant_work_id(
                                    network,
                                    &authorization,
                                )
                                .as_bytes(),
                            )
                    {
                        return Err(ExecutionError::Identity);
                    }
                }
                let attempt = GrantAttempt {
                    path: path.to_owned(),
                    _lock: lock,
                    record,
                };
                if created {
                    attempt.persist()?;
                }
                AttemptRecord::Grant(attempt)
            }
        };
        Ok(Self {
            path: path.to_owned(),
            input: digest,
            terms,
            record,
            newly_bound: false,
            retain_results: false,
        })
    }

    /// Opt into private storage of verified output and transcript bytes.
    pub fn retain_results(&mut self, retain: bool) {
        self.retain_results = retain;
    }

    pub fn bind_target(&mut self, target: ExecutionTarget) -> Result<()> {
        let created = match &mut self.record {
            AttemptRecord::Paid(purchase) => purchase.bind_target(PurchaseTarget {
                network: target.network.as_str().into(),
                provider: target.provider,
            })?,
            AttemptRecord::Grant(attempt) => {
                let target = GrantTarget {
                    network: target.network.as_str().into(),
                    provider: target.provider,
                };
                match &attempt.record.target {
                    Some(existing) if existing == &target => false,
                    Some(_) => return Err(ExecutionError::Identity),
                    None => {
                        attempt.record.target = Some(target);
                        attempt.persist()?;
                        true
                    }
                }
            }
        };
        self.newly_bound |= created;
        Ok(())
    }

    fn matches(&self, input: &JobInput, terms: ExecutionTerms) -> Result<()> {
        if self.input != input.tracking_digest() || self.terms != terms {
            return Err(ExecutionError::Identity);
        }
        Ok(())
    }
}

/// An already-open session; this enum owns no endpoint or listener.
pub enum ExecutionSession<'a> {
    Paid(&'a mut PaidWorkSession),
    Grant(&'a mut crate::grant_client::GrantSession),
}

pub enum ExecutionResult {
    Paid(PaidWorkResult),
    Grant(crate::grant_client::GrantWorkResult),
}

#[derive(Default)]
pub struct ExecutionObservers {
    pub progress: Option<PaidProgress>,
    pub accepted: Option<crate::transact::Accepted>,
}

impl ExecutionAttempt {
    /// Select and preflight a paid channel, then bind its target before funding
    /// or setup signatures. Reopening an existing binding permits retained-channel
    /// recovery only; it never authorizes fresh funding.
    pub async fn open_paid_session(
        &mut self,
        input: &JobInput,
        options: PaidWorkOptions,
        endpoint: iroh::Endpoint,
        settlement_key: hellas_kernel::Secp256k1Signer,
        owner: std::sync::Arc<crate::client_owner::ClientOwner>,
        funding: crate::paid_client::SessionFundingOptions,
    ) -> Result<PaidWorkSession> {
        let terms = ExecutionTerms::Paid {
            price: options.expected_price,
        };
        self.matches(input, terms)?;
        let job = Job::from_input(options.expected_price, input.clone())?;
        let target = PurchaseTarget {
            network: options.config.chain.network.as_str().into(),
            provider: options.provider,
        };
        let AttemptRecord::Paid(purchase) = &mut self.record else {
            return Err(ExecutionError::Identity);
        };
        if purchase.has_target() && !purchase.matches_target(&target) {
            return Err(ExecutionError::Identity);
        }
        let fresh = !purchase.has_target() || self.newly_bound;
        let mode = if fresh {
            crate::paid_client::SessionOpenMode::Job(&job)
        } else {
            crate::paid_client::SessionOpenMode::Retained
        };
        let mut session = PaidWorkSession::open_intent(
            options,
            endpoint,
            settlement_key,
            owner,
            mode,
            funding,
            Some(Box::new(|| {
                purchase.bind_target(target)?;
                self.newly_bound = false;
                Ok(())
            })),
        )
        .await?;
        let descriptor = session.descriptor();
        if let Err(error) = purchase.bind_channel(descriptor.channel().id(), descriptor.bond_edge())
        {
            session.shutdown().await;
            return Err(error.into());
        }
        Ok(session)
    }
}

impl ExecutionAttempt {
    /// Bind the selected grant provider before opening its non-spending session.
    pub async fn open_grant_session(
        &mut self,
        options: crate::grant_client::GrantSessionOptions,
        transport: crate::grant_client::GrantTransport,
    ) -> Result<crate::grant_client::GrantSession> {
        if !matches!(self.terms, ExecutionTerms::Grant { .. }) {
            return Err(ExecutionError::Identity);
        }
        let offer = options.target.offer();
        let provider = hellas_client::ProviderAddress::of(&offer.provider)
            .map_err(crate::grant_client::GrantClientError::from)?;
        self.bind_target(ExecutionTarget {
            network: offer.network,
            provider,
        })?;
        let mut session = crate::grant_client::GrantSession::open(options, transport).await?;
        let result = match &mut self.record {
            AttemptRecord::Grant(attempt) => attempt.bind_channel(session.store().channel().id),
            _ => Err(ExecutionError::Identity),
        };
        if let Err(error) = result {
            let _ = session.shutdown().await;
            return Err(error);
        }
        Ok(session)
    }
}

impl<'a> ExecutionSession<'a> {
    /// Execute the original input under the session's funding mode.
    pub async fn execute(
        &mut self,
        input: JobInput,
        terms: ExecutionTerms,
        signer: &ProducerSigningKey,
        observers: ExecutionObservers,
        mut attempt: Option<&mut ExecutionAttempt>,
    ) -> Result<ExecutionResult> {
        if let Some(attempt) = attempt.as_deref_mut() {
            attempt.matches(&input, terms)?;
            attempt.newly_bound = false;
        }
        let result = match (self, terms) {
            (Self::Paid(session), ExecutionTerms::Paid { price }) => {
                let job = Job::from_input(price, input)?;
                let target = session.execution_target();
                let purchase = match attempt.as_deref_mut() {
                    Some(attempt) => match &mut attempt.record {
                        AttemptRecord::Paid(purchase) => {
                            let target = PurchaseTarget {
                                network: target.network.as_str().into(),
                                provider: target.provider,
                            };
                            if !purchase.matches_target(&target) {
                                return Err(ExecutionError::Identity);
                            }
                            purchase.bind_channel(
                                session.descriptor().channel().id(),
                                session.descriptor().bond_edge(),
                            )?;
                            if purchase.has_proposal_intent() {
                                return Err(ExecutionError::RecoveryRequired);
                            }
                            Some(purchase)
                        }
                        _ => return Err(ExecutionError::Identity),
                    },
                    None => None,
                };
                Ok(ExecutionResult::Paid(
                    crate::transact::transact(
                        session,
                        &job,
                        signer,
                        crate::transact::TransactionOptions {
                            purchase,
                            // A fresh facade call is an explicit new attempt;
                            // recovery never searches for a matching old job here.
                            new_purchase: true,
                            progress: observers.progress,
                            accepted: observers.accepted,
                            ..Default::default()
                        },
                    )
                    .await?,
                ))
            }
            (Self::Grant(session), ExecutionTerms::Grant { resource }) => {
                let target = session.execution_target()?;
                let tracker = match attempt.as_deref_mut() {
                    Some(attempt) => match &mut attempt.record {
                        AttemptRecord::Grant(tracker) => {
                            let target = GrantTarget {
                                network: target.network.as_str().into(),
                                provider: target.provider,
                            };
                            if tracker.record.target.as_ref() != Some(&target) {
                                return Err(ExecutionError::Identity);
                            }
                            tracker.bind_channel(session.store().channel().id)?;
                            if tracker.record.work.is_some() {
                                return Err(ExecutionError::RecoveryRequired);
                            }
                            Some(tracker)
                        }
                        _ => return Err(ExecutionError::Identity),
                    },
                    None => None,
                };
                session.refresh().await?;
                let policy = session
                    .offer()
                    .offer()
                    .grant
                    .policies
                    .iter()
                    .find(|policy| policy.resource == resource)
                    .ok_or(ExecutionError::Identity)?;
                let mut input = input;
                if let JobInput::Fetch {
                    contract, request, ..
                } = &mut input
                    && contract.schema() == hellas_rpc::FetchSchema::HttpV1
                {
                    let template = policy.https.as_ref().ok_or(ExecutionError::Identity)?;
                    let mut http = hellas_rpc::http_fetch::HttpFetchRequest::decode(request)
                        .map_err(|_| ExecutionError::Identity)?;
                    template
                        .prepare(&mut http)
                        .map_err(|_| ExecutionError::Identity)?;
                    *request = serde_json::to_vec(&http)?;
                }
                let prepared = prepare_grant_input(
                    &input,
                    policy,
                    session.offer(),
                    session.execution_signer(),
                )?;
                let content = input.content();
                Ok(ExecutionResult::Grant(
                    session
                        .run_tracked_current(resource, prepared, &content, observers, tracker)
                        .await?,
                ))
            }
            _ => Err(ExecutionError::Identity),
        }?;
        if let Some(attempt) = attempt {
            match &result {
                ExecutionResult::Paid(result) => attempt.complete(
                    result.work_id,
                    &result.output,
                    result.transcript.clone(),
                    true,
                )?,
                ExecutionResult::Grant(result) => {
                    let transcript = hellas_channel::model::work::encode_transcript(&result.events)
                        .map_err(|_| ExecutionError::Identity)?;
                    attempt.complete(
                        result.work_id,
                        &result.output,
                        transcript,
                        result.result.outcome
                            == hellas_channel::model::work::ResultOutcome::Finished,
                    )?;
                }
            }
        }
        Ok(result)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CompletionReceipt {
    format: String,
    input: [u8; 32],
    terms: ExecutionTerms,
    work: [u8; 32],
    output: hellas_rpc::ContentId,
    transcript: hellas_rpc::ContentRef,
    finished: bool,
    retained: bool,
    reported: bool,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RetainedResult {
    output: hellas_rpc::protocol::invocation::output::InvocationOutput,
    transcript: serde_bytes::ByteBuf,
}
/// Verified bytes retained for repeated caller delivery without execution.
pub struct RetainedExecutionResult {
    pub output: hellas_rpc::protocol::invocation::output::InvocationOutput,
    pub transcript: Vec<u8>,
}
const MAX_RESULT_RECEIPT_BYTES: usize =
    2 * hellas_rpc::protocol::invocation::MAX_INVOCATION_BYTES + 4096;

impl ExecutionAttempt {
    fn sidecar(&self, suffix: &str) -> Result<PathBuf> {
        let name = self.path.file_name().ok_or(ExecutionError::Identity)?;
        let digest = Digest::hash(name.as_encoded_bytes());
        let directory = self
            .path
            .parent()
            .ok_or(ExecutionError::Identity)?
            .join(".hellas-execution");
        Ok(directory.join(format!("{}{suffix}", hex::encode(digest.as_bytes()))))
    }
    fn read_receipt(&self) -> Result<Option<CompletionReceipt>> {
        let path = self.sidecar(".receipt")?;
        let bytes = match hellas_private::read_bounded_regular_file(&path, 4096) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let receipt: CompletionReceipt = serde_json::from_slice(&bytes)?;
        if receipt.format != "hellas.work-completion.v1"
            || receipt.input != *self.input.as_bytes()
            || receipt.terms != self.terms
            || (matches!(self.terms, ExecutionTerms::Paid { .. }) && !receipt.finished)
        {
            return Err(ExecutionError::Identity);
        }
        let work = match &self.record {
            AttemptRecord::Paid(purchase) => purchase.work_id().map(|id| *id.as_bytes()),
            AttemptRecord::Grant(attempt) => attempt.record.work,
        };
        if work != Some(receipt.work) {
            return Err(ExecutionError::Identity);
        }
        Ok(Some(receipt))
    }
    fn complete(
        &mut self,
        work: Digest,
        output: &hellas_rpc::protocol::invocation::output::InvocationOutput,
        transcript: Vec<u8>,
        finished: bool,
    ) -> Result<()> {
        if self.read_receipt()?.is_some() {
            return Err(ExecutionError::RecoveryRequired);
        }
        if transcript.len() > hellas_rpc::protocol::invocation::MAX_INVOCATION_BYTES {
            return Err(ExecutionError::Identity);
        }
        let output_id = output.content_id().map_err(|_| ExecutionError::Identity)?;
        let transcript_ref = hellas_rpc::ContentRef::for_bytes(&transcript);
        if self.retain_results {
            let artifact = RetainedResult {
                output: output.clone(),
                transcript: transcript.into(),
            };
            let bytes =
                hellas_rpc::protocol::value::encode_bounded(&artifact, MAX_RESULT_RECEIPT_BYTES)
                    .map_err(|_| ExecutionError::Identity)?;
            let path = self.sidecar(".result")?;
            hellas_private::create_dir_all_durable(path.parent().ok_or(ExecutionError::Identity)?)?;
            hellas_private::write_atomically(&path, ".writing", &bytes)?;
        }
        let receipt = CompletionReceipt {
            format: "hellas.work-completion.v1".into(),
            input: *self.input.as_bytes(),
            terms: self.terms,
            work: *work.as_bytes(),
            output: output_id,
            transcript: transcript_ref,
            finished,
            retained: self.retain_results,
            reported: false,
        };
        let path = self.sidecar(".receipt")?;
        hellas_private::create_dir_all_durable(path.parent().ok_or(ExecutionError::Identity)?)?;
        hellas_private::write_atomically(&path, ".writing", &serde_json::to_vec(&receipt)?)?;
        Ok(())
    }
    /// Read retained bytes locally; missing bytes are distinct from execution status.
    pub fn retained_result(&self) -> Result<Option<RetainedExecutionResult>> {
        let Some(receipt) = self.read_receipt()? else {
            return Ok(None);
        };
        if !receipt.retained {
            return Ok(None);
        }
        let bytes = match hellas_private::read_bounded_regular_file(
            &self.sidecar(".result")?,
            MAX_RESULT_RECEIPT_BYTES,
        ) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let artifact: RetainedResult =
            hellas_rpc::protocol::value::decode_canonical_bounded(&bytes, MAX_RESULT_RECEIPT_BYTES)
                .map_err(|_| ExecutionError::Identity)?;
        if artifact
            .output
            .content_id()
            .map_err(|_| ExecutionError::Identity)?
            != receipt.output
            || hellas_rpc::ContentRef::for_bytes(&artifact.transcript) != receipt.transcript
        {
            return Err(ExecutionError::Identity);
        }
        Ok(Some(RetainedExecutionResult {
            output: artifact.output,
            transcript: artifact.transcript.into_vec(),
        }))
    }
    /// Record delivery only after the caller has committed its own result.
    pub fn reported(&mut self) -> Result<()> {
        let mut receipt = self
            .read_receipt()?
            .ok_or(ExecutionError::RecoveryRequired)?;
        if !receipt.reported {
            receipt.reported = true;
            hellas_private::write_atomically(
                &self.sidecar(".receipt")?,
                ".writing",
                &serde_json::to_vec(&receipt)?,
            )?;
        }
        if let AttemptRecord::Paid(purchase) = &mut self.record {
            purchase.reported()?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Acceptance {
    Unknown,
    Accepted,
    Rejected,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Terminal {
    Unknown,
    Verified,
    Rejected,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Payment {
    NotApplicable,
    Pending,
    Unpaid,
    Paid,
}
/// Orthogonal local facts; unavailable bytes are not a retry instruction.
pub struct ExecutionFacts {
    pub target_bound: bool,
    pub channel_bound: bool,
    pub work: Option<Digest>,
    pub acceptance: Acceptance,
    pub terminal: Terminal,
    pub payment: Payment,
    pub result_available: bool,
    pub reported: bool,
}
impl ExecutionAttempt {
    /// Bounded local inspection; does not open a session or modify markers.
    pub fn inspect(&self) -> Result<ExecutionFacts> {
        let receipt = self.read_receipt()?;
        let (target_bound, channel_bound, work, acceptance, terminal, payment, paid_reported) =
            match &self.record {
                AttemptRecord::Paid(purchase) => {
                    use crate::transact::PurchaseStatus as P;
                    match purchase.status()? {
                        P::Absent | P::InputBound => (
                            false,
                            false,
                            None,
                            Acceptance::Unknown,
                            Terminal::Unknown,
                            Payment::Pending,
                            false,
                        ),
                        P::TargetBound => (
                            true,
                            false,
                            None,
                            Acceptance::Unknown,
                            Terminal::Unknown,
                            Payment::Pending,
                            false,
                        ),
                        P::ChannelBound => (
                            true,
                            true,
                            None,
                            Acceptance::Unknown,
                            Terminal::Unknown,
                            Payment::Pending,
                            false,
                        ),
                        P::Running { work } => (
                            purchase.has_target(),
                            true,
                            work,
                            if work.is_some() {
                                Acceptance::Accepted
                            } else {
                                Acceptance::Unknown
                            },
                            Terminal::Unknown,
                            Payment::Pending,
                            false,
                        ),
                        P::Paying { work } => (
                            purchase.has_target(),
                            true,
                            Some(work),
                            Acceptance::Accepted,
                            Terminal::Verified,
                            Payment::Pending,
                            false,
                        ),
                        P::Paid { work, reported } => (
                            purchase.has_target(),
                            true,
                            Some(work),
                            Acceptance::Accepted,
                            Terminal::Verified,
                            Payment::Paid,
                            reported,
                        ),
                        P::Rejected { work } => (
                            purchase.has_target(),
                            true,
                            Some(work),
                            Acceptance::Accepted,
                            Terminal::Rejected,
                            Payment::Unpaid,
                            false,
                        ),
                    }
                }
                AttemptRecord::Grant(attempt) => (
                    attempt.record.target.is_some(),
                    attempt.record.channel.is_some(),
                    attempt.record.work.map(Digest::from_bytes),
                    if attempt.record.rejected {
                        Acceptance::Rejected
                    } else if receipt.is_some() {
                        Acceptance::Accepted
                    } else {
                        Acceptance::Unknown
                    },
                    if attempt.record.rejected {
                        Terminal::Rejected
                    } else if let Some(receipt) = &receipt {
                        if receipt.finished {
                            Terminal::Verified
                        } else {
                            Terminal::Rejected
                        }
                    } else {
                        Terminal::Unknown
                    },
                    Payment::NotApplicable,
                    false,
                ),
            };
        Ok(ExecutionFacts {
            target_bound,
            channel_bound,
            work,
            acceptance,
            terminal,
            payment,
            result_available: self.retained_result()?.is_some(),
            reported: paid_reported || receipt.as_ref().is_some_and(|receipt| receipt.reported),
        })
    }
}

impl<'a> ExecutionSession<'a> {
    /// Reconcile only the bound work. This never allocates a nonce or proposes
    /// another execution, though a previously verified paid result may be paid.
    /// Original-format markers with a work ID retain exact-work recovery.
    /// Without that ID or a per-attempt request binding, a reused channel nonce
    /// is ambiguous even for identical input. Recovery then returns
    /// `PurchaseError::Unfinished` and leaves the attempt unchanged.
    pub async fn recover(&mut self, attempt: &mut ExecutionAttempt) -> Result<ExecutionFacts> {
        attempt.newly_bound = false;
        match (self, &mut attempt.record) {
            (Self::Paid(session), AttemptRecord::Paid(purchase)) => {
                let target = session.execution_target();
                if !purchase.matches_target(&PurchaseTarget {
                    network: target.network.as_str().into(),
                    provider: target.provider,
                }) {
                    return Err(ExecutionError::Identity);
                }
                purchase.bind_channel(
                    session.descriptor().channel().id(),
                    session.descriptor().bond_edge(),
                )?;
                if purchase.work_id().is_none()
                    && let Some(work) = session
                        .with_state(|state| purchase.accepted_work(state))
                        .await??
                {
                    // Persist identity before reconciling a result or payment.
                    purchase.accepting(work)?;
                }
                if !matches!(
                    purchase.status()?,
                    crate::transact::PurchaseStatus::Paid { .. }
                        | crate::transact::PurchaseStatus::Rejected { .. }
                ) && let Some(work) = purchase.work_id()
                {
                    match session.recorded_terminal(work).await? {
                        Some(true) => purchase.paid(work)?,
                        Some(false) => purchase.unpaid(work)?,
                        None if session.recover_verified_payment(work).await? => {
                            purchase.paid(work)?
                        }
                        None => (),
                    }
                }
            }
            (Self::Grant(session), AttemptRecord::Grant(tracker)) => {
                let target = session.execution_target()?;
                if tracker.record.target.as_ref()
                    != Some(&GrantTarget {
                        network: target.network.as_str().into(),
                        provider: target.provider,
                    })
                {
                    return Err(ExecutionError::Identity);
                }
                tracker.bind_channel(session.store().channel().id)?;
                if let Some(work) = tracker.record.work.map(Digest::from_bytes) {
                    if tracker.record.rejected {
                        session.resolve_recorded_refusal(work).await?;
                        return attempt.inspect();
                    }
                    match session.store().book().pending_proposal() {
                        Some(pending) if pending != work => return Err(ExecutionError::Identity),
                        Some(_) => {
                            session.recover_tracked(Some(tracker)).await?;
                        }
                        None => {
                            if session.store().book().job_by_id(work).is_some_and(|job| {
                                job.phase() == hellas_channel::work_store::JobPhase::HalfSigned
                            }) {
                                tracker.record.rejected = true;
                                tracker.persist()?;
                            }
                        }
                    }
                    let observed =
                        session.store().book().job_by_id(work).map(|job| {
                            (job.phase(), job.result().map(|(result, _)| result.outcome))
                        });
                    let mut facts = attempt.inspect()?;
                    if let Some((phase, terminal)) = observed {
                        if phase != hellas_channel::work_store::JobPhase::HalfSigned {
                            facts.acceptance = Acceptance::Accepted;
                        }
                        if let Some(outcome) = terminal {
                            facts.terminal = if outcome
                                == hellas_channel::model::work::ResultOutcome::Finished
                            {
                                Terminal::Verified
                            } else {
                                Terminal::Rejected
                            };
                        }
                    }
                    return Ok(facts);
                }
            }
            _ => return Err(ExecutionError::Identity),
        }
        attempt.inspect()
    }
}

impl ExecutionAttempt {
    /// Inspect the canonical grant journal without opening a network session or
    /// changing its clock. The caller supplies its existing session options.
    pub async fn inspect_grant(
        &self,
        options: &crate::grant_client::GrantSessionOptions,
    ) -> Result<ExecutionFacts> {
        let mut facts = self.inspect()?;
        let AttemptRecord::Grant(tracker) = &self.record else {
            return Err(ExecutionError::Identity);
        };
        let Some(work) = tracker.record.work.map(Digest::from_bytes) else {
            return Ok(facts);
        };
        let offer = options.target.offer();
        let provider = hellas_client::ProviderAddress::of(&offer.provider)
            .map_err(crate::grant_client::GrantClientError::from)?;
        let target = GrantTarget {
            network: offer.network.as_str().into(),
            provider,
        };
        if tracker.record.target.as_ref() != Some(&target) {
            return Err(ExecutionError::Identity);
        }
        let client = hellas_channel::model::grant::ChannelClient {
            principal: options.principal,
            node: hellas_auth::authority::NodeKey::from_public_key(options.signer.public_key())
                .map_err(|_| ExecutionError::Identity)?,
        };
        let channel = offer.channel(client);
        if tracker.record.channel != Some(channel) {
            return Err(ExecutionError::Identity);
        }
        let state = hellas_authority::work_store::grant::GrantChannelState {
            id: channel,
            grant: offer.grant.id,
            generation: offer.generation,
            client,
        };
        let directory = options.journal_root.join(hex::encode(channel.0.as_bytes()));
        let observed = hellas_authority::work_store::grant::GrantClientStore::inspect_work(
            &directory,
            offer.network,
            offer.provider.clone(),
            state,
            work,
        )
        .await
        .map_err(crate::grant_client::GrantClientError::from)?;
        if let Some(observed) = observed {
            if observed.phase != hellas_channel::work_store::JobPhase::HalfSigned {
                facts.acceptance = Acceptance::Accepted;
            } else if !observed.pending {
                facts.acceptance = Acceptance::Rejected;
                facts.terminal = Terminal::Rejected;
            }
            if let Some(result) = observed.result {
                facts.terminal = if result.result.outcome
                    == hellas_channel::model::work::ResultOutcome::Finished
                {
                    Terminal::Verified
                } else {
                    Terminal::Rejected
                };
            }
        }
        Ok(facts)
    }
}
