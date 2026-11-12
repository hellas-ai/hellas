//! Native work execution and caller-owned attempt tracking.
use crate::gateway_work::WorkRequest;
use crate::job::{Job, JobInput};
use crate::paid_client::{PaidWorkOptions, PaidWorkResult, PaidWorkSession};
use crate::transact::{PaidAttemptPath, Purchase, PurchaseTarget};
use hellas_auth::{Digest, ProducerSigningKey, authority::ResourceId};
use hellas_channel::model::grant::ChannelId;
use hellas_channel::model::work::PrivateRecord;
use hellas_channel::work::PaidProgress;
use hellas_kernel::NetworkId;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

mod executor;
pub use executor::{Executor, GrantExecution, PaidExecution};
#[cfg(feature = "compute")]
pub mod local;

/// Format tag of a persisted grant attempt record.
const GRANT_ATTEMPT_FORMAT: &str = "hellas.grant-attempt.v1";
/// Format tag of a persisted completion receipt.
const WORK_COMPLETION_FORMAT: &str = "hellas.work-completion.v1";
/// Retained paid work must not monopolize a channel a new request needs.
const PAID_RECOVERY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

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
    #[error("paid output is unavailable; recover the original attempt or explicitly buy again")]
    ResultUnavailable,
    #[error(
        "the original attempt is unresolved (work {:?}, terminal {:?}, payment {:?}, result available: {}); no new work was proposed",
        .0.work, .0.terminal, .0.payment, .0.result_available
    )]
    Unresolved(Box<ExecutionFacts>),
    #[error("this attempt is already terminal; start a new attempt")]
    Terminal,
    #[error("delivery failed: {0}")]
    Delivery(Box<dyn std::error::Error + Send + Sync>),
    #[cfg(feature = "compute")]
    #[error("local execution failed: {0}")]
    Local(String),
    #[cfg(feature = "compute")]
    #[error("local admission refused: {0}")]
    LocalAdmission(String),
    #[error(transparent)]
    Stopped(#[from] RequestStopped),
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
pub(crate) type Result<T> = std::result::Result<T, ExecutionError>;

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
}
impl ExecutionAttempt {
    pub fn open(path: &Path, input: &JobInput, terms: ExecutionTerms) -> Result<Self> {
        if matches!(terms, ExecutionTerms::Paid { .. }) {
            return Err(ExecutionError::Identity);
        }
        Self::open_inner(path, None, input, terms, true)
    }

    /// Open only an existing attempt, failing closed if its record was lost.
    pub fn open_existing(path: &Path, input: &JobInput, terms: ExecutionTerms) -> Result<Self> {
        if matches!(terms, ExecutionTerms::Paid { .. }) {
            return Err(ExecutionError::Identity);
        }
        Self::open_inner(path, None, input, terms, false)
    }

    pub fn open_paid(path: &PaidAttemptPath, input: &JobInput, price: u64) -> Result<Self> {
        Self::open_inner(
            path.as_path(),
            Some(path),
            input,
            ExecutionTerms::Paid { price },
            true,
        )
    }

    pub fn open_existing_paid(
        path: &PaidAttemptPath,
        input: &JobInput,
        price: u64,
    ) -> Result<Self> {
        Self::open_inner(
            path.as_path(),
            Some(path),
            input,
            ExecutionTerms::Paid { price },
            false,
        )
    }

    fn open_inner(
        path: &Path,
        paid_path: Option<&PaidAttemptPath>,
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
                let paid_path = paid_path.ok_or(ExecutionError::Identity)?;
                AttemptRecord::Paid(if create {
                    Purchase::open_tracked(paid_path, &job)?
                } else {
                    Purchase::open_existing_tracked(paid_path, &job)?
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
                            format: GRANT_ATTEMPT_FORMAT.into(),
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
                if record.format != GRANT_ATTEMPT_FORMAT
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
        })
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

/// One verified completion, whatever funded it.
pub struct Completed {
    pub work_id: Digest,
    pub output: hellas_rpc::protocol::invocation::output::InvocationOutput,
    /// Canonical bytes of the signed transcript the output was verified from.
    pub transcript: Vec<u8>,
    pub provider_key: hellas_auth::PublicKey,
    /// Paid work only: what was paid, on which channel.
    pub paid: Option<PaidReceipt>,
    /// Everything the protocol proved for a live run; absent when retained
    /// bytes are delivered again.
    pub live: Option<ExecutionResult>,
}

pub enum ExecutionResult {
    Paid(Box<PaidWorkResult>),
    Grant(Box<crate::grant_client::GrantWorkResult>),
}

#[derive(Clone, Copy, Debug)]
pub struct PaidReceipt {
    pub price: u64,
    pub channel_id: Digest,
    pub bond_edge: hellas_kernel::EdgeId,
    /// Provider payout once the caller settled the channel.
    pub settled: Option<u64>,
}

#[derive(Default)]
pub struct ExecutionObservers {
    pub progress: Option<PaidProgress>,
    pub accepted: Option<crate::transact::Accepted>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RequestStopped {
    #[error("request cancelled before proposal")]
    Disconnected,
    #[error("request deadline elapsed, including queue wait")]
    Deadline,
}

/// Where an attempt stopped, which decides whether a pool may try another
/// provider. Only failures provably before this request's proposal may.
#[derive(Debug, thiserror::Error)]
pub enum AttemptError {
    #[error(transparent)]
    Stopped(#[from] RequestStopped),
    #[error(transparent)]
    PreProposal(Box<ExecutionError>),
    #[error(transparent)]
    Committed(Box<ExecutionError>),
}
impl From<AttemptError> for ExecutionError {
    fn from(error: AttemptError) -> Self {
        match error {
            AttemptError::Stopped(stopped) => Self::Stopped(stopped),
            AttemptError::PreProposal(error) | AttemptError::Committed(error) => *error,
        }
    }
}

/// The caller's cancellation: Ctrl-C for a command, a closed HTTP receiver
/// for a gateway request.
pub type Stop = futures::future::Shared<futures::future::BoxFuture<'static, ()>>;
pub fn stop_on(signal: impl std::future::Future<Output = ()> + Send + 'static) -> Stop {
    use futures::FutureExt as _;
    signal.boxed().shared()
}

/// Hands a verified completion to its consumer before it is reported.
pub type Delivery<'a> = Box<
    dyn FnOnce(&Completed) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>>
        + Send
        + 'a,
>;

#[derive(Default)]
pub struct Controls<'a> {
    /// One absolute deadline over queueing, execution, delivery and report.
    pub deadline: Option<tokio::time::Instant>,
    pub stop: Option<Stop>,
    pub observers: ExecutionObservers,
    pub deliver: Option<Delivery<'a>>,
}

/// `operation` under `deadline`.
pub(crate) async fn within<T>(
    deadline: Option<tokio::time::Instant>,
    operation: impl std::future::Future<Output = T>,
) -> std::result::Result<T, RequestStopped> {
    match deadline {
        Some(deadline) => tokio::time::timeout_at(deadline, operation)
            .await
            .map_err(|_| RequestStopped::Deadline),
        None => Ok(operation.await),
    }
}

/// Run `operation` under `deadline`, abandoning it on `stop` unless
/// `proposed` says its proposal may already have left this process.
pub(crate) async fn before_proposal<T>(
    deadline: Option<tokio::time::Instant>,
    stop: &Stop,
    proposed: Option<&AtomicBool>,
    operation: impl std::future::Future<Output = T>,
) -> std::result::Result<T, RequestStopped> {
    if deadline.is_some_and(|deadline| tokio::time::Instant::now() >= deadline) {
        return Err(RequestStopped::Deadline);
    }
    let operation = within(deadline, operation);
    tokio::pin!(operation);
    tokio::select! {
        biased;
        () = stop.clone() => {
            if !proposed.is_some_and(|proposed| proposed.load(Ordering::Acquire)) {
                return Err(RequestStopped::Disconnected);
            }
            operation.await
        }
        result = &mut operation => result,
    }
}

/// What a paid session is opened for. Only a job may fund a new channel.
pub enum PaidOpen<'a> {
    Retained,
    Job(&'a Job),
    /// A tracked job: its target binds at the funding boundary, after quote
    /// and preflight. A bound attempt reopens its retained channel only.
    Attempt(&'a Job, &'a mut ExecutionAttempt),
}

/// The one paid channel opener, for commands and gateway pools alike. Any
/// error is before this request's proposal. `connection_timeout` bounds
/// reaching the provider, not owner funding or chain finality.
pub async fn open_paid_session(
    options: PaidWorkOptions,
    endpoint: iroh::Endpoint,
    settlement_key: hellas_kernel::Secp256k1Signer,
    owner: std::sync::Arc<crate::client_owner::ClientOwner>,
    funding: crate::paid_client::SessionFundingOptions,
    open: PaidOpen<'_>,
    connection_timeout: Option<std::time::Duration>,
) -> Result<PaidWorkSession> {
    let PaidOpen::Attempt(job, attempt) = open else {
        let (job, allow_funding) = match open {
            PaidOpen::Job(job) => (Some(job), true),
            _ => (None, false),
        };
        return Ok(Box::pin(PaidWorkSession::open_inner(
            options,
            endpoint,
            settlement_key,
            owner,
            crate::paid_client::OpenIntent {
                job: job.map(|job| Box::new(job.clone())),
                allow_funding,
                before_open: None,
            },
            connection_timeout,
            funding,
        ))
        .await?);
    };
    attempt.matches(
        job.input(),
        ExecutionTerms::Paid {
            price: options.expected_price,
        },
    )?;
    let target = PurchaseTarget {
        network: options.config.network().as_str().into(),
        provider: options.provider,
    };
    let AttemptRecord::Paid(purchase) = &mut attempt.record else {
        return Err(ExecutionError::Identity);
    };
    purchase
        .ensure_state_key(&options.config.chain.state_key())
        .map_err(|_| ExecutionError::Identity)?;
    if purchase.has_target() && !purchase.matches_target(&target) {
        return Err(ExecutionError::Identity);
    }
    let fresh = !purchase.has_target() || attempt.newly_bound;
    let newly_bound = &mut attempt.newly_bound;
    let mut session = Box::pin(PaidWorkSession::open_inner(
        options,
        endpoint,
        settlement_key,
        owner,
        crate::paid_client::OpenIntent {
            job: fresh.then(|| Box::new(job.clone())),
            allow_funding: fresh,
            before_open: Some(Box::new(|| {
                purchase.bind_target(target)?;
                *newly_bound = false;
                Ok(())
            })),
        },
        connection_timeout,
        funding,
    ))
    .await?;
    let descriptor = session.descriptor();
    let AttemptRecord::Paid(purchase) = &mut attempt.record else {
        unreachable!("checked above");
    };
    if let Err(error) = purchase.ensure_channel(descriptor.channel().id(), descriptor.bond_edge()) {
        session.shutdown().await;
        return Err(error.into());
    }
    Ok(session)
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

impl ExecutionAttempt {
    /// This paid attempt's purchase, checked against the open session.
    fn paid_on(&mut self, session: &PaidWorkSession) -> Result<&mut Purchase> {
        let AttemptRecord::Paid(purchase) = &mut self.record else {
            return Err(ExecutionError::Identity);
        };
        purchase
            .ensure_chain(session)
            .map_err(|_| ExecutionError::Identity)?;
        let target = session.execution_target();
        if !purchase.matches_target(&PurchaseTarget {
            network: target.network.as_str().into(),
            provider: target.provider,
        }) {
            return Err(ExecutionError::Identity);
        }
        self.newly_bound = false;
        let descriptor = session.descriptor();
        purchase.ensure_channel(descriptor.channel().id(), descriptor.bond_edge())?;
        Ok(purchase)
    }

    /// This grant attempt's record, checked against the open session.
    fn grant_on(
        &mut self,
        session: &crate::grant_client::GrantSession,
    ) -> Result<&mut GrantAttempt> {
        let AttemptRecord::Grant(tracker) = &mut self.record else {
            return Err(ExecutionError::Identity);
        };
        let target = session.execution_target()?;
        if tracker.record.target.as_ref()
            != Some(&GrantTarget {
                network: target.network.as_str().into(),
                provider: target.provider,
            })
        {
            return Err(ExecutionError::Identity);
        }
        self.newly_bound = false;
        tracker.bind_channel(session.store().channel().id)?;
        Ok(tracker)
    }
}

type Attempted<T> = std::result::Result<T, AttemptError>;
fn pre<E: Into<ExecutionError>>(error: E) -> AttemptError {
    AttemptError::PreProposal(Box::new(error.into()))
}
fn committed<E: Into<ExecutionError>>(error: E) -> AttemptError {
    AttemptError::Committed(Box::new(error.into()))
}

impl ExecutionSession<'_> {
    /// The one request lifecycle, on a session the caller opened and closes.
    /// It prepares the input, proposes and collects it, retains a tracked
    /// result, hands it to `controls.deliver` and only then reports it.
    /// `controls.stop` abandons the request only before its proposal; after
    /// it, collection and payment continue until `controls.deadline`.
    ///
    /// Boxed rather than an `async fn`: every command and gateway awaits it
    /// inside its own future, and its state must not be composed inline there.
    pub fn run(
        &mut self,
        request: &WorkRequest,
        terms: ExecutionTerms,
        signer: &ProducerSigningKey,
        controls: Controls<'_>,
        attempt: Option<&mut ExecutionAttempt>,
    ) -> impl std::future::Future<Output = Attempted<Completed>> {
        Box::pin(self.run_inner(request, terms, signer, controls, attempt))
    }

    async fn run_inner(
        &mut self,
        request: &WorkRequest,
        terms: ExecutionTerms,
        signer: &ProducerSigningKey,
        controls: Controls<'_>,
        mut attempt: Option<&mut ExecutionAttempt>,
    ) -> Attempted<Completed> {
        let Controls {
            deadline,
            stop,
            observers,
            deliver,
        } = controls;
        let stop = stop.unwrap_or_else(|| stop_on(std::future::pending()));
        if let Some(attempt) = attempt.as_deref() {
            let WorkRequest::Job(input) = request else {
                return Err(pre(ExecutionError::Identity));
            };
            attempt.matches(input, terms).map_err(pre)?;
        }
        let completed = match (self, terms) {
            (Self::Paid(session), ExecutionTerms::Paid { price }) => {
                run_paid(
                    session,
                    request,
                    price,
                    signer,
                    (deadline, &stop, observers),
                    attempt.as_deref_mut(),
                )
                .await?
            }
            (Self::Grant(session), ExecutionTerms::Grant { resource }) => {
                run_grant(
                    session,
                    request,
                    resource,
                    (deadline, &stop, observers),
                    attempt.as_deref_mut(),
                )
                .await?
            }
            _ => return Err(pre(ExecutionError::Identity)),
        };
        if let Some(deliver) = deliver {
            deliver(&completed).map_err(|error| committed(ExecutionError::Delivery(error)))?;
            if let Some(attempt) = attempt {
                attempt.reported().map_err(committed)?;
            }
        }
        Ok(completed)
    }
}

type RunControls<'a> = (Option<tokio::time::Instant>, &'a Stop, ExecutionObservers);

async fn run_paid(
    session: &mut PaidWorkSession,
    request: &WorkRequest,
    price: u64,
    signer: &ProducerSigningKey,
    (deadline, stop, observers): RunControls<'_>,
    mut attempt: Option<&mut ExecutionAttempt>,
) -> Attempted<Completed> {
    let WorkRequest::Job(input) = request else {
        return Err(pre(ExecutionError::Identity));
    };
    let job = Job::from_input(price, input.clone()).map_err(pre)?;
    let tracked = attempt.is_some();
    let purchase = match attempt.as_deref_mut() {
        Some(attempt) => {
            let purchase = attempt.paid_on(session).map_err(pre)?;
            if purchase.has_proposal_intent() {
                return Err(committed(ExecutionError::RecoveryRequired));
            }
            Some(purchase)
        }
        None => None,
    };
    // An untracked request first resumes the channel's retained work; it
    // never proposes this request, so its failure leaves fallback open. A
    // tracked attempt recovers only itself.
    if !tracked && session.needs_recovery() {
        let bound = tokio::time::Instant::now() + PAID_RECOVERY_TIMEOUT;
        let deadline = Some(deadline.map_or(bound, |deadline| deadline.min(bound)));
        before_proposal(
            deadline,
            stop,
            None,
            session.run(None, &crate::paid_client::empty_content(), true, None),
        )
        .await?
        .map_err(pre)?;
    }
    // The proposal nonce is journaled before its signature is released.
    let floor = session
        .with_state(|state| state.proposal_nonce_high_water())
        .await
        .map_err(pre)?;
    let proposed = Arc::new(AtomicBool::new(false));
    let result = before_proposal(
        deadline,
        stop,
        Some(&proposed),
        crate::transact::transact(
            session,
            &job,
            signer,
            crate::transact::TransactionOptions {
                purchase,
                // A request is always a new purchase; recovery never searches
                // for a matching old job here.
                new_purchase: true,
                progress: observers.progress,
                accepted: observers.accepted,
                proposed: Some(&proposed),
            },
        ),
    )
    .await?;
    let result = match result {
        Ok(result) => result,
        Err(error) => {
            let uncertain = matches!(
                &error,
                crate::transact::TransactError::Client(
                    crate::paid_client::PaidClientError::Propose(
                        hellas_channel::work::ProposeError::Store(
                            hellas_channel::work_store::WorkStoreError::Journal(_)
                        )
                    )
                )
            );
            let after = session
                .with_state(|state| state.proposal_nonce_high_water())
                .await
                .ok();
            return Err(
                if !proposed.load(Ordering::Acquire) && !uncertain && after == Some(floor) {
                    pre(error)
                } else {
                    committed(error)
                },
            );
        }
    };
    let completed = paid_completed(result);
    if let Some(attempt) = attempt {
        attempt
            .complete(
                completed.work_id,
                &completed.output,
                completed.transcript.clone(),
                true,
                completed.paid.map(|paid| PaidDelivery {
                    channel_id: paid.channel_id,
                    bond_edge: paid.bond_edge.to_bytes(),
                    provider_key: completed.provider_key,
                }),
            )
            .map_err(committed)?;
    }
    Ok(completed)
}

pub(crate) fn paid_completed(result: crate::paid_client::PaidWorkResult) -> Completed {
    Completed {
        work_id: result.work_id,
        output: result.output.clone(),
        transcript: result.transcript.clone(),
        provider_key: result.provider_key,
        paid: Some(PaidReceipt {
            price: result.job_price,
            channel_id: result.channel_id,
            bond_edge: result.bond_edge,
            settled: None,
        }),
        live: Some(ExecutionResult::Paid(Box::new(result))),
    }
}

async fn run_grant(
    session: &mut crate::grant_client::GrantSession,
    request: &WorkRequest,
    resource: ResourceId,
    (deadline, stop, observers): RunControls<'_>,
    mut attempt: Option<&mut ExecutionAttempt>,
) -> Attempted<Completed> {
    let tracker = match attempt.as_deref_mut() {
        Some(attempt) => {
            let tracker = attempt.grant_on(session).map_err(pre)?;
            if tracker.record.work.is_some() {
                return Err(committed(ExecutionError::RecoveryRequired));
            }
            Some(tracker)
        }
        None => None,
    };
    let assurance = session.assurance();
    before_proposal(deadline, stop, None, async {
        session.recover().await?;
        session.refresh().await
    })
    .await?
    .map_err(pre)?;
    // Re-admit the original request under the refreshed resource terms.
    let policy = session
        .offer()
        .offer()
        .grant
        .policies
        .iter()
        .find(|policy| policy.resource == resource)
        .ok_or(pre(ExecutionError::Identity))?;
    let input = request
        .admitted(
            &policy.invocation_policy,
            policy.https.as_ref(),
            assurance,
            false,
        )
        .map_err(pre)?;
    let prepared = prepare_grant_input(&input, policy, session.offer(), session.execution_signer())
        .map_err(pre)?;
    let proposed = AtomicBool::new(false);
    let content = input.content();
    let result = before_proposal(
        deadline,
        stop,
        Some(&proposed),
        session.run_resource(
            resource,
            prepared,
            &content,
            ExecutionObservers {
                progress: observers.progress.clone(),
                accepted: observers.accepted.clone(),
            },
            Some(&proposed),
            tracker,
        ),
    )
    .await?;
    let result = result.map_err(|error| {
        if !proposed.load(Ordering::Acquire) && session.store().book().pending_proposal().is_none()
        {
            pre(error)
        } else {
            committed(error)
        }
    })?;
    let finished = result.result.outcome == hellas_channel::model::work::ResultOutcome::Finished;
    let completed = grant_completed(result)?;
    if let Some(attempt) = attempt {
        attempt
            .complete(
                completed.work_id,
                &completed.output,
                completed.transcript.clone(),
                finished,
                None,
            )
            .map_err(committed)?;
    }
    Ok(completed)
}

pub(crate) fn grant_completed(
    result: crate::grant_client::GrantWorkResult,
) -> Attempted<Completed> {
    Ok(Completed {
        work_id: result.work_id,
        transcript: hellas_channel::model::work::encode_transcript(&result.events)
            .map_err(|_| committed(ExecutionError::Identity))?,
        output: result.output.clone(),
        provider_key: result.provider_key,
        paid: None,
        live: Some(ExecutionResult::Grant(Box::new(result))),
    })
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CompletionReceipt {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    paid: Option<PaidDelivery>,
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
#[derive(Clone, Serialize, Deserialize)]
struct PaidDelivery {
    channel_id: Digest,
    bond_edge: [u8; 32],
    provider_key: hellas_auth::PublicKey,
}

const MAX_RESULT_RECEIPT_BYTES: usize =
    2 * hellas_rpc::protocol::invocation::MAX_INVOCATION_BYTES + 4096;

impl ExecutionAttempt {
    /// Paid sidecars follow the selected store's policy. Grant attempts live at
    /// a caller-chosen path with no store policy and keep the durable write.
    fn sidecar_durability(&self) -> hellas_private::Durability {
        match &self.record {
            AttemptRecord::Paid(purchase) => purchase.durability(),
            AttemptRecord::Grant(_) => hellas_private::Durability::Power,
        }
    }
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
        if receipt.format != WORK_COMPLETION_FORMAT
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
        paid: Option<PaidDelivery>,
    ) -> Result<()> {
        if self.read_receipt()?.is_some() {
            return Err(ExecutionError::RecoveryRequired);
        }
        if transcript.len() > hellas_rpc::protocol::invocation::MAX_INVOCATION_BYTES {
            return Err(ExecutionError::Identity);
        }
        let output_id = output.content_id().map_err(|_| ExecutionError::Identity)?;
        let transcript_ref = hellas_rpc::ContentRef::for_bytes(&transcript);
        let artifact = RetainedResult {
            output: output.clone(),
            transcript: transcript.into(),
        };
        let bytes =
            hellas_rpc::protocol::value::encode_bounded(&artifact, MAX_RESULT_RECEIPT_BYTES)
                .map_err(|_| ExecutionError::Identity)?;
        let durability = self.sidecar_durability();
        let path = self.sidecar(".result")?;
        durability.create_dir_all(path.parent().ok_or(ExecutionError::Identity)?)?;
        durability.write_atomically(&path, ".writing", &bytes)?;
        let receipt = CompletionReceipt {
            paid,
            format: WORK_COMPLETION_FORMAT.into(),
            input: *self.input.as_bytes(),
            terms: self.terms,
            work: *work.as_bytes(),
            output: output_id,
            transcript: transcript_ref,
            finished,
            retained: true,
            reported: false,
        };
        let path = self.sidecar(".receipt")?;
        durability.write_atomically(&path, ".writing", &serde_json::to_vec(&receipt)?)?;
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
    /// Load paid delivery without opening a channel or proposing work again.
    pub fn retained_paid_result(&self) -> Result<Option<Completed>> {
        let Some(retained) = self.retained_result()? else {
            let facts = self.inspect()?;
            if facts.payment == Payment::Paid || facts.reported || self.read_receipt()?.is_some() {
                return Err(ExecutionError::ResultUnavailable);
            }
            return Ok(None);
        };
        let receipt = self.read_receipt()?.ok_or(ExecutionError::Identity)?;
        let ExecutionTerms::Paid { price } = receipt.terms else {
            return Err(ExecutionError::Identity);
        };
        let paid = receipt.paid.ok_or(ExecutionError::Identity)?;
        let AttemptRecord::Paid(purchase) = &self.record else {
            return Err(ExecutionError::Identity);
        };
        let bond_edge = hellas_kernel::EdgeId::from_bytes(paid.bond_edge);
        if purchase.bound_channel() != Some((paid.channel_id, bond_edge)) {
            return Err(ExecutionError::Identity);
        }
        Ok(Some(Completed {
            output: retained.output,
            transcript: retained.transcript,
            work_id: Digest::from_bytes(receipt.work),
            provider_key: paid.provider_key,
            paid: Some(PaidReceipt {
                price,
                channel_id: paid.channel_id,
                bond_edge,
                settled: None,
            }),
            live: None,
        }))
    }

    /// Record delivery only after the caller has committed its own result.
    pub fn reported(&mut self) -> Result<()> {
        let mut receipt = self
            .read_receipt()?
            .ok_or(ExecutionError::RecoveryRequired)?;
        if !receipt.reported {
            receipt.reported = true;
            self.sidecar_durability().write_atomically(
                &self.sidecar(".receipt")?,
                ".writing",
                &serde_json::to_vec(&receipt)?,
            )?;
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
#[derive(Debug)]
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
        let (target_bound, channel_bound, work, acceptance, terminal, payment) = match &self.record
        {
            AttemptRecord::Paid(purchase) => {
                let outcome = purchase.outcome();
                (
                    purchase.has_target(),
                    purchase.has_proposal_intent(),
                    outcome.map(|(work, _)| work),
                    if outcome.is_some() {
                        Acceptance::Accepted
                    } else {
                        Acceptance::Unknown
                    },
                    match outcome {
                        Some((_, true)) => Terminal::Verified,
                        Some((_, false)) => Terminal::Rejected,
                        None => Terminal::Unknown,
                    },
                    match outcome {
                        Some((_, true)) => Payment::Paid,
                        Some((_, false)) => Payment::Unpaid,
                        None => Payment::Pending,
                    },
                )
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
            reported: receipt.as_ref().is_some_and(|receipt| receipt.reported),
        })
    }
}

impl<'a> ExecutionSession<'a> {
    /// Reconcile only the bound work. This never allocates a nonce or proposes
    /// another execution, though a previously verified paid result may be paid.
    pub async fn recover(&mut self, attempt: &mut ExecutionAttempt) -> Result<ExecutionFacts> {
        match self {
            Self::Paid(session) => {
                let purchase = attempt.paid_on(session)?;
                // Unfinished accepted work is re-derived from the signed
                // journal on each recovery; only its outcome is recorded.
                let accepted = match purchase.outcome() {
                    Some(_) => None,
                    None => {
                        session
                            .with_state(|state| purchase.accepted_work(state))
                            .await??
                    }
                };
                if let Some(work) = accepted {
                    match session.recorded_terminal(work).await? {
                        Some(true) => purchase.paid(work)?,
                        Some(false) => purchase.unpaid(work)?,
                        None if session.recover_verified_payment(work).await? => {
                            purchase.paid(work)?
                        }
                        None => (),
                    }
                }
                let mut facts = attempt.inspect()?;
                if let Some(work) = accepted
                    && facts.work.is_none()
                {
                    facts.work = Some(work);
                    facts.acceptance = Acceptance::Accepted;
                }
                return Ok(facts);
            }
            Self::Grant(session) => {
                let tracker = attempt.grant_on(session)?;
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
        let directory = options
            .journal_root
            .child(hex::encode(channel.0.as_bytes()));
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
