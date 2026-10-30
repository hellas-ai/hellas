//! One job execution path for caller folders, helpers and gateways.
mod purchase;
use crate::{
    job::{Job, JobError},
    paid_client::{PaidClientError, PaidWorkResult, PaidWorkSession},
};
use hellas_auth::ProducerSigningKey;
use hellas_channel::work::PaidProgress;
use hellas_rpc::ContentRef;
use hellas_rpc::protocol::invocation::PreparedInvocation;
pub(crate) use purchase::PurchaseTarget;
pub use purchase::{Purchase, PurchaseError, PurchaseRecovery, PurchaseStatus};
use std::sync::atomic::AtomicBool;

#[derive(Debug, thiserror::Error)]
pub enum TransactError {
    #[error(transparent)]
    Purchase(#[from] PurchaseError),
    #[error(
        "provider charges {quoted} per job; this job says {requested}. Nothing was signed or paid."
    )]
    Price { quoted: u64, requested: u64 },
    #[error("job application is not admitted by this provider. Nothing was signed or paid.")]
    Application,
    #[error(transparent)]
    Job(#[from] JobError),
    #[error(transparent)]
    Client(#[from] PaidClientError),
    #[error(transparent)]
    Canonical(#[from] hellas_rpc::protocol::value::CanonicalDecodeError),
    #[error("purchase nonce overflow")]
    NonceOverflow,
}
type Result<T> = std::result::Result<T, TransactError>;

/// Called once a provider has accepted a job, before any of its output,
/// with the work id it accepted and its key.
pub type Accepted =
    std::sync::Arc<dyn Fn(hellas_rpc::provenance::ExecutionProvenance) + Send + Sync>;

#[derive(Default)]
pub struct TransactionOptions<'a> {
    pub settle: bool,
    pub purchase: Option<&'a mut Purchase>,
    /// Gateways start a new purchase for each HTTP request. Folder commands
    /// instead resume an unpaid matching authorization after interruption.
    pub new_purchase: bool,
    pub progress: Option<PaidProgress>,
    pub accepted: Option<Accepted>,
    pub proposed: Option<&'a AtomicBool>,
}

/// Selects a retained purchase by its signed content commitment. This works for
/// metadata-only Fetch journals: the caller supplies the original job folder,
/// and the existing authorization supplies the durable purchase counter.
async fn prepare(
    session: &PaidWorkSession,
    job: &Job,
    key: &ProducerSigningKey,
    resume: bool,
    purchase: Option<&Purchase>,
) -> Result<(u64, PreparedInvocation)> {
    let descriptor = session.descriptor();
    let channel = descriptor.channel().id();
    let runner = hellas_auth::PublicKey::Secp256k1(descriptor.channel().provider_key().to_bytes());
    let policy = descriptor.invocation_policy();
    let (next, retained) = session
        .with_state(|state| {
            (
                state.proposal_nonce_high_water().checked_add(1),
                state
                    .jobs()
                    .filter(|entry| {
                        entry.authorization().payment_deadline >= state.cursor().0
                            && (entry.phase() != hellas_channel::work_store::JobPhase::HalfSigned
                                || entry.authorization().acceptance_deadline >= state.cursor().0)
                    })
                    .map(|entry| *entry.authorization())
                    .collect::<Vec<_>>(),
            )
        })
        .await?;
    if let Some(nonce) = purchase
        .map(|purchase| purchase.nonce(channel))
        .transpose()?
        .flatten()
    {
        let prepared = job.prepare(key, job.purchase_nonce(channel, nonce), runner, policy)?;
        let content = ContentRef::for_bytes(&prepared.canonical_bytes()?);
        if retained
            .iter()
            .any(|auth| auth.proposal_nonce == nonce && auth.input_content == content)
            || next == Some(nonce)
        {
            return Ok((nonce, prepared));
        }
        return Err(PurchaseError::Unfinished {
            work: "retained purchase".into(),
            reason: "its original authorization is unavailable",
        }
        .into());
    }
    if resume {
        let mut found = None;
        for authorization in retained {
            let prepared = job.prepare(
                key,
                job.purchase_nonce(channel, authorization.proposal_nonce),
                runner,
                policy,
            )?;
            if ContentRef::for_bytes(&prepared.canonical_bytes()?) == authorization.input_content {
                if found.is_some() {
                    return Err(PaidClientError::AmbiguousRecovery.into());
                }
                found = Some((authorization.proposal_nonce, prepared));
            }
        }
        if let Some(prepared) = found {
            return Ok(prepared);
        }
    }
    let nonce = next.ok_or(TransactError::NonceOverflow)?;
    Ok((
        nonce,
        job.prepare(key, job.purchase_nonce(channel, nonce), runner, policy)?,
    ))
}

pub async fn transact(
    session: &mut PaidWorkSession,
    job: &Job,
    key: &ProducerSigningKey,
    mut options: TransactionOptions<'_>,
) -> Result<PaidWorkResult> {
    if let Some(purchase) = options.purchase.as_deref() {
        purchase.ensure_executable()?;
    }
    let quoted = session.descriptor().payment_policy().fixed_price;
    if quoted != job.price() {
        return Err(TransactError::Price {
            quoted,
            requested: job.price(),
        });
    }
    let resume = !options.new_purchase
        && !options
            .purchase
            .as_deref()
            .is_some_and(Purchase::buys_again);
    let (nonce, prepared) = prepare(session, job, key, resume, options.purchase.as_deref()).await?;
    if let Some(purchase) = options.purchase.as_deref_mut() {
        purchase.begin(
            session.descriptor().channel().id(),
            session.descriptor().bond_edge(),
            nonce,
        )?;
    }
    let content = job.content();
    let mut result = session
        .run_prepared(
            Some(prepared),
            &content,
            false,
            options.progress,
            options.accepted,
            options.proposed,
            options.purchase,
        )
        .await?
        .ok_or(PaidClientError::MissingState("transaction result"))?;
    if options.settle {
        result.settled_provider_payout = Some(session.settle().await?);
    }
    Ok(result)
}
