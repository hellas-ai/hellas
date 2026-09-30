//! The client's own re-execution: does the answer this provider signed
//! reproduce from the inputs both parties agreed to?
//!
//! # Why it sits here
//!
//! Because the re-execution must not be able to reach the provider.
//! Everything here takes bytes and returns a digest; nothing here opens a
//! connection, reads a store, or consults a piece of provider metadata
//! that is not inside the authorization the client itself signed. A
//! module inside the executor could not credibly claim that. This one
//! can: the engine arrives through [`Reproducer`], never through a
//! dependency, and `hellas-client`'s closure holds no `hellas-executor`
//! and no model weights under any feature it has. The boundary that makes
//! the re-execution separate is the trait, not a crate.
//!
//! # What is reproduced, exactly
//!
//! [`reproduce`] rebuilds `PaidJobResultV1::canonical_output_digest` from
//! scratch and returns it. That digest binds the whole answer — the
//! output token ids in position order, the final position, the stop
//! reason and matched stop-token witness, the output text artifact, and the usage counts
//! (`hellas_rpc::protocol::work::canonical_output_digest`) — so
//! reproducing it reproduces all of them. Every part of it except the
//! tokens, stop reason, and matched stop-token witness is *derived* here from the job's own
//! inputs, through the same [`completed_text`] the provider's artifact
//! store uses; the tokens and the stop reason come from re-running the
//! model.
//!
//! What it does not check, and what is checked elsewhere: that the result
//! is the one the provider signed, that it names this job, and that the
//! transcript it summarises is this job's — those are the endpoint
//! journal's, established when the delivery was recorded
//! (`hellas_work::work_store::Channel`), on commit and on every
//! replay. Repeating them here would be a second opinion about a question
//! already settled.
//!
//! # What it cannot do
//!
//! It cannot be more separate than its [`Reproducer`] engine is. The
//! milestone this re-execution exists for wants a *second* deterministic
//! implementation of the same model, and there is not one in this
//! repository: the executor has exactly one backend. So this module
//! defines the seam and derives everything around it, and the separation
//! of the answer itself is exactly the separation of whatever is plugged
//! in. Running the provider's own implementation here would reproduce its
//! bugs as faithfully as its correct answers, and would not be a
//! re-execution worth the name.
//!
//! It also cannot say the provider *computed* the answer rather than
//! recalling one. No result protocol can; the sole proposal nonce bounds
//! the damage to the one job the client actually asked for.

use hellas_kernel::NetworkId;
use hellas_rpc::evaluate::{EvaluateStopReason, EvaluateTerminal, EvaluateUsage};
use hellas_rpc::protocol::artifacts::{
    OutputAddressed as _, PreparedPaidInputV1, TextArtifact, TextExecutionId, completed_text,
};
use hellas_rpc::protocol::work::{PaidJobResultV1, canonical_output_digest};
use hellas_rpc::{ContentId, Digest};

/// Why a result could not be reproduced at all.
///
/// A fault is not a mismatch: it says the re-execution did not happen, so
/// it is neither a passed check nor a proved fraud. A mismatch — a
/// re-execution that ran and produced a different answer — is
/// [`Reproduction::Refuted`], not a fault.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ReproduceFault {
    /// The bundle's own bodies are not canonical, or do not parse.
    #[error("prepared input: {0}")]
    Body(String),
    /// The bundle names a job this profile does not reproduce.
    #[error("this profile cannot reproduce a job whose {what}")]
    Unsupported {
        /// What about the job is out of profile.
        what: &'static str,
    },
    /// The engine did not produce an answer.
    #[error("the reproduction engine failed: {0}")]
    Engine(String),
    /// The derived usage counts overflowed.
    #[error("checked arithmetic overflowed deriving {field}")]
    Overflow {
        /// Which computation overflowed.
        field: &'static str,
    },
}

/// Everything a deterministic engine needs to run one paid job again.
///
/// It is derived from the accepted bundle and from nothing else, so two
/// clients holding the same authorization ask the same question.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReproductionRequest {
    /// Content ID of the exact program manifest the execution is bound to.
    ///
    /// The identity artifact's bound term and the evaluate request are both
    /// checked against this ID before an engine receives the request. The
    /// manifest already commits to its complete application pair and root, so
    /// no evaluator-specific identity is repeated here.
    pub execution_environment: ContentId,
    /// The whole prompt, in token ids.
    ///
    /// For this profile it is the execution's prompt tokens: the only
    /// legal start is an identity artifact, which carries no prior
    /// state, so there is nothing in front of them.
    pub prompt_token_ids: Vec<u32>,
    /// The generation limit the signed policy fixes.
    pub max_new_tokens: u32,
    /// The stop tokens it fixes.
    pub stop_token_ids: Vec<u32>,
}

/// What one reproduction produced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reproduced {
    /// The generated token ids, in position order.
    pub output_token_ids: Vec<u32>,
    /// Why generation stopped.
    pub stop_reason: EvaluateStopReason,
    /// The selected stop token returned by the runtime, present exactly when
    /// `stop_reason` is [`EvaluateStopReason::STOP_TOKEN`].
    pub matched_stop_token_id: Option<u32>,
}

/// Whether a reproduction reproduced the signed answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reproduction {
    /// The re-execution reproduced exactly the signed answer.
    Matched,
    /// The re-execution ran and produced a different answer. This is the
    /// finding, not a failure to check: the digest it produced is carried
    /// so the refutation can be recorded against the signed result.
    Refuted {
        /// The answer digest the re-execution produced.
        reproduction_digest: Digest,
    },
}

/// A deterministic, separate implementation of the profile's execution.
///
/// One method, and it takes the client's own journal-held bundle — the
/// one both parties signed, never anything a provider sent on the wire.
/// A real implementation runs the retained request in that bundle through
/// the same evaluate implementation the provider used, in-process, with
/// no gateway and no network. It is async because driving an executor is.
/// "Deterministic" is the implementor's obligation and this trait cannot
/// check it: an engine that sampled would refute an honest provider,
/// which is a wrong answer rather than a caught one.
pub trait Reproducer {
    /// Runs one accepted job's retained request to its terminal.
    ///
    /// # Errors
    ///
    /// [`ReproduceFault::Engine`] for any reason the engine has, and
    /// [`ReproduceFault::Body`] / [`ReproduceFault::Unsupported`] when the
    /// bundle is not one this profile can run. A fault is not a mismatch:
    /// it says the re-execution did not happen.
    fn reproduce(
        &self,
        bundle: &PreparedPaidInputV1,
    ) -> impl std::future::Future<Output = Result<Reproduced, ReproduceFault>> + Send;
}

/// Derives the question to ask an engine from one accepted bundle.
///
/// # Errors
///
/// [`ReproduceFault::Body`] when the bundle's bodies do not parse, and
/// [`ReproduceFault::Unsupported`] when the job does not start from an
/// identity artifact — the one start this profile admits, and the one
/// whose prompt is the whole input.
pub fn plan(bundle: &PreparedPaidInputV1) -> Result<ReproductionRequest, ReproduceFault> {
    let parts = bundle
        .parts()
        .map_err(|error| ReproduceFault::Body(error.to_string()))?;
    let TextArtifact::Identity { bound_term } = &parts.identity_artifact else {
        return Err(ReproduceFault::Unsupported {
            what: "input is a previous output rather than an identity",
        });
    };
    let manifest_id = parts.manifest.content_id();
    if parts.evaluate_request.execution_environment != manifest_id {
        return Err(ReproduceFault::Body(
            "evaluate request does not name the carried program manifest".to_string(),
        ));
    }
    if bound_term.as_bytes() != manifest_id.as_bytes() {
        return Err(ReproduceFault::Body(
            "identity artifact is not bound to the carried program manifest".to_string(),
        ));
    }
    Ok(ReproductionRequest {
        execution_environment: manifest_id,
        prompt_token_ids: parts
            .prompt_tokens
            .as_slice()
            .iter()
            .map(|token| token.as_u32())
            .collect(),
        max_new_tokens: parts.text_policy.max_new_tokens(),
        stop_token_ids: parts
            .text_policy
            .stop_token_ids()
            .iter()
            .map(|token| token.as_u32())
            .collect(),
    })
}

/// Runs the job again and reports whether the signed answer is the one
/// that comes back.
///
/// `network`, `work_id`, `bundle`, and `result` must be one job's, as the
/// endpoint journal that recorded the delivery established. Nothing here
/// re-establishes that: the digest below binds the network and the work
/// id, so a mismatched pair reproduces as [`Reproduction::Refuted`]
/// rather than a wrong verdict, but the finding it produces would name
/// the wrong cause.
///
/// # Errors
///
/// [`ReproduceFault`] when the re-execution could not be made at all — a
/// bundle that does not parse, a job out of profile, an engine fault, or
/// an overflow. A caller must not treat a fault as a passed check or as a
/// proved fraud. A re-execution that *ran* and disagreed is not an error:
/// it is [`Reproduction::Refuted`].
pub async fn reproduce<E: Reproducer + ?Sized>(
    engine: &E,
    network: NetworkId,
    work_id: Digest,
    bundle: &PreparedPaidInputV1,
    result: &PaidJobResultV1,
) -> Result<Reproduction, ReproduceFault> {
    let request = plan(bundle)?;
    let produced = engine.reproduce(bundle).await?;
    let digest = reproduced_output_digest(network, work_id, bundle, &request, &produced)?;
    if digest.as_bytes() == result.canonical_output_digest.as_bytes() {
        Ok(Reproduction::Matched)
    } else {
        Ok(Reproduction::Refuted {
            reproduction_digest: digest,
        })
    }
}

/// Rebuilds the canonical answer digest a correct provider would have
/// signed for this reproduction.
///
/// Everything but the tokens, stop reason, and matched stop-token witness is derived: the output
/// artifact through [`completed_text`], the usage from the two token
/// counts, and the billable total from those. A provider that generated
/// these tokens has no freedom left in any of it.
fn reproduced_output_digest(
    network: NetworkId,
    work_id: Digest,
    bundle: &PreparedPaidInputV1,
    request: &ReproductionRequest,
    produced: &Reproduced,
) -> Result<Digest, ReproduceFault> {
    let parts = bundle
        .parts()
        .map_err(|error| ReproduceFault::Body(error.to_string()))?;
    let execution = TextExecutionId::from_digest(parts.evaluate_request.text_execution);
    let completed = completed_text(
        execution,
        &request.prompt_token_ids,
        &produced.output_token_ids,
    );

    let input_units =
        u64::try_from(request.prompt_token_ids.len()).map_err(|_| ReproduceFault::Overflow {
            field: "input token count",
        })?;
    let output_units =
        u64::try_from(produced.output_token_ids.len()).map_err(|_| ReproduceFault::Overflow {
            field: "output token count",
        })?;
    let usage = EvaluateUsage {
        input_units,
        output_units,
    };
    let billable_units = usage
        .billable_units()
        .map_err(|_| ReproduceFault::Overflow {
            field: "billable units",
        })?;
    let terminal = EvaluateTerminal {
        final_position: output_units,
        stop_reason: produced.stop_reason,
        matched_stop_token_id: produced.matched_stop_token_id,
        text_artifact: completed.artifact.output_id().digest(),
        usage,
        billable_units,
    };
    canonical_output_digest(network, work_id, &produced.output_token_ids, &terminal)
        .map_err(|error| ReproduceFault::Body(error.to_string()))
}
