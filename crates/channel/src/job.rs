//! Invocation binding shared by paid and granted jobs.
use crate::model::grant::GrantJobAuthorizationV1;
use crate::model::work::{
    EncodedNetwork, JobDeadlines, JobPaymentPolicyV2, PaidChannel, PaidJobAuthorizationV2,
    PaidJobResultV1, PaidWorkError, ResultOutcome, check_authorization_core,
    job_payment_policy_digest, work_id, xfh,
};
use hellas_auth::{Digest, PublicKey};
use hellas_kernel::{Key, NetworkId};
use hellas_rpc::protocol::invocation::{AdmissionFacts, InvocationPolicy, PreparedInvocation};
use hellas_rpc::{ContentId, ContentRef, OutputEventEnvelope, RequestCommitment, Retention};

const POLICY: &[u8] = b"hellas.work.invocation-policy.v1";
const INPUT: &[u8] = b"hellas.work.prepared-input.v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WorkContext {
    pub network: NetworkId,
    pub channel: Digest,
    pub client: Key,
    pub provider: Key,
}
impl From<&PaidChannel> for WorkContext {
    fn from(channel: &PaidChannel) -> Self {
        Self {
            network: channel.network(),
            channel: channel.id(),
            client: channel.client_key(),
            provider: channel.provider_key(),
        }
    }
}

/// Exact application and content commitments, with funding's retention rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JobInputBinding {
    pub work_policy_digest: Digest,
    pub input_content: ContentRef,
    pub prepared_input_digest: Digest,
    pub request_commitment: RequestCommitment,
    pub environment_commitment: ContentId,
    pub retention: Retention,
}
impl From<&PaidJobAuthorizationV2> for JobInputBinding {
    fn from(a: &PaidJobAuthorizationV2) -> Self {
        Self {
            work_policy_digest: a.work_policy_digest,
            input_content: a.input_content,
            prepared_input_digest: a.prepared_input_digest,
            request_commitment: a.request_commitment,
            environment_commitment: a.environment_commitment,
            retention: a.retention,
        }
    }
}
impl From<&GrantJobAuthorizationV1> for JobInputBinding {
    fn from(a: &GrantJobAuthorizationV1) -> Self {
        Self {
            work_policy_digest: a.work_policy_digest,
            input_content: a.input_content,
            prepared_input_digest: a.prepared_input_digest,
            request_commitment: a.request_commitment,
            environment_commitment: a.environment_commitment,
            retention: Retention::Ephemeral,
        }
    }
}

pub fn policy_digest(
    network: NetworkId,
    channel: Digest,
    policy: &InvocationPolicy,
) -> Result<Digest, PaidWorkError> {
    Ok(xfh(
        POLICY,
        &[
            EncodedNetwork::new(network).as_slice(),
            channel.as_bytes(),
            &policy.canonical_bytes()?,
        ],
    ))
}

pub fn bound_prepared_input_digest(
    network: NetworkId,
    channel: Digest,
    input: &PreparedInvocation,
) -> Result<Digest, PaidWorkError> {
    Ok(xfh(
        INPUT,
        &[
            EncodedNetwork::new(network).as_slice(),
            channel.as_bytes(),
            &input.canonical_bytes()?,
        ],
    ))
}

pub fn prepared_input_digest(
    channel: &PaidChannel,
    input: &PreparedInvocation,
) -> Result<Digest, PaidWorkError> {
    bound_prepared_input_digest(channel.network(), channel.id(), input)
}

/// Derive the proposed bytes; the receiver independently admits their contents.
pub fn propose(
    channel: &PaidChannel,
    policy: &InvocationPolicy,
    payment: &JobPaymentPolicyV2,
    input: &PreparedInvocation,
    proposal_nonce: u64,
    deadlines: JobDeadlines,
) -> Result<PaidJobAuthorizationV2, PaidWorkError> {
    Ok(PaidJobAuthorizationV2 {
        channel_id: channel.id(),
        work_policy_digest: policy_digest(channel.network(), channel.id(), policy)?,
        payment_policy_digest: job_payment_policy_digest(channel.network(), channel.id(), payment),
        input_content: ContentRef::for_bytes(&input.canonical_bytes()?),
        prepared_input_digest: prepared_input_digest(channel, input)?,
        proposal_nonce,
        acceptance_deadline: deadlines.acceptance,
        request_commitment: input.request.commitment()?,
        environment_commitment: input.request.execution_environment,
        price: payment.fixed_price,
        terminal_deadline: deadlines.terminal,
        payment_deadline: deadlines.payment,
        retention: if input.request.retain {
            Retention::Retain
        } else {
            Retention::Ephemeral
        },
    })
}

pub fn check_authorization(
    channel: &PaidChannel,
    a: &PaidJobAuthorizationV2,
    policy: &InvocationPolicy,
    payment: &JobPaymentPolicyV2,
    height: u64,
) -> Result<Digest, PaidWorkError> {
    check_authorization_core(
        channel,
        a,
        policy_digest(channel.network(), channel.id(), policy)?,
        payment,
        height,
    )
}

/// Every input byte, identity, policy and funded retention rule is authenticated
/// before RPC performs the application's admission checks.
pub fn check_input(
    context: &WorkContext,
    binding: &JobInputBinding,
    policy: &InvocationPolicy,
    input: &PreparedInvocation,
) -> Result<AdmissionFacts, PaidWorkError> {
    let bytes = input.canonical_bytes()?;
    let checks = [
        (
            "work_policy_digest",
            binding.work_policy_digest == policy_digest(context.network, context.channel, policy)?,
        ),
        (
            "input_content",
            binding.input_content == ContentRef::for_bytes(&bytes),
        ),
        (
            "prepared_input_digest",
            binding.prepared_input_digest
                == bound_prepared_input_digest(context.network, context.channel, input)?,
        ),
        (
            "request_commitment",
            binding.request_commitment == input.request.commitment()?,
        ),
        (
            "environment_commitment",
            binding.environment_commitment == input.request.execution_environment,
        ),
        (
            "runner_public_key",
            input.request.runner_public_key == PublicKey::Secp256k1(context.provider.to_bytes()),
        ),
        (
            "retention",
            input.request.retain == binding.retention.should_retain(),
        ),
        (
            "application_policy",
            input.application_policy.as_bytes() == policy.canonical_bytes()?.as_slice(),
        ),
    ];
    for (field, valid) in checks {
        if !valid {
            return Err(PaidWorkError::Mismatch { field });
        }
    }
    Ok(policy.admit(input, &PublicKey::Secp256k1(context.client.to_bytes()))?)
}

/// Paid acceptance checks app retention again even when uploads were already held.
pub fn check_paid_input(
    channel: &PaidChannel,
    a: &PaidJobAuthorizationV2,
    policy: &InvocationPolicy,
    input: &PreparedInvocation,
) -> Result<AdmissionFacts, PaidWorkError> {
    let facts = check_input(&channel.into(), &a.into(), policy, input)?;
    if a.retention != facts.retention {
        return Err(PaidWorkError::Mismatch {
            field: "paid content retention",
        });
    }
    Ok(facts)
}

/// The only invocation-to-receipt conversion, used for both funding models.
pub fn terminal_result(
    context: &WorkContext,
    work: Digest,
    binding: &JobInputBinding,
    policy: &InvocationPolicy,
    input: &PreparedInvocation,
    events: &[OutputEventEnvelope],
) -> Result<PaidJobResultV1, PaidWorkError> {
    check_input(context, binding, policy, input)?;
    let verified = input.verify_output(
        policy,
        &PublicKey::Secp256k1(context.client.to_bytes()),
        &PublicKey::Secp256k1(context.provider.to_bytes()),
        events,
    )?;
    let terminal = events
        .last()
        .ok_or_else(|| PaidWorkError::Transcript("missing terminal".into()))?;
    Ok(PaidJobResultV1 {
        work_id: work,
        terminal_transcript_commitment: terminal.event_commitment(),
        canonical_output_digest: Digest::from_bytes(*verified.output_id.as_bytes()),
        outcome: if verified.output.is_success() {
            ResultOutcome::Finished
        } else {
            ResultOutcome::Failed
        },
        transcript_content: verified.transcript,
    })
}

pub fn paid_terminal_result(
    channel: &PaidChannel,
    a: &PaidJobAuthorizationV2,
    policy: &InvocationPolicy,
    input: &PreparedInvocation,
    events: &[OutputEventEnvelope],
) -> Result<PaidJobResultV1, PaidWorkError> {
    check_paid_input(channel, a, policy, input)?;
    terminal_result(
        &channel.into(),
        work_id(channel, a),
        &a.into(),
        policy,
        input,
        events,
    )
}

pub fn check_result(
    context: &WorkContext,
    work: Digest,
    binding: &JobInputBinding,
    policy: &InvocationPolicy,
    input: &PreparedInvocation,
    events: &[OutputEventEnvelope],
    result: &PaidJobResultV1,
) -> Result<(), PaidWorkError> {
    if terminal_result(context, work, binding, policy, input, events)? != *result {
        return Err(PaidWorkError::Mismatch {
            field: "result against its transcript",
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests;

/// The exact neutral object set named by this manifest and prepared-input reference.
pub fn content_closure(
    policy: &InvocationPolicy,
    manifest: &hellas_rpc::ProgramManifest,
    program_root: &[u8],
    prepared: ContentRef,
) -> Result<Vec<ContentRef>, PaidWorkError> {
    let mut objects = std::collections::BTreeMap::new();
    for object in policy
        .content_closure(manifest, program_root)?
        .into_iter()
        .chain([prepared])
    {
        if objects
            .insert(object.id(), object.bytes())
            .is_some_and(|bytes| bytes != object.bytes())
        {
            return Err(PaidWorkError::Mismatch {
                field: "content closure length",
            });
        }
    }
    Ok(objects
        .into_iter()
        .map(|(id, bytes)| ContentRef::new(id, bytes))
        .collect())
}
