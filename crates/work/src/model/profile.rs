//! Dispatch for the private paid-work profiles. The channel economics are
//! shared; each profile verifies its own input and terminal transcript.

use crate::model::prepared_input::PreparedPaidInputV1;
use crate::model::work::{
    self, EvaluatePolicyV2, JobDeadlines, JobPaymentPolicyV2, PaidChannel, PaidJobAuthorizationV2,
    PaidJobResultV1, PaidWorkError, PrivateRecord,
};
use crate::model::{
    fetch as work_fetch,
    fetch::{FetchPolicyV2, FetchRoutePolicy, PreparedPaidFetchInputV1},
};
use hellas_auth::Digest;
use hellas_rpc::protocol::value::CanonicalDecodeError;
use hellas_rpc::{ContentId, OutputEventEnvelope};

/// Identity bindings shared by paid and granted execution. This contains no
/// financial edge, credit, clock or settlement constructor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WorkContext {
    pub network: hellas_kernel::NetworkId,
    pub channel: Digest,
    pub client: hellas_kernel::Key,
    pub provider: hellas_kernel::Key,
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

/// Application commitments, independent of how the job was funded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JobInputBinding {
    pub prepared_input_digest: Digest,
    pub request_commitment: hellas_rpc::RequestCommitment,
    pub environment_commitment: ContentId,
}
impl From<&PaidJobAuthorizationV2> for JobInputBinding {
    fn from(auth: &PaidJobAuthorizationV2) -> Self {
        Self {
            prepared_input_digest: auth.prepared_input_digest,
            request_commitment: auth.request_commitment,
            environment_commitment: auth.environment_commitment,
        }
    }
}
impl From<&crate::model::grant::GrantJobAuthorizationV1> for JobInputBinding {
    fn from(auth: &crate::model::grant::GrantJobAuthorizationV1) -> Self {
        Self {
            prepared_input_digest: auth.prepared_input_digest,
            request_commitment: auth.request_commitment,
            environment_commitment: auth.environment_commitment,
        }
    }
}

/// The execution contract fixed when a channel is mounted.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub enum WorkPolicy {
    /// Reproducible local evaluation.
    Evaluate(EvaluatePolicyV2),
    /// An authenticated fetch transcript under the committed route policy.
    Fetch {
        /// Fixed-width resource envelope.
        policy: FetchPolicyV2,
        /// Canonical body opening the policy's route commitment.
        route: FetchRoutePolicy,
        /// Canonical semantics opening the environment manifest's root.
        contract: hellas_rpc::protocol::fetch_contract::FetchContract,
    },
}

impl From<EvaluatePolicyV2> for WorkPolicy {
    fn from(policy: EvaluatePolicyV2) -> Self {
        Self::Evaluate(policy)
    }
}

impl WorkPolicy {
    /// Checks the envelope and opens every variable policy commitment.
    pub fn check(&self) -> Result<(), PaidWorkError> {
        match self {
            Self::Evaluate(policy) => work::check_work_policy(policy),
            Self::Fetch {
                policy,
                route,
                contract,
            } => {
                work_fetch::check_fetch_policy(policy)?;
                let body = route.canonical_body_bytes();
                FetchRoutePolicy::from_canonical_body_bytes(&body)?;
                if work_fetch::fetch_route_commitment(&body)? != policy.route_commitment {
                    return Err(PaidWorkError::Mismatch {
                        field: "route_commitment",
                    });
                }
                if policy.allowed_environment != contract.manifest_id() {
                    return Err(PaidWorkError::Mismatch {
                        field: "Fetch contract manifest",
                    });
                }
                if matches!(route, FetchRoutePolicy::OpenFetch { .. })
                    && contract.schema()
                        != hellas_rpc::protocol::fetch_contract::FetchSchema::HttpV1
                {
                    return Err(PaidWorkError::Mismatch {
                        field: "open-fetch HTTPS manifest",
                    });
                }
                Ok(())
            }
        }
    }

    /// The manifest that every proposal must name.
    pub const fn allowed_environment(&self) -> ContentId {
        match self {
            Self::Evaluate(p) => p.allowed_environment,
            Self::Fetch { policy, .. } => policy.allowed_environment,
        }
    }

    /// Maximum retained encoded transcript.
    pub const fn max_spool_bytes(&self) -> u64 {
        match self {
            Self::Evaluate(p) => p.max_spool_bytes,
            Self::Fetch { policy, .. } => policy.max_spool_bytes,
        }
    }

    /// Maximum encoded delivery frame.
    pub const fn max_encoded_result_frame(&self) -> u32 {
        match self {
            Self::Evaluate(p) => p.max_encoded_result_frame,
            Self::Fetch { policy, .. } => policy.max_encoded_result_frame,
        }
    }

    /// Checks a proposal against this profile's commitment and envelope.
    pub fn check_authorization(
        &self,
        channel: &PaidChannel,
        payment: &JobPaymentPolicyV2,
        authorization: &PaidJobAuthorizationV2,
        height: u64,
    ) -> Result<Digest, PaidWorkError> {
        match self {
            Self::Evaluate(policy) => {
                work::check_authorization(channel, authorization, policy, payment, height)
            }
            Self::Fetch { policy, .. } => work_fetch::check_fetch_authorization(
                channel,
                authorization,
                policy,
                payment,
                height,
            ),
        }
    }

    /// Builds the authorization using the matching profile's digest domains.
    pub fn propose(
        &self,
        channel: &PaidChannel,
        payment: &JobPaymentPolicyV2,
        input: &PreparedWorkInput,
        nonce: u64,
        deadlines: JobDeadlines,
    ) -> Result<PaidJobAuthorizationV2, PaidWorkError> {
        match (self, input) {
            (Self::Evaluate(policy), PreparedWorkInput::Evaluate(input)) => {
                work::propose_authorization(channel, policy, payment, input, nonce, deadlines)
            }
            (Self::Fetch { policy, .. }, PreparedWorkInput::Fetch(input)) => {
                work_fetch::propose_fetch_authorization(
                    channel, policy, payment, input, nonce, deadlines,
                )
            }
            _ => Err(PaidWorkError::Mismatch {
                field: "paid work profile",
            }),
        }
    }

    /// Opens the prepared input and checks its profile-specific constraints.
    pub fn check_input(
        &self,
        channel: &PaidChannel,
        authorization: &PaidJobAuthorizationV2,
        input: &PreparedWorkInput,
    ) -> Result<(), PaidWorkError> {
        self.check_bound_input(&channel.into(), &authorization.into(), input)
    }

    /// Validates the same resource contract under either funding model.
    pub fn check_bound_input(
        &self,
        context: &WorkContext,
        binding: &JobInputBinding,
        input: &PreparedWorkInput,
    ) -> Result<(), PaidWorkError> {
        match (self, input) {
            (Self::Evaluate(policy), PreparedWorkInput::Evaluate(input)) => {
                work::check_bound_evaluate_input(context, binding, policy, input)
            }
            (
                Self::Fetch {
                    policy,
                    route,
                    contract,
                },
                PreparedWorkInput::Fetch(input),
            ) => {
                self.check()?;
                work_fetch::check_bound_fetch_input(context, binding, policy, route, input)?;
                let parts = input.parts()?;
                if parts.contract != *contract {
                    return Err(PaidWorkError::Mismatch {
                        field: "Fetch input contract",
                    });
                }
                let request = hellas_rpc::fetch::verify_input_events(&parts.fetch_input_transcript)
                    .map_err(|error| PaidWorkError::Transcript(error.to_string()))?;
                if request.retention != hellas_rpc::Retention::Ephemeral {
                    return Err(PaidWorkError::Mismatch {
                        field: "paid fetch requires ephemeral retention",
                    });
                }
                Ok(())
            }
            _ => Err(PaidWorkError::Mismatch {
                field: "paid work profile",
            }),
        }
    }

    /// Verifies bounds and the result against the authenticated prepared input.
    pub fn terminal_result(
        &self,
        channel: &PaidChannel,
        authorization: &PaidJobAuthorizationV2,
        input: &PreparedWorkInput,
        transcript: &[OutputEventEnvelope],
    ) -> Result<PaidJobResultV1, PaidWorkError> {
        self.bound_terminal_result(
            &channel.into(),
            work::work_id(channel, authorization),
            &authorization.into(),
            input,
            transcript,
        )
    }

    /// A verified result has the same record and digest for either funding.
    pub fn bound_terminal_result(
        &self,
        context: &WorkContext,
        work_id: Digest,
        binding: &JobInputBinding,
        input: &PreparedWorkInput,
        transcript: &[OutputEventEnvelope],
    ) -> Result<PaidJobResultV1, PaidWorkError> {
        self.check_bound_input(context, binding, input)?;
        if let Self::Fetch { policy, .. } = self {
            work_fetch::check_fetch_output_limits(policy, transcript)?;
        }
        input.bound_terminal_result(context, work_id, binding, transcript)
    }

    /// Commits to this resource policy in a funding-separated channel.
    pub fn digest(&self, network: hellas_kernel::NetworkId, channel: Digest) -> Digest {
        match self {
            Self::Evaluate(p) => work::evaluate_policy_v2_digest(network, channel, p),
            Self::Fetch { policy, .. } => {
                work_fetch::fetch_policy_v2_digest(network, channel, policy)
            }
        }
    }

    /// Canonical bytes retained in a close descriptor. Both profiles use their V2 record tags.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::Evaluate(policy) => policy.encode(),
            Self::Fetch {
                policy,
                route,
                contract,
            } => {
                let mut bytes = policy.encode();
                let mut body = hellas_rpc::DagCborEncoder::new();
                body.array(2);
                body.bytes(&route.canonical_body_bytes());
                body.bytes(&contract.canonical_bytes());
                bytes.extend_from_slice(&body.into_bytes());
                bytes
            }
        }
    }

    /// Strictly decodes one complete profile policy.
    pub fn decode(bytes: &[u8]) -> Result<Self, PaidWorkError> {
        let profile = if bytes.get(1) == Some(&7) {
            let (record, body) = bytes
                .split_at_checked(FetchPolicyV2::ENCODED_SIZE)
                .ok_or_else(|| CanonicalDecodeError::new("truncated fetch policy"))?;
            let mut decoder = hellas_rpc::protocol::value::CanonicalDecoder::new(body);
            decoder.array_exact(2)?;
            let route = FetchRoutePolicy::from_canonical_body_bytes(decoder.bytes()?)?;
            let contract =
                hellas_rpc::protocol::fetch_contract::FetchContract::from_canonical_bytes(
                    decoder.bytes()?,
                )?;
            decoder.finish()?;
            Self::Fetch {
                policy: FetchPolicyV2::decode(record)?,
                route,
                contract,
            }
        } else {
            Self::Evaluate(EvaluatePolicyV2::decode(bytes)?)
        };
        profile.check()?;
        if profile.encode() != bytes {
            return Err(CanonicalDecodeError::new("noncanonical work policy").into());
        }
        Ok(profile)
    }
}

/// Canonical prepared input retained by a paid-work journal.
///
/// The formats are disjoint: Evaluate has exactly six length-prefixed bodies,
/// Fetch exactly three. Both decoders reject trailing bytes. Dispatch therefore
/// preserves existing Evaluate bytes without guessing from unsigned metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PreparedWorkInput {
    /// The committed local artifact graph.
    Evaluate(PreparedPaidInputV1),
    /// The signed fetch request and its manifest.
    Fetch(PreparedPaidFetchInputV1),
}

impl From<PreparedPaidInputV1> for PreparedWorkInput {
    fn from(input: PreparedPaidInputV1) -> Self {
        Self::Evaluate(input)
    }
}

impl From<PreparedPaidFetchInputV1> for PreparedWorkInput {
    fn from(input: PreparedPaidFetchInputV1) -> Self {
        Self::Fetch(input)
    }
}

impl PreparedWorkInput {
    /// Decodes a complete bounded bundle under exactly one profile.
    pub fn decode(bytes: &[u8], budget: usize) -> Result<Self, CanonicalDecodeError> {
        if let Ok(input) = PreparedPaidInputV1::decode(bytes, budget) {
            return Ok(Self::Evaluate(input));
        }
        PreparedPaidFetchInputV1::decode(bytes, budget).map(Self::Fetch)
    }

    /// Returns the original profile's canonical bytes.
    pub fn encode(&self) -> Result<Vec<u8>, CanonicalDecodeError> {
        match self {
            Self::Evaluate(input) => input.encode(),
            Self::Fetch(input) => input.encode(),
        }
    }

    /// The caller's authenticated request identity, independent of payment.
    pub fn input_commitment(&self) -> Result<hellas_rpc::InputCommitment, PaidWorkError> {
        match self {
            Self::Evaluate(input) => Ok(hellas_rpc::evaluate::input_commitment(
                &input.parts()?.evaluate_request,
            )),
            Self::Fetch(input) => Ok(hellas_rpc::fetch::verify_input_events(
                &input.parts()?.fetch_input_transcript,
            )
            .map_err(|e| PaidWorkError::Transcript(e.to_string()))?
            .input_commitment),
        }
    }

    /// Assurance requested by the canonical input, checked before disclosing it.
    pub fn assurance(&self) -> Result<hellas_rpc::Assurance, PaidWorkError> {
        match self {
            Self::Evaluate(input) => Ok(input.parts()?.evaluate_request.assurance),
            Self::Fetch(input) => Ok(hellas_rpc::fetch::verify_input_events(
                &input.parts()?.fetch_input_transcript,
            )
            .map_err(|e| PaidWorkError::Transcript(e.to_string()))?
            .assurance),
        }
    }

    /// Recomputes the prepared-input commitment during journal replay.
    pub fn digest(&self, channel: &PaidChannel) -> Result<Digest, PaidWorkError> {
        self.bound_digest(channel.network(), channel.id())
    }

    /// Prepared-input bytes and domains are unchanged across funding models.
    pub fn bound_digest(
        &self,
        network: hellas_kernel::NetworkId,
        channel: Digest,
    ) -> Result<Digest, PaidWorkError> {
        match self {
            Self::Evaluate(input) => work::bound_prepared_input_digest(network, channel, input),
            Self::Fetch(input) => {
                work_fetch::bound_prepared_fetch_input_digest(network, channel, input)
            }
        }
    }

    /// Rebuilds a result in the profile selected by the journaled input.
    pub fn terminal_result(
        &self,
        channel: &PaidChannel,
        authorization: &PaidJobAuthorizationV2,
        transcript: &[OutputEventEnvelope],
    ) -> Result<PaidJobResultV1, PaidWorkError> {
        self.bound_terminal_result(
            &channel.into(),
            work::work_id(channel, authorization),
            &authorization.into(),
            transcript,
        )
    }

    /// Rebuilds a result from resource identity rather than payment terms.
    pub fn bound_terminal_result(
        &self,
        context: &WorkContext,
        work_id: Digest,
        binding: &JobInputBinding,
        transcript: &[OutputEventEnvelope],
    ) -> Result<PaidJobResultV1, PaidWorkError> {
        match self {
            Self::Evaluate(_) => work::bound_evaluate_terminal_result(
                context,
                work_id,
                binding.request_commitment,
                transcript,
            ),
            Self::Fetch(bundle) => {
                let parts = bundle.parts()?;
                let input = hellas_rpc::fetch::verify_input_events(&parts.fetch_input_transcript)
                    .map_err(|e| PaidWorkError::Transcript(e.to_string()))?;
                let (result, output) = work_fetch::bound_fetch_terminal_result(
                    context,
                    work_id,
                    binding.request_commitment,
                    transcript,
                    input.assurance,
                )?;
                if input.input_commitment.digest() != binding.request_commitment.digest() {
                    return Err(PaidWorkError::Mismatch {
                        field: "Fetch input commitment",
                    });
                }
                if parts.contract.schema()
                    == hellas_rpc::protocol::fetch_contract::FetchSchema::HttpV1
                {
                    let request =
                        hellas_rpc::http_fetch::HttpFetchRequest::decode(input.body.as_bytes())
                            .map_err(|e| PaidWorkError::Transcript(e.to_string()))?;
                    hellas_rpc::http_fetch::HttpFetchResponse::from_output(&request, &output)
                        .map_err(|e| PaidWorkError::Transcript(e.to_string()))?;
                }
                Ok(result)
            }
        }
    }
}
