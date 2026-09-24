//! Dispatch for the private paid-work profiles. The channel economics are
//! shared; each profile verifies its own input and terminal transcript.

use super::artifacts::PreparedPaidInputV1;
use super::value::CanonicalDecodeError;
use super::work::{
    self, JobDeadlines, PaidChannel, PaidExecutionPolicyV1, PaidJobAuthorizationV1,
    PaidJobResultV1, PaidWorkError, PrivateRecord,
};
use super::work_fetch::{self, FetchRoutePolicy, PaidFetchPolicyV1, PreparedPaidFetchInputV1};
use crate::{ContentId, Digest, OutputEventEnvelope};

/// The execution contract fixed when a channel is mounted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PaidWorkPolicy {
    /// Reproducible local evaluation.
    Evaluate(PaidExecutionPolicyV1),
    /// An authenticated fetch transcript under the committed route policy.
    Fetch {
        /// Fixed-width resource and price envelope.
        policy: PaidFetchPolicyV1,
        /// Canonical body opening the policy's route commitment.
        route: FetchRoutePolicy,
    },
}

impl From<PaidExecutionPolicyV1> for PaidWorkPolicy {
    fn from(policy: PaidExecutionPolicyV1) -> Self {
        Self::Evaluate(policy)
    }
}

impl PaidWorkPolicy {
    /// Checks the envelope and opens every variable policy commitment.
    pub fn check(&self) -> Result<(), PaidWorkError> {
        match self {
            Self::Evaluate(policy) => work::check_execution_policy(policy),
            Self::Fetch { policy, route } => {
                work_fetch::check_fetch_policy(policy)?;
                let body = route.canonical_body_bytes();
                FetchRoutePolicy::from_canonical_body_bytes(&body)?;
                if work_fetch::fetch_route_commitment(&body)? != policy.route_commitment {
                    return Err(PaidWorkError::Mismatch {
                        field: "route_commitment",
                    });
                }
                if matches!(route, FetchRoutePolicy::OpenFetch { .. })
                    && policy.allowed_environment != crate::FetchEnvironment::Http.manifest_id()
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

    /// Fixed price both endpoints derive before admission.
    pub const fn fixed_price(&self) -> u64 {
        match self {
            Self::Evaluate(p) => p.fixed_price,
            Self::Fetch { policy, .. } => policy.fixed_price,
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

    /// Dispatch, delivery, and oracle grace margins, in finalized blocks.
    pub const fn margins(&self) -> (u64, u64, u64) {
        match self {
            Self::Evaluate(p) => (
                p.dispatch_margin_blocks,
                p.delivery_margin_blocks,
                p.oracle_grace_blocks,
            ),
            Self::Fetch { policy: p, .. } => (
                p.dispatch_margin_blocks,
                p.delivery_margin_blocks,
                p.oracle_grace_blocks,
            ),
        }
    }

    /// Checks a proposal against this profile's commitment and envelope.
    pub fn check_authorization(
        &self,
        channel: &PaidChannel,
        authorization: &PaidJobAuthorizationV1,
        height: u64,
    ) -> Result<Digest, PaidWorkError> {
        match self {
            Self::Evaluate(policy) => {
                work::check_authorization(channel, authorization, policy, height)
            }
            Self::Fetch { policy, .. } => {
                work_fetch::check_fetch_authorization(channel, authorization, policy, height)
            }
        }
    }

    /// Builds the authorization using the matching profile's digest domains.
    pub fn propose(
        &self,
        channel: &PaidChannel,
        input: &PreparedPaidWorkInput,
        nonce: u64,
        deadlines: JobDeadlines,
    ) -> Result<PaidJobAuthorizationV1, PaidWorkError> {
        match (self, input) {
            (Self::Evaluate(policy), PreparedPaidWorkInput::Evaluate(input)) => {
                work::propose_authorization(channel, policy, input, nonce, deadlines)
            }
            (Self::Fetch { policy, .. }, PreparedPaidWorkInput::Fetch(input)) => {
                work_fetch::propose_fetch_authorization(channel, policy, input, nonce, deadlines)
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
        authorization: &PaidJobAuthorizationV1,
        input: &PreparedPaidWorkInput,
    ) -> Result<(), PaidWorkError> {
        match (self, input) {
            (Self::Evaluate(policy), PreparedPaidWorkInput::Evaluate(input)) => {
                work::check_prepared_input(channel, authorization, policy, input)
            }
            (Self::Fetch { policy, route }, PreparedPaidWorkInput::Fetch(input)) => {
                work_fetch::check_prepared_fetch_input(
                    channel,
                    authorization,
                    policy,
                    route,
                    input,
                )?;
                let parts = input.parts()?;
                let request = crate::fetch::verify_input_events(&parts.fetch_input_transcript)
                    .map_err(|error| PaidWorkError::Transcript(error.to_string()))?;
                if request.retention != crate::Retention::Ephemeral {
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
        authorization: &PaidJobAuthorizationV1,
        input: &PreparedPaidWorkInput,
        transcript: &[OutputEventEnvelope],
    ) -> Result<PaidJobResultV1, PaidWorkError> {
        self.check_input(channel, authorization, input)?;
        if let Self::Fetch { policy, .. } = self {
            work_fetch::check_fetch_output_limits(policy, transcript)?;
        }
        input.terminal_result(channel, authorization, transcript)
    }

    /// Canonical bytes retained in a close descriptor. Evaluate bytes are unchanged.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::Evaluate(policy) => policy.encode(),
            Self::Fetch { policy, route } => {
                let mut bytes = policy.encode();
                bytes.extend_from_slice(&route.canonical_body_bytes());
                bytes
            }
        }
    }

    /// Strictly decodes one complete profile policy.
    pub fn decode(bytes: &[u8]) -> Result<Self, PaidWorkError> {
        let profile = if bytes.get(1) == Some(&5) {
            let (record, body) = bytes
                .split_at_checked(PaidFetchPolicyV1::ENCODED_SIZE)
                .ok_or_else(|| CanonicalDecodeError::new("truncated fetch policy"))?;
            Self::Fetch {
                policy: PaidFetchPolicyV1::decode(record)?,
                route: FetchRoutePolicy::from_canonical_body_bytes(body)?,
            }
        } else {
            Self::Evaluate(PaidExecutionPolicyV1::decode(bytes)?)
        };
        profile.check()?;
        Ok(profile)
    }
}

/// Canonical prepared input retained by a paid-work journal.
///
/// The formats are disjoint: Evaluate has exactly six length-prefixed bodies,
/// Fetch exactly two. Both decoders reject trailing bytes. Dispatch therefore
/// preserves existing Evaluate bytes without guessing from unsigned metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PreparedPaidWorkInput {
    /// The committed local artifact graph.
    Evaluate(PreparedPaidInputV1),
    /// The signed fetch request and its manifest.
    Fetch(PreparedPaidFetchInputV1),
}

impl From<PreparedPaidInputV1> for PreparedPaidWorkInput {
    fn from(input: PreparedPaidInputV1) -> Self {
        Self::Evaluate(input)
    }
}

impl From<PreparedPaidFetchInputV1> for PreparedPaidWorkInput {
    fn from(input: PreparedPaidFetchInputV1) -> Self {
        Self::Fetch(input)
    }
}

impl PreparedPaidWorkInput {
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
    pub fn input_commitment(&self) -> Result<crate::InputCommitment, PaidWorkError> {
        match self {
            Self::Evaluate(input) => Ok(crate::evaluate::input_commitment(
                &input.parts()?.evaluate_request,
            )),
            Self::Fetch(input) => Ok(crate::fetch::verify_input_events(
                &input.parts()?.fetch_input_transcript,
            )
            .map_err(|e| PaidWorkError::Transcript(e.to_string()))?
            .input_commitment),
        }
    }

    /// Assurance requested by the canonical input, checked before disclosing it.
    pub fn assurance(&self) -> Result<crate::Assurance, PaidWorkError> {
        match self {
            Self::Evaluate(input) => Ok(input.parts()?.evaluate_request.assurance),
            Self::Fetch(input) => Ok(crate::fetch::verify_input_events(
                &input.parts()?.fetch_input_transcript,
            )
            .map_err(|e| PaidWorkError::Transcript(e.to_string()))?
            .assurance),
        }
    }

    /// Recomputes the prepared-input commitment during journal replay.
    pub fn digest(&self, channel: &PaidChannel) -> Result<Digest, PaidWorkError> {
        match self {
            Self::Evaluate(input) => work::prepared_input_digest(channel, input),
            Self::Fetch(input) => work_fetch::prepared_fetch_input_digest(channel, input),
        }
    }

    /// Rebuilds a result in the profile selected by the journaled input.
    pub fn terminal_result(
        &self,
        channel: &PaidChannel,
        authorization: &PaidJobAuthorizationV1,
        transcript: &[OutputEventEnvelope],
    ) -> Result<PaidJobResultV1, PaidWorkError> {
        match self {
            Self::Evaluate(_) => work::terminal_result(channel, authorization, transcript),
            Self::Fetch(bundle) => {
                let parts = bundle.parts()?;
                let input = crate::fetch::verify_input_events(&parts.fetch_input_transcript)
                    .map_err(|e| PaidWorkError::Transcript(e.to_string()))?;
                let result = work_fetch::terminal_fetch_result(
                    channel,
                    authorization,
                    transcript,
                    input.assurance,
                )?;
                if input.execution_environment == crate::FetchEnvironment::Http.manifest_id() {
                    let request =
                        crate::http_fetch::HttpFetchRequest::decode(input.body.as_bytes())
                            .map_err(|e| PaidWorkError::Transcript(e.to_string()))?;
                    let output = crate::fetch::verify_output_events(
                        input.input_commitment,
                        input.assurance,
                        transcript,
                    )
                    .map_err(|e| PaidWorkError::Transcript(e.to_string()))?;
                    crate::http_fetch::HttpFetchResponse::from_output(&request, &output)
                        .map_err(|e| PaidWorkError::Transcript(e.to_string()))?;
                }
                Ok(result)
            }
        }
    }
}
