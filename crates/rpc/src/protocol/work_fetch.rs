//! Paid Fetch binds a caller-signed request and manifest to a channel authorization.
//! Results must verify under the requested assurance and the channel's provider key.
//! Fetch policies use record tag 5 and separate digest domains from Evaluate.

use hellas_kernel::{Encode, NetworkId};
use hellas_xet::{MIN_CHUNK_SIZE, XetFileHasher};

use crate::fetch::{FetchProtocolError, MAX_FETCH_ROUTE_COMPONENT_BYTES};
use crate::protocol::artifacts::BundleReader;
use crate::protocol::value::{
    CanonicalDecodeError, CanonicalDecoder, canonical_dag_cbor, decode_canonical_dag_cbor,
};
use crate::protocol::work::{
    BodyReader, EncodedNetwork, JobDeadlines, PaidChannel, PaidJobAuthorizationV1, PaidJobResultV1,
    PaidWorkError, PrivateRecord, check_authorization_core, length_prefix, put_u32, put_u64, tag,
    work_id, xfh, xh,
};
use crate::{
    Assurance, ContentId, Digest, InputCommitment, InputEventEnvelope, OutputEventEnvelope,
    ProgramManifest, PublicKey, RequestCommitment,
};

// Digest domains are part of the wire contract.

/// Commitment to the canonical route-policy body.
const FETCH_ROUTE: &[u8] = b"hellas.work.fetch-route.v1";
/// Commitment to the per-channel fetch execution policy.
const FETCH_POLICY: &[u8] = b"hellas.work.fetch-policy.v1";
/// Commitment to the prepared fetch input bundle.
const PREPARED_FETCH_INPUT: &[u8] = b"hellas.work.prepared-fetch-input.v1";
/// The normalized fetch answer authenticated by the signed transcript.
const FETCH_OUTPUT: &[u8] = b"hellas.work.fetch-output.v1";

// ── The route policy ──────────────────────────────────────────────────

/// Schema tag of the sealed-route body.
const SEALED_ROUTE_SCHEMA: &str = "hellas.work.fetch-route.sealed.v1";
/// Schema tag of the open-fetch body.
const OPEN_FETCH_SCHEMA: &str = "hellas.work.fetch-route.open.v1";

/// Canonical route policy. Its variable-length body is committed by digest in
/// the fixed-width `PaidFetchPolicyV1` record and opened during input validation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FetchRoutePolicy {
    /// Requires the signed request to use this service and method.
    SealedRoute {
        /// The signed `service` component, e.g. `openai`.
        service: String,
        /// The signed `method` component, e.g. `responses`.
        method: String,
    },
    /// Caller-signed HTTPS URLs under the generic HTTP manifest. Host and
    /// required-pin constraints are checked before paid acceptance; the driver
    /// enforces normal certificate validation, DNS/address checks and no redirects.
    /// An empty host list permits any public host under the operator's egress policy.
    OpenFetch {
        /// Whether the driver must pin the upstream's SPKI.
        require_spki_pin: bool,
        /// Hosts the driver may egress to; empty means any public host.
        allowed_hosts: Vec<String>,
    },
}

impl FetchRoutePolicy {
    /// Builds a route with nonempty service and method components bounded by
    /// `MAX_FETCH_ROUTE_COMPONENT_BYTES`.
    pub fn sealed_route(
        service: impl Into<String>,
        method: impl Into<String>,
    ) -> Result<Self, FetchProtocolError> {
        let service = service.into();
        let method = method.into();
        if service.is_empty() {
            return Err(FetchProtocolError::EmptyService);
        }
        if method.is_empty() {
            return Err(FetchProtocolError::EmptyMethod);
        }
        if service.len() > MAX_FETCH_ROUTE_COMPONENT_BYTES {
            return Err(FetchProtocolError::RouteComponentLimit {
                field: "service",
                actual: service.len(),
            });
        }
        if method.len() > MAX_FETCH_ROUTE_COMPONENT_BYTES {
            return Err(FetchProtocolError::RouteComponentLimit {
                field: "method",
                actual: method.len(),
            });
        }
        Ok(Self::SealedRoute { service, method })
    }

    /// Sorts and deduplicates the host allowlist before commitment. Admission checks
    /// exact hosts and required pins; the HTTPS driver checks certificates and addresses.
    #[must_use]
    pub fn open_fetch(require_spki_pin: bool, allowed_hosts: impl Into<Vec<String>>) -> Self {
        let mut allowed_hosts = allowed_hosts.into();
        allowed_hosts.sort_unstable();
        allowed_hosts.dedup();
        Self::OpenFetch {
            require_spki_pin,
            allowed_hosts,
        }
    }

    /// Canonical route encoding. The pin flag is encoded as integer 0 or 1.
    #[must_use]
    pub fn canonical_body_bytes(&self) -> Vec<u8> {
        let mut encoder = crate::DagCborEncoder::new();
        match self {
            Self::SealedRoute { service, method } => {
                encoder.array(3);
                encoder.str(SEALED_ROUTE_SCHEMA);
                encoder.str(service);
                encoder.str(method);
            }
            Self::OpenFetch {
                require_spki_pin,
                allowed_hosts,
            } => {
                encoder.array(3);
                encoder.str(OPEN_FETCH_SCHEMA);
                encoder.u64(u64::from(*require_spki_pin));
                encoder.array(allowed_hosts.len() as u64);
                for host in allowed_hosts {
                    encoder.str(host);
                }
            }
        }
        encoder.into_bytes()
    }

    /// Rejects unknown schemas, invalid components, noncanonical encodings and
    /// trailing bytes. Re-encoding must reproduce the input.
    pub fn from_canonical_body_bytes(bytes: &[u8]) -> Result<Self, CanonicalDecodeError> {
        let mut decoder = CanonicalDecoder::new(bytes);
        let len = decoder.array_len()?;
        let policy = match decoder.str()? {
            SEALED_ROUTE_SCHEMA => {
                if len != 3 {
                    return Err(CanonicalDecodeError::new(format!(
                        "{SEALED_ROUTE_SCHEMA} expected array length 3, got {len}"
                    )));
                }
                let service = decoder.str()?.to_string();
                let method = decoder.str()?.to_string();
                Self::sealed_route(service, method)
                    .map_err(|error| CanonicalDecodeError::new(error.to_string()))?
            }
            OPEN_FETCH_SCHEMA => {
                if len != 3 {
                    return Err(CanonicalDecodeError::new(format!(
                        "{OPEN_FETCH_SCHEMA} expected array length 3, got {len}"
                    )));
                }
                let require_spki_pin = match decoder.u64()? {
                    0 => false,
                    1 => true,
                    other => {
                        return Err(CanonicalDecodeError::new(format!(
                            "require_spki_pin must be 0 or 1, got {other}"
                        )));
                    }
                };
                let hosts = decoder.array_len()?;
                let mut allowed_hosts = Vec::with_capacity(hosts);
                for _ in 0..hosts {
                    allowed_hosts.push(decoder.str()?.to_string());
                }
                Self::open_fetch(require_spki_pin, allowed_hosts)
            }
            other => {
                return Err(CanonicalDecodeError::new(format!(
                    "unexpected fetch route schema tag {other:?}"
                )));
            }
        };
        decoder.finish()?;
        if policy.canonical_body_bytes() != bytes {
            return Err(CanonicalDecodeError::new(
                "fetch route policy is not in canonical DAG-CBOR form",
            ));
        }
        Ok(policy)
    }
}

/// Hashes the length-prefixed route body with the streaming hasher.
pub fn fetch_route_commitment(canonical_body_bytes: &[u8]) -> Result<Digest, PaidWorkError> {
    Ok(xfh(
        FETCH_ROUTE,
        &[
            &length_prefix(canonical_body_bytes, "fetch route policy length")?,
            canonical_body_bytes,
        ],
    ))
}

// ── The fetch execution policy ────────────────────────────────────────

/// Fixed-width Fetch policy: manifest, route digest, resource limits, timing
/// margins and fixed price. Encoded under record tag 5.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PaidFetchPolicyV1 {
    /// The one fetch environment manifest this channel will run.
    pub allowed_environment: ContentId,
    /// Commitment to the canonical route-policy body.
    pub route_commitment: Digest,
    /// Largest signed `request.body` this channel accepts, in bytes.
    pub max_request_body_bytes: u32,
    /// Largest output transcript this channel accepts, in events.
    pub max_output_events: u32,
    /// Largest cumulative output payload this channel accepts, in bytes.
    pub max_output_bytes: u32,
    /// Largest spool the provider may retain for one job.
    pub max_spool_bytes: u64,
    /// Largest complete encoded result frame, transport framing
    /// included.
    pub max_encoded_result_frame: u32,
    /// Maximum size of the complete encoded prepared-input bundle.
    pub max_encoded_prepared_input: u32,
    /// Blocks allowed from acceptance to durable terminal readiness.
    pub dispatch_margin_blocks: u64,
    /// Blocks allowed to transfer the largest legal result.
    pub delivery_margin_blocks: u64,
    /// Blocks allowed for reexecution, invoicing, and admission.
    pub oracle_grace_blocks: u64,
    /// Price of one accepted terminal result.
    pub fixed_price: u64,
}

impl PrivateRecord for PaidFetchPolicyV1 {
    const TAG: u8 = tag::PAID_FETCH_POLICY;
    const BODY_SIZE: usize = 2 * 32 + 3 * 4 + 8 + 2 * 4 + 4 * 8;

    fn encode_body(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.allowed_environment.as_bytes());
        out.extend_from_slice(self.route_commitment.as_bytes());
        put_u32(out, self.max_request_body_bytes);
        put_u32(out, self.max_output_events);
        put_u32(out, self.max_output_bytes);
        put_u64(out, self.max_spool_bytes);
        put_u32(out, self.max_encoded_result_frame);
        put_u32(out, self.max_encoded_prepared_input);
        put_u64(out, self.dispatch_margin_blocks);
        put_u64(out, self.delivery_margin_blocks);
        put_u64(out, self.oracle_grace_blocks);
        put_u64(out, self.fixed_price);
    }

    fn decode_body(reader: &mut BodyReader<'_>) -> Result<Self, PaidWorkError> {
        Ok(Self {
            allowed_environment: ContentId::from_bytes(reader.bytes32()?),
            route_commitment: Digest::from_bytes(reader.bytes32()?),
            max_request_body_bytes: reader.u32()?,
            max_output_events: reader.u32()?,
            max_output_bytes: reader.u32()?,
            max_spool_bytes: reader.u64()?,
            max_encoded_result_frame: reader.u32()?,
            max_encoded_prepared_input: reader.u32()?,
            dispatch_margin_blocks: reader.u64()?,
            delivery_margin_blocks: reader.u64()?,
            oracle_grace_blocks: reader.u64()?,
            fixed_price: reader.u64()?,
        })
    }
}

/// Requires positive resource limits, timing margins and price.
pub fn check_fetch_policy(policy: &PaidFetchPolicyV1) -> Result<(), PaidWorkError> {
    for (field, value) in [
        ("fixed_price", policy.fixed_price),
        (
            "max_request_body_bytes",
            u64::from(policy.max_request_body_bytes),
        ),
        ("max_output_events", u64::from(policy.max_output_events)),
        ("max_output_bytes", u64::from(policy.max_output_bytes)),
        ("max_spool_bytes", policy.max_spool_bytes),
        (
            "max_encoded_result_frame",
            u64::from(policy.max_encoded_result_frame),
        ),
        (
            "max_encoded_prepared_input",
            u64::from(policy.max_encoded_prepared_input),
        ),
        ("dispatch_margin_blocks", policy.dispatch_margin_blocks),
        ("delivery_margin_blocks", policy.delivery_margin_blocks),
        ("oracle_grace_blocks", policy.oracle_grace_blocks),
    ] {
        if value == 0 {
            return Err(PaidWorkError::PolicyZero { field });
        }
    }
    Ok(())
}

/// Fetch policy digest stored in the authorization's `execution_policy_digest`.
pub fn fetch_policy_digest(channel: &PaidChannel, policy: &PaidFetchPolicyV1) -> Digest {
    let network_bytes = channel.network_bytes();
    xh(
        FETCH_POLICY,
        &[
            network_bytes.as_slice(),
            channel.id().as_bytes(),
            &policy.encode(),
        ],
    )
}

// ── The prepared fetch input bundle ───────────────────────────────────

/// Canonical signed input transcript and manifest, each prefixed by a big-endian
/// `u32` length. The original bytes are retained because the authorization commits
/// to them; `parts` verifies canonical encoding when parsing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedPaidFetchInputV1 {
    fetch_input_transcript: Vec<u8>,
    environment_manifest: Vec<u8>,
}

/// Parsed canonical request transcript and manifest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedPaidFetchInputParts {
    /// The signed fetch input events, strictly decoded.
    pub fetch_input_transcript: Vec<InputEventEnvelope>,
    /// The strictly decoded environment manifest carried by the bundle.
    pub manifest: ProgramManifest,
}

impl PreparedPaidFetchInputV1 {
    /// Encodes the signed input events and manifest into a prepared bundle.
    pub fn new(
        fetch_input_transcript: &[InputEventEnvelope],
        environment_manifest: &ProgramManifest,
    ) -> Result<Self, PaidWorkError> {
        Ok(Self {
            fetch_input_transcript: encode_input_transcript(fetch_input_transcript)?,
            environment_manifest: environment_manifest.canonical_bytes(),
        })
    }

    /// Encodes each body with a big-endian `u32` length, rejecting overflow.
    pub fn encode(&self) -> Result<Vec<u8>, CanonicalDecodeError> {
        let mut bytes = Vec::new();
        for body in self.bodies() {
            let len = u32::try_from(body.len()).map_err(|_| {
                CanonicalDecodeError::new(format!(
                    "prepared fetch input body is {} bytes, over the u32 length prefix",
                    body.len()
                ))
            })?;
            bytes.extend_from_slice(&len.to_be_bytes());
            bytes.extend_from_slice(body);
        }
        Ok(bytes)
    }

    /// Decodes two length-prefixed bodies within the total `budget`, rejecting
    /// truncation, overflow and trailing bytes.
    pub fn decode(bytes: &[u8], budget: usize) -> Result<Self, CanonicalDecodeError> {
        if bytes.len() > budget {
            return Err(CanonicalDecodeError::new(format!(
                "prepared fetch input is {} bytes, over the {budget}-byte budget",
                bytes.len()
            )));
        }
        let mut reader = BundleReader::new(bytes, budget);
        let bundle = Self {
            fetch_input_transcript: reader.body("fetch_input_transcript")?,
            environment_manifest: reader.body("environment_manifest")?,
        };
        if reader.offset() != bytes.len() {
            return Err(CanonicalDecodeError::new(format!(
                "trailing bytes after prepared fetch input: {}",
                bytes.len() - reader.offset()
            )));
        }
        Ok(bundle)
    }

    /// Parses both bodies and requires their canonical encoding to match the
    /// committed bytes.
    pub fn parts(&self) -> Result<PreparedPaidFetchInputParts, CanonicalDecodeError> {
        Ok(PreparedPaidFetchInputParts {
            fetch_input_transcript: decode_input_transcript(&self.fetch_input_transcript)?,
            manifest: ProgramManifest::from_canonical_bytes(&self.environment_manifest)?,
        })
    }

    fn bodies(&self) -> [&[u8]; 2] {
        [&self.fetch_input_transcript, &self.environment_manifest]
    }
}

/// Canonical DAG-CBOR encoding of the signed input envelopes.
fn encode_input_transcript(transcript: &[InputEventEnvelope]) -> Result<Vec<u8>, PaidWorkError> {
    canonical_dag_cbor(&transcript.to_vec())
        .map_err(|error| PaidWorkError::Transcript(error.to_string()))
}

/// Reads the signed fetch input events back, accepting only the canonical
/// spelling.
fn decode_input_transcript(bytes: &[u8]) -> Result<Vec<InputEventEnvelope>, CanonicalDecodeError> {
    decode_canonical_dag_cbor(bytes)
}

/// Hashes the complete prepared bundle, bound to the channel and network.
pub fn prepared_fetch_input_digest(
    channel: &PaidChannel,
    bundle: &PreparedPaidFetchInputV1,
) -> Result<Digest, PaidWorkError> {
    let network_bytes = channel.network_bytes();
    Ok(xfh(
        PREPARED_FETCH_INPUT,
        &[
            network_bytes.as_slice(),
            channel.id().as_bytes(),
            &bundle.encode()?,
        ],
    ))
}

// ── Authorization ─────────────────────────────────────────────────────

/// Derives authorization commitments from the verified request, policy and channel.
/// Only the nonce and deadlines are caller-selected. Admission rules are enforced
/// by `check_fetch_authorization` and `check_prepared_fetch_input`.
pub fn propose_fetch_authorization(
    channel: &PaidChannel,
    policy: &PaidFetchPolicyV1,
    bundle: &PreparedPaidFetchInputV1,
    proposal_nonce: u64,
    deadlines: JobDeadlines,
) -> Result<PaidJobAuthorizationV1, PaidWorkError> {
    let terms = channel.payment_terms();
    let parts = bundle.parts()?;
    let input = crate::fetch::verify_input_events(&parts.fetch_input_transcript)
        .map_err(|error| PaidWorkError::Transcript(error.to_string()))?;
    Ok(PaidJobAuthorizationV1 {
        channel_id: channel.id(),
        bond_edge: terms.bond_edge,
        bond_terms_hash: terms.bond_terms_hash(),
        payment_edge: channel.payment_edge(),
        payment_terms_hash: channel.payment_terms_hash(),
        execution_policy_digest: fetch_policy_digest(channel, policy),
        prepared_input_digest: prepared_fetch_input_digest(channel, bundle)?,
        proposal_nonce,
        acceptance_deadline: deadlines.acceptance,
        request_commitment: RequestCommitment::from_digest(input.input_commitment.digest()),
        environment_commitment: parts.manifest.content_id(),
        price: policy.fixed_price,
        terminal_deadline: deadlines.terminal,
        payment_deadline: deadlines.payment,
    })
}

/// Checks channel, policy, price and deadline bounds at the finalized height;
/// returns the work ID.
pub fn check_fetch_authorization(
    channel: &PaidChannel,
    authorization: &PaidJobAuthorizationV1,
    policy: &PaidFetchPolicyV1,
    finalized_height: u64,
) -> Result<Digest, PaidWorkError> {
    check_fetch_policy(policy)?;
    check_authorization_core(
        channel,
        authorization,
        fetch_policy_digest(channel, policy),
        policy.allowed_environment,
        policy.fixed_price,
        finalized_height,
    )
}

/// Checks bundle bounds, commitments, caller signature, route and environment
/// against the channel policy and authorization. Open Fetch also checks its HTTP
/// schema, host allowlist and required pins. The HTTPS driver checks certificates
/// and addresses when connecting.
pub fn check_prepared_fetch_input(
    channel: &PaidChannel,
    authorization: &PaidJobAuthorizationV1,
    policy: &PaidFetchPolicyV1,
    route: &FetchRoutePolicy,
    bundle: &PreparedPaidFetchInputV1,
) -> Result<(), PaidWorkError> {
    let encoded = bundle.encode()?;
    let limit = u64::from(policy.max_encoded_prepared_input);
    let actual = u64::try_from(encoded.len()).map_err(|_| PaidWorkError::Overflow {
        field: "prepared input length",
    })?;
    if actual > limit {
        return Err(PaidWorkError::OverEnvelope {
            field: "prepared input length",
            actual,
            limit,
        });
    }
    if prepared_fetch_input_digest(channel, bundle)?.as_bytes()
        != authorization.prepared_input_digest.as_bytes()
    {
        return Err(PaidWorkError::Mismatch {
            field: "prepared_input_digest",
        });
    }

    let parts = bundle.parts()?;
    let input = crate::fetch::verify_input_events(&parts.fetch_input_transcript)
        .map_err(|error| PaidWorkError::Transcript(error.to_string()))?;

    // The signing key must also be the channel's client key.
    if input.caller_key != PublicKey::Secp256k1(channel.client_key().to_bytes()) {
        return Err(PaidWorkError::Mismatch {
            field: "caller_key",
        });
    }

    // The supplied route body is accounted to the signed policy before it
    // is allowed to constrain anything: a route whose commitment differs
    // is a route this channel never sold, whatever it claims.
    if fetch_route_commitment(&route.canonical_body_bytes())?.as_bytes()
        != policy.route_commitment.as_bytes()
    {
        return Err(PaidWorkError::Mismatch {
            field: "route_commitment",
        });
    }
    if let FetchRoutePolicy::SealedRoute { service, method } = route {
        for (field, holds) in [
            ("service", input.service == *service),
            ("method", input.method == *method),
        ] {
            if !holds {
                return Err(PaidWorkError::Mismatch { field });
            }
        }
    }

    if let FetchRoutePolicy::OpenFetch {
        require_spki_pin,
        allowed_hosts,
    } = route
    {
        if parts.manifest.content_id() != crate::FetchEnvironment::Http.manifest_id() {
            return Err(PaidWorkError::Mismatch {
                field: "open-fetch HTTPS manifest",
            });
        }
        let request = crate::http_fetch::HttpFetchRequest::decode(input.body.as_bytes())
            .map_err(|e| PaidWorkError::Transcript(e.to_string()))?;
        let url = request
            .parsed_url()
            .map_err(|e| PaidWorkError::Transcript(e.to_string()))?;
        if (*require_spki_pin && request.tls.spki_sha256.is_empty())
            || (!allowed_hosts.is_empty()
                && !allowed_hosts
                    .iter()
                    .any(|h| Some(h.as_str()) == url.host_str()))
        {
            return Err(PaidWorkError::Mismatch {
                field: "open-fetch host or pin policy",
            });
        }
    }

    let graph = [
        (
            "manifest content id",
            parts.manifest.content_id().as_bytes() == input.execution_environment.as_bytes(),
        ),
        (
            "environment_commitment",
            input.execution_environment.as_bytes()
                == authorization.environment_commitment.as_bytes(),
        ),
        (
            "allowed_environment",
            parts.manifest.content_id().as_bytes() == policy.allowed_environment.as_bytes(),
        ),
        (
            "request_commitment",
            RequestCommitment::from_digest(input.input_commitment.digest()).as_bytes()
                == authorization.request_commitment.as_bytes(),
        ),
    ];
    for (field, holds) in graph {
        if !holds {
            return Err(PaidWorkError::Mismatch { field });
        }
    }

    let body = u64::try_from(input.body.as_bytes().len()).map_err(|_| PaidWorkError::Overflow {
        field: "request body length",
    })?;
    let limit = u64::from(policy.max_request_body_bytes);
    if body > limit {
        return Err(PaidWorkError::OverEnvelope {
            field: "request body",
            actual: body,
            limit,
        });
    }

    Ok(())
}

/// Enforces the channel's output limits before a result is recorded or paid.
/// Both counts include the terminal envelope, matching the Fetch wire limits.
pub fn check_fetch_output_limits(
    policy: &PaidFetchPolicyV1,
    transcript: &[OutputEventEnvelope],
) -> Result<(), PaidWorkError> {
    let bytes = transcript.iter().try_fold(0_u64, |total, event| {
        total
            .checked_add(event.payload().len() as u64)
            .ok_or(PaidWorkError::Overflow {
                field: "fetch output bytes",
            })
    })?;
    for (field, actual, limit) in [
        (
            "fetch output events",
            transcript.len() as u64,
            u64::from(policy.max_output_events),
        ),
        (
            "fetch output bytes",
            bytes,
            u64::from(policy.max_output_bytes),
        ),
    ] {
        if actual > limit {
            return Err(PaidWorkError::OverEnvelope {
                field,
                actual,
                limit,
            });
        }
    }
    Ok(())
}

// ── The terminal result ───────────────────────────────────────────────

/// Hashes the concatenated canonical event and terminal payload bytes.
/// Envelope framing is bound separately by the terminal transcript commitment.
/// Changing payload encodings, including how content is split into events, can
/// change this digest.
#[must_use]
pub fn fetch_canonical_output_digest(
    network: NetworkId,
    work_id: Digest,
    event_payloads: &[Vec<u8>],
    terminal_payload: &[u8],
) -> Digest {
    let network_bytes = EncodedNetwork::new(network);
    let mut hasher = XetFileHasher::new();
    hasher.update(FETCH_OUTPUT);
    hasher.update(network_bytes.as_slice());
    hasher.update(work_id.as_bytes());
    for payload in event_payloads {
        hasher.update(payload);
    }
    hasher.update(terminal_payload);
    hasher.finalize()
}

/// Verifies the result using the assurance from the authenticated request and
/// requires the channel's provider key. Returns commitments to the signed
/// transcript and its payload bytes.
pub fn terminal_fetch_result(
    channel: &PaidChannel,
    authorization: &PaidJobAuthorizationV1,
    transcript: &[OutputEventEnvelope],
    assurance: Assurance,
) -> Result<PaidJobResultV1, PaidWorkError> {
    let input = InputCommitment::from_digest(authorization.request_commitment.digest());
    let output = crate::fetch::verify_output_events(input, assurance, transcript)
        .map_err(|error| PaidWorkError::Transcript(error.to_string()))?;

    // Bind the transcript signer to the channel's provider.
    if output.producer_key != PublicKey::Secp256k1(channel.provider_key().to_bytes()) {
        return Err(PaidWorkError::Mismatch {
            field: "transcript producer key",
        });
    }

    let Some(terminal_event) = transcript.last() else {
        // Verification already requires a terminal; keep this path fallible.
        return Err(PaidWorkError::Transcript(
            "the terminal transcript is empty".to_string(),
        ));
    };

    let (event_payloads, terminal_payload) = output.output_event_payloads();
    for payload in event_payloads {
        crate::fetch::decode_fetch_event_payload(payload)
            .map_err(|error| PaidWorkError::Transcript(error.to_string()))?;
    }
    crate::fetch::decode_fetch_terminal_payload(terminal_payload)
        .map_err(|error| PaidWorkError::Transcript(error.to_string()))?;
    let work_id = work_id(channel, authorization);
    Ok(PaidJobResultV1 {
        work_id,
        terminal_transcript_commitment: terminal_event.event_commitment(),
        canonical_output_digest: fetch_canonical_output_digest(
            channel.network(),
            work_id,
            event_payloads,
            terminal_payload,
        ),
    })
}

// ── Bounds ────────────────────────────────────────────────────────────

// The fixed policy digest must fit the single-chunk hasher. Variable bodies
// use the streaming hasher.
const _: () = assert!(
    FETCH_POLICY.len()
        + <NetworkId as Encode>::MAX_ENCODED_SIZE
        + 32
        + PaidFetchPolicyV1::ENCODED_SIZE
        < MIN_CHUNK_SIZE,
    "a single-chunk preimage that reaches MIN_CHUNK_SIZE panics the hasher"
);
