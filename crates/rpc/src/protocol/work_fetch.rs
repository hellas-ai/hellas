//! The paid-fetch profile: private records for paid jobs whose execution
//! is a Fetch request rather than a local evaluation.
//!
//! The shared machinery in [`super::work`] is profile-agnostic: the
//! authorization binds a policy digest, a prepared-input digest, a request
//! commitment, and an environment commitment, and the result and payment
//! records derive from it. What a profile owns is the meaning of those
//! four commitments. For the evaluate profile the policy is
//! [`super::work::PaidExecutionPolicyV1`] and the prepared input is a
//! six-body artifact bundle; for this profile the policy is
//! [`PaidFetchPolicyV1`] and the prepared input is the client's signed
//! fetch input transcript together with the environment manifest it runs
//! in.
//!
//! A paid fetch job buys one provider-signed HTTP transformation — one
//! [`crate::fetch`] call — rather than local model evaluation. The client
//! signs the request as a fetch input transcript; the provider answers
//! with a signed fetch output transcript; this module is where those
//! transcripts meet the channel's money. The record tag and the digest
//! domains below are what separate the two profiles on the wire: a tag-5
//! policy is a fetch policy under every decoder, and a digest computed
//! here cannot be reproduced by the evaluate profile's domains.

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

// ── Domains ───────────────────────────────────────────────────────────
//
// Same discipline as `super::work`: every digest here is the Xet hash of
// one of these byte strings followed by canonical fields, the strings are
// written once, and changing one changes every digest computed under it.

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

/// The route a fetch channel sells, committed to by digest.
///
/// A [`PaidFetchPolicyV1`] cannot carry this body — it is variable-length,
/// and the policy record is fixed-width — so the policy carries
/// [`fetch_route_commitment`] of its canonical bytes instead, and
/// [`check_prepared_fetch_input`] opens the commitment before comparing
/// anything against it. That is the same arrangement the evaluate profile
/// uses for its generation policy: a variable-length canonical body, a
/// fixed digest in the record.
///
/// The body is canonical DAG-CBOR with one schema tag per variant, so a
/// route has exactly one byte spelling and the commitment cannot be
/// opened to a different route than the one that was hashed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FetchRoutePolicy {
    /// The one `(service, method)` pair this channel sells.
    ///
    /// These are the route labels a sealed fetch input transcript signs;
    /// the paid profile refuses a job whose signed labels differ, so the
    /// pair here is the whole of the channel's routing vocabulary.
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
    /// Builds the sealed route, applying the same component rules the
    /// fetch transcript scheme applies to the signed `service` and
    /// `method` events: neither empty, neither over
    /// [`MAX_FETCH_ROUTE_COMPONENT_BYTES`]. The two rules are shared with
    /// `crate::fetch` rather than restated, so a route this profile
    /// accepts is a route the transcript scheme accepts.
    ///
    /// # Errors
    ///
    /// [`FetchProtocolError::EmptyService`], [`FetchProtocolError::EmptyMethod`],
    /// or [`FetchProtocolError::RouteComponentLimit`] — the fetch
    /// protocol's own route errors, because they are the fetch protocol's
    /// own rules.
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

    /// Builds the open-fetch vocabulary.
    ///
    /// The host list is sorted and deduplicated: an allowlist is a set,
    /// and a set with two spellings would be two commitments to one
    /// policy. Admission matches exact canonical URL host names and checks
    /// required pins; the HTTPS interpreter performs certificate and address
    /// checks when connecting.
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

    /// Returns the canonical body bytes the policy commits to.
    ///
    /// The one boolean encodes as the integer `0` or `1`: the canonical
    /// encoder has no boolean primitive, and a definite two-value integer
    /// is the smallest encoding that cannot drift.
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

    /// Decodes one canonical route-policy body, strictly.
    ///
    /// Strict the way a committed body has to be: an unknown schema, a
    /// wrong array length, a pin that is not `0` or `1`, a trailing byte,
    /// and a noncanonical integer are all refused, and the value is
    /// re-encoded and compared so the bytes accepted are the bytes
    /// [`Self::canonical_body_bytes`] would have produced. The sealed
    /// variant is rebuilt through [`Self::sealed_route`], so a body that
    /// spells a route the transcript scheme would refuse is refused here
    /// too.
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

/// Returns the commitment a [`PaidFetchPolicyV1`] names as its route.
///
/// Length-prefixed and streamed, mirroring
/// [`super::work::generation_policy_digest`]: the route body is
/// variable-length, so this digest must not use the single-chunk hasher.
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

/// Everything about *how* a paid fetch job may execute, fixed before it
/// does: the fetch profile's tag-5 analogue of
/// [`super::work::PaidExecutionPolicyV1`].
///
/// One signed body carries the environment, the route commitment, the
/// resource envelope, the timing margins, and the price. Where the
/// evaluate policy commits to a generation-policy body and an identity
/// artifact, this one commits to a [`FetchRoutePolicy`] body: what the
/// channel may *reach* replaces what the channel may *generate*, because
/// a fetch job's variable choices are its upstream route, not its
/// sampling parameters.
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
    /// Largest complete encoded prepared-input bundle.
    ///
    /// The evaluate profile bounds its bundle with the quote-response
    /// limit because the bundle is the quote's payload; this profile
    /// names the bundle's own limit instead, so the two numbers a fetch
    /// channel wants cannot force each other.
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

/// Checks that a fetch policy is a usable profile at all.
///
/// A zero here is not a small bound, it is an absent one — the same rule
/// [`super::work::check_execution_policy`] states for the evaluate
/// profile. Unlike that policy there is no field whose zero reads as a
/// usable limit: a zero request-body bound admits no valid JSON body, a
/// zero output bound admits no terminal event, and the margins and price
/// are zero for no lawful channel. All ten are therefore required.
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

/// Returns the digest an authorization names as its execution policy.
///
/// The shared [`PaidJobAuthorizationV1`] field is called
/// `execution_policy_digest` because the record predates the second
/// profile; under this profile it carries this digest.
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

/// The two canonical bodies a paid fetch job is prepared from, in one
/// length-delimited byte string.
///
/// The fetch analogue of
/// [`crate::protocol::artifacts::PreparedPaidInputV1`]:
/// same `u32` big-endian length prefixes, same budget-checked
/// [`Self::decode`], same strict [`Self::parts`]. Where the evaluate
/// bundle carries an artifact graph, this one carries exactly the two
/// things the profile's commitments are opened from: the client's signed
/// fetch input transcript, and the manifest of the environment it runs
/// in.
///
/// It carries bytes rather than parsed values for the same reason the
/// evaluate bundle does — the bytes are what the digest commits to — with
/// one sharpened consequence: the signed transcript's canonical bytes are
/// hashed here, so [`Self::parts`] decodes it strictly rather than with
/// the permissive DAG-CBOR decoder a transport boundary might use.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedPaidFetchInputV1 {
    fetch_input_transcript: Vec<u8>,
    environment_manifest: Vec<u8>,
}

/// The two bodies of a [`PreparedPaidFetchInputV1`], parsed.
///
/// The manifest is retained as its parsed value for the same reason the
/// evaluate bundle retains its own: parsing proves the carried bytes were
/// canonical, and re-encoding recovers them exactly.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedPaidFetchInputParts {
    /// The signed fetch input events, strictly decoded.
    pub fetch_input_transcript: Vec<InputEventEnvelope>,
    /// The strictly decoded environment manifest carried by the bundle.
    pub manifest: ProgramManifest,
}

impl PreparedPaidFetchInputV1 {
    /// Builds a bundle from the signed input events and the manifest,
    /// encoding each body once.
    ///
    /// # Errors
    ///
    /// [`PaidWorkError::Transcript`] when the transcript's canonical
    /// encoding cannot be allocated.
    pub fn new(
        fetch_input_transcript: &[InputEventEnvelope],
        environment_manifest: &ProgramManifest,
    ) -> Result<Self, PaidWorkError> {
        Ok(Self {
            fetch_input_transcript: encode_input_transcript(fetch_input_transcript)?,
            environment_manifest: environment_manifest.canonical_bytes(),
        })
    }

    /// Returns the canonical encoding: two unsigned big-endian `u32`
    /// lengths, each immediately followed by that many body bytes.
    ///
    /// Fallible for the one reason the evaluate bundle's is: a body whose
    /// length does not fit its `u32` prefix has no encoding here, because
    /// truncating the prefix would be a second spelling of the same bytes.
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

    /// Decodes a bundle, refusing anything that does not fit `budget`.
    ///
    /// `budget` is the profile's complete-bundle limit
    /// ([`PaidFetchPolicyV1::max_encoded_prepared_input`]), checked against
    /// the input before the first length is read and against the running
    /// total after each one, so the two individually representable lengths
    /// cannot add up to a bundle this endpoint never agreed to hold.
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

    /// Parses both bodies, rejecting either that is not canonical.
    ///
    /// Both bodies arrive already bounded: by [`Self::decode`]'s budget
    /// for a received bundle, or by [`Self::new`]'s construction for a
    /// local one. The transcript is decoded strictly — decoded,
    /// re-encoded, and compared — because its bytes are what
    /// [`prepared_fetch_input_digest`] commits to, so a noncanonical
    /// spelling is a different bundle and must not parse as this one.
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

/// Encodes the signed fetch input events for the bundle.
///
/// The input-side analogue of [`super::work::encode_transcript`]: DAG-CBOR
/// over the signed envelopes, through the same derived `Serialize`. The
/// one difference is that this encoding *is* hashed — it is a bundle body
/// — which is why [`decode_input_transcript`] below is strict where
/// [`super::work::decode_transcript`] is not.
fn encode_input_transcript(transcript: &[InputEventEnvelope]) -> Result<Vec<u8>, PaidWorkError> {
    canonical_dag_cbor(&transcript.to_vec())
        .map_err(|error| PaidWorkError::Transcript(error.to_string()))
}

/// Reads the signed fetch input events back, accepting only the canonical
/// spelling.
fn decode_input_transcript(bytes: &[u8]) -> Result<Vec<InputEventEnvelope>, CanonicalDecodeError> {
    decode_canonical_dag_cbor(bytes)
}

/// Returns the digest an authorization names as its prepared input.
///
/// Streamed, mirroring [`super::work::prepared_input_digest`]: the bundle
/// carries a signed transcript whose size is the client's to choose
/// within the policy bound, so it is one of the preimages with no fixed
/// width.
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

/// Builds one fetch job's authorization, deriving every field the
/// channel, the policy, and the prepared inputs already fix.
///
/// The fetch analogue of [`super::work::propose_authorization`], with the
/// same narrow guarantee: the nonce and the three deadlines are the only
/// choices left to the caller, and every other field is read out of
/// something that already exists. The request commitment is computed the
/// fetch ticket flow's way — the signed input transcript is verified by
/// [`crate::fetch::verify_input_events`], and its input commitment is the
/// request commitment — so a proposal cannot name a commitment its own
/// transcript does not produce.
///
/// It checks nothing beyond what deriving those fields requires.
/// [`check_fetch_authorization`] and [`check_prepared_fetch_input`] are
/// where the refusals are written, and they are what the *other* party
/// runs.
///
/// # Errors
///
/// [`PaidWorkError::Body`] when the bundle's own bodies are not canonical,
/// [`PaidWorkError::Transcript`] when the carried events are not one
/// well-formed signed fetch input, and [`PaidWorkError::Overflow`] when
/// the bundle is too large to length-prefix.
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

/// Checks one authorization against the channel, the fetch policy it
/// names, and the height it is being signed at, and returns its
/// `work_id`.
///
/// The fetch analogue of [`super::work::check_authorization`]. Everything
/// the two profiles mean by *accepting* a job — channel fields, bond
/// cover, price cover, deadline window — is shared
/// [`check_authorization_core`]; what differs is which policy digest,
/// environment, and price those rules are applied to, and that is what
/// this wrapper supplies.
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

/// Checks the prepared fetch bundle against the authorization, the
/// policy, and the route policy that commit to it.
///
/// The fetch analogue of [`super::work::check_prepared_input`], and the
/// same statement in this profile's vocabulary: holding a bundle whose
/// digest matches is not knowing what is in it. The checks, in order:
/// the bundle fits the policy's encoding bound; its digest is the
/// authorization's; the signed events verify as one caller-signed fetch
/// input chain under [`crate::fetch::verify_input_events`] — which also
/// applies the fetch protocol's own hard bounds, including
/// [`crate::fetch::MAX_FETCH_REQUEST_BODY_BYTES`]; the caller is the
/// channel's client; the signed assurance selects the result scheme; the route body
/// opens the policy's route commitment and, for a sealed route, names the
/// service and method the events sign; the manifest, the events'
/// environment, the policy's allowed environment, and the
/// authorization's environment commitment are one; and the request
/// commitment is the verified transcript's.
///
/// The route policy is an argument rather than a bundle body because the
/// bundle is the client's statement of the job and the route is the
/// channel's statement of what it sells: the two meet here, against the
/// commitment both signed into the policy.
///
/// Open Fetch additionally verifies the generic HTTPS manifest, request schema,
/// host allowlist and any required SPKI pin. Network-dependent certificate and
/// address checks happen inside that interpreter at dispatch.
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

    // The fetch analogue of the evaluate profile's runner-key rule: the
    // request must be the client's own, and one verified signature chain
    // is how a fetch request says whose it is. Verification takes the key
    // from the first event, so it cannot say whose key it is; this is
    // what says it is the client's.
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

/// Returns the digest of the normalized fetch answer.
///
/// Chunk boundaries are not part of the answer, exactly as in
/// [`super::work::canonical_output_digest`]: the semantic event payloads
/// and the terminal payload are flattened into one byte stream, so two
/// providers that split the same answer across different signed events
/// produce the same digest here while producing different transcript
/// commitments. The fetch answer has no token ids and no counts to
/// cross-check — the payload bytes are the answer, which is why this
/// digest, unlike the evaluate one, has nothing to refuse. The payloads
/// are canonical DAG-CBOR with distinct event and terminal codec strings,
/// so a reader that parses the stream can still tell where the terminal
/// begins even though this digest does not bind that boundary; the
/// transcript commitment beside it binds the framing exactly.
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

/// Builds the result record for the fetch transcript one invocation of
/// this job produced.
///
/// The fetch analogue of [`super::work::terminal_result`], with the same
/// shape and the same reason for it: what makes a result the provider's
/// own is that the events it summarises verify as one signed chain — the
/// fetch scheme, this authorization's request commitment, contiguous
/// sequence from the output genesis, and a terminal event at the end,
/// which is exactly what [`crate::fetch::verify_output_events`] checks.
/// None of that can be supplied by a caller holding a commitment, so no
/// path here accepts one.
///
/// The two digests it produces say different things about the same
/// invocation, as they do for evaluate:
/// `terminal_transcript_commitment` binds the provider's exact signed
/// framing; [`fetch_canonical_output_digest`] binds the flattened answer,
/// so two transcripts that split the same payloads differently agree on
/// it.
///
/// # Errors
///
/// [`PaidWorkError::Transcript`] when the events are not one verified
/// fetch output transcript for this authorization's request.
/// [`PaidWorkError::Mismatch`] when they were produced under a key this
/// channel does not call the provider.
pub fn terminal_fetch_result(
    channel: &PaidChannel,
    authorization: &PaidJobAuthorizationV1,
    transcript: &[OutputEventEnvelope],
) -> Result<PaidJobResultV1, PaidWorkError> {
    terminal_fetch_result_with_assurance(
        channel,
        authorization,
        transcript,
        Assurance::ProducerSigned,
    )
}

/// Verifies the assurance committed by the caller's authenticated input.
pub fn terminal_fetch_result_with_assurance(
    channel: &PaidChannel,
    authorization: &PaidJobAuthorizationV1,
    transcript: &[OutputEventEnvelope],
    assurance: Assurance,
) -> Result<PaidJobResultV1, PaidWorkError> {
    let input = InputCommitment::from_digest(authorization.request_commitment.digest());
    let output = crate::fetch::verify_output_events(input, assurance, transcript)
        .map_err(|error| PaidWorkError::Transcript(error.to_string()))?;

    // Verification above establishes that one key signed every event; it
    // takes that key from the first event, so it cannot say whose key it
    // is. This is what says it is the provider's — the same compressed
    // secp256k1 point the payment terms name as a party.
    if output.producer_key != PublicKey::Secp256k1(channel.provider_key().to_bytes()) {
        return Err(PaidWorkError::Mismatch {
            field: "transcript producer key",
        });
    }

    let Some(terminal_event) = transcript.last() else {
        // Unreachable for the same reason as in
        // `super::work::terminal_result`: verification refuses an empty
        // transcript, and a non-empty slice has a last element. Written as
        // a refusal because nothing in this module panics.
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

const ENCODED_NETWORK: usize = <NetworkId as Encode>::MAX_ENCODED_SIZE;

/// Widest of this module's fixed records: the one record, today. Written
/// as a named bound rather than inline so a second fetch record must
/// widen it deliberately, as `super::work::WIDEST_RECORD` does for its
/// five.
const WIDEST_RECORD: usize = PaidFetchPolicyV1::ENCODED_SIZE;

/// Longest of this module's single-chunk domains. The three
/// variable-body digests are streamed and need no bound; the one
/// fixed-record digest — [`fetch_policy_digest`] — does.
const LONGEST_XH_DOMAIN: usize = FETCH_POLICY.len();

/// Largest complete `XH` preimage this module can produce:
/// `domain || network || channel_id || record`, the one record-shaped
/// preimage here.
const WIDEST_XH_PREIMAGE: usize = LONGEST_XH_DOMAIN + ENCODED_NETWORK + 32 + WIDEST_RECORD;

const _: () = assert!(
    WIDEST_XH_PREIMAGE < MIN_CHUNK_SIZE,
    "a single-chunk preimage that reaches MIN_CHUNK_SIZE panics the hasher"
);
