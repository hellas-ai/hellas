//! Canonical private authorization, result, and payment records.
//!
//! Both parties sign the authorization; the provider signs the result;
//! the client signs the payment binding and kernel [`EarnedCertificate`].
//! Digests bind the network and channel. Consensus settles the cumulative
//! certificate, while these private records identify the job it paid for.
//!
//! [`CreditLedger`] checks cumulative payment arithmetic. Durable endpoint
//! state in `hellas-work` prevents duplicate job payments across restarts.
//! Payment requires an authenticated result; local reproduction is optional.
//! These records grant no correctness-challenge or slashing right.
//!
//! Fixed-width preimages use [`SingleChunkHasher`] with compile-time bounds
//! below [`hellas_xet::MIN_CHUNK_SIZE`]. Variable-width preimages use
//! [`XetFileHasher`]. Signatures accompany the bodies rather than changing
//! their canonical encoding; changing a domain or encoding changes signatures.

use hellas_kernel::{
    BufferWriter, EarnedCertificate, EdgeId, Encode, Key, NetworkId, PayloadHash, Terms, TermsHash,
    WorkPaymentSettlement, WorkPaymentTerms,
};
use hellas_xet::{MIN_CHUNK_SIZE, SingleChunkHasher, XetFileHasher};

use crate::evaluate::{EvaluateTerminal, validate_terminal_stop_witness, verify_output_events};
use crate::protocol::artifacts::{
    Canonical, InputAddressed, OutputAddressed, PreparedPaidInputV1, SourceRef, TextArtifact,
    TextPolicy,
};
use crate::protocol::value::{CanonicalDecodeError, canonical_dag_cbor, decode_dag_cbor};
use crate::{
    Assurance, ContentId, Digest, Evaluate, EventCommitment, InputCommitment, OutputEventEnvelope,
    PublicKey, RequestCommitment,
};

// ── Domains ───────────────────────────────────────────────────────────
//
// Every digest in this module is the Xet hash of one of these byte
// strings followed by canonical fields. Changing a string changes every
// digest computed under it, which is why they are written once here and
// never spelled at a call site.

/// Channel identity domain.
const CHANNEL: &[u8] = b"hellas.work.channel.v2";
/// Salted commitment to the static channel credit policy.
const PAID_CHANNEL_POLICY: &[u8] = b"hellas.work.paid-channel-policy.v1";
/// Commitment to the canonical generation-policy body.
const GENERATION_POLICY: &[u8] = b"hellas.work.generation-policy.v1";
/// Commitment to the canonical identity-artifact body.
const IDENTITY_SOURCE: &[u8] = b"hellas.work.identity-source.v1";
/// Commitment to the per-channel execution policy.
const EXECUTION_POLICY: &[u8] = b"hellas.work.execution-policy.v1";
/// Commitment to the prepared input bundle.
const PREPARED_INPUT: &[u8] = b"hellas.work.prepared-input.v1";
/// The job authorization, whose digest is the `work_id`.
const PAID_JOB_AUTHORIZE: &[u8] = b"hellas.work.paid-job-authorize.v1";
/// The provider's signed result.
const PAID_JOB_RESULT: &[u8] = b"hellas.work.paid-job-result.v1";
/// The client's binding of one certificate to one job's result.
const PAYMENT_BINDING: &[u8] = b"hellas.work.payment-binding.v1";
/// The client's request that one job's plaintext be released to it, on
/// one connection.
const DELIVERY_REQUEST: &[u8] = b"hellas.work.delivery-request.v1";
/// The normalized Evaluate answer the client's re-execution compares.
const EVALUATE_OUTPUT: &[u8] = b"hellas.work.evaluate-output.v2";

// ── Envelope ──────────────────────────────────────────────────────────

/// First envelope byte of every fixed private record.
const FORMAT_VERSION: u8 = 1;

/// Second envelope byte: which record this is.
///
/// These are RPC-protocol tags. They are not kernel canonical tags and
/// they are never accepted L1 bytes; the numbers are local to this
/// module and shared only between the two endpoints. The fetch profile's
/// policy record ([`super::work_fetch`]) takes its tag from this same
/// registry, so two profiles can never assign one number.
pub(crate) mod tag {
    pub(crate) const PAID_CHANNEL_POLICY: u8 = 0;
    pub(crate) const PAID_EXECUTION_POLICY: u8 = 1;
    pub(crate) const PAID_JOB_AUTHORIZATION: u8 = 2;
    pub(crate) const PAID_JOB_RESULT: u8 = 3;
    pub(crate) const PAYMENT_BINDING: u8 = 4;
    pub(crate) const PAID_FETCH_POLICY: u8 = 5;
}

/// Bytes the envelope occupies: `format_version:u8 || record_tag:u8`.
const ENVELOPE_SIZE: usize = 2;

// ── Errors ────────────────────────────────────────────────────────────

/// Why a paid-work record was refused.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PaidWorkError {
    /// The envelope's first byte was not the format version `1`.
    #[error("private-work format version {actual} is not {FORMAT_VERSION}")]
    UnknownFormatVersion {
        /// Version byte carried.
        actual: u8,
    },
    /// The envelope named a different record than the one being decoded.
    #[error("private-work record tag {actual} is not the expected {expected}")]
    WrongRecordTag {
        /// Tag the decoder wanted.
        expected: u8,
        /// Tag the bytes carried.
        actual: u8,
    },
    /// A fixed record was truncated, padded, or trailed.
    #[error("private-work record is {actual} bytes, expected exactly {expected}")]
    RecordLength {
        /// Length this record always has.
        expected: usize,
        /// Length the bytes had.
        actual: usize,
    },
    /// A field did not equal the value the surrounding context fixes.
    #[error("{field} does not match the value its channel, policy, or authorization fixes")]
    Mismatch {
        /// Which field disagreed.
        field: &'static str,
    },
    /// The price was zero or above the bond's cover.
    #[error("price {price} is outside 1..={max_job_price}")]
    PriceOutOfRange {
        /// Price the authorization named.
        price: u64,
        /// Largest price the tag-4 bond covers.
        max_job_price: u64,
    },
    /// The four deadlines were not strictly increasing.
    #[error(
        "deadlines must satisfy acceptance {acceptance} < terminal {terminal} \
         < payment {payment} < admission horizon {horizon}"
    )]
    DeadlineOrder {
        /// Last height the authorization may be signed at.
        acceptance: u64,
        /// Last height a terminal result is owed by.
        terminal: u64,
        /// Last height payment is owed by.
        payment: u64,
        /// Height after which the channel admits no work.
        horizon: u64,
    },
    /// The signing height was already past the acceptance deadline.
    #[error("finalized height {height} is past the acceptance deadline {deadline}")]
    AcceptanceExpired {
        /// Finalized height at the signature.
        height: u64,
        /// Deadline the authorization carries.
        deadline: u64,
    },
    /// A profile bound that must be positive was zero.
    #[error("execution policy field {field} must not be zero")]
    PolicyZero {
        /// Which bound was zero.
        field: &'static str,
    },
    /// A request exceeded the resource envelope both parties authorize.
    #[error("{field} is {actual}, over the authorized limit {limit}")]
    OverEnvelope {
        /// Which bound was exceeded.
        field: &'static str,
        /// Value the request asked for.
        actual: u64,
        /// Value the signed policy allows.
        limit: u64,
    },
    /// A nested canonical body was not canonical.
    #[error("prepared input body: {0}")]
    Body(#[from] CanonicalDecodeError),
    /// Checked arithmetic would have wrapped.
    #[error("checked arithmetic overflowed computing {field}")]
    Overflow {
        /// Which computation overflowed.
        field: &'static str,
    },
    /// The payment would settle more than the edge can pay.
    #[error("cumulative {cumulative} exceeds the payment edge capacity {capacity}")]
    OverCapacity {
        /// Cumulative the payment would reach.
        cumulative: u64,
        /// Capacity the kernel will admit on this edge.
        capacity: u64,
    },
    /// The events offered as one job's terminal transcript are not one,
    /// or the bytes offered are not events at all.
    ///
    /// The text is the stream verifier's or the codec's own, rendered
    /// rather than nested: neither error type is `Clone` or `PartialEq`,
    /// and this one is both because every record rule here is compared
    /// in a test. Nothing decides on the string.
    #[error("terminal transcript: {0}")]
    Transcript(String),
}

// ── Records ───────────────────────────────────────────────────────────

/// One fixed-width private record: an envelope and a body.
///
/// The trait exists so the envelope, the exact-length rule, and the
/// unknown-tag rejection are written once. Five copies of "check the
/// version, check the tag, check the length" is five chances to write
/// one of them differently.
pub trait PrivateRecord: Sized {
    /// This record's tag byte.
    const TAG: u8;
    /// Bytes the body occupies. Every record here is fixed-width.
    const BODY_SIZE: usize;
    /// Bytes the envelope and body occupy together.
    const ENCODED_SIZE: usize = ENVELOPE_SIZE + Self::BODY_SIZE;

    /// Appends the body's canonical bytes.
    fn encode_body(&self, out: &mut Vec<u8>);

    /// Reads a body from exactly [`Self::BODY_SIZE`] bytes.
    fn decode_body(reader: &mut BodyReader<'_>) -> Result<Self, PaidWorkError>;

    /// Returns the canonical encoding, envelope included.
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::ENCODED_SIZE);
        out.push(FORMAT_VERSION);
        out.push(Self::TAG);
        self.encode_body(&mut out);
        debug_assert_eq!(out.len(), Self::ENCODED_SIZE);
        out
    }

    /// Decodes exactly one record, rejecting any other spelling.
    ///
    /// The length is checked first and exactly: these records are
    /// fixed-width, so a truncated body and a trailing byte are the same
    /// mistake and get the same refusal.
    fn decode(bytes: &[u8]) -> Result<Self, PaidWorkError> {
        if bytes.len() != Self::ENCODED_SIZE {
            return Err(PaidWorkError::RecordLength {
                expected: Self::ENCODED_SIZE,
                actual: bytes.len(),
            });
        }
        let (envelope, body) = bytes.split_at(ENVELOPE_SIZE);
        match envelope {
            [FORMAT_VERSION, tag] if *tag == Self::TAG => {}
            [FORMAT_VERSION, tag] => {
                return Err(PaidWorkError::WrongRecordTag {
                    expected: Self::TAG,
                    actual: *tag,
                });
            }
            [version, _] => {
                return Err(PaidWorkError::UnknownFormatVersion { actual: *version });
            }
            _ => {
                return Err(PaidWorkError::RecordLength {
                    expected: Self::ENCODED_SIZE,
                    actual: bytes.len(),
                });
            }
        }
        let mut reader = BodyReader { bytes: body };
        let record = Self::decode_body(&mut reader)?;
        // Unreachable while every `decode_body` reads exactly
        // `BODY_SIZE` bytes, which is what the length check above
        // already guaranteed it was handed. It is kept because that is a
        // property of five separate implementations rather than of this
        // one: a field dropped from a `decode_body` whose `BODY_SIZE`
        // was left alone leaves bytes here, and this is the only place
        // that would notice. No test isolates it, and none claims to.
        if reader.bytes.is_empty() {
            Ok(record)
        } else {
            Err(PaidWorkError::RecordLength {
                expected: Self::ENCODED_SIZE,
                actual: bytes.len(),
            })
        }
    }
}

/// Static per-channel credit policy, committed at channel setup.
///
/// It is checked once, before any job exists, and its commitment
/// occupies `WorkPaymentTerms.private_policy_commitment`. Per-job data
/// cannot live there: the commitment is fixed by the payment edge's id,
/// so a per-job body would mean a new edge — and a new channel — for
/// every job.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PaidChannelPolicyV1 {
    /// Compute the provider may lose to a defaulting client before it
    /// stops working for that client.
    pub compute_credit_limit: u64,
    /// Plaintext value the provider may deliver unpaid before it stops
    /// delivering to that client.
    pub delivery_credit_limit: u64,
}

impl PrivateRecord for PaidChannelPolicyV1 {
    const TAG: u8 = tag::PAID_CHANNEL_POLICY;
    const BODY_SIZE: usize = 2 * 8;

    fn encode_body(&self, out: &mut Vec<u8>) {
        put_u64(out, self.compute_credit_limit);
        put_u64(out, self.delivery_credit_limit);
    }

    fn decode_body(reader: &mut BodyReader<'_>) -> Result<Self, PaidWorkError> {
        Ok(Self {
            compute_credit_limit: reader.u64()?,
            delivery_credit_limit: reader.u64()?,
        })
    }
}

/// Everything about *how* a paid job may execute, fixed before it does.
///
/// One signed body carries the environment, the two content
/// sub-commitments, the whole resource envelope, the timing margins, and
/// the price. Every one of those is therefore something both parties
/// authorized rather than a local convention one of them applied.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PaidExecutionPolicyV1 {
    /// The one environment manifest this channel will run.
    pub allowed_environment: ContentId,
    /// Commitment to the canonical generation-policy body.
    pub generation_policy_digest: Digest,
    /// Commitment to the canonical identity-artifact body.
    pub identity_source_digest: Digest,
    /// Largest prompt this channel accepts, in tokens.
    pub max_prompt_tokens: u32,
    /// Largest generation this channel accepts, in tokens.
    pub max_new_tokens: u32,
    /// Largest stop-token list this channel accepts.
    pub max_stop_token_ids: u16,
    /// Largest spool the provider may retain for one job.
    pub max_spool_bytes: u64,
    /// Largest complete encoded result frame, transport framing
    /// included.
    pub max_encoded_result_frame: u32,
    /// Largest complete encoded quote response, bundle included.
    pub max_encoded_quote_response: u32,
    /// Blocks allowed from acceptance to durable terminal readiness.
    pub dispatch_margin_blocks: u64,
    /// Blocks allowed to transfer the largest legal result.
    pub delivery_margin_blocks: u64,
    /// Blocks allowed for reexecution, invoicing, and admission.
    pub oracle_grace_blocks: u64,
    /// Price of one accepted terminal result.
    pub fixed_price: u64,
}

impl PrivateRecord for PaidExecutionPolicyV1 {
    const TAG: u8 = tag::PAID_EXECUTION_POLICY;
    const BODY_SIZE: usize = 3 * 32 + 4 + 4 + 2 + 8 + 4 + 4 + 8 + 8 + 8 + 8;

    fn encode_body(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.allowed_environment.as_bytes());
        out.extend_from_slice(self.generation_policy_digest.as_bytes());
        out.extend_from_slice(self.identity_source_digest.as_bytes());
        put_u32(out, self.max_prompt_tokens);
        put_u32(out, self.max_new_tokens);
        out.extend_from_slice(&self.max_stop_token_ids.to_be_bytes());
        put_u64(out, self.max_spool_bytes);
        put_u32(out, self.max_encoded_result_frame);
        put_u32(out, self.max_encoded_quote_response);
        put_u64(out, self.dispatch_margin_blocks);
        put_u64(out, self.delivery_margin_blocks);
        put_u64(out, self.oracle_grace_blocks);
        put_u64(out, self.fixed_price);
    }

    fn decode_body(reader: &mut BodyReader<'_>) -> Result<Self, PaidWorkError> {
        Ok(Self {
            allowed_environment: ContentId::from_bytes(reader.bytes32()?),
            generation_policy_digest: Digest::from_bytes(reader.bytes32()?),
            identity_source_digest: Digest::from_bytes(reader.bytes32()?),
            max_prompt_tokens: reader.u32()?,
            max_new_tokens: reader.u32()?,
            max_stop_token_ids: reader.u16()?,
            max_spool_bytes: reader.u64()?,
            max_encoded_result_frame: reader.u32()?,
            max_encoded_quote_response: reader.u32()?,
            dispatch_margin_blocks: reader.u64()?,
            delivery_margin_blocks: reader.u64()?,
            oracle_grace_blocks: reader.u64()?,
            fixed_price: reader.u64()?,
        })
    }
}

/// One job, as both parties agreed to it before any work happened.
///
/// Its digest is the `work_id`. Both parties sign that digest, and every
/// later record names it, so a result or a payment can be traced back
/// to exactly one accepted job or to nothing at all.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PaidJobAuthorizationV1 {
    /// Channel this job belongs to.
    pub channel_id: Digest,
    /// Bond edge insuring the channel.
    pub bond_edge: EdgeId,
    /// Commitment to that bond's terms.
    pub bond_terms_hash: TermsHash,
    /// Payment edge this job will be paid from.
    pub payment_edge: EdgeId,
    /// Commitment to that payment edge's terms.
    pub payment_terms_hash: TermsHash,
    /// Commitment to the execution policy in force.
    pub execution_policy_digest: Digest,
    /// Commitment to the prepared input bundle.
    pub prepared_input_digest: Digest,
    /// Client-chosen nonce making this proposal unique.
    ///
    /// Freshness is the client's own duty, and cannot be anything else:
    /// nothing in one authorization distinguishes a fresh nonce from a
    /// repeated one, and by the time a ledger could say, the job is
    /// already accepted. Repeating it is not a payment risk — two
    /// proposals identical in every field are one `work_id`, and
    /// [`CreditLedger`] pays a `work_id` once — it is a delivery risk:
    /// the client has ordered one job and will be paid one job's
    /// answer.
    pub proposal_nonce: u64,
    /// Last height at which this authorization may be signed.
    pub acceptance_deadline: u64,
    /// The Evaluate request commitment this job computes.
    pub request_commitment: RequestCommitment,
    /// Content id of the environment manifest it runs in.
    pub environment_commitment: ContentId,
    /// Price of the accepted terminal result.
    pub price: u64,
    /// Last height a terminal result is owed by.
    pub terminal_deadline: u64,
    /// Last height payment is owed by.
    pub payment_deadline: u64,
}

impl PrivateRecord for PaidJobAuthorizationV1 {
    const TAG: u8 = tag::PAID_JOB_AUTHORIZATION;
    const BODY_SIZE: usize = 9 * 32 + 5 * 8;

    fn encode_body(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.channel_id.as_bytes());
        out.extend_from_slice(self.bond_edge.as_bytes());
        out.extend_from_slice(self.bond_terms_hash.as_bytes());
        out.extend_from_slice(self.payment_edge.as_bytes());
        out.extend_from_slice(self.payment_terms_hash.as_bytes());
        out.extend_from_slice(self.execution_policy_digest.as_bytes());
        out.extend_from_slice(self.prepared_input_digest.as_bytes());
        put_u64(out, self.proposal_nonce);
        put_u64(out, self.acceptance_deadline);
        out.extend_from_slice(self.request_commitment.as_bytes());
        out.extend_from_slice(self.environment_commitment.as_bytes());
        put_u64(out, self.price);
        put_u64(out, self.terminal_deadline);
        put_u64(out, self.payment_deadline);
    }

    fn decode_body(reader: &mut BodyReader<'_>) -> Result<Self, PaidWorkError> {
        Ok(Self {
            channel_id: Digest::from_bytes(reader.bytes32()?),
            bond_edge: EdgeId::from_bytes(reader.bytes32()?),
            bond_terms_hash: TermsHash::from_bytes(reader.bytes32()?),
            payment_edge: EdgeId::from_bytes(reader.bytes32()?),
            payment_terms_hash: TermsHash::from_bytes(reader.bytes32()?),
            execution_policy_digest: Digest::from_bytes(reader.bytes32()?),
            prepared_input_digest: Digest::from_bytes(reader.bytes32()?),
            proposal_nonce: reader.u64()?,
            acceptance_deadline: reader.u64()?,
            request_commitment: RequestCommitment::from_digest(Digest::from_bytes(
                reader.bytes32()?,
            )),
            environment_commitment: ContentId::from_bytes(reader.bytes32()?),
            price: reader.u64()?,
            terminal_deadline: reader.u64()?,
            payment_deadline: reader.u64()?,
        })
    }
}

/// The provider's signed statement of what one accepted job produced.
///
/// It carries no price and no profile field. Its record tag and digest
/// domain fix the profile, and the price lives in the authorization it
/// names — a second copy could only ever disagree with the first.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PaidJobResultV1 {
    /// The authorization digest this result answers.
    pub work_id: Digest,
    /// Event commitment of the one valid terminal envelope, exactly as
    /// the verified transcript produced it.
    pub terminal_transcript_commitment: EventCommitment,
    /// Digest of the normalized answer the client's re-execution
    /// compares.
    pub canonical_output_digest: Digest,
}

impl PrivateRecord for PaidJobResultV1 {
    const TAG: u8 = tag::PAID_JOB_RESULT;
    const BODY_SIZE: usize = 3 * 32;

    fn encode_body(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.work_id.as_bytes());
        out.extend_from_slice(self.terminal_transcript_commitment.as_bytes());
        out.extend_from_slice(self.canonical_output_digest.as_bytes());
    }

    fn decode_body(reader: &mut BodyReader<'_>) -> Result<Self, PaidWorkError> {
        Ok(Self {
            work_id: Digest::from_bytes(reader.bytes32()?),
            terminal_transcript_commitment: EventCommitment::from_digest(Digest::from_bytes(
                reader.bytes32()?,
            )),
            canonical_output_digest: Digest::from_bytes(reader.bytes32()?),
        })
    }
}

/// The client's statement of what one certificate paid for.
///
/// This is the record that gives the scalar a meaning: it names the job,
/// the exact result being paid for, and the exact certificate paying for
/// it. The client signs it, and only the client: the price is fixed by
/// the authorization both parties signed, and the result is already the
/// provider's own signed statement, so a provider counter-signature here
/// would restate two things it has already said.
///
/// It carries no price and no cumulative. Both are derivable — the price
/// from the authorization the `work_id` is the digest of, the cumulative
/// from the certificate — and a copy of a derivable number is a second
/// place for it to disagree.
///
/// It carries no channel id either. The digest this record is signed as
/// binds the network and the channel ([`payment_binding_digest`]), so a
/// binding lifted into another channel is not a binding there.
///
/// It is private evidence: consensus never sees it, and it never alters
/// settlement. It exists so a crash-recovered endpoint can prove to
/// itself what a number bought.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PaymentBindingV1 {
    /// The accepted job being paid for.
    pub work_id: Digest,
    /// The provider-signed result being paid for.
    pub result_digest: Digest,
    /// Digest of the exact certificate the client signed.
    pub certificate_digest: PayloadHash,
}

impl PrivateRecord for PaymentBindingV1 {
    const TAG: u8 = tag::PAYMENT_BINDING;
    const BODY_SIZE: usize = 3 * 32;

    fn encode_body(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.work_id.as_bytes());
        out.extend_from_slice(self.result_digest.as_bytes());
        out.extend_from_slice(self.certificate_digest.as_bytes());
    }

    fn decode_body(reader: &mut BodyReader<'_>) -> Result<Self, PaidWorkError> {
        Ok(Self {
            work_id: Digest::from_bytes(reader.bytes32()?),
            result_digest: Digest::from_bytes(reader.bytes32()?),
            certificate_digest: PayloadHash::from_bytes(reader.bytes32()?),
        })
    }
}

// ── Body reading and writing ──────────────────────────────────────────

pub(crate) fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

pub(crate) fn put_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}

/// Cursor over a fixed record body.
///
/// Every integer here is unsigned big-endian and every digest is raw
/// 32 bytes; there is no length prefix inside a fixed body, because
/// every field's width is part of the schema.
#[derive(Debug)]
pub struct BodyReader<'a> {
    bytes: &'a [u8],
}

impl BodyReader<'_> {
    fn take<const N: usize>(&mut self) -> Result<[u8; N], PaidWorkError> {
        let (head, rest) = self
            .bytes
            .split_at_checked(N)
            .ok_or(PaidWorkError::RecordLength {
                expected: N,
                actual: self.bytes.len(),
            })?;
        let mut out = [0_u8; N];
        out.copy_from_slice(head);
        self.bytes = rest;
        Ok(out)
    }

    pub(crate) fn bytes32(&mut self) -> Result<[u8; 32], PaidWorkError> {
        self.take::<32>()
    }

    fn u16(&mut self) -> Result<u16, PaidWorkError> {
        self.take::<2>().map(u16::from_be_bytes)
    }

    pub(crate) fn u32(&mut self) -> Result<u32, PaidWorkError> {
        self.take::<4>().map(u32::from_be_bytes)
    }

    pub(crate) fn u64(&mut self) -> Result<u64, PaidWorkError> {
        self.take::<8>().map(u64::from_be_bytes)
    }
}

// ── Hashing ───────────────────────────────────────────────────────────

/// A [`NetworkId`] in its canonical encoding: one length byte, then the
/// id.
///
/// The kernel's own encoder writes it, so the network bytes inside these
/// digests are the same bytes inside a kernel authorization hash. The
/// length prefix is why a two-character id followed by a channel cannot
/// hash like a one-character id followed by a different one.
pub(crate) struct EncodedNetwork {
    bytes: [u8; <NetworkId as Encode>::MAX_ENCODED_SIZE],
    len: usize,
}

impl EncodedNetwork {
    pub(crate) fn new(network: NetworkId) -> Self {
        let mut bytes = [0_u8; <NetworkId as Encode>::MAX_ENCODED_SIZE];
        let mut writer = BufferWriter::new(&mut bytes);
        network.encode_to(&mut writer);
        let len = writer.position();
        Self { bytes, len }
    }

    /// Returns the encoded id, and nothing else.
    ///
    /// The index cannot be out of range: `BufferWriter` never reports a
    /// position past the buffer it was given. It is written as an index
    /// rather than a `get(..len).unwrap_or(&self.bytes)` because the
    /// fallback in that spelling is a *different preimage* — the whole
    /// zero-padded buffer — and every digest in this module would move
    /// silently under it. A bug that cannot happen should not have a
    /// second answer ready.
    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

/// `XH(D, fields...)`: the single-chunk Xet hash of `D` followed by the
/// concatenated field bytes.
///
/// Every caller's complete preimage is bounded at compile time by an
/// assertion below, because [`SingleChunkHasher::update`] panics rather
/// than erroring once a preimage reaches [`MIN_CHUNK_SIZE`].
pub(crate) fn xh(domain: &[u8], fields: &[&[u8]]) -> Digest {
    let mut hasher = SingleChunkHasher::new();
    hasher.update(domain);
    for field in fields {
        hasher.update(field);
    }
    hasher.finalize()
}

/// `XFH(D, fields...)`: the streaming Xet file hash of the same bytes.
///
/// Used where a legal preimage can cross [`MIN_CHUNK_SIZE`]. It equals
/// one-shot [`Digest::hash`] of the same concatenation under every write
/// segmentation, which is what lets a caller stream a large body without
/// holding it.
pub(crate) fn xfh(domain: &[u8], fields: &[&[u8]]) -> Digest {
    let mut hasher = XetFileHasher::new();
    hasher.update(domain);
    for field in fields {
        hasher.update(field);
    }
    hasher.finalize()
}

const fn wider(a: usize, b: usize) -> usize {
    if a > b { a } else { b }
}

/// Widest of the five records, taken rather than named.
const WIDEST_RECORD: usize = wider(
    wider(
        PaidChannelPolicyV1::ENCODED_SIZE,
        PaidExecutionPolicyV1::ENCODED_SIZE,
    ),
    wider(
        wider(
            PaidJobAuthorizationV1::ENCODED_SIZE,
            PaidJobResultV1::ENCODED_SIZE,
        ),
        PaymentBindingV1::ENCODED_SIZE,
    ),
);
/// Longest of the record domains, likewise taken rather than named.
const LONGEST_DOMAIN: usize = wider(
    wider(PAID_CHANNEL_POLICY.len(), EXECUTION_POLICY.len()),
    wider(
        wider(PAID_JOB_AUTHORIZE.len(), PAID_JOB_RESULT.len()),
        PAYMENT_BINDING.len(),
    ),
);
const ENCODED_NETWORK: usize = <NetworkId as Encode>::MAX_ENCODED_SIZE;

/// Largest complete `XH` preimage this module can produce.
///
/// Every `XH` preimage has one of two shapes, and both are bounded below
/// rather than assumed to be covered by the other. The record-shaped
/// preimages — `domain || network || channel_id || record` — take the
/// widest record and the longest domain from the sets above, so a sixth
/// record, or one that grew, cannot invalidate this bound by being
/// overlooked.
const WIDEST_XH_PREIMAGE: usize = LONGEST_DOMAIN + ENCODED_NETWORK + 32 + WIDEST_RECORD;

const _: () = assert!(
    WIDEST_XH_PREIMAGE < MIN_CHUNK_SIZE,
    "a single-chunk preimage that reaches MIN_CHUNK_SIZE panics the hasher"
);
// `domain || network || payment_edge || payment_terms || bond_edge ||
// bond_terms`: the channel id is derived before a channel id exists, so
// it is the one preimage with no channel field.
const _: () = assert!(
    CHANNEL.len() + ENCODED_NETWORK + 4 * 32 < MIN_CHUNK_SIZE,
    "channel id preimage must stay under MIN_CHUNK_SIZE"
);

// ── The channel ───────────────────────────────────────────────────────

/// The payment channel a paid job belongs to: its two kernel edges,
/// their terms, and the id derived from them.
///
/// Every digest in this module takes the network and the channel id from
/// here rather than from a caller's own copy. The id has one derivation
/// and the terms it was derived from travel with it, so no call site can
/// hash a channel id against terms that do not produce it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PaidChannel {
    network: NetworkId,
    payment_edge: EdgeId,
    payment_terms: WorkPaymentTerms,
    payment_terms_hash: TermsHash,
    channel_policy: PaidChannelPolicyV1,
    id: Digest,
}

impl PaidChannel {
    /// Derives a channel from its payment edge, that edge's terms, and
    /// the credit policy those terms commit to.
    ///
    /// The bond edge and bond terms hash are read out of the payment
    /// terms rather than passed in: the payment body already embeds the
    /// complete bond, so a separately supplied bond could only ever be
    /// the wrong one.
    ///
    /// The credit policy is opened here, once, against
    /// `private_policy_commitment`, and then travels with the channel.
    /// A policy checked at a call site is a policy some other call site
    /// can decline to check; a channel that cannot be constructed
    /// without opening its own commitment has no such call site. The
    /// commitment is salted because the credit domain is small enough to
    /// enumerate.
    pub fn new(
        network: NetworkId,
        payment_edge: EdgeId,
        payment_terms: WorkPaymentTerms,
        salt: &[u8; 32],
        channel_policy: PaidChannelPolicyV1,
    ) -> Result<Self, PaidWorkError> {
        if private_policy_commitment(network, salt, &channel_policy)
            != payment_terms.private_policy_commitment
        {
            return Err(PaidWorkError::Mismatch {
                field: "private_policy_commitment",
            });
        }
        let payment_terms_hash = Terms::work_payment(payment_terms.clone()).hash();
        let bond_terms_hash = payment_terms.bond_terms_hash();
        let network_bytes = EncodedNetwork::new(network);
        let id = xh(
            CHANNEL,
            &[
                network_bytes.as_slice(),
                payment_edge.as_bytes(),
                payment_terms_hash.as_bytes(),
                payment_terms.bond_edge.as_bytes(),
                bond_terms_hash.as_bytes(),
            ],
        );
        Ok(Self {
            network,
            payment_edge,
            payment_terms,
            payment_terms_hash,
            channel_policy,
            id,
        })
    }

    /// Returns the channel id: the value every record carries and every
    /// digest binds.
    pub const fn id(&self) -> Digest {
        self.id
    }

    /// Returns the network this channel's authorizations are bound to.
    pub const fn network(&self) -> NetworkId {
        self.network
    }

    /// Returns the payment edge.
    pub const fn payment_edge(&self) -> EdgeId {
        self.payment_edge
    }

    /// Returns the payment terms commitment.
    pub const fn payment_terms_hash(&self) -> TermsHash {
        self.payment_terms_hash
    }

    /// Returns the payment terms.
    pub const fn payment_terms(&self) -> &WorkPaymentTerms {
        &self.payment_terms
    }

    /// Returns the credit policy this channel's terms commit to.
    pub const fn channel_policy(&self) -> &PaidChannelPolicyV1 {
        &self.channel_policy
    }

    /// Returns the client's settlement key: the payment edge's maker.
    pub const fn client_key(&self) -> Key {
        self.payment_terms.parties().maker()
    }

    /// Returns the provider's settlement key: the payment edge's taker.
    pub const fn provider_key(&self) -> Key {
        self.payment_terms.parties().taker()
    }

    pub(crate) fn network_bytes(&self) -> EncodedNetwork {
        EncodedNetwork::new(self.network)
    }
}

// ── Digests ───────────────────────────────────────────────────────────

/// Returns the commitment that occupies
/// `WorkPaymentTerms.private_policy_commitment`.
///
/// Salted, because the credit domain is small enough to enumerate: an
/// unsalted commitment to two integers is a commitment anyone can invert
/// by guessing.
pub fn private_policy_commitment(
    network: NetworkId,
    salt: &[u8; 32],
    policy: &PaidChannelPolicyV1,
) -> [u8; 32] {
    let network_bytes = EncodedNetwork::new(network);
    xh(
        PAID_CHANNEL_POLICY,
        &[network_bytes.as_slice(), salt, &policy.encode()],
    )
    .into_bytes()
}

/// Returns the commitment to a canonical generation-policy body.
///
/// Length-prefixed and streamed: a generation policy is variable-length,
/// so this is one of the four digests that must not use the single-chunk
/// hasher.
pub fn generation_policy_digest(
    canonical_text_policy_bytes: &[u8],
) -> Result<Digest, PaidWorkError> {
    Ok(xfh(
        GENERATION_POLICY,
        &[
            &length_prefix(canonical_text_policy_bytes, "generation policy length")?,
            canonical_text_policy_bytes,
        ],
    ))
}

/// Match a request against the channel's generation ceiling and stop policy.
/// The commitment is the canonical policy at the maximum permitted length;
/// the job authorization separately commits to the exact requested length.
pub fn matches_generation_policy(
    policy: &PaidExecutionPolicyV1,
    requested: &TextPolicy,
) -> Result<bool, PaidWorkError> {
    if requested.max_new_tokens() == 0 {
        return Err(PaidWorkError::PolicyZero {
            field: "request max_new_tokens",
        });
    }
    if requested.max_new_tokens() > policy.max_new_tokens {
        return Err(PaidWorkError::OverEnvelope {
            field: "max_new_tokens",
            actual: u64::from(requested.max_new_tokens()),
            limit: u64::from(policy.max_new_tokens),
        });
    }
    let ceiling = TextPolicy::new(
        policy.max_new_tokens,
        requested.stop_token_ids().iter().copied(),
    );
    Ok(
        generation_policy_digest(&requested.canonical_bytes())? == policy.generation_policy_digest
            || generation_policy_digest(&ceiling.canonical_bytes())?
                == policy.generation_policy_digest,
    )
}

/// Returns the commitment to a canonical identity-artifact body.
pub fn identity_source_digest(
    canonical_identity_artifact_bytes: &[u8],
) -> Result<Digest, PaidWorkError> {
    Ok(xfh(
        IDENTITY_SOURCE,
        &[
            &length_prefix(
                canonical_identity_artifact_bytes,
                "identity artifact length",
            )?,
            canonical_identity_artifact_bytes,
        ],
    ))
}

/// Returns the four-byte length prefix that separates a body from
/// whatever follows it.
///
/// The prefix is what stops one body's tail from being read as the next
/// body's head, so a length that did not fit it would be a prefix that
/// separates nothing. A body that large is unreachable through any
/// bounded decoder here; it is refused rather than truncated because a
/// truncated prefix is a second legal spelling of the same bytes.
pub(crate) fn length_prefix(bytes: &[u8], field: &'static str) -> Result<[u8; 4], PaidWorkError> {
    let len = u32::try_from(bytes.len()).map_err(|_| PaidWorkError::Overflow { field })?;
    Ok(len.to_be_bytes())
}

/// Returns the digest an authorization names as its execution policy.
pub fn execution_policy_digest(channel: &PaidChannel, policy: &PaidExecutionPolicyV1) -> Digest {
    let network_bytes = channel.network_bytes();
    xh(
        EXECUTION_POLICY,
        &[
            network_bytes.as_slice(),
            channel.id.as_bytes(),
            &policy.encode(),
        ],
    )
}

/// Returns the digest an authorization names as its prepared input.
///
/// Streamed, because the bundle carries whole artifact bodies and is
/// the widest of the four preimages with no fixed width.
pub fn prepared_input_digest(
    channel: &PaidChannel,
    bundle: &PreparedPaidInputV1,
) -> Result<Digest, PaidWorkError> {
    let network_bytes = channel.network_bytes();
    Ok(xfh(
        PREPARED_INPUT,
        &[
            network_bytes.as_slice(),
            channel.id.as_bytes(),
            &bundle.encode()?,
        ],
    ))
}

/// Returns the `work_id`: the digest both parties sign to accept a job.
pub fn work_id(channel: &PaidChannel, authorization: &PaidJobAuthorizationV1) -> Digest {
    let network_bytes = channel.network_bytes();
    xh(
        PAID_JOB_AUTHORIZE,
        &[
            network_bytes.as_slice(),
            channel.id.as_bytes(),
            &authorization.encode(),
        ],
    )
}

/// Returns the digest the provider signs to deliver a result.
pub fn result_digest(channel: &PaidChannel, result: &PaidJobResultV1) -> Digest {
    let network_bytes = channel.network_bytes();
    xh(
        PAID_JOB_RESULT,
        &[
            network_bytes.as_slice(),
            channel.id.as_bytes(),
            &result.encode(),
        ],
    )
}

/// Returns the digest the client signs beside its certificate.
pub fn payment_binding_digest(channel: &PaidChannel, binding: &PaymentBindingV1) -> Digest {
    let network_bytes = channel.network_bytes();
    xh(
        PAYMENT_BINDING,
        &[
            network_bytes.as_slice(),
            channel.id.as_bytes(),
            &binding.encode(),
        ],
    )
}

/// Returns the digest the client signs to ask for one job's plaintext.
///
/// Four things, and each is load-bearing. The network and the channel,
/// because a signature is only ever about one channel of one network.
/// The `work_id`, because it is the job whose answer is being asked
/// for. The domain string above, because it is the action — a
/// signature made to pay for a job is not a signature to be handed the
/// job. And the connection's TLS exporter, because it is what makes
/// this unreplayable: the value is derived from the live QUIC session
/// and is known to exactly its two ends, so a request lifted off one
/// connection authorises nothing on another.
///
/// A `work_id` is not any of that. It is in the client's logs, it is
/// the first thing a provider learns from a proposal, and it names a
/// job rather than granting anything about it.
#[must_use]
pub fn delivery_request_digest(
    channel: &PaidChannel,
    work_id: Digest,
    exporter: &[u8; 32],
) -> Digest {
    let network_bytes = channel.network_bytes();
    xh(
        DELIVERY_REQUEST,
        &[
            network_bytes.as_slice(),
            channel.id.as_bytes(),
            work_id.as_bytes(),
            exporter,
        ],
    )
}

/// Returns the digest of the normalized Evaluate answer.
///
/// Chunk boundaries are not part of the answer: the token deltas are
/// flattened into one ordered list, so two providers that split the same
/// tokens into different signed events produce the same digest here
/// while producing different transcript commitments. This is the digest
/// the client's independent reexecution compares; the transcript
/// commitment beside it is what binds the provider's exact signed
/// framing.
pub fn canonical_output_digest(
    network: NetworkId,
    work_id: Digest,
    output_token_ids: &[u32],
    terminal: &EvaluateTerminal,
) -> Result<Digest, PaidWorkError> {
    validate_terminal_stop_witness(terminal).map_err(|_| PaidWorkError::Mismatch {
        field: "matched stop token id",
    })?;
    let output_count =
        u64::try_from(output_token_ids.len()).map_err(|_| PaidWorkError::Overflow {
            field: "output token count",
        })?;
    if output_count != terminal.final_position || output_count != terminal.usage.output_units {
        return Err(PaidWorkError::Mismatch {
            field: "output token count",
        });
    }
    let billable = terminal
        .usage
        .input_units
        .checked_add(terminal.usage.output_units)
        .ok_or(PaidWorkError::Overflow {
            field: "billable units",
        })?;
    if billable != terminal.billable_units {
        return Err(PaidWorkError::Mismatch {
            field: "billable units",
        });
    }

    let network_bytes = EncodedNetwork::new(network);
    let mut hasher = XetFileHasher::new();
    hasher.update(EVALUATE_OUTPUT);
    hasher.update(network_bytes.as_slice());
    hasher.update(work_id.as_bytes());
    hasher.update(&output_count.to_be_bytes());
    for token in output_token_ids {
        hasher.update(&token.to_be_bytes());
    }
    hasher.update(&terminal.final_position.to_be_bytes());
    hasher.update(&[terminal.stop_reason.as_u8()]);
    match terminal.matched_stop_token_id {
        Some(token_id) => {
            hasher.update(&[1]);
            hasher.update(&token_id.to_be_bytes());
        }
        None => hasher.update(&[0]),
    }
    hasher.update(terminal.text_artifact.as_bytes());
    hasher.update(&terminal.usage.input_units.to_be_bytes());
    hasher.update(&terminal.usage.output_units.to_be_bytes());
    hasher.update(&billable.to_be_bytes());
    Ok(hasher.finalize())
}

// ── Checks ────────────────────────────────────────────────────────────

/// Checks that an execution policy is a usable profile at all.
///
/// A zero here is not a small bound, it is an absent one: a zero margin
/// gives a deadline no time to be met in, a zero spool is a result the
/// provider may not retain long enough to deliver, and a zero price is a
/// job nobody is paid for.
///
/// `max_stop_token_ids` is the one bound that may be zero, and is
/// therefore deliberately absent from this list: a channel that admits
/// no stop tokens is a channel whose jobs run to `max_new_tokens`, which
/// is a usable channel. Zero reads there as the limit it is, not as an
/// unset field.
pub fn check_execution_policy(policy: &PaidExecutionPolicyV1) -> Result<(), PaidWorkError> {
    for (field, value) in [
        ("fixed_price", policy.fixed_price),
        ("max_prompt_tokens", u64::from(policy.max_prompt_tokens)),
        ("max_new_tokens", u64::from(policy.max_new_tokens)),
        ("max_spool_bytes", policy.max_spool_bytes),
        (
            "max_encoded_result_frame",
            u64::from(policy.max_encoded_result_frame),
        ),
        (
            "max_encoded_quote_response",
            u64::from(policy.max_encoded_quote_response),
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

/// The three heights one job is bound by.
///
/// A struct rather than three positional `u64`s, which are ordered,
/// interchangeable, and a signature whose mistakes compile.
///
/// None of the three is derived from the execution policy, and that is
/// deliberate: the policy measures *margins* — dispatch, delivery,
/// oracle grace — and a margin is how much room a deadline needs, never
/// which height a client wants its answer by. Where the two meet is
/// `ReadyChannel::check_signable`, which refuses deadlines the measured
/// margins cannot fit inside.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JobDeadlines {
    /// Last height at which this authorization may be signed.
    pub acceptance: u64,
    /// Last height a terminal result is owed by.
    pub terminal: u64,
    /// Last height payment is owed by.
    pub payment: u64,
}

/// Builds one job's authorization, deriving every field the channel, the
/// policy, and the prepared inputs already fix.
///
/// The nonce and the three deadlines are the only choices left to the
/// caller. Every other field is read out of something that already
/// exists, so a proposal built here cannot name a price the policy does
/// not fix, an environment its own request does not run in, or an input
/// digest its own bundle does not hash to.
///
/// It checks nothing. [`check_authorization`] and
/// [`check_prepared_input`] are where the refusals are written, once,
/// and they are what the *other* party runs; a proposer that skipped
/// them would only be refused later. What construction here buys is
/// narrower and worth stating exactly: the fields it derives cannot
/// disagree with their sources, so the checks that compare them can
/// only fail on the caller's four choices or on a channel and policy
/// that were already wrong.
///
/// # Errors
///
/// [`PaidWorkError::Body`] when the bundle's own bodies are not
/// canonical, and [`PaidWorkError::Overflow`] when it is too large to
/// length-prefix.
pub fn propose_authorization(
    channel: &PaidChannel,
    policy: &PaidExecutionPolicyV1,
    bundle: &PreparedPaidInputV1,
    proposal_nonce: u64,
    deadlines: JobDeadlines,
) -> Result<PaidJobAuthorizationV1, PaidWorkError> {
    let terms = channel.payment_terms();
    let request = bundle.parts()?.evaluate_request;
    Ok(PaidJobAuthorizationV1 {
        channel_id: channel.id(),
        bond_edge: terms.bond_edge,
        bond_terms_hash: terms.bond_terms_hash(),
        payment_edge: channel.payment_edge(),
        payment_terms_hash: channel.payment_terms_hash(),
        execution_policy_digest: execution_policy_digest(channel, policy),
        prepared_input_digest: prepared_input_digest(channel, bundle)?,
        proposal_nonce,
        acceptance_deadline: deadlines.acceptance,
        request_commitment: Evaluate::commit_request(&request),
        environment_commitment: request.execution_environment,
        price: policy.fixed_price,
        terminal_deadline: deadlines.terminal,
        payment_deadline: deadlines.payment,
    })
}

/// Returns the kernel payload hash one of this module's digests is
/// signed as.
///
/// A digest and a payload hash are both 32 bytes, and a signature is
/// over the second. Written once so no call site re-wraps it, and so
/// the two spellings cannot drift apart.
#[must_use]
pub const fn signing_hash(digest: Digest) -> PayloadHash {
    PayloadHash::from_bytes(digest.into_bytes())
}

/// Checks one authorization against the channel, the policy it names,
/// and the height it is being signed at, and returns its `work_id`.
///
/// Both parties run this before signing, and both run it from their own
/// locally hash-verified terms. What it establishes is that signing the
/// authorization digest is the same act for both of them: the same
/// channel, the same bond cover, the same policy, the same price, a
/// price the channel's own credit limits cover, and a window that has
/// not already closed.
pub fn check_authorization(
    channel: &PaidChannel,
    authorization: &PaidJobAuthorizationV1,
    policy: &PaidExecutionPolicyV1,
    finalized_height: u64,
) -> Result<Digest, PaidWorkError> {
    check_execution_policy(policy)?;
    check_authorization_core(
        channel,
        authorization,
        execution_policy_digest(channel, policy),
        policy.allowed_environment,
        policy.fixed_price,
        finalized_height,
    )
}

/// The authorization arithmetic every paid-work profile shares.
///
/// The profiles differ in what a policy *is* — the evaluate profile's is
/// [`PaidExecutionPolicyV1`], the fetch profile's is in
/// [`super::work_fetch`] — but not in what signing one *means*: the same
/// channel fields, the same bond cover, the same credit-limit cover, the
/// same deadline window. That part is written once here so the two
/// profiles cannot drift into two different definitions of acceptance.
/// What each caller supplies is its own policy digest, environment, and
/// price; what this function supplies is everything else.
pub(crate) fn check_authorization_core(
    channel: &PaidChannel,
    authorization: &PaidJobAuthorizationV1,
    policy_digest: Digest,
    allowed_environment: ContentId,
    fixed_price: u64,
    finalized_height: u64,
) -> Result<Digest, PaidWorkError> {
    let terms = channel.payment_terms();
    let expected = [
        (
            "channel_id",
            authorization.channel_id.as_bytes() == channel.id.as_bytes(),
        ),
        (
            "bond_edge",
            authorization.bond_edge.as_bytes() == terms.bond_edge.as_bytes(),
        ),
        (
            "bond_terms_hash",
            authorization.bond_terms_hash.as_bytes() == terms.bond_terms_hash().as_bytes(),
        ),
        (
            "payment_edge",
            authorization.payment_edge.as_bytes() == channel.payment_edge.as_bytes(),
        ),
        (
            "payment_terms_hash",
            authorization.payment_terms_hash.as_bytes() == channel.payment_terms_hash.as_bytes(),
        ),
        (
            "execution_policy_digest",
            authorization.execution_policy_digest.as_bytes() == policy_digest.as_bytes(),
        ),
        (
            "environment_commitment",
            authorization.environment_commitment.as_bytes() == allowed_environment.as_bytes(),
        ),
    ];
    for (field, holds) in expected {
        if !holds {
            return Err(PaidWorkError::Mismatch { field });
        }
    }

    let max_job_price = terms.bond_terms.max_job_price;
    if authorization.price == 0 || authorization.price > max_job_price {
        return Err(PaidWorkError::PriceOutOfRange {
            price: authorization.price,
            max_job_price,
        });
    }
    if authorization.price != fixed_price {
        return Err(PaidWorkError::Mismatch { field: "price" });
    }

    // The policy is per-authorization and only its digest is
    // signed, so a channel may see many of them. The credit limits are
    // per-channel and are opened once, at construction. That is why the
    // two are compared here, against this job's price, rather than once
    // at setup against whichever policy happened to be in hand: a
    // defaulting client's gain is bounded by these two limits, so a
    // limit below one job's price is a job's worth of value the ledger
    // never accounted for.
    let credit = channel.channel_policy();
    for (field, limit) in [
        (
            "price against compute_credit_limit",
            credit.compute_credit_limit,
        ),
        (
            "price against delivery_credit_limit",
            credit.delivery_credit_limit,
        ),
    ] {
        if limit < authorization.price {
            return Err(PaidWorkError::OverEnvelope {
                field,
                actual: authorization.price,
                limit,
            });
        }
    }

    if finalized_height > authorization.acceptance_deadline {
        return Err(PaidWorkError::AcceptanceExpired {
            height: finalized_height,
            deadline: authorization.acceptance_deadline,
        });
    }
    let horizon = terms.admission_horizon().get();
    if !(authorization.acceptance_deadline < authorization.terminal_deadline
        && authorization.terminal_deadline < authorization.payment_deadline
        && authorization.payment_deadline < horizon)
    {
        return Err(PaidWorkError::DeadlineOrder {
            acceptance: authorization.acceptance_deadline,
            terminal: authorization.terminal_deadline,
            payment: authorization.payment_deadline,
            horizon,
        });
    }

    Ok(work_id(channel, authorization))
}

/// Checks the prepared bundle against the authorization and policy that
/// commit to it.
///
/// Holding a bundle whose digest matches is not the same as knowing what
/// is in it. This walks the whole graph: the request's commitment, the
/// environment it names, the execution that request is addressed by, the
/// prompt and policy that execution names, the identity artifact it
/// starts from, and the resource envelope all of those have to fit
/// inside. Signing the digest never substitutes for this.
pub fn check_prepared_input(
    channel: &PaidChannel,
    authorization: &PaidJobAuthorizationV1,
    policy: &PaidExecutionPolicyV1,
    bundle: &PreparedPaidInputV1,
) -> Result<(), PaidWorkError> {
    let encoded = bundle.encode()?;
    let limit = u64::from(policy.max_encoded_quote_response);
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
    if prepared_input_digest(channel, bundle)?.as_bytes()
        != authorization.prepared_input_digest.as_bytes()
    {
        return Err(PaidWorkError::Mismatch {
            field: "prepared_input_digest",
        });
    }

    let parts = bundle.parts()?;
    let request = &parts.evaluate_request;

    if request.assurance != Assurance::ProducerSigned {
        return Err(PaidWorkError::Mismatch {
            field: "request assurance",
        });
    }
    if request.runner_public_key != PublicKey::Secp256k1(channel.client_key().to_bytes()) {
        return Err(PaidWorkError::Mismatch {
            field: "runner_public_key",
        });
    }

    // The identity artifact is the only legal start for this profile: a
    // job that resumed a previous output would be paid for work whose
    // input this bundle does not carry.
    //
    // Its bound term is the manifest identity the execution resolves in. A
    // party reconstructing this source reads that exact manifest from the
    // prepared bundle, so an identity naming another environment is a job
    // that would fault at dispatch after both parties had signed for it.
    let TextArtifact::Identity { bound_term, .. } = &parts.identity_artifact else {
        return Err(PaidWorkError::Mismatch {
            field: "identity_artifact kind",
        });
    };
    if bound_term.as_bytes() != request.execution_environment.as_bytes() {
        return Err(PaidWorkError::Mismatch {
            field: "identity_artifact bound_term",
        });
    }
    let identity_id = parts.identity_artifact.output_id();
    if parts.text_execution.from() != &SourceRef::output(identity_id) {
        return Err(PaidWorkError::Mismatch {
            field: "text_execution source",
        });
    }

    let graph = [
        (
            "manifest content id",
            parts.manifest.content_id().as_bytes() == request.execution_environment.as_bytes(),
        ),
        (
            "environment_commitment",
            request.execution_environment.as_bytes()
                == authorization.environment_commitment.as_bytes(),
        ),
        (
            "request_commitment",
            Evaluate::commit_request(request).as_bytes()
                == authorization.request_commitment.as_bytes(),
        ),
        (
            "text_execution id",
            parts.text_execution.input_id().as_bytes() == request.text_execution.as_bytes(),
        ),
        (
            "prompt_tokens id",
            parts.text_execution.prompt_tokens().as_bytes()
                == parts.prompt_tokens.output_id().as_bytes(),
        ),
        (
            "text_policy id",
            parts.text_execution.policy().as_bytes() == parts.text_policy.output_id().as_bytes(),
        ),
        (
            "generation_policy_digest",
            matches_generation_policy(policy, &parts.text_policy)?,
        ),
        (
            "identity_source_digest",
            identity_source_digest(&parts.identity_artifact.canonical_bytes())?.as_bytes()
                == policy.identity_source_digest.as_bytes(),
        ),
    ];
    for (field, holds) in graph {
        if !holds {
            return Err(PaidWorkError::Mismatch { field });
        }
    }

    let envelope = [
        (
            "prompt tokens",
            parts.prompt_tokens.as_slice().len() as u64,
            u64::from(policy.max_prompt_tokens),
        ),
        (
            "max_new_tokens",
            u64::from(parts.text_policy.max_new_tokens()),
            u64::from(policy.max_new_tokens),
        ),
        (
            "stop token ids",
            parts.text_policy.stop_token_ids().len() as u64,
            u64::from(policy.max_stop_token_ids),
        ),
    ];
    for (field, actual, limit) in envelope {
        if actual > limit {
            return Err(PaidWorkError::OverEnvelope {
                field,
                actual,
                limit,
            });
        }
    }
    // Zero is not "no limit" here, whatever a quote parser elsewhere
    // makes of it: a job authorized to generate nothing has no terminal
    // result to be paid for.
    if parts.text_policy.max_new_tokens() == 0 {
        return Err(PaidWorkError::PolicyZero {
            field: "request max_new_tokens",
        });
    }

    Ok(())
}

/// Builds the result record for the transcript one invocation of this
/// job produced.
///
/// The only constructor of a [`PaidJobResultV1`] in this crate, and it
/// takes the whole transcript rather than any digest of it. That is the
/// point: what makes a result the provider's own is that the events it
/// summarises verify as one signed chain — this profile's scheme, this
/// authorization's request commitment, contiguous positions from zero,
/// and a decodable terminal at the end. None of that can be supplied by
/// a caller holding a commitment, so no path here accepts one.
///
/// The two digests it produces say different things about the same
/// invocation. `terminal_transcript_commitment` is the last event's own
/// commitment, so it binds the provider's exact signed framing,
/// including how the tokens were split across events.
/// `canonical_output_digest` binds the flattened answer, so two
/// transcripts that split the same tokens differently agree on it.
///
/// # Errors
///
/// [`PaidWorkError::Transcript`] when the events are not one verified
/// terminal transcript for this authorization's request: empty,
/// mis-signed, out of order, addressed to another request, or ending in
/// an event that is not a decodable terminal.
/// [`PaidWorkError::Mismatch`] when they were produced under a key this
/// channel does not call the provider. Whatever
/// [`canonical_output_digest`] refuses about the terminal's own counts.
pub fn terminal_result(
    channel: &PaidChannel,
    authorization: &PaidJobAuthorizationV1,
    transcript: &[OutputEventEnvelope],
) -> Result<PaidJobResultV1, PaidWorkError> {
    let input = InputCommitment::from_digest(authorization.request_commitment.digest());
    let output = verify_output_events(input, Assurance::ProducerSigned, transcript)
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
        // Unreachable: verification refuses an empty transcript, and a
        // non-empty slice has a last element. Written as a refusal
        // because nothing in this module panics; no test isolates it,
        // and none claims to.
        return Err(PaidWorkError::Transcript(
            "the terminal transcript is empty".to_string(),
        ));
    };

    // Chunk boundaries are dropped here and nowhere else. The deltas
    // were verified to start at zero and to be contiguous, so their
    // concatenation is the answer in position order.
    let output_token_ids: Vec<u32> = output
        .token_deltas
        .iter()
        .flat_map(|delta| delta.token_ids.iter().copied())
        .collect();

    let work_id = work_id(channel, authorization);
    Ok(PaidJobResultV1 {
        work_id,
        terminal_transcript_commitment: terminal_event.event_commitment(),
        canonical_output_digest: canonical_output_digest(
            channel.network(),
            work_id,
            &output_token_ids,
            &output.terminal,
        )?,
    })
}

// ── Carrying a transcript ─────────────────────────────────────────────

/// Encodes one job's transcript for storage and transport.
///
/// DAG-CBOR over the signed envelopes, through the same derived
/// `Serialize` the rest of this crate's stream types use. Nothing in the
/// paid protocol hashes these bytes: what binds a transcript to a job is
/// [`terminal_result`] rebuilding the signed result from the decoded
/// *events*, so a re-encoding that moved a field would fail that
/// comparison rather than slip past a byte check. There is therefore no
/// domain string here and no golden vector: the meaning is checked, not
/// the spelling.
///
/// # Errors
///
/// [`PaidWorkError::Transcript`] when the encoder cannot allocate.
pub fn encode_transcript(transcript: &[OutputEventEnvelope]) -> Result<Vec<u8>, PaidWorkError> {
    canonical_dag_cbor(&transcript.to_vec())
        .map_err(|error| PaidWorkError::Transcript(error.to_string()))
}

/// Reads a transcript back, refusing anything over `budget`.
///
/// `budget` is the caller's spool bound. It is checked against the input
/// before a byte is decoded, because the decoder allocates from what the
/// bytes claim and a bound applied afterwards would already have paid
/// for the claim.
///
/// # Errors
///
/// [`PaidWorkError::OverEnvelope`] above `budget`, and
/// [`PaidWorkError::Transcript`] when the bytes are not a transcript.
pub fn decode_transcript(
    bytes: &[u8],
    budget: usize,
) -> Result<Vec<OutputEventEnvelope>, PaidWorkError> {
    let actual = u64::try_from(bytes.len()).map_err(|_| PaidWorkError::Overflow {
        field: "transcript length",
    })?;
    let limit = u64::try_from(budget).map_err(|_| PaidWorkError::Overflow {
        field: "transcript budget",
    })?;
    if actual > limit {
        return Err(PaidWorkError::OverEnvelope {
            field: "transcript length",
            actual,
            limit,
        });
    }
    decode_dag_cbor(bytes).map_err(|error| PaidWorkError::Transcript(error.to_string()))
}

/// Checks that a result answers the accepted job, and returns its
/// digest.
pub fn check_result(
    channel: &PaidChannel,
    work_id: Digest,
    result: &PaidJobResultV1,
) -> Result<Digest, PaidWorkError> {
    if result.work_id.as_bytes() != work_id.as_bytes() {
        return Err(PaidWorkError::Mismatch { field: "work_id" });
    }
    Ok(result_digest(channel, result))
}

/// Builds the one payment a delivered result may be settled by: the
/// certificate consensus will see, and the private binding that says
/// what it bought.
///
/// This is the only way either is made, and the two are made together
/// because neither is checkable without the other. A certificate alone
/// is a number, and a binding alone names a certificate that need not
/// exist. Both endpoints call this — the client to build what it signs,
/// [`CreditLedger::credit_payment`] to rebuild what it is handed — so
/// a rule enforced by construction here cannot be enforced differently
/// by the two of them.
///
/// Nothing it produces is a function of anything but the channel, the
/// job, and `credited`. In particular there is no price argument: the
/// price is the one the authorization both parties signed fixes, and a
/// caller that could pass another would be a caller that could set it.
///
/// It builds a payment for whatever `credited` it is given, and will
/// therefore build a second payment for a job that already has one.
/// Nothing here can tell the two apart, and nothing here tries:
/// [`CreditLedger::credit_payment`] is where a job is paid for at most
/// once.
///
/// The capacity bound is the kernel's own [`WorkPaymentSettlement`], not
/// a number this module derives. A certificate above the smaller of the
/// two route totals, less the omission bond, is one no close will pay,
/// and `EdgeState.value` is not that bound. Taking the settlement rather
/// than a bare integer is what stops an endpoint from supplying its own
/// arithmetic here.
///
/// # Errors
///
/// [`PaidWorkError::Mismatch`] when the result does not answer this
/// authorization, [`PaidWorkError::Overflow`] when the cumulative would
/// wrap, and [`PaidWorkError::OverCapacity`] when it would exceed what
/// this edge can settle.
pub fn next_payment(
    channel: &PaidChannel,
    authorization: &PaidJobAuthorizationV1,
    result: &PaidJobResultV1,
    credited: u64,
    settlement: WorkPaymentSettlement,
) -> Result<(EarnedCertificate, PaymentBindingV1), PaidWorkError> {
    let work_id = work_id(channel, authorization);
    let result_digest = check_result(channel, work_id, result)?;
    let cumulative = credited
        .checked_add(authorization.price)
        .ok_or(PaidWorkError::Overflow {
            field: "earned cumulative",
        })?;
    if cumulative > settlement.capacity() {
        return Err(PaidWorkError::OverCapacity {
            cumulative,
            capacity: settlement.capacity(),
        });
    }
    let certificate =
        EarnedCertificate::new(channel.payment_edge, channel.payment_terms_hash, cumulative);
    let binding = PaymentBindingV1 {
        work_id,
        result_digest,
        certificate_digest: certificate.digest(channel.network),
    };
    Ok((certificate, binding))
}

/// What one endpoint has already credited on one channel.
///
/// One value: the cumulative amount already credited. Individual jobs
/// are retained by the durable work store, while this value supplies the
/// arithmetic shared by all of them: each payment adds its price on top
/// of it and its certificate must settle exactly that sum.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CreditLedger {
    credited_cumulative: u64,
}

impl CreditLedger {
    /// A channel that has credited nothing.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Restores a checkpointed cumulative credit total.
    ///
    /// A journal checkpoint carries this value across a rotation. The
    /// store validates it against its retained payment terminals before
    /// it is trusted; this constructor only restores the number.
    #[must_use]
    pub const fn from_credited_cumulative(credited_cumulative: u64) -> Self {
        Self {
            credited_cumulative,
        }
    }

    /// Returns the cumulative amount already credited.
    pub const fn credited_cumulative(&self) -> u64 {
        self.credited_cumulative
    }

    /// Checks that a certificate and its binding pay for exactly this
    /// job, and credits it if they do.
    ///
    /// This is the join between the private evidence and the one number
    /// consensus sees, and it is the only place the two meet. It
    /// establishes that the certificate the client is about to sign —
    /// or that a provider is about to bank — settles this channel's
    /// credited total plus exactly one job's authorized price, for a
    /// result the provider signed against exactly that job.
    ///
    /// What the caller still owns: keeping this ledger — one per
    /// channel, across restarts — and verifying the client's signatures
    /// over the binding and over the certificate. This function reads
    /// bodies, never signatures.
    ///
    /// # Errors
    ///
    /// [`PaidWorkError::Mismatch`] when the binding or the certificate is
    /// not the one this job at this ledger position produces, and
    /// whatever [`next_payment`] refuses about the job itself.
    pub fn credit_payment(
        &mut self,
        channel: &PaidChannel,
        authorization: &PaidJobAuthorizationV1,
        result: &PaidJobResultV1,
        binding: &PaymentBindingV1,
        certificate: &EarnedCertificate,
        settlement: WorkPaymentSettlement,
    ) -> Result<(), PaidWorkError> {
        let (expected_certificate, expected_binding) = next_payment(
            channel,
            authorization,
            result,
            self.credited_cumulative,
            settlement,
        )?;

        // The certificate's three fields, each against what this channel
        // and this ledger position fix. All three together are the whole
        // of an `EarnedCertificate`, which is what makes the binding
        // check below a statement about *this* certificate rather than
        // about some certificate with the same digest field.
        let expected = [
            (
                "certificate payment_edge",
                certificate.payment_edge().as_bytes()
                    == expected_certificate.payment_edge().as_bytes(),
            ),
            (
                "certificate payment_terms_hash",
                certificate.payment_terms_hash().as_bytes()
                    == expected_certificate.payment_terms_hash().as_bytes(),
            ),
            (
                "certificate earned_cumulative",
                certificate.earned_cumulative() == expected_certificate.earned_cumulative(),
            ),
            (
                "binding work_id",
                binding.work_id.as_bytes() == expected_binding.work_id.as_bytes(),
            ),
            (
                "binding result_digest",
                binding.result_digest.as_bytes() == expected_binding.result_digest.as_bytes(),
            ),
            (
                "binding certificate_digest",
                binding.certificate_digest.as_bytes()
                    == expected_binding.certificate_digest.as_bytes(),
            ),
        ];
        for (field, holds) in expected {
            if !holds {
                return Err(PaidWorkError::Mismatch { field });
            }
        }

        self.credited_cumulative = expected_certificate.earned_cumulative();
        Ok(())
    }
}
