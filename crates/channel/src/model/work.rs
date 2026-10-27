//! Canonical private authorization, result, and payment records.
//!
//! Both parties sign the authorization; the provider signs the result;
//! the client signs the payment binding and kernel [`EarnedCertificate`].
//! Digests bind the network and channel. Consensus settles the cumulative
//! certificate, while these private records identify the job it paid for.
//!
//! [`CreditLedger`] checks cumulative payment arithmetic. Durable endpoint
//! state in `hellas-channel` prevents duplicate job payments across restarts.
//! Payment requires an authenticated result that obeys the declared stop rule.
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

use hellas_auth::Digest;
use hellas_rpc::protocol::value::{CanonicalDecodeError, canonical_dag_cbor, decode_dag_cbor};
use hellas_rpc::{ContentId, EventCommitment, OutputEventEnvelope, RequestCommitment, Retention};

/// Allocating encoding for native/wire consumers; the kernel remains allocation-free.
pub fn encode_kernel<E: Encode>(value: &E) -> Vec<u8> {
    let mut bytes = vec![0; value.encoded_size()];
    let written = value.write_to(&mut bytes);
    bytes.truncate(written);
    bytes
}

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

/// The job authorization, whose digest is the `work_id`.
const JOB_PAYMENT_POLICY: &[u8] = b"hellas.work.job-payment-policy.v2";
const PAID_JOB_AUTHORIZE: &[u8] = b"hellas.work.paid-job-authorize.v2";
/// The provider's signed result.
const PAID_JOB_RESULT: &[u8] = b"hellas.work.paid-job-result.v1";
/// The client's binding of one certificate to one job's result.
const PAYMENT_BINDING: &[u8] = b"hellas.work.payment-binding.v1";
/// The client's request that one job's plaintext be released to it, on
/// one connection.
const DELIVERY_REQUEST: &[u8] = b"hellas.work.delivery-request.v1";

// ── Envelope ──────────────────────────────────────────────────────────

/// First envelope byte of every fixed private record.
const FORMAT_VERSION: u8 = 1;

/// Private-record tags shared by the endpoints; these are never L1 bytes.
pub(crate) mod tag {
    // Tags 1, 2 and 5 are reserved.
    pub(crate) const PAID_CHANNEL_POLICY: u8 = 0;
    pub(crate) const PAID_JOB_RESULT: u8 = 3;
    pub(crate) const PAYMENT_BINDING: u8 = 4;
    pub(crate) const JOB_PAYMENT_POLICY_V2: u8 = 8;
    pub(crate) const PAID_JOB_AUTHORIZATION_V2: u8 = 9;
    pub(crate) const GRANT_JOB_AUTHORIZATION_V1: u8 = 10;
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
/// unknown-tag rejection are written once. Independent copies of "check the
/// version, check the tag, check the length" are separate chances to write
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
        // property of separate implementations rather than of this
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
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
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

/// V2 payment authorization binds separate execution and payment policies.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PaidJobAuthorizationV2 {
    /// Channel this job belongs to.
    pub channel_id: Digest,
    /// Commitment to the execution policy in force.
    pub work_policy_digest: Digest,
    /// Commitment to the separate job payment policy.
    pub payment_policy_digest: Digest,
    /// Commitment to the prepared input bundle.
    pub input_content: hellas_rpc::ContentRef,
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
    /// The invocation request commitment this job computes.
    pub request_commitment: RequestCommitment,
    /// Content id of the environment manifest it runs in.
    pub environment_commitment: ContentId,
    /// Price of the accepted terminal result.
    pub price: u64,
    /// Last height a terminal result is owed by.
    pub terminal_deadline: u64,
    /// Last height payment is owed by.
    pub payment_deadline: u64,
    /// Per-job content retention, fixed before the first upload chunk.
    pub retention: Retention,
}

impl PrivateRecord for PaidJobAuthorizationV2 {
    const TAG: u8 = tag::PAID_JOB_AUTHORIZATION_V2;
    const BODY_SIZE: usize = 6 * 32 + 5 * 8 + 40 + 1;

    fn encode_body(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.channel_id.as_bytes());
        out.extend_from_slice(self.work_policy_digest.as_bytes());
        out.extend_from_slice(self.payment_policy_digest.as_bytes());
        out.extend_from_slice(&hellas_rpc::protocol::content_upload::encode_reference(
            self.input_content,
        ));
        out.extend_from_slice(self.prepared_input_digest.as_bytes());
        put_u64(out, self.proposal_nonce);
        put_u64(out, self.acceptance_deadline);
        out.extend_from_slice(self.request_commitment.as_bytes());
        out.extend_from_slice(self.environment_commitment.as_bytes());
        put_u64(out, self.price);
        put_u64(out, self.terminal_deadline);
        put_u64(out, self.payment_deadline);
        out.push(match self.retention {
            Retention::Ephemeral => 0,
            Retention::Retain => 1,
        });
    }

    fn decode_body(reader: &mut BodyReader<'_>) -> Result<Self, PaidWorkError> {
        Ok(Self {
            channel_id: Digest::from_bytes(reader.bytes32()?),
            work_policy_digest: Digest::from_bytes(reader.bytes32()?),
            payment_policy_digest: Digest::from_bytes(reader.bytes32()?),
            input_content: hellas_rpc::ContentRef::new(
                ContentId::from_bytes(reader.bytes32()?),
                reader.u64()?,
            ),
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
            retention: match reader.take::<1>()?[0] {
                0 => Retention::Ephemeral,
                1 => Retention::Retain,
                _ => return Err(PaidWorkError::Mismatch { field: "retention" }),
            },
        })
    }
}

/// Classification authenticated by the invocation terminal. A failed job is
/// never payable, including after payload-free journal replay.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResultOutcome {
    Finished,
    Failed,
}

/// Provider-signed invocation evidence. The outcome and exact transcript
/// reference remain available during metadata-only replay.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PaidJobResultV1 {
    /// The authorization digest this result answers.
    pub work_id: Digest,
    /// Event commitment of the one valid terminal envelope, exactly as
    /// the verified transcript produced it.
    pub terminal_transcript_commitment: EventCommitment,
    /// Digest of the authenticated normalized invocation output.
    pub canonical_output_digest: Digest,
    /// Whether the authenticated terminal completed successfully.
    pub outcome: ResultOutcome,
    /// Exact canonical signed envelopes, independently of normalized output.
    pub transcript_content: hellas_rpc::ContentRef,
}

impl PrivateRecord for PaidJobResultV1 {
    const TAG: u8 = tag::PAID_JOB_RESULT;
    const BODY_SIZE: usize = 3 * 32 + 1 + 40;

    fn encode_body(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.work_id.as_bytes());
        out.extend_from_slice(self.terminal_transcript_commitment.as_bytes());
        out.extend_from_slice(self.canonical_output_digest.as_bytes());
        out.push(match self.outcome {
            ResultOutcome::Finished => 0,
            ResultOutcome::Failed => 1,
        });
        out.extend_from_slice(&hellas_rpc::protocol::content_upload::encode_reference(
            self.transcript_content,
        ));
    }

    fn decode_body(reader: &mut BodyReader<'_>) -> Result<Self, PaidWorkError> {
        Ok(Self {
            work_id: Digest::from_bytes(reader.bytes32()?),
            terminal_transcript_commitment: EventCommitment::from_digest(Digest::from_bytes(
                reader.bytes32()?,
            )),
            canonical_output_digest: Digest::from_bytes(reader.bytes32()?),
            outcome: match reader.take::<1>()?[0] {
                0 => ResultOutcome::Finished,
                1 => ResultOutcome::Failed,
                _ => {
                    return Err(PaidWorkError::Mismatch {
                        field: "result outcome",
                    });
                }
            },
            transcript_content: hellas_rpc::ContentRef::new(
                ContentId::from_bytes(reader.bytes32()?),
                reader.u64()?,
            ),
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
    pub(crate) fn take<const N: usize>(&mut self) -> Result<[u8; N], PaidWorkError> {
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
pub fn xfh(domain: &[u8], fields: &[&[u8]]) -> Digest {
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

/// Maximum over every fixed-width funding record.
const WIDEST_RECORD: usize = {
    let widths = [
        PaidChannelPolicyV1::ENCODED_SIZE,
        JobPaymentPolicyV2::ENCODED_SIZE,
        PaidJobAuthorizationV2::ENCODED_SIZE,
        crate::model::grant::GrantJobAuthorizationV1::ENCODED_SIZE,
        PaidJobResultV1::ENCODED_SIZE,
        PaymentBindingV1::ENCODED_SIZE,
    ];
    let mut max = 0;
    let mut i = 0;
    while i < widths.len() {
        max = wider(max, widths[i]);
        i += 1;
    }
    max
};
const LONGEST_DOMAIN: usize = {
    let domains = [
        PAID_CHANNEL_POLICY,
        JOB_PAYMENT_POLICY,
        crate::model::grant::GRANT_JOB_AUTHORIZE,
        PAID_JOB_AUTHORIZE,
        PAID_JOB_RESULT,
        PAYMENT_BINDING,
    ];
    let mut max = 0;
    let mut i = 0;
    while i < domains.len() {
        max = wider(max, domains[i].len());
        i += 1;
    }
    max
};
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

    /// Returns the key that signs for the client: the payment edge
    /// maker's signer.
    pub const fn client_key(&self) -> Key {
        self.payment_terms.parties().maker().signer()
    }

    /// Returns the key that signs for the provider: the payment edge
    /// taker's signer.
    pub const fn provider_key(&self) -> Key {
        self.payment_terms.parties().taker().signer()
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

/// Returns the `work_id`: the digest both parties sign to accept a job.
pub fn work_id(channel: &PaidChannel, authorization: &PaidJobAuthorizationV2) -> Digest {
    paid_work_v2_id(channel.network(), channel.id(), authorization)
}

/// Returns the digest the provider signs to deliver a result.
pub fn result_digest(channel: &PaidChannel, result: &PaidJobResultV1) -> Digest {
    bound_result_digest(channel.network(), channel.id(), result)
}

/// The shared digest domain, bound to a funding-separated channel identity.
pub fn bound_result_digest(
    network: NetworkId,
    channel: Digest,
    result: &PaidJobResultV1,
) -> Digest {
    let network_bytes = EncodedNetwork::new(network);
    xh(
        PAID_JOB_RESULT,
        &[
            network_bytes.as_slice(),
            channel.as_bytes(),
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
    bound_delivery_request_digest(channel.network(), channel.id(), work_id, exporter)
}

/// The shared digest domain, bound to a funding-separated channel identity.
pub fn bound_delivery_request_digest(
    network: NetworkId,
    channel: Digest,
    work_id: Digest,
    exporter: &[u8; 32],
) -> Digest {
    let network_bytes = EncodedNetwork::new(network);
    xh(
        DELIVERY_REQUEST,
        &[
            network_bytes.as_slice(),
            channel.as_bytes(),
            work_id.as_bytes(),
            exporter,
        ],
    )
}

// ── Checks ────────────────────────────────────────────────────────────

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

/// Funding arithmetic shared by every paid invocation. Application admission
/// separately opens the signed policy and prepared-input commitments.
pub(crate) fn check_authorization_core(
    channel: &PaidChannel,
    authorization: &PaidJobAuthorizationV2,
    policy_digest: Digest,
    payment: &JobPaymentPolicyV2,
    finalized_height: u64,
) -> Result<Digest, PaidWorkError> {
    payment.check()?;
    let terms = channel.payment_terms();
    let expected = [
        (
            "channel_id",
            authorization.channel_id.as_bytes() == channel.id.as_bytes(),
        ),
        (
            "work_policy_digest",
            authorization.work_policy_digest.as_bytes() == policy_digest.as_bytes(),
        ),
        (
            "payment_policy_digest",
            authorization.payment_policy_digest
                == job_payment_policy_digest(channel.network(), channel.id(), payment),
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
    if authorization.price != payment.fixed_price {
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

// ── Carrying a transcript ─────────────────────────────────────────────

/// Canonical signed-envelope bytes named by the receipt's transcript reference.
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
    authorization: &PaidJobAuthorizationV2,
    result: &PaidJobResultV1,
    credited: u64,
    settlement: WorkPaymentSettlement,
) -> Result<(EarnedCertificate, PaymentBindingV1), PaidWorkError> {
    if result.outcome != ResultOutcome::Finished {
        return Err(PaidWorkError::Mismatch {
            field: "failed result is not payable",
        });
    }

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
        authorization: &PaidJobAuthorizationV2,
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

/// The price and block margins of payment-funded execution.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobPaymentPolicyV2 {
    /// Price of one accepted terminal result.
    pub fixed_price: u64,
    /// Acceptance-to-terminal budget in finalized blocks.
    pub dispatch_margin_blocks: u64,
    /// Result transfer budget in finalized blocks.
    pub delivery_margin_blocks: u64,
    /// Payment and admission budget in finalized blocks.
    pub oracle_grace_blocks: u64,
}
impl PrivateRecord for JobPaymentPolicyV2 {
    const TAG: u8 = tag::JOB_PAYMENT_POLICY_V2;
    const BODY_SIZE: usize = 4 * 8;
    fn encode_body(&self, out: &mut Vec<u8>) {
        put_u64(out, self.fixed_price);
        put_u64(out, self.dispatch_margin_blocks);
        put_u64(out, self.delivery_margin_blocks);
        put_u64(out, self.oracle_grace_blocks);
    }
    fn decode_body(reader: &mut BodyReader<'_>) -> Result<Self, PaidWorkError> {
        Ok(Self {
            fixed_price: reader.u64()?,
            dispatch_margin_blocks: reader.u64()?,
            delivery_margin_blocks: reader.u64()?,
            oracle_grace_blocks: reader.u64()?,
        })
    }
}
impl JobPaymentPolicyV2 {
    /// Rejects free jobs and zero-length payment windows.
    pub fn check(&self) -> Result<(), PaidWorkError> {
        for (field, value) in [
            ("fixed_price", self.fixed_price),
            ("dispatch_margin_blocks", self.dispatch_margin_blocks),
            ("delivery_margin_blocks", self.delivery_margin_blocks),
            ("oracle_grace_blocks", self.oracle_grace_blocks),
        ] {
            if value == 0 {
                return Err(PaidWorkError::PolicyZero { field });
            }
        }
        Ok(())
    }
    /// The three positive block margins in dispatch/delivery/oracle order.
    pub const fn margins(&self) -> (u64, u64, u64) {
        (
            self.dispatch_margin_blocks,
            self.delivery_margin_blocks,
            self.oracle_grace_blocks,
        )
    }
}

/// Network- and channel-bound payment terms digest.
pub fn job_payment_policy_digest(
    network: NetworkId,
    channel: Digest,
    policy: &JobPaymentPolicyV2,
) -> Digest {
    versioned_record_digest(JOB_PAYMENT_POLICY, network, channel, &policy.encode())
}

/// Checks the payment terms retained for an accepted job, without reapplying
/// its acceptance deadline during execution or delivery.
pub fn check_payment_policy_binding(
    channel: &PaidChannel,
    authorization: &PaidJobAuthorizationV2,
    payment: &JobPaymentPolicyV2,
) -> Result<(), PaidWorkError> {
    payment.check()?;
    if authorization.payment_policy_digest
        != job_payment_policy_digest(channel.network(), channel.id(), payment)
    {
        return Err(PaidWorkError::Mismatch {
            field: "payment_policy_digest",
        });
    }
    if authorization.price != payment.fixed_price {
        return Err(PaidWorkError::Mismatch { field: "price" });
    }
    Ok(())
}
/// The V2 work id signed by both payment parties.
pub fn paid_work_v2_id(
    network: NetworkId,
    channel: Digest,
    authorization: &PaidJobAuthorizationV2,
) -> Digest {
    versioned_record_digest(
        PAID_JOB_AUTHORIZE,
        network,
        channel,
        &authorization.encode(),
    )
}
pub(crate) fn versioned_record_digest(
    domain: &[u8],
    network: NetworkId,
    channel: Digest,
    bytes: &[u8],
) -> Digest {
    xh(
        domain,
        &[
            EncodedNetwork::new(network).as_slice(),
            channel.as_bytes(),
            bytes,
        ],
    )
}
