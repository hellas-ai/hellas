//! Canonical byte encoding and hash binding for kernel types.
//!
//! Every kernel value that participates in a hash commitment or that
//! gets stored at the chain boundary implements [`Encode`]. Values that
//! can also be reconstructed from canonical bytes additionally implement
//! [`Decode`]. Opaque hash newtypes ([`crate::CoinId`], [`crate::EdgeId`],
//! [`crate::TermsHash`], [`crate::PayloadHash`]) decode through their
//! `from_bytes` reconstitution paths; their canonical bytes remain the fixed
//! 32-byte commitment payload.
//!
//! Hash inputs and serialization inputs are unified. The bytes a value
//! emits via `encode_to` are *the* canonical bytes; commitments are
//! the Xet file hash of `domain ‖ encode_to(value)`. Round-tripping through
//! `encode_to` / `decode` preserves hash by construction.
//!
//! The encoding is hand-rolled byte concatenation in a documented order
//! per type. No allocator. No format negotiation. `MAX_ENCODED_SIZE` is
//! a compile-time bound per type so callers can stack-allocate buffers.
//!
//! Composite values start with a two-byte envelope: canonical format version
//! `1`, followed by a globally unique type tag. Tagged enums then carry a
//! third byte selecting the variant. Primitive integers and byte newtypes stay
//! fixed-width and untagged so they remain suitable as fields and hash inputs.

#![allow(clippy::redundant_pub_crate)]

use crate::primitive::Party;

pub(crate) const ENVELOPE_SIZE: usize = 2;
const FORMAT_VERSION: u8 = 1;

pub(crate) mod tag {
    pub(crate) const BLOCK_HEIGHT: u8 = 1;
    pub(crate) const FEES: u8 = 2;
    pub(crate) const PARTIES: u8 = 3;
    pub(crate) const COIN: u8 = 4;
    pub(crate) const EDGE: u8 = 5;
    pub(crate) const FUNDING: u8 = 6;
    pub(crate) const PAYOUT: u8 = 7;
    // 8 was the standalone dispute seal. Deleted with the external
    // violation close; the byte is an ordinary rejection.
    pub(crate) const WEBAUTHN_ASSERTION: u8 = 9;
    pub(crate) const AUTH: u8 = 10;
    pub(crate) const TERMS: u8 = 11;
    pub(crate) const PROOF: u8 = 12;
    pub(crate) const TX: u8 = 13;
    // Tag numbers are fixed consensus assignments, not the next free
    // slot: the gaps below are reserved and must not be filled in.
    pub(crate) const EARNED_CERTIFICATE: u8 = 20;
    pub(crate) const PAYMENT_CLOSE_START: u8 = 21;
    pub(crate) const PAYMENT_CLOSE_RESPONSE: u8 = 22;
    pub(crate) const PAYMENT_CLOSE_PENDING: u8 = 23;
    pub(crate) const REGISTRY_CHUNK: u8 = 24;
    pub(crate) const BOND_LEASE: u8 = 31;
    pub(crate) const PARTY_AUTH: u8 = 32;
}

/// Streaming destination for [`Encode`] output.
///
/// Implemented for raw byte buffers and the allocation-free Xet single-chunk
/// hasher so one `encode_to` body drives serialization and hashing.
pub trait Writer {
    /// Appends `bytes` to the destination.
    fn write(&mut self, bytes: &[u8]);
}

impl Writer for hellas_xet::SingleChunkHasher {
    fn write(&mut self, bytes: &[u8]) {
        self.update(bytes);
    }
}

/// Streaming write of canonical bytes into a `&mut [u8]`.
///
/// The buffer must be at least `value.encoded_size()` bytes for every
/// value the writer consumes; smaller buffers panic on the first
/// [`Writer::write`] that exceeds capacity. This is a programming-error
/// contract: every [`Encode`] type self-reports `encoded_size()`, so
/// callers can size the buffer exactly. The kernel does not offer a
/// fallible variant — undersized buffers indicate a caller bug, not a
/// runtime condition.
#[derive(Debug)]
pub struct BufferWriter<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> BufferWriter<'a> {
    /// Wraps a byte slice for streaming writes starting at offset 0.
    ///
    /// The slice must be sized to hold the full encoding the caller
    /// intends to write. See the type-level documentation on
    /// [`BufferWriter`] for the precondition contract.
    #[must_use]
    pub const fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Returns the number of bytes written so far.
    #[must_use]
    pub const fn position(&self) -> usize {
        self.pos
    }
}

impl Writer for BufferWriter<'_> {
    /// Appends `bytes` at the current write position.
    ///
    /// # Panics
    ///
    /// Panics if `bytes.len()` would exceed the remaining buffer
    /// capacity (`self.buf.len() - self.pos`). This indicates the
    /// caller sized the buffer below the value's `encoded_size()` —
    /// a programming error.
    #[allow(
        clippy::indexing_slicing,
        reason = "undersized buffers are a documented caller bug; panicking here is the contract"
    )]
    fn write(&mut self, bytes: &[u8]) {
        let end = self.pos + bytes.len();
        self.buf[self.pos..end].copy_from_slice(bytes);
        self.pos = end;
    }
}

/// Canonical byte encoding of a kernel value.
///
/// The bytes emitted by `encode_to` are the protocol commitment input.
/// `MAX_ENCODED_SIZE` is the compile-time upper bound (which equals
/// `encoded_size()` for fixed-shape types).
pub trait Encode {
    /// Maximum number of bytes any value of this type emits.
    const MAX_ENCODED_SIZE: usize;

    /// Actual number of bytes this value emits.
    fn encoded_size(&self) -> usize;

    /// Streams the canonical byte representation.
    fn encode_to<W: Writer + ?Sized>(&self, writer: &mut W);

    /// Writes the canonical byte representation into a slice.
    ///
    /// `buf` must be at least [`Self::MAX_ENCODED_SIZE`] bytes long.
    ///
    /// Returns the number of bytes written. Default impl uses
    /// [`BufferWriter`].
    fn write_to(&self, buf: &mut [u8]) -> usize {
        let mut writer = BufferWriter::new(buf);
        self.encode_to(&mut writer);
        writer.position()
    }
}

/// Canonical byte decoding of a kernel value.
///
/// Returns the decoded value plus the number of bytes consumed. Nested
/// decoders advance `buf = &buf[consumed..]` for the next field.
pub trait Decode: Sized {
    /// Parses a canonical byte representation.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError`] when the input bytes are malformed (too
    /// short, invalid variant tag, list length exceeds the type bound).
    fn decode(buf: &[u8]) -> Result<(Self, usize), DecodeError>;

    /// Parses one complete canonical value and rejects trailing bytes.
    ///
    /// Nested codecs use [`Self::decode`] so they can continue with later
    /// fields. Chain and persistence boundaries should use `decode_exact` so
    /// alternate encodings cannot hide data after an otherwise valid value.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError`] when decoding fails or when `buf` contains
    /// bytes after the decoded value.
    fn decode_exact(buf: &[u8]) -> Result<Self, DecodeError> {
        let (value, consumed) = Self::decode(buf)?;
        match buf.len().checked_sub(consumed) {
            Some(0) => Ok(value),
            Some(remaining) => Err(DecodeError::TrailingBytes { remaining }),
            None => Err(DecodeError::InvalidConsumption {
                consumed,
                available: buf.len(),
            }),
        }
    }
}

/// Reason a [`Decode`] attempt failed.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub enum DecodeError {
    /// Input ended before the decoder had enough bytes.
    InsufficientBytes {
        /// Bytes the decoder needed.
        needed: usize,
        /// Bytes the decoder saw.
        got: usize,
    },
    /// Format version, type tag, or variant tag is not recognized here.
    InvalidTag {
        /// Unrecognized tag byte.
        tag: u8,
    },
    /// List length prefix exceeded the type's compile-time capacity.
    InvalidLength {
        /// Length the input declared.
        got: usize,
        /// Maximum the type permits.
        max: usize,
    },
    /// A nested decoder reported consuming more bytes than were available.
    InvalidConsumption {
        /// Bytes the nested decoder reported consuming.
        consumed: usize,
        /// Bytes available to that decoder.
        available: usize,
    },
    /// A complete-value decoder found bytes after the canonical value.
    TrailingBytes {
        /// Number of unconsumed bytes.
        remaining: usize,
    },
    /// Every byte parsed, but the parsed fields are not the one canonical
    /// encoding of any value: a derived field disagrees with the field it
    /// is derived from, or declared-dead bytes are not zero. Accepting
    /// such an input would give one state two byte representations.
    NonCanonical {
        /// Name of the field whose canonical rule the input broke.
        field: &'static str,
    },
}

pub(crate) fn encode_envelope<W: Writer + ?Sized>(writer: &mut W, type_tag: u8) {
    writer.write(&[FORMAT_VERSION, type_tag]);
}

pub(crate) fn decode_envelope(buf: &[u8], expected_tag: u8) -> Result<usize, DecodeError> {
    let (header, consumed) = decode_fixed::<{ ENVELOPE_SIZE }>(buf)?;
    let version = header
        .first()
        .copied()
        .ok_or(DecodeError::InsufficientBytes {
            needed: ENVELOPE_SIZE,
            got: 0,
        })?;
    if version != FORMAT_VERSION {
        return Err(DecodeError::InvalidTag { tag: version });
    }
    let type_tag = header
        .get(1)
        .copied()
        .ok_or(DecodeError::InsufficientBytes {
            needed: ENVELOPE_SIZE,
            got: 1,
        })?;
    if type_tag != expected_tag {
        return Err(DecodeError::InvalidTag { tag: type_tag });
    }
    Ok(consumed)
}

/// Reads the type tag of the envelope at the head of `buf` without
/// consuming it.
///
/// For the one decoder that dispatches on the *nested* envelope rather
/// than on a variant byte: a `Tx::Move` body is a complete tagged
/// composite, so its tag is where the action kind lives and a second
/// action byte beside it would be a redundant encoding. The tag is only
/// peeked — the selected body still runs [`decode_envelope`], which is
/// what checks the format version and rejects a mismatch.
pub(crate) fn peek_envelope_tag(buf: &[u8]) -> Result<u8, DecodeError> {
    let (header, _) = decode_fixed::<{ ENVELOPE_SIZE }>(buf)?;
    header
        .get(1)
        .copied()
        .ok_or(DecodeError::InsufficientBytes {
            needed: ENVELOPE_SIZE,
            got: 1,
        })
}

pub(crate) fn decode_field<T: Decode>(buf: &[u8], consumed: &mut usize) -> Result<T, DecodeError> {
    let rest = buf
        .get(*consumed..)
        .ok_or(DecodeError::InvalidConsumption {
            consumed: *consumed,
            available: buf.len(),
        })?;
    let (value, field_consumed) = T::decode(rest)?;
    if field_consumed > rest.len() {
        return Err(DecodeError::InvalidConsumption {
            consumed: field_consumed,
            available: rest.len(),
        });
    }
    *consumed += field_consumed;
    Ok(value)
}

/// Reads `N` canonical bytes without allocating.
pub(crate) fn decode_fixed<const N: usize>(buf: &[u8]) -> Result<([u8; N], usize), DecodeError> {
    let Some(head) = buf.get(..N) else {
        return Err(DecodeError::InsufficientBytes {
            needed: N,
            got: buf.len(),
        });
    };
    let mut bytes = [0_u8; N];
    bytes.copy_from_slice(head);
    Ok((bytes, N))
}

// -- Xet commitment over canonical bytes -------------------------------------

/// Computes the canonical Xet commitment over `value`'s bytes with domain
/// separation.
///
/// All kernel commitments funnel through this function. The protocol
/// hash binding is the Xet file hash of `domain ‖ value.encode_to(...)`.
pub(crate) fn hash<T: Encode + ?Sized>(domain: &[u8], value: &T) -> hellas_xet::XetHash {
    let mut hasher = hellas_xet::SingleChunkHasher::new();
    hasher.update(domain);
    value.encode_to(&mut hasher);
    hasher.finalize()
}

// -- Primitive impls ---------------------------------------------------------

impl Encode for u8 {
    const MAX_ENCODED_SIZE: usize = 1;
    fn encoded_size(&self) -> usize {
        1
    }
    fn encode_to<W: Writer + ?Sized>(&self, writer: &mut W) {
        writer.write(&[*self]);
    }
}

impl Decode for u8 {
    fn decode(buf: &[u8]) -> Result<(Self, usize), DecodeError> {
        let byte = *buf.first().ok_or(DecodeError::InsufficientBytes {
            needed: 1,
            got: buf.len(),
        })?;
        Ok((byte, 1))
    }
}

impl<const N: usize> Encode for [u8; N] {
    const MAX_ENCODED_SIZE: usize = N;

    fn encoded_size(&self) -> usize {
        N
    }

    fn encode_to<W: Writer + ?Sized>(&self, writer: &mut W) {
        writer.write(self);
    }
}

impl<const N: usize> Decode for [u8; N] {
    fn decode(buf: &[u8]) -> Result<(Self, usize), DecodeError> {
        decode_fixed(buf)
    }
}

impl Encode for u16 {
    const MAX_ENCODED_SIZE: usize = 2;
    fn encoded_size(&self) -> usize {
        2
    }
    fn encode_to<W: Writer + ?Sized>(&self, writer: &mut W) {
        writer.write(&self.to_be_bytes());
    }
}

impl Decode for u16 {
    fn decode(buf: &[u8]) -> Result<(Self, usize), DecodeError> {
        let Some(head) = buf.get(..2) else {
            return Err(DecodeError::InsufficientBytes {
                needed: 2,
                got: buf.len(),
            });
        };
        let mut bytes = [0_u8; 2];
        bytes.copy_from_slice(head);
        Ok((Self::from_be_bytes(bytes), 2))
    }
}

impl Encode for u32 {
    const MAX_ENCODED_SIZE: usize = 4;
    fn encoded_size(&self) -> usize {
        4
    }
    fn encode_to<W: Writer + ?Sized>(&self, writer: &mut W) {
        writer.write(&self.to_be_bytes());
    }
}

impl Decode for u32 {
    fn decode(buf: &[u8]) -> Result<(Self, usize), DecodeError> {
        let Some(head) = buf.get(..4) else {
            return Err(DecodeError::InsufficientBytes {
                needed: 4,
                got: buf.len(),
            });
        };
        let mut bytes = [0_u8; 4];
        bytes.copy_from_slice(head);
        Ok((Self::from_be_bytes(bytes), 4))
    }
}

impl Encode for u64 {
    const MAX_ENCODED_SIZE: usize = 8;
    fn encoded_size(&self) -> usize {
        8
    }
    fn encode_to<W: Writer + ?Sized>(&self, writer: &mut W) {
        writer.write(&self.to_be_bytes());
    }
}

impl Decode for u64 {
    fn decode(buf: &[u8]) -> Result<(Self, usize), DecodeError> {
        let Some(head) = buf.get(..8) else {
            return Err(DecodeError::InsufficientBytes {
                needed: 8,
                got: buf.len(),
            });
        };
        let mut bytes = [0_u8; 8];
        bytes.copy_from_slice(head);
        Ok((Self::from_be_bytes(bytes), 8))
    }
}

// `usize` is encoded as `u64 big-endian`. The kernel's bounded lists
// fit easily in `u32`, but we use `u64` to keep cross-platform hashes
// stable and to match the historical `Digest::usize` encoding so the
// protocol commitment stays the same across this refactor.
// `Self` in these signatures IS `usize` (clippy::use_self insists on the
// keyword); read `MAX_ENCODED_SIZE: Self` as `: usize`.
impl Encode for usize {
    const MAX_ENCODED_SIZE: Self = 8;
    fn encoded_size(&self) -> Self {
        8
    }
    fn encode_to<W: Writer + ?Sized>(&self, writer: &mut W) {
        let as_u64 = u64::try_from(*self).unwrap_or(u64::MAX);
        writer.write(&as_u64.to_be_bytes());
    }
}

impl Decode for usize {
    fn decode(buf: &[u8]) -> Result<(Self, usize), DecodeError> {
        let (value, consumed) = u64::decode(buf)?;
        // On 64-bit platforms (the only ones we target) this fits.
        let as_usize = Self::try_from(value).unwrap_or(Self::MAX);
        Ok((as_usize, consumed))
    }
}

// -- Party (1-byte tag) ------------------------------------------------------

impl Encode for Party {
    const MAX_ENCODED_SIZE: usize = 1;
    fn encoded_size(&self) -> usize {
        1
    }
    fn encode_to<W: Writer + ?Sized>(&self, writer: &mut W) {
        writer.write(&[self.tag()]);
    }
}

impl Decode for Party {
    fn decode(buf: &[u8]) -> Result<(Self, usize), DecodeError> {
        let (byte, consumed) = u8::decode(buf)?;
        Self::from_tag(byte)
            .map(|party| (party, consumed))
            .ok_or(DecodeError::InvalidTag { tag: byte })
    }
}

// -- Option<T> (presence byte) ----------------------------------------------
// An optional field is one presence byte, then the value only when it is
// present. Absence writes nothing after its byte, so an absent value has
// exactly one encoding and can never be read as a present all-zero one.

const ABSENT: u8 = 0;
const PRESENT: u8 = 1;

impl<T: Encode> Encode for Option<T> {
    const MAX_ENCODED_SIZE: usize = u8::MAX_ENCODED_SIZE + T::MAX_ENCODED_SIZE;

    fn encoded_size(&self) -> usize {
        u8::MAX_ENCODED_SIZE + self.as_ref().map_or(0, Encode::encoded_size)
    }

    fn encode_to<W: Writer + ?Sized>(&self, writer: &mut W) {
        match self {
            None => ABSENT.encode_to(writer),
            Some(value) => {
                PRESENT.encode_to(writer);
                value.encode_to(writer);
            }
        }
    }
}

impl<T: Decode> Decode for Option<T> {
    fn decode(buf: &[u8]) -> Result<(Self, usize), DecodeError> {
        let mut consumed = 0;
        match decode_field::<u8>(buf, &mut consumed)? {
            ABSENT => Ok((None, consumed)),
            PRESENT => {
                let value = decode_field(buf, &mut consumed)?;
                Ok((Some(value), consumed))
            }
            tag => Err(DecodeError::InvalidTag { tag }),
        }
    }
}

// -- List<T, N> blanket impls -------------------------------------------------
// List is encoded as `<len: usize big-endian> ‖ <entries...>` where each
// entry uses its own canonical encoding. `MAX_ENCODED_SIZE` reserves the
// max-length case; `encoded_size()` reports the actual size for the
// current live length.

impl<T: Encode, const N: usize> Encode for crate::List<T, N> {
    const MAX_ENCODED_SIZE: usize = <usize as Encode>::MAX_ENCODED_SIZE + N * T::MAX_ENCODED_SIZE;

    fn encoded_size(&self) -> usize {
        let mut size = <usize as Encode>::MAX_ENCODED_SIZE;
        for item in self {
            size += item.encoded_size();
        }
        size
    }

    fn encode_to<W: Writer + ?Sized>(&self, writer: &mut W) {
        self.len().encode_to(writer);
        for item in self {
            item.encode_to(writer);
        }
    }
}

impl<T: Decode + Copy + Default, const N: usize> Decode for crate::List<T, N> {
    fn decode(buf: &[u8]) -> Result<(Self, usize), DecodeError> {
        let (len, mut consumed) = usize::decode(buf)?;
        if len > N {
            return Err(DecodeError::InvalidLength { got: len, max: N });
        }
        let mut items = [T::default(); N];
        for slot in items.iter_mut().take(len) {
            *slot = decode_field(buf, &mut consumed)?;
        }
        // Type bound: `len <= N`, so `List::take` is exact.
        Ok((Self::take(items, len), consumed))
    }
}

#[cfg(test)]
mod tests {
    use super::Encode;
    use crate::consts::{
        CLOSE, COIN_GENESIS, COIN_PAYOUT, EDGE_OPEN, ID_LENGTH, MAX_EDGE_OUTPUTS, MAX_PARTY_INPUTS,
        OPEN, REGISTRY_CHUNK_ID, SIG_PLACEHOLDER, TERMS_BASIC, TERMS_WORK_PAYMENT,
        TERMS_WORK_STAKE_BOND,
    };
    use crate::{CoinId, EdgeId, Key, List, NetworkId, PayloadHash, Payout, Terms, TermsHash};

    #[test]
    fn every_commitment_preimage_fits_one_xet_chunk() {
        let lengths = [
            COIN_GENESIS.len() + u32::MAX_ENCODED_SIZE,
            COIN_PAYOUT.len()
                + EdgeId::MAX_ENCODED_SIZE
                + usize::MAX_ENCODED_SIZE
                + Key::MAX_ENCODED_SIZE,
            EDGE_OPEN.len()
                + TermsHash::MAX_ENCODED_SIZE
                + 2 * <List<CoinId, MAX_PARTY_INPUTS>>::MAX_ENCODED_SIZE,
            // Terms decode recomputes this hash, so a body wide enough
            // to reach the chunk bound would be a remotely triggered
            // halt in a kernel that cannot unwind. Every domain is
            // measured against the *widest* body, not its own.
            TERMS_BASIC.len() + Terms::MAX_ENCODED_SIZE,
            TERMS_WORK_PAYMENT.len() + Terms::MAX_ENCODED_SIZE,
            TERMS_WORK_STAKE_BOND.len() + Terms::MAX_ENCODED_SIZE,
            OPEN.len() + EdgeId::MAX_ENCODED_SIZE,
            CLOSE.len()
                + EdgeId::MAX_ENCODED_SIZE
                + u8::MAX_ENCODED_SIZE
                + TermsHash::MAX_ENCODED_SIZE
                + <List<Payout, MAX_EDGE_OUTPUTS>>::MAX_ENCODED_SIZE,
            SIG_PLACEHOLDER.len()
                + u8::MAX_ENCODED_SIZE
                + Key::MAX_ENCODED_SIZE
                + PayloadHash::MAX_ENCODED_SIZE,
            REGISTRY_CHUNK_ID.len()
                + NetworkId::MAX_ENCODED_SIZE
                + u8::MAX_ENCODED_SIZE
                + ID_LENGTH
                + u8::MAX_ENCODED_SIZE,
        ];
        assert!(
            lengths
                .into_iter()
                .all(|length| length < hellas_xet::MIN_CHUNK_SIZE)
        );
    }
}

/// A cursor over one record's canonical bytes.
#[derive(Debug)]
pub struct Cursor<'a> {
    bytes: &'a [u8],
}

impl<'a> Cursor<'a> {
    /// Starts a cursor at the beginning of `bytes`.
    #[must_use]
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    /// Returns whether every byte has been read.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Takes one byte.
    pub fn byte(&mut self) -> Option<u8> {
        let (head, rest) = self.bytes.split_first()?;
        self.bytes = rest;
        Some(*head)
    }

    /// Takes exactly `len` bytes.
    pub fn take(&mut self, len: usize) -> Option<&'a [u8]> {
        let (head, rest) = self.bytes.split_at_checked(len)?;
        self.bytes = rest;
        Some(head)
    }

    /// Takes a fixed-width array.
    pub fn array<const N: usize>(&mut self) -> Option<[u8; N]> {
        let head = self.take(N)?;
        let mut out = [0_u8; N];
        out.copy_from_slice(head);
        Some(out)
    }

    /// Takes one big-endian `u64`.
    pub fn u64(&mut self) -> Option<u64> {
        self.array::<8>().map(u64::from_be_bytes)
    }

    /// Takes every remaining byte.
    ///
    /// Only legal as a record's last field, where "the rest" and "a
    /// length-prefixed body" are the same bytes and the prefix would be
    /// a second, disagreeable spelling of the record's own length.
    pub const fn rest(&mut self) -> &'a [u8] {
        let all = self.bytes;
        self.bytes = &[];
        all
    }
}

impl Cursor<'_> {
    /// Reads one kernel value and advances by its decoded size.
    pub fn field<T: Decode>(&mut self) -> Option<T> {
        let (value, consumed) = T::decode(self.bytes).ok()?;
        self.bytes = self.bytes.get(consumed..)?;
        Some(value)
    }

    /// Reads the length-prefixed network name used in Work records.
    pub fn network(&mut self) -> Option<crate::NetworkId> {
        let len = usize::from(self.byte()?);
        let name = core::str::from_utf8(self.take(len)?).ok()?;
        crate::NetworkId::new(name)
    }
}
