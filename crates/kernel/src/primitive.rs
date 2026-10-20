//! Byte-level primitives: settlement keys, object identifiers, protocol tags.
//!
//! No direct abstract counterpart — the model addresses objects by tagged
//! identifiers (`MakerCoin`, `Edge1`, …) declared in `models/types.qnt`.
//! These byte newtypes are the kernel's concrete realization of those
//! abstract tags; structural invariants come from how they are used in
//! [`crate::object`] and [`crate::op`].
//!
//! # Hash newtype discipline
//!
//! Two categories of 32-byte newtypes live here:
//!
//! - **Object identifiers** ([`CoinId`], [`EdgeId`]). These routinely
//!   enter the kernel from observed bytes — genesis allocations, MMR
//!   reads, RPC payloads. Both implement [`Encode`] + [`Decode`] (where
//!   applicable) and have a public `from_bytes` constructor. The
//!   integrity story is at the *derivation site*: the kernel's
//!   `CoinId::genesis`/`CoinId::payout`/`Tx::edge_id_of` helpers are the
//!   canonical ways to produce *fresh* ids.
//! - **Cryptographic commitments** ([`TermsHash`], [`PayloadHash`]).
//!   These are pure derived outputs of `Terms::hash()`,
//!   `Tx::open_hash`, and `Tx::payload_hash`. They implement [`Encode`] only — you can
//!   serialize a commitment you hold, you cannot deserialize one in
//!   isolation. The `pub(crate) from_bytes` constructor is reserved for
//!   the kernel's own round-trip decoders on object types containing
//!   one of these commitments as a field.

use core::fmt;
use hellas_xet::{SingleChunkHasher, XetHash};

use crate::canonical::{Decode, DecodeError, Encode, Writer, decode_fixed};
use crate::consts::{HASH_LENGTH, ID_LENGTH, KEY_LENGTH, SIG_LENGTH};

/// Settlement public key controlling owner-only objects.
#[derive(Debug, Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Key([u8; Self::LENGTH]);

impl Default for Key {
    fn default() -> Self {
        Self([0; Self::LENGTH])
    }
}

impl Key {
    /// Encoded length of a compressed settlement key.
    pub const LENGTH: usize = KEY_LENGTH;

    /// Creates a settlement key from canonical bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; Self::LENGTH]) -> Self {
        Self(bytes)
    }

    /// Returns the canonical byte representation.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; Self::LENGTH] {
        self.0
    }

    /// Borrows the canonical byte representation.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::LENGTH] {
        &self.0
    }
}

impl Encode for Key {
    const MAX_ENCODED_SIZE: usize = Self::LENGTH;
    fn encoded_size(&self) -> usize {
        Self::LENGTH
    }
    fn encode_to<W: Writer + ?Sized>(&self, writer: &mut W) {
        writer.write(&self.0);
    }
}

impl Decode for Key {
    fn decode(buf: &[u8]) -> Result<(Self, usize), DecodeError> {
        decode_fixed::<{ Self::LENGTH }>(buf).map(|(bytes, n)| (Self(bytes), n))
    }
}

/// Stable identifier for a coin object.
///
/// Coin ids are derived as `H(coin_tag ‖ ...)`. Their byte representation
/// cannot collide with that of an [`EdgeId`] under this domain separation.
#[derive(Debug, Clone, Copy, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CoinId(XetHash);

impl CoinId {
    /// Encoded length of a coin identifier.
    pub const LENGTH: usize = ID_LENGTH;

    pub(crate) const ZERO: Self = Self(XetHash::ZERO);

    /// Reconstructs a coin id from canonical bytes.
    ///
    /// `CoinId` is an *object identifier* — it routinely enters the
    /// kernel from observed bytes (genesis allocation, MMR reads, RPC
    /// payloads). Public `from_bytes` is therefore legitimate; the
    /// integrity discipline that applies here is the kernel's
    /// canonical derivation helpers ([`Self::genesis`], `Self::payout`)
    /// for producing fresh ids.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; Self::LENGTH]) -> Self {
        Self(XetHash::from_bytes(bytes))
    }

    /// Returns the canonical byte representation.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; Self::LENGTH] {
        self.0.into_bytes()
    }

    /// Borrows the canonical byte representation.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::LENGTH] {
        self.0.as_bytes()
    }

    /// Derives the canonical id for a genesis coin allocation.
    ///
    /// Genesis coins are produced at chain bootstrap; the kernel commits
    /// to a deterministic id derived from the allocation index. Callers
    /// (e.g. consensus configuration) supply indices and the kernel
    /// returns the canonical ids.
    #[must_use]
    pub fn genesis(index: u32) -> Self {
        Self(crate::canonical::hash(crate::consts::COIN_GENESIS, &index))
    }

    /// Derives one coin issued by a consuming owner reshape.
    #[must_use]
    pub fn reshape(
        network: crate::NetworkId,
        inputs: &crate::List<Self, { crate::MAX_EDGE_INPUTS }>,
        index: usize,
        owner: Key,
    ) -> Self {
        let mut hasher = SingleChunkHasher::new();
        hasher.update(crate::consts::COIN_RESHAPE);
        network.encode_to(&mut hasher);
        inputs.encode_to(&mut hasher);
        index.encode_to(&mut hasher);
        owner.encode_to(&mut hasher);
        Self(hasher.finalize())
    }

    /// Derives the canonical id for one close payout coin.
    ///
    /// The delegate the coin carries is not in the preimage: the edge
    /// and the position already make the id unique, and one close pays
    /// each position exactly once.
    pub(crate) fn payout(edge: EdgeId, index: usize, owner: Key) -> Self {
        let mut hasher = SingleChunkHasher::new();
        hasher.update(crate::consts::COIN_PAYOUT);
        edge.encode_to(&mut hasher);
        index.encode_to(&mut hasher);
        owner.encode_to(&mut hasher);
        Self(hasher.finalize())
    }
}

impl Encode for CoinId {
    const MAX_ENCODED_SIZE: usize = Self::LENGTH;
    fn encoded_size(&self) -> usize {
        Self::LENGTH
    }
    fn encode_to<W: Writer + ?Sized>(&self, writer: &mut W) {
        writer.write(self.0.as_bytes());
    }
}

impl Decode for CoinId {
    fn decode(buf: &[u8]) -> Result<(Self, usize), DecodeError> {
        decode_fixed::<{ Self::LENGTH }>(buf).map(|(bytes, n)| (Self::from_bytes(bytes), n))
    }
}

/// Stable identifier for an edge object.
///
/// Edge ids are derived as `H(edge_tag ‖ ...)`. Their byte representation
/// cannot collide with that of a [`CoinId`] under this domain separation.
#[derive(Debug, Clone, Copy, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EdgeId(XetHash);

impl EdgeId {
    /// Encoded length of an edge identifier.
    pub const LENGTH: usize = ID_LENGTH;

    /// Reconstructs an edge id from canonical bytes.
    ///
    /// `EdgeId` is an *object identifier* — it routinely enters the
    /// kernel from observed bytes (MMR reads, RPC payloads). Public
    /// `from_bytes` is legitimate; the integrity discipline is at the
    /// kernel's canonical derivation site (`Tx::edge_id_of`).
    #[must_use]
    pub const fn from_bytes(bytes: [u8; Self::LENGTH]) -> Self {
        Self(XetHash::from_bytes(bytes))
    }

    /// Returns the canonical byte representation.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; Self::LENGTH] {
        self.0.into_bytes()
    }

    /// Borrows the canonical byte representation.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::LENGTH] {
        self.0.as_bytes()
    }
}

impl Encode for EdgeId {
    const MAX_ENCODED_SIZE: usize = Self::LENGTH;
    fn encoded_size(&self) -> usize {
        Self::LENGTH
    }
    fn encode_to<W: Writer + ?Sized>(&self, writer: &mut W) {
        writer.write(self.0.as_bytes());
    }
}

impl Decode for EdgeId {
    fn decode(buf: &[u8]) -> Result<(Self, usize), DecodeError> {
        decode_fixed::<{ Self::LENGTH }>(buf).map(|(bytes, n)| (Self::from_bytes(bytes), n))
    }
}

/// Commitment to the open terms of an edge.
#[derive(Debug, Clone, Copy, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TermsHash(XetHash);

impl TermsHash {
    /// Encoded length of a terms commitment.
    pub const LENGTH: usize = HASH_LENGTH;

    /// Reconstructs a terms commitment from canonical bytes.
    ///
    /// Public because terms commitments legitimately cross protocol
    /// boundaries (job acceptances name a bond's terms by hash) — the
    /// kernel still only honors a commitment that matches a live
    /// edge's committed hash, so a forged value cannot authorize
    /// anything. Contrast [`CoinId::from_bytes`], which stays private
    /// because ids are derived, never received.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; Self::LENGTH]) -> Self {
        Self(XetHash::from_bytes(bytes))
    }

    /// Returns the canonical byte representation.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; Self::LENGTH] {
        self.0.into_bytes()
    }

    /// Borrows the canonical byte representation.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::LENGTH] {
        self.0.as_bytes()
    }
}

impl Encode for TermsHash {
    const MAX_ENCODED_SIZE: usize = Self::LENGTH;
    fn encoded_size(&self) -> usize {
        Self::LENGTH
    }
    fn encode_to<W: Writer + ?Sized>(&self, writer: &mut W) {
        writer.write(self.0.as_bytes());
    }
}

impl Decode for TermsHash {
    fn decode(buf: &[u8]) -> Result<(Self, usize), DecodeError> {
        decode_fixed::<{ Self::LENGTH }>(buf).map(|(bytes, n)| (Self::from_bytes(bytes), n))
    }
}

/// Commitment to one concrete transaction authorization payload.
#[derive(Debug, Clone, Copy, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PayloadHash(XetHash);

impl PayloadHash {
    /// Encoded length of a payload commitment.
    pub const LENGTH: usize = HASH_LENGTH;

    /// Builds a payload commitment from raw digest bytes.
    ///
    /// Public, unlike the state-object id constructors: a payload hash
    /// is a *message* commitment, not a store-integrity identifier.
    /// Protocol layers define their own domain-separated payloads
    /// (e.g. job acceptance/result contexts) and sign them with the
    /// same kernel signer machinery. Forging one buys nothing — a
    /// signature only ever attests to the hash that was signed.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; Self::LENGTH]) -> Self {
        Self(XetHash::from_bytes(bytes))
    }

    /// Returns the canonical byte representation.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; Self::LENGTH] {
        self.0.into_bytes()
    }

    /// Borrows the canonical byte representation.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::LENGTH] {
        self.0.as_bytes()
    }
}

impl Encode for PayloadHash {
    const MAX_ENCODED_SIZE: usize = Self::LENGTH;
    fn encoded_size(&self) -> usize {
        Self::LENGTH
    }
    fn encode_to<W: Writer + ?Sized>(&self, writer: &mut W) {
        writer.write(self.0.as_bytes());
    }
}

impl Decode for PayloadHash {
    fn decode(buf: &[u8]) -> Result<(Self, usize), DecodeError> {
        decode_fixed::<{ Self::LENGTH }>(buf).map(|(bytes, n)| (Self::from_bytes(bytes), n))
    }
}

/// Compact settlement signature bytes.
#[derive(Debug, Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Sig([u8; Self::LENGTH]);

impl Default for Sig {
    fn default() -> Self {
        Self([0; Self::LENGTH])
    }
}

impl Sig {
    /// Encoded length of a compact settlement signature.
    pub const LENGTH: usize = SIG_LENGTH;

    /// Creates a settlement signature from canonical bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; Self::LENGTH]) -> Self {
        Self(bytes)
    }

    /// Returns the canonical byte representation.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; Self::LENGTH] {
        self.0
    }

    /// Borrows the canonical byte representation.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::LENGTH] {
        &self.0
    }

    /// Creates a deterministic signature placeholder for modelling.
    ///
    /// This is forgeable and not a cryptographic signature. Whether the kernel
    /// accepts this shape is decided by the [`crate::SigVerifier`] passed at
    /// apply time. Gated behind the `placeholders` feature so production
    /// builds cannot construct one.
    #[cfg(any(test, feature = "placeholders"))]
    #[must_use]
    pub fn placeholder(key: Key, hash: PayloadHash) -> Self {
        let mut out = [0_u8; Self::LENGTH];
        let (first_half, second_half) = out.split_at_mut(PayloadHash::LENGTH);
        first_half.copy_from_slice(&Self::half(key, hash, 0));
        second_half.copy_from_slice(&Self::half(key, hash, 1));

        Self(out)
    }

    #[cfg(any(test, feature = "placeholders"))]
    fn half(key: Key, hash: PayloadHash, index: u8) -> [u8; PayloadHash::LENGTH] {
        let mut hasher = SingleChunkHasher::new();
        hasher.update(crate::consts::SIG_PLACEHOLDER);
        index.encode_to(&mut hasher);
        key.encode_to(&mut hasher);
        hash.encode_to(&mut hasher);
        hasher.finalize().into_bytes()
    }
}

impl Encode for Sig {
    const MAX_ENCODED_SIZE: usize = Self::LENGTH;
    fn encoded_size(&self) -> usize {
        Self::LENGTH
    }
    fn encode_to<W: Writer + ?Sized>(&self, writer: &mut W) {
        writer.write(&self.0);
    }
}

impl Decode for Sig {
    fn decode(buf: &[u8]) -> Result<(Self, usize), DecodeError> {
        decode_fixed::<{ Self::LENGTH }>(buf).map(|(bytes, n)| (Self(bytes), n))
    }
}

/// Compact chain-version-local protocol code.
///
/// A deployment's own label on a [`crate::Terms::basic`] edge, carried in
/// the terms preimage and therefore in the edge id. No kernel rule reads
/// it: it separates one operator's Basic edges from another's, and that
/// separation is the whole of its behaviour. It has no meaning on the work-payment or work-stake bodies,
/// which do not carry it.
///
/// This is deliberately one byte in v1: protocol tags are scarce, governed hot
/// path identifiers. Widening it changes terms commitments and requires a chain
/// version boundary.
#[derive(Debug, Clone, Copy, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ProtocolCode(u8);

impl ProtocolCode {
    /// Creates a protocol code.
    #[must_use]
    pub const fn new(value: u8) -> Self {
        Self(value)
    }

    /// Returns the integer protocol code.
    #[must_use]
    pub const fn get(self) -> u8 {
        self.0
    }
}

impl Encode for ProtocolCode {
    const MAX_ENCODED_SIZE: usize = 1;
    fn encoded_size(&self) -> usize {
        1
    }
    fn encode_to<W: Writer + ?Sized>(&self, writer: &mut W) {
        self.0.encode_to(writer);
    }
}

impl Decode for ProtocolCode {
    fn decode(buf: &[u8]) -> Result<(Self, usize), DecodeError> {
        let (byte, n) = u8::decode(buf)?;
        Ok((Self(byte), n))
    }
}

/// Positional party in a v1 bilateral edge.
#[derive(Debug, Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Party {
    /// Party whose open intent or offer is being filled.
    Maker,

    /// Party that fills the maker's open intent or offer.
    Taker,
}

impl Party {
    /// Returns the canonical one-byte party tag.
    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            Self::Maker => 0,
            Self::Taker => 1,
        }
    }

    /// Decodes a canonical one-byte party tag.
    #[must_use]
    pub const fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            0 => Some(Self::Maker),
            1 => Some(Self::Taker),
            _ => None,
        }
    }

    /// Returns the keys `parties` commits for this position.
    ///
    /// The work-channel roles *are* these positions — on a payment edge
    /// the client is the maker and the provider is the taker — so one
    /// closed enum names the party behind every payment-close action, and
    /// a role that could not answer this question could not be checked.
    #[must_use]
    pub const fn keys_of(self, parties: crate::object::Parties) -> crate::object::PartyKeys {
        match self {
            Self::Maker => parties.maker(),
            Self::Taker => parties.taker(),
        }
    }
}

impl fmt::Display for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}
