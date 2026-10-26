//! Domain types used by the Hellas chain and light-client API.
//!
//! Every transaction the chain admits is a kernel transaction, and every
//! signature on one is checked inside the kernel. Nothing in this module
//! verifies a signature.

/// Digest used by chain-facing APIs.
pub use commonware_cryptography::sha256::Digest;

/// Decoding helper for domain types.
pub use commonware_codec::DecodeExt;
/// Encoding helper for domain types.
pub use commonware_codec::Encode;

use bytes::BytesMut;
use commonware_codec::{
    EncodeSize, Error as CodecError, FixedSize, RangeCfg, Read, ReadExt, Write,
};
/// Signing helper for domain key types.
pub use commonware_cryptography::Signer;
use commonware_cryptography::{Hasher, Sha256, ed25519};
use hellas_kernel::{
    Coin as KernelCoin, Decode as KernelDecode, Edge as KernelEdge, Encode as KernelEncode, Fees,
    Key as KernelKey, NetworkId, RegistryChunk as KernelRegistryChunk, Tx as KernelTx,
};

/// Validator public key.
pub type PublicKey = ed25519::PublicKey;
/// Validator private key.
pub type PrivateKey = ed25519::PrivateKey;
/// Object identifier in the chain state.
pub type ObjectId = Digest;

/// Raw compressed settlement key used for stored object ownership.
///
/// This type does not validate a curve. Both compressed P-256 and
/// compressed secp256k1 keys are 33-byte settlement keys, and the kernel
/// decides which one a witness is checked against.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SettlementKey(KernelKey);

impl SettlementKey {
    /// Raw encoded key length.
    pub const LENGTH: usize = KernelKey::LENGTH;

    /// Creates a settlement key without curve validation.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; Self::LENGTH]) -> Self {
        Self(KernelKey::from_bytes(bytes))
    }

    /// Returns the raw key bytes.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; Self::LENGTH] {
        self.0.to_bytes()
    }

    /// Borrows the raw key bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::LENGTH] {
        self.0.as_bytes()
    }

    /// Returns the kernel settlement key.
    #[must_use]
    pub const fn into_kernel(self) -> KernelKey {
        self.0
    }
}

impl From<KernelKey> for SettlementKey {
    fn from(key: KernelKey) -> Self {
        Self(key)
    }
}

impl From<SettlementKey> for KernelKey {
    fn from(key: SettlementKey) -> Self {
        key.0
    }
}

impl AsRef<[u8]> for SettlementKey {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl core::fmt::Display for SettlementKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&bs58::encode(self.as_bytes()).into_string())
    }
}

impl core::str::FromStr for SettlementKey {
    type Err = SettlementKeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = bs58::decode(s)
            .into_vec()
            .map_err(SettlementKeyError::Base58)?;
        let actual = bytes.len();
        let bytes: [u8; Self::LENGTH] = bytes
            .try_into()
            .map_err(|_| SettlementKeyError::InvalidLength { actual })?;
        Ok(Self::from_bytes(bytes))
    }
}

/// Settlement-key parsing error.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SettlementKeyError {
    /// Invalid base58 encoding.
    #[error("invalid base58: {0}")]
    Base58(bs58::decode::Error),
    /// The decoded key was not exactly 33 bytes.
    #[error("settlement key must be 33 bytes, got {actual}")]
    InvalidLength {
        /// Decoded byte length.
        actual: usize,
    },
}

impl FixedSize for SettlementKey {
    const SIZE: usize = Self::LENGTH;
}

impl Write for SettlementKey {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        buf.put_slice(self.as_bytes());
    }
}

impl Read for SettlementKey {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _cfg: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self::from_bytes(<[u8; Self::LENGTH]>::read(buf)?))
    }
}

/// Bounded array-backed list for chain wire payloads.
///
/// Local to this crate so the commonware codec impls below can live
/// beside the type (orphan rule); the chain wire format is independent
/// of the kernel's canonical encoding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bounded<T, const N: usize> {
    items: [T; N],
    len: usize,
}

impl<T, const N: usize> Bounded<T, N> {
    /// Creates a bounded list from a backing array and live length.
    #[must_use]
    pub fn new(items: [T; N], len: usize) -> Option<Self> {
        (len <= N).then_some(Self { items, len })
    }

    /// Borrows the live entries.
    ///
    /// Every constructor (including the codec `Read` impls) establishes
    /// `len <= N`.
    #[must_use]
    pub fn as_slice(&self) -> &[T] {
        &self.items[..self.len]
    }

    /// Returns the number of live entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns true when the list has no live entries. Kept as the
    /// pair `len` requires, not because a caller exists today.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Iterates over the live entries.
    pub fn iter(&self) -> core::slice::Iter<'_, T> {
        self.as_slice().iter()
    }
}

impl<'a, T, const N: usize> IntoIterator for &'a Bounded<T, N> {
    type Item = &'a T;
    type IntoIter = core::slice::Iter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.as_slice().iter()
    }
}

impl<T: Write, const N: usize> Write for Bounded<T, N> {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.as_slice().write(buf);
    }
}

impl<T: EncodeSize, const N: usize> EncodeSize for Bounded<T, N> {
    fn encode_size(&self) -> usize {
        self.as_slice().encode_size()
    }

    fn encode_inline_size(&self) -> usize {
        self.as_slice().encode_inline_size()
    }
}

impl<const N: usize> Read for Bounded<u8, N> {
    type Cfg = (RangeCfg<usize>, ());

    fn read_cfg(buf: &mut impl bytes::Buf, (range, _cfg): &Self::Cfg) -> Result<Self, CodecError> {
        let len = usize::read_cfg(buf, range)?;
        if len > N {
            return Err(CodecError::InvalidLength(len));
        }
        let mut items = [0_u8; N];
        for slot in items.iter_mut().take(len) {
            *slot = u8::read(buf)?;
        }
        Ok(Self { items, len })
    }
}

/// Threshold signature variant used by consensus.
#[cfg(feature = "domain-consensus")]
pub type ThresholdVariant = commonware_cryptography::bls12381::primitives::variant::MinPk;
/// Threshold signature share.
#[cfg(feature = "domain-consensus")]
pub type ThresholdShare = commonware_cryptography::bls12381::primitives::group::Share;
/// Threshold sharing polynomial.
#[cfg(feature = "domain-consensus")]
pub type ThresholdPolynomial =
    commonware_cryptography::bls12381::primitives::sharing::Sharing<ThresholdVariant>;
/// Consensus signing scheme.
#[cfg(feature = "domain-consensus")]
pub type Scheme = commonware_consensus::simplex::scheme::bls12381_threshold::vrf::Scheme<
    PublicKey,
    ThresholdVariant,
>;
/// Consensus context.
#[cfg(feature = "domain-consensus")]
pub type Context = commonware_consensus::simplex::types::Context<Digest, PublicKey>;
/// Consensus activity event.
#[cfg(feature = "domain-consensus")]
pub type Activity = commonware_consensus::simplex::types::Activity<Scheme, Digest>;

/// Maximum transactions per block.
pub const MAX_TXS_PER_BLOCK: usize = 256;
/// Maximum aggregate encoded transaction bytes admitted to one block.
///
/// This proposer-advisory budget leaves 256 KiB beneath the 1 MiB P2P message
/// ceiling for the block envelope, consensus metadata, and framing overhead.
/// The transport ceiling and [`MAX_TXS_PER_BLOCK`] are the consensus hard
/// bounds. Candidates that overflow this budget remain in the mempool.
pub const MAX_BLOCK_TX_BYTES: usize = 768 * 1024;
/// Consensus-critical kernel fee schedule compiled into the chain.
pub const KERNEL_FEES: Fees = Fees::ZERO;
/// Longest lifetime, in blocks, any edge may commit at open.
///
/// A stand-in for a bound the kernel already knows how to derive:
/// `open_lifetime_fee` prices `fees.lifetime * blocks` against the
/// open's funding, so with a real fee schedule an edge may live
/// exactly as long as it prepaid for. [`KERNEL_FEES`] is `Fees::ZERO`,
/// which makes that derivation charge nothing, so consensus caps the
/// span directly until a schedule is set. Delete this in favour of the
/// derived bound when it is.
pub const MAX_EDGE_LIFETIME_BLOCKS: u64 = 1_000_000;
/// Returns the deterministic object id for a genesis allocation.
#[must_use]
pub fn genesis_object_id(validator_index: u16) -> ObjectId {
    let mut buf = BytesMut::new();
    buf.extend_from_slice(b"hellas-genesis");
    validator_index.write(&mut buf);
    Sha256::hash(&buf)
}

/// Returns the chain object id for a kernel coin id.
#[must_use]
#[cfg(any(feature = "indexer", feature = "validator"))]
pub(crate) fn coin_object_id(id: hellas_kernel::CoinId) -> ObjectId {
    ObjectId::from(id.to_bytes())
}

/// Returns the chain object id for a kernel edge id.
#[must_use]
#[cfg(any(feature = "indexer", feature = "validator"))]
pub(crate) fn edge_object_id(id: hellas_kernel::EdgeId) -> ObjectId {
    ObjectId::from(id.to_bytes())
}

/// Returns the chain object id for a kernel registry chunk id.
///
/// Like the coin and edge helpers, this is the identity map: the kernel
/// already domain-separates the three derivations, so the chain does not
/// separate them a second time.
///
/// Validator-only, unlike its coin and edge siblings. Those two are also
/// read by the owner index, which an indexer builds; registry chunks are
/// consensus state that no owner owns, so nothing outside execution
/// addresses one.
#[must_use]
#[cfg(any(feature = "validator", feature = "full-node"))]
pub(crate) fn registry_chunk_object_id(id: hellas_kernel::RegistryChunkId) -> ObjectId {
    ObjectId::from(id.to_bytes())
}

/// A genesis document names a network id the kernel cannot carry.
#[derive(Debug, Clone, Eq, PartialEq, thiserror::Error)]
#[error("genesis network id `{0}` does not fit a kernel NetworkId")]
pub struct NetworkIdError(pub String);

/// The network id a loaded genesis document names.
///
/// The single conversion from "the document this node was started
/// with" to "the network every signature it makes is bound to". It
/// lives here rather than in `config`: reading a network off a document
/// is what every signer does, and only a validator reads a validator
/// config.
///
/// There is deliberately no compile-time default. A binary that
/// carries one silently re-domains every signature in the tree the
/// moment that constant moves, which is not hypothetical.
pub fn network_id(genesis: &crate::genesis::Genesis) -> Result<NetworkId, NetworkIdError> {
    NetworkId::new(&genesis.network_id).ok_or_else(|| NetworkIdError(genesis.network_id.clone()))
}

// --- Stored objects (gated) ---

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// Chain coin object.
pub struct Coin {
    /// Coin owner.
    pub owner: SettlementKey,
    /// The one other key that may spend this coin, and only to fund a
    /// work open or bond under its own signature.
    pub delegate: Option<SettlementKey>,
    /// Coin value.
    pub value: u64,
}

impl Coin {
    /// An undelegated coin.
    #[must_use]
    pub const fn owned(owner: SettlementKey, value: u64) -> Self {
        Self {
            owner,
            delegate: None,
            value,
        }
    }
}

impl From<KernelCoin> for Coin {
    fn from(coin: KernelCoin) -> Self {
        Self {
            owner: SettlementKey::from(coin.owner()),
            delegate: coin.delegate().map(SettlementKey::from),
            value: coin.value(),
        }
    }
}

impl From<Coin> for KernelCoin {
    fn from(coin: Coin) -> Self {
        Self::issue(
            coin.owner.into_kernel(),
            coin.delegate.map(SettlementKey::into_kernel),
            coin.value,
        )
    }
}

/// Kind of object stored in the chain's single object namespace.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObjectKind {
    /// Owner-controlled coin.
    Coin,
    /// Kernel settlement edge.
    Edge,
    /// Kernel registry chunk. Consensus state with no owner: it is
    /// authenticated by the same state root as coins and edges, but no
    /// party spends it and no owner index tracks it.
    RegistryChunk,
    /// Consensus owner-tree metadata.
    OwnerData,
}

impl core::fmt::Display for ObjectKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Coin => f.write_str("coin"),
            Self::Edge => f.write_str("edge"),
            Self::RegistryChunk => f.write_str("registry-chunk"),
            Self::OwnerData => f.write_str("owner-data"),
        }
    }
}

/// Object stored under a chain object id.
///
/// The commonware fixed-size representation is a one-byte kind followed by
/// the selected kernel canonical payload, then zero padding through the
/// maximum payload size. There is no independent chain encoding for either
/// arm.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Object {
    /// Coin payload.
    Coin(Coin),
    /// Edge payload.
    Edge(KernelEdge),
    /// Registry chunk payload.
    RegistryChunk(KernelRegistryChunk),
    /// Canonical owner-tree node bytes. Only consensus host code writes these records.
    OwnerData([u8; crate::owner_proof::OWNER_NODE_BYTES]),
}

/// The larger of two sizes, in a const context.
const fn larger(left: usize, right: usize) -> usize {
    if left > right { left } else { right }
}

impl Object {
    const COIN_TAG: u8 = 0;
    const EDGE_TAG: u8 = 1;
    const REGISTRY_CHUNK_TAG: u8 = 2;
    const OWNER_DATA_TAG: u8 = 3;

    /// Fixed payload area following the one-byte object-kind tag.
    ///
    /// Derived, never written down: every stored object is padded to the
    /// widest arm, so a literal here would silently truncate the moment
    /// a kernel payload grew past it.
    pub const PAYLOAD_SIZE: usize = larger(
        crate::owner_proof::OWNER_NODE_BYTES,
        larger(
            KernelCoin::MAX_ENCODED_SIZE,
            larger(
                KernelEdge::MAX_ENCODED_SIZE,
                KernelRegistryChunk::MAX_ENCODED_SIZE,
            ),
        ),
    );

    /// Returns the stored object's kind.
    #[must_use]
    pub const fn kind(&self) -> ObjectKind {
        match self {
            Self::Coin(_) => ObjectKind::Coin,
            Self::Edge(_) => ObjectKind::Edge,
            Self::RegistryChunk(_) => ObjectKind::RegistryChunk,
            Self::OwnerData(_) => ObjectKind::OwnerData,
        }
    }

    fn write_payload<T: KernelEncode>(value: &T, buf: &mut impl bytes::BufMut) {
        let mut payload = [0_u8; Self::PAYLOAD_SIZE];
        let written = value.write_to(&mut payload);
        debug_assert!(written <= Self::PAYLOAD_SIZE);
        buf.put_slice(&payload);
    }

    fn read_payload<T: KernelDecode>(payload: &[u8]) -> Result<T, CodecError> {
        let (value, consumed) = T::decode(payload)
            .map_err(|_| CodecError::Invalid("Object", "invalid kernel canonical payload"))?;
        let padding = payload.get(consumed..).ok_or(CodecError::Invalid(
            "Object",
            "invalid kernel decode length",
        ))?;
        if padding.iter().any(|byte| *byte != 0) {
            return Err(CodecError::Invalid(
                "Object",
                "non-zero canonical payload padding",
            ));
        }
        Ok(value)
    }
}

impl FixedSize for Object {
    const SIZE: usize = u8::SIZE + Self::PAYLOAD_SIZE;
}

impl Write for Object {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        match self {
            Self::Coin(coin) => {
                Self::COIN_TAG.write(buf);
                let kernel_coin = KernelCoin::from(*coin);
                Self::write_payload(&kernel_coin, buf);
            }
            Self::Edge(edge) => {
                Self::EDGE_TAG.write(buf);
                Self::write_payload(edge, buf);
            }
            Self::OwnerData(data) => {
                Self::OWNER_DATA_TAG.write(buf);
                let mut payload = [0_u8; Self::PAYLOAD_SIZE];
                payload[..crate::owner_proof::OWNER_NODE_BYTES].copy_from_slice(data);
                buf.put_slice(&payload);
            }
            Self::RegistryChunk(chunk) => {
                Self::REGISTRY_CHUNK_TAG.write(buf);
                Self::write_payload(chunk, buf);
            }
        }
    }
}

impl Read for Object {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _cfg: &Self::Cfg) -> Result<Self, CodecError> {
        let tag = u8::read(buf)?;
        let payload = <[u8; Self::PAYLOAD_SIZE]>::read(buf)?;
        match tag {
            Self::OWNER_DATA_TAG => {
                let (node, padding) = payload.split_at(crate::owner_proof::OWNER_NODE_BYTES);
                if padding.iter().any(|byte| *byte != 0) {
                    return Err(CodecError::Invalid("Object", "non-zero owner node padding"));
                }
                let mut data = [0_u8; crate::owner_proof::OWNER_NODE_BYTES];
                data.copy_from_slice(node);
                Ok(Self::OwnerData(data))
            }
            Self::COIN_TAG => {
                let coin = Self::read_payload::<KernelCoin>(&payload)?;
                Ok(Self::Coin(Coin::from(coin)))
            }
            Self::EDGE_TAG => Ok(Self::Edge(Self::read_payload::<KernelEdge>(&payload)?)),
            Self::REGISTRY_CHUNK_TAG => Ok(Self::RegistryChunk(Self::read_payload::<
                KernelRegistryChunk,
            >(&payload)?)),
            _ => Err(CodecError::InvalidEnum(tag)),
        }
    }
}

#[cfg(test)]
pub(crate) fn test_registry_chunk() -> KernelRegistryChunk {
    // Two chunks, so the stored chunk is a full one rather than the
    // easier remainder case.
    let value = [0x5a_u8; hellas_kernel::REGISTRY_CHUNK_DATA_CAPACITY + 3];
    hellas_kernel::RegistryChunk::split(
        hellas_kernel::RegistryNamespace::BondLease,
        hellas_kernel::RegistryRecordTag::BondLease,
        &value,
        0,
    )
    .expect("test value splits into two chunks")
}

#[cfg(test)]
pub(crate) fn test_edge() -> KernelEdge {
    let mut bytes = Vec::with_capacity(KernelEdge::MAX_ENCODED_SIZE);
    bytes.extend_from_slice(&[1, 5]);
    bytes.extend_from_slice(&100_u64.to_be_bytes());
    bytes.extend_from_slice(&10_u64.to_be_bytes());
    bytes.extend_from_slice(&[1, 2]);
    for value in [1_u64, 2, 3, 4] {
        bytes.extend_from_slice(&value.to_be_bytes());
    }
    bytes.extend_from_slice(&[1, 1]);
    bytes.extend_from_slice(&99_u64.to_be_bytes());
    // Parties: each is owner, signer, then an absent payout delegate.
    bytes.extend_from_slice(&[1, 3]);
    bytes.extend_from_slice(&[2; KernelKey::LENGTH]);
    bytes.extend_from_slice(&[2; KernelKey::LENGTH]);
    bytes.push(0);
    bytes.extend_from_slice(&[3; KernelKey::LENGTH]);
    bytes.extend_from_slice(&[3; KernelKey::LENGTH]);
    bytes.push(0);
    bytes.extend_from_slice(&[4; 32]);
    // CloseKindSet: the basic-terms set (mutual, timeout).
    bytes.push(0b011);
    assert_eq!(
        bytes.len(),
        KernelEdge::MAX_ENCODED_SIZE - 2 * KernelKey::LENGTH
    );
    KernelEdge::decode_exact(&bytes).expect("test edge must use the kernel canonical layout")
}

// --- Transaction (gated) ---

/// Wire tag of the one transaction arm.
///
/// A fixed consensus assignment, not a position. 0 and 1 were the
/// deleted chain-side transfer and merge, which verified their own
/// passkey signatures beside the kernel's; both bytes are ordinary
/// rejections and neither is reserved. Moving coins between owners is the
/// kernel's owner reshape.
const KERNEL_TAG: u8 = 2;

// Keep transactions inline/stack-allocated to avoid per-transaction heap churn in hot paths.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug)]
/// Chain transaction.
pub enum Transaction {
    /// Canonically encoded transaction for the settlement kernel.
    Kernel(KernelTx),
}

/// The network every in-crate test signs under.
///
/// One definition: a test that built its signature under a different
/// network than the one its verifier runs on would fail for the right
/// reason but the wrong cause, and the failure would read as a broken
/// signature rather than a mismatched fixture.
#[cfg(any(test, feature = "test-support"))]
pub(crate) const TEST_NETWORK: NetworkId = match NetworkId::new("hellas-chain-test") {
    Some(network) => network,
    None => panic!("literal is a legal network id"),
};

impl EncodeSize for Transaction {
    fn encode_size(&self) -> usize {
        match self {
            Self::Kernel(tx) => u8::SIZE + tx.encoded_size().encode_size() + tx.encoded_size(),
        }
    }
}

struct KernelTransactionWriter<'a, B: ?Sized>(&'a mut B);

impl<B: bytes::BufMut + ?Sized> hellas_kernel::Writer for KernelTransactionWriter<'_, B> {
    fn write(&mut self, bytes: &[u8]) {
        self.0.put_slice(bytes);
    }
}

impl Write for Transaction {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        match self {
            Self::Kernel(tx) => {
                KERNEL_TAG.write(buf);
                tx.encoded_size().write(buf);
                tx.encode_to(&mut KernelTransactionWriter(buf));
            }
        }
    }
}

impl Read for Transaction {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _cfg: &Self::Cfg) -> Result<Self, CodecError> {
        let tag = u8::read(buf)?;
        match tag {
            KERNEL_TAG => {
                let payload = Bounded::<u8, { KernelTx::MAX_ENCODED_SIZE }>::read_cfg(
                    buf,
                    &(RangeCfg::new(0..=KernelTx::MAX_ENCODED_SIZE), ()),
                )?;
                KernelTx::decode_exact(payload.as_slice())
                    .map(Self::Kernel)
                    .map_err(|_| {
                        CodecError::Invalid("Transaction", "invalid canonical kernel transaction")
                    })
            }
            _ => Err(CodecError::InvalidEnum(tag)),
        }
    }
}

#[cfg(test)]
#[allow(clippy::disallowed_types, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use commonware_codec::{DecodeExt, Encode};
    use hellas_kernel::test_support::{valid_mutual_close_tx, valid_open_tx};

    #[test]
    fn object_coin_codec_uses_kernel_canonical_payload_and_zero_padding() {
        let owner = SettlementKey::from_bytes([0x31; SettlementKey::LENGTH]);
        let delegate = SettlementKey::from_bytes([0x41; SettlementKey::LENGTH]);
        for coin in [
            Coin::owned(owner, 123),
            Coin {
                owner,
                delegate: Some(delegate),
                value: 123,
            },
        ] {
            let object = Object::Coin(coin);
            let encoded = object.encode();

            let kernel_coin = KernelCoin::from(coin);
            assert_eq!(
                kernel_coin.delegate().map(SettlementKey::from),
                coin.delegate
            );
            let mut canonical = [0_u8; KernelCoin::MAX_ENCODED_SIZE];
            let canonical_len = kernel_coin.write_to(&mut canonical);

            assert_eq!(encoded.len(), Object::SIZE);
            assert_eq!(encoded[0], Object::COIN_TAG);
            assert_eq!(&encoded[1..1 + canonical_len], &canonical[..canonical_len]);
            assert!(encoded[1 + canonical_len..].iter().all(|byte| *byte == 0));
            assert_eq!(Object::decode(encoded).expect("object decode"), object);
        }
    }

    #[test]
    fn object_edge_codec_uses_kernel_canonical_payload() {
        let edge = test_edge();
        let object = Object::Edge(edge);
        let encoded = object.encode();
        let mut canonical = [0_u8; KernelEdge::MAX_ENCODED_SIZE];
        let canonical_len = edge.write_to(&mut canonical);

        // Neither party commits a payout delegate, so the edge is two
        // absent keys short of the widest one and the rest is padding.
        assert_eq!(
            canonical_len,
            Object::PAYLOAD_SIZE - 2 * SettlementKey::LENGTH
        );
        assert_eq!(encoded[0], Object::EDGE_TAG);
        assert_eq!(&encoded[1..1 + canonical_len], &canonical[..canonical_len]);
        assert!(encoded[1 + canonical_len..].iter().all(|byte| *byte == 0));
        assert_eq!(Object::decode(encoded).expect("object decode"), object);
    }

    #[test]
    fn stored_object_is_298_bytes_across_every_arm() {
        // The stored object is a one-byte kind tag plus a payload area
        // padded to the widest kernel arm. That arm is the edge: since
        // each party commits an owner, a signer and an optional payout
        // delegate, an edge is 297 canonical bytes at its widest, above
        // the 130-byte registry chunk and the 77-byte delegated coin.
        // This number is load-bearing for the fixed-size QMDB journal:
        // changing it rewrites every stored object, which is why it is
        // pinned rather than derived here.
        assert_eq!(KernelRegistryChunk::MAX_ENCODED_SIZE, 130);
        assert_eq!(KernelCoin::MAX_ENCODED_SIZE, 77);
        assert_eq!(KernelEdge::MAX_ENCODED_SIZE, 297);
        const { assert!(KernelCoin::MAX_ENCODED_SIZE <= KernelEdge::MAX_ENCODED_SIZE) };
        assert_eq!(Object::PAYLOAD_SIZE, 297);
        assert_eq!(Object::SIZE, 298);

        let chunk = test_registry_chunk();
        for object in [
            Object::Coin(Coin::owned(
                SettlementKey::from_bytes([0x42; SettlementKey::LENGTH]),
                7,
            )),
            Object::Edge(test_edge()),
            Object::RegistryChunk(chunk),
        ] {
            assert_eq!(object.encode().len(), Object::SIZE);
        }
    }

    #[test]
    fn object_registry_chunk_codec_uses_kernel_canonical_payload_and_zero_padding() {
        let chunk = test_registry_chunk();
        let object = Object::RegistryChunk(chunk);
        let encoded = object.encode();

        let mut canonical = [0_u8; KernelRegistryChunk::MAX_ENCODED_SIZE];
        let canonical_len = chunk.write_to(&mut canonical);

        assert_eq!(encoded[0], Object::REGISTRY_CHUNK_TAG);
        assert_eq!(&encoded[1..1 + canonical_len], &canonical);
        assert!(encoded[1 + canonical_len..].iter().all(|byte| *byte == 0));
        assert_eq!(Object::decode(encoded).expect("object decode"), object);
        assert_eq!(object.kind(), ObjectKind::RegistryChunk);
        assert_eq!(ObjectKind::RegistryChunk.to_string(), "registry-chunk");
    }

    #[test]
    fn object_codec_rejects_non_zero_padding() {
        let object = Object::Coin(Coin::owned(
            SettlementKey::from_bytes([0x42; SettlementKey::LENGTH]),
            7,
        ));
        let mut encoded = object.encode().to_vec();
        let last = encoded.len() - 1;
        encoded[last] = 1;
        assert!(Object::decode(encoded.as_slice()).is_err());
    }

    #[test]
    fn settlement_key_base58_roundtrip_does_not_validate_a_curve() {
        let key = SettlementKey::from_bytes([0xa5; SettlementKey::LENGTH]);
        assert_eq!(key.encode().as_ref(), key.as_bytes());
        assert_eq!(
            SettlementKey::decode(key.as_bytes().as_slice()).expect("raw settlement key"),
            key
        );
        let encoded = key.to_string();
        let decoded: SettlementKey = encoded.parse().expect("base58 settlement key");
        assert_eq!(decoded, key);
    }

    #[test]
    fn the_transaction_max_encoding_fits_advisory_block_budget() {
        let kernel_max =
            u8::SIZE + KernelTx::MAX_ENCODED_SIZE.encode_size() + KernelTx::MAX_ENCODED_SIZE;
        assert!(
            kernel_max < MAX_BLOCK_TX_BYTES / 8,
            "kernel maximum {kernel_max} is not far below advisory block budget {MAX_BLOCK_TX_BYTES}"
        );
    }

    /// A maximum-width close start: the widest revealed payment terms
    /// plus a present certificate.
    fn payment_close_start_tx() -> KernelTx {
        use hellas_kernel::{
            EarnedCertificate, Move, Party, PartyAuth, PaymentCloseStart, Payout as KernelPayout,
            Sig, Terms as KernelTerms, WorkPaymentTerms, WorkStakeBondTerms,
        };

        let maker = hellas_kernel::Key::from_bytes([0x31; 33]);
        let taker = hellas_kernel::Key::from_bytes([0x32; 33]);
        let bond = WorkStakeBondTerms {
            parties: hellas_kernel::Parties::new(
                hellas_kernel::PartyKeys::sole(taker),
                hellas_kernel::PartyKeys::sole(maker),
            ),
            timeout: hellas_kernel::BlockHeight::new(900),
            timeout_outputs: hellas_kernel::List::all(
                [KernelPayout::new(taker, 3); hellas_kernel::MAX_EDGE_OUTPUTS],
            ),
            max_job_price: 4,
        };
        let terms = KernelTerms::work_payment(WorkPaymentTerms {
            bond_edge: hellas_kernel::EdgeId::from_bytes([0x44; 32]),
            bond_terms: bond,
            private_policy_commitment: [0x55; 32],
            omit_response_blocks: 64,
            start_validity_blocks: 8,
            omission_bond: 2,
        });
        let edge = hellas_kernel::EdgeId::from_bytes([0x11; 32]);
        let certificate = EarnedCertificate::new(edge, terms.hash(), 4_242);
        KernelTx::move_action(Move::StartPaymentClose(PaymentCloseStart::new(
            edge,
            terms,
            Party::Taker,
            (900, 907),
            Some((certificate, PartyAuth::owner(Sig::from_bytes([0x66; 64])))),
            PartyAuth::owner(Sig::from_bytes([0x77; 64])),
        )))
    }

    fn payment_close_response_tx() -> KernelTx {
        use hellas_kernel::{
            EarnedCertificate, Move, Party, PartyAuth, PaymentCloseResponse, Sig, StartId,
            TermsHash,
        };

        let edge = hellas_kernel::EdgeId::from_bytes([0x11; 32]);
        let terms = TermsHash::from_bytes([0x22; 32]);
        KernelTx::move_action(Move::RespondPaymentClose(PaymentCloseResponse::new(
            edge,
            StartId::from_bytes([0x33; 32]),
            Party::Taker,
            (
                EarnedCertificate::new(edge, terms, 4_242),
                PartyAuth::owner(Sig::from_bytes([0x66; 64])),
            ),
            PartyAuth::owner(Sig::from_bytes([0x77; 64])),
        )))
    }

    fn assert_kernel_codec_roundtrip(kernel_tx: KernelTx) {
        let expected_payload_len = kernel_tx.encoded_size();
        let mut canonical = [0_u8; KernelTx::MAX_ENCODED_SIZE];
        let canonical_len = kernel_tx.write_to(&mut canonical);
        let tx = Transaction::Kernel(kernel_tx.clone());
        let encoded = tx.encode();
        assert_eq!(encoded[0], 2);
        let mut body = &encoded[1..];
        assert_eq!(
            usize::read_cfg(&mut body, &RangeCfg::new(0..=KernelTx::MAX_ENCODED_SIZE),)
                .expect("kernel payload length"),
            expected_payload_len
        );
        assert_eq!(body, &canonical[..canonical_len]);
        let decoded = Transaction::decode(encoded).expect("kernel transaction decode");
        let Transaction::Kernel(decoded) = decoded;
        assert_eq!(decoded, kernel_tx);
    }

    #[test]
    fn kernel_open_codec_roundtrip() {
        assert_kernel_codec_roundtrip(valid_open_tx().expect("valid kernel open fixture"));
    }

    #[test]
    fn kernel_close_codec_roundtrip() {
        assert_kernel_codec_roundtrip(valid_mutual_close_tx().expect("valid kernel close fixture"));
    }

    #[test]
    fn kernel_move_codec_roundtrip() {
        assert_kernel_codec_roundtrip(payment_close_start_tx());
        assert_kernel_codec_roundtrip(payment_close_response_tx());
    }

    /// The chain wrapper is a tag byte plus the payload length as a
    /// commonware-codec varint — **three** bytes for every payload in
    /// `128..=16,383`, which is every payment-close body. A wrapped-size
    /// quote of nine would be reading the length as a fixed `usize`.
    #[test]
    fn the_payment_close_chain_wrapper_is_three_bytes() {
        for (kernel_tx, kernel_len, chain_len) in [
            (payment_close_start_tx(), 703, 706),
            (payment_close_response_tx(), 286, 289),
        ] {
            assert_eq!(kernel_tx.encoded_size(), kernel_len);
            let encoded = Transaction::Kernel(kernel_tx).encode();
            assert_eq!(encoded.len(), chain_len);
            assert_eq!(encoded.len() - kernel_len, 3);
            // Tag byte, then a two-byte varint length.
            assert_eq!(encoded[0], 2);
            assert_eq!(kernel_len.encode_size(), 2);
        }

        // The formula is length-dependent, not globally three: a payload
        // under 128 bytes has a one-byte length.
        assert_eq!(82_usize.encode_size(), 1);
        assert_eq!(16_383_usize.encode_size(), 2);
        assert_eq!(16_384_usize.encode_size(), 3);
    }

    #[test]
    fn kernel_codec_rejects_over_length_payload() {
        let mut encoded = BytesMut::new();
        2u8.write(&mut encoded);
        (KernelTx::MAX_ENCODED_SIZE + 1).write(&mut encoded);
        assert!(Transaction::decode(encoded).is_err());
    }

    #[test]
    fn kernel_codec_rejects_trailing_garbage_inside_payload() {
        let kernel_tx = valid_open_tx().expect("valid kernel open fixture");
        let mut canonical = [0_u8; KernelTx::MAX_ENCODED_SIZE];
        let canonical_len = kernel_tx.write_to(&mut canonical);
        let mut encoded = BytesMut::new();
        2u8.write(&mut encoded);
        (canonical_len + 1).write(&mut encoded);
        encoded.extend_from_slice(&canonical[..canonical_len]);
        encoded.extend_from_slice(&[0xff]);
        assert!(Transaction::decode(encoded).is_err());
    }

    /// 0 and 1 were the deleted chain-side transfer and merge. They are
    /// rejections like any other unassigned byte, not reserved arms.
    #[test]
    fn transaction_codec_rejects_unknown_tag() {
        for tag in [0, 1, 3, 0xff] {
            assert!(
                matches!(
                    Transaction::decode([tag].as_slice()),
                    Err(CodecError::InvalidEnum(found)) if found == tag
                ),
                "transaction tag {tag}",
            );
        }
    }

    /// The funded accounts in the shipped genesis documents are
    /// derivations, not opaque strings.
    ///
    /// The devnet README documents the low secret scalars used below.
    #[test]
    fn shipped_genesis_allocations_match_their_documented_scalars() {
        fn address_for(scalar: u8) -> String {
            let mut raw = [0_u8; 32];
            raw[31] = scalar;
            let key = p256::ecdsa::SigningKey::from_slice(&raw).expect("valid scalar");
            let point = key.verifying_key().to_sec1_point(true);
            let bytes: [u8; SettlementKey::LENGTH] = point
                .as_bytes()
                .try_into()
                .expect("a compressed P-256 point is 33 bytes");
            SettlementKey::from_bytes(bytes).to_string()
        }

        let genesis: crate::genesis::Genesis =
            serde_json::from_str(crate::genesis::HELLAS_DEVNET_1_JSON)
                .expect("shipped document parses");
        let funded: Vec<&str> = genesis
            .allocations
            .iter()
            .map(|allocation| allocation.address.as_str())
            .collect();
        let mut expected: Vec<String> = [1_u8, 2].into_iter().map(address_for).collect();
        // The foundation allocation is documented in the network README; its
        // key is generated independently, not derived from a public scalar.
        expected.push("25uDmUCQcwYUHHyXthtEspGB2KVTmbys8vTSqAMXKNqRV".to_string());
        assert_eq!(funded, expected, "{}", genesis.network_id);
    }

    #[test]
    fn bounded_read_rejects_len_over_capacity_despite_loose_range() {
        // A caller passing a RangeCfg wider than the type's capacity must
        // still get a decode error, not a corrupt list.
        let oversized: Bounded<u8, 8> = Bounded::new([7; 8], 8).expect("fits");
        let encoded = oversized.encode();
        let decoded =
            Bounded::<u8, 4>::read_cfg(&mut encoded.as_ref(), &(RangeCfg::new(0..=usize::MAX), ()));
        assert!(matches!(decoded, Err(CodecError::InvalidLength(8))));
    }
}
