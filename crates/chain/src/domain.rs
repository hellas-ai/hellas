//! Domain types used by the Hellas chain and light-client API.
//!
//! # `WebAuthn` policy divergence
//!
//! [`Transaction::verify_signature`] enforces a browser-shaped policy:
//! UP *and* UV flags, an HTTPS origin allowlist, and `rpIdHash` binding.
//! The kernel's open-authorization verifier (`hellas-kernel`, feature
//! `webauthn`) is deliberately looser — UP *or* UV, origin ignored — and
//! treats `WebAuthn` as a portable P-256 transaction-signing envelope.
//! They are different products; do not wire one where the other is
//! expected.

/// Digest used by chain-facing APIs.
pub use commonware_cryptography::sha256::Digest;

/// Decoding helper for domain types.
pub use commonware_codec::DecodeExt;
/// Encoding helper for domain types.
pub use commonware_codec::Encode;

use base64ct::{Base64UrlUnpadded, Encoding};
use bytes::BytesMut;
use commonware_codec::{
    EncodeSize, Error as CodecError, FixedSize, RangeCfg, Read, ReadExt, Write,
};
/// Signing helper for domain key types.
pub use commonware_cryptography::Signer;
use commonware_cryptography::{Hasher, Sha256, ed25519, secp256r1};
use hellas_kernel::{
    Coin as KernelCoin, Decode as KernelDecode, Edge as KernelEdge, Encode as KernelEncode, Fees,
    Key as KernelKey, NetworkId, RegistryChunk as KernelRegistryChunk, Tx as KernelTx,
};
use p256::ecdsa::signature::Verifier as _;
use serde_json::Value as JsonValue;
use sha2::{Digest as _, Sha256 as Sha2};
use url::Url;

/// Validator public key.
pub type PublicKey = ed25519::PublicKey;
/// Validator private key.
pub type PrivateKey = ed25519::PrivateKey;
/// User public key.
pub type UserPublicKey = secp256r1::standard::PublicKey;
/// User signature.
pub type UserSignature = secp256r1::standard::Signature;
/// Object identifier in the chain state.
pub type ObjectId = Digest;

/// User address derived from a secp256r1 public key.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Address(UserPublicKey);

impl Address {
    /// Returns the public key encoded by this address.
    #[must_use]
    pub const fn public_key(&self) -> &UserPublicKey {
        &self.0
    }
}

impl From<UserPublicKey> for Address {
    fn from(pk: UserPublicKey) -> Self {
        Self(pk)
    }
}

impl core::fmt::Display for Address {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        use commonware_codec::Encode;
        f.write_str(&bs58::encode(self.0.encode()).into_string())
    }
}

impl core::str::FromStr for Address {
    type Err = AddressError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = bs58::decode(s).into_vec().map_err(AddressError::Base58)?;
        let pk = UserPublicKey::decode(bytes.as_slice()).map_err(|_| AddressError::InvalidKey)?;
        Ok(Self(pk))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
/// Address parsing error.
pub enum AddressError {
    /// Invalid base58 encoding.
    #[error("invalid base58: {0}")]
    Base58(bs58::decode::Error),
    /// Invalid secp256r1 public key bytes.
    #[error("invalid secp256r1 public key")]
    InvalidKey,
}

impl FixedSize for Address {
    const SIZE: usize = UserPublicKey::SIZE;
}

impl Write for Address {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.0.write(buf);
    }
}

impl Read for Address {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _cfg: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self(UserPublicKey::read(buf)?))
    }
}

/// Raw compressed settlement key used for stored object ownership.
///
/// Unlike [`Address`], this type does not validate a curve. Both compressed
/// P-256 and compressed secp256k1 keys are 33-byte settlement keys. Legacy
/// [`Transaction::Transfer`] and [`Transaction::MergeCoin`] verification
/// explicitly converts a stored key back to [`Address`] and rejects keys that
/// are not valid P-256 encodings.
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

impl From<&Address> for SettlementKey {
    fn from(address: &Address) -> Self {
        let mut bytes = [0_u8; Self::LENGTH];
        bytes.copy_from_slice(address.public_key().as_ref());
        Self::from_bytes(bytes)
    }
}

impl From<Address> for SettlementKey {
    fn from(address: Address) -> Self {
        Self::from(&address)
    }
}

impl TryFrom<SettlementKey> for Address {
    type Error = AddressError;

    fn try_from(key: SettlementKey) -> Result<Self, Self::Error> {
        UserPublicKey::decode(key.as_bytes().as_slice())
            .map(Self)
            .map_err(|_| AddressError::InvalidKey)
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

impl<const N: usize> Read for Bounded<ObjectId, N> {
    type Cfg = (RangeCfg<usize>, ());

    fn read_cfg(buf: &mut impl bytes::Buf, (range, _cfg): &Self::Cfg) -> Result<Self, CodecError> {
        let len = usize::read_cfg(buf, range)?;
        if len > N {
            return Err(CodecError::InvalidLength(len));
        }
        let mut items = [ObjectId::from([0; 32]); N];
        for slot in items.iter_mut().take(len) {
            *slot = ObjectId::read(buf)?;
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

/// `WebAuthn` policy version.
pub const WEBAUTHN_POLICY_VERSION: u8 = 1;
/// Whether `WebAuthn` user presence is required.
pub const WEBAUTHN_REQUIRE_UP: bool = true;
/// Whether `WebAuthn` user verification is required.
pub const WEBAUTHN_REQUIRE_UV: bool = true;
/// Whether cross-origin assertions are rejected.
pub const WEBAUTHN_REQUIRE_CROSS_ORIGIN_FALSE: bool = true;
/// Whether HTTPS origins are required.
pub const WEBAUTHN_REQUIRE_HTTPS_ORIGIN: bool = true;
/// Whether HTTP localhost origins are allowed.
pub const WEBAUTHN_ALLOW_HTTP_LOCALHOST_ORIGIN: bool = true;
/// Whether attested credential data is allowed.
pub const WEBAUTHN_ALLOW_ATTESTED_CREDENTIAL_DATA: bool = false;
/// Whether `WebAuthn` extensions are allowed.
pub const WEBAUTHN_ALLOW_EXTENSIONS: bool = false;
/// Required `WebAuthn` client data type.
pub const WEBAUTHN_TYPE_GET: &str = "webauthn.get";

/// Domain separator for `WebAuthn` challenges.
pub const CHALLENGE_DOMAIN: &[u8] = b"hellas-webauthn-challenge-v1";
/// Transfer transaction tag.
pub const TRANSFER_TAG: u8 = 0x01;
/// Merge transaction tag.
pub const MERGE_TAG: u8 = 0x02;
/// Maximum merge input count.
pub const MAX_MERGE_INPUTS: usize = 32;
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
/// Minimum `WebAuthn` authenticator data length.
pub const MIN_AUTHENTICATOR_DATA_LEN: usize = 37;
/// Maximum `WebAuthn` authenticator data length.
pub const MAX_AUTHENTICATOR_DATA_LEN: usize = 256;
/// Maximum `WebAuthn` client data JSON length.
pub const MAX_CLIENT_DATA_JSON_LEN: usize = 1024;

/// Bounded authenticator data carried by a `WebAuthn` signature.
pub type AuthenticatorData = Bounded<u8, MAX_AUTHENTICATOR_DATA_LEN>;
/// Bounded client data JSON carried by a `WebAuthn` signature.
pub type ClientDataJson = Bounded<u8, MAX_CLIENT_DATA_JSON_LEN>;
/// Bounded merge input list.
pub type MergeInputs = Bounded<ObjectId, MAX_MERGE_INPUTS>;

/// Returns the deterministic object id for a genesis allocation.
#[must_use]
pub fn genesis_object_id(validator_index: u16) -> ObjectId {
    let mut buf = BytesMut::new();
    buf.extend_from_slice(b"hellas-genesis");
    validator_index.write(&mut buf);
    Sha256::hash(&buf)
}

/// Returns the deterministic object id for a transaction output.
#[must_use]
pub fn output_object_id(tx_digest: &Digest, output_index: u8) -> ObjectId {
    let mut buf = BytesMut::new();
    tx_digest.write(&mut buf);
    output_index.write(&mut buf);
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
#[cfg(any(feature = "validator", feature = "explorer-origin"))]
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
/// lives here, beside the challenge builders it feeds, rather than in
/// `config`: reading a network off a document is what every signer
/// does, and only a validator reads a validator config.
///
/// There is deliberately no compile-time default. A binary that
/// carries one silently re-domains every signature in the tree the
/// moment that constant moves, which is not hypothetical.
pub fn network_id(genesis: &crate::genesis::Genesis) -> Result<NetworkId, NetworkIdError> {
    NetworkId::new(&genesis.network_id).ok_or_else(|| NetworkIdError(genesis.network_id.clone()))
}

/// Writes the network-scoped domain prefix every `WebAuthn` challenge
/// starts with.
///
/// The network is a runtime value, not a constant: a passkey signature
/// says "I authorize this transfer *on this network*", and a compiled-in
/// chain id would silently re-domain every signature in the tree the
/// moment that constant moved. [`NetworkId`]'s own encoding is
/// length-prefixed, which is what keeps the prefix unambiguous when a
/// variable-width id sits next to the tag.
fn challenge_prefix(buf: &mut BytesMut, network: NetworkId, tag: u8) {
    buf.extend_from_slice(CHALLENGE_DOMAIN);
    WEBAUTHN_POLICY_VERSION.write(buf);
    let mut encoded = [0_u8; NetworkId::MAX_ENCODED_SIZE];
    let len = network.write_to(&mut encoded);
    buf.extend_from_slice(&encoded[..len]);
    tag.write(buf);
}

/// Returns the `WebAuthn` challenge for a transfer transaction on
/// `network`.
#[must_use]
pub fn transfer_challenge(
    network: NetworkId,
    input: &ObjectId,
    recipient: &Address,
    amount: u64,
) -> Digest {
    let mut buf = BytesMut::new();
    challenge_prefix(&mut buf, network, TRANSFER_TAG);
    input.write(&mut buf);
    recipient.write(&mut buf);
    amount.write(&mut buf);
    Sha256::hash(&buf)
}

/// Returns the `WebAuthn` challenge for a merge transaction on
/// `network`.
#[must_use]
pub fn merge_challenge(network: NetworkId, sorted_inputs: &[ObjectId]) -> Digest {
    let mut buf = BytesMut::new();
    challenge_prefix(&mut buf, network, MERGE_TAG);
    sorted_inputs.write(&mut buf);
    Sha256::hash(&buf)
}

fn sha256_bytes(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha2::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

#[cfg(test)]
fn secp256r1_key_from_material(material: &[u8]) -> p256::ecdsa::SigningKey {
    let mut salt = 0u8;
    loop {
        let mut hasher = Sha2::new();
        hasher.update(b"hellas-secp256r1-material-v1");
        hasher.update(material);
        hasher.update([salt]);
        let raw: [u8; 32] = hasher.finalize().into();
        if let Ok(key) = p256::ecdsa::SigningKey::from_slice(&raw) {
            return key;
        }
        salt = salt.wrapping_add(1);
    }
}

fn localhost_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost") || host == "127.0.0.1" || host == "::1"
}

fn origin_is_allowed(url: &Url) -> bool {
    let scheme = url.scheme();
    (scheme == "https")
        || (WEBAUTHN_ALLOW_HTTP_LOCALHOST_ORIGIN
            && scheme == "http"
            && url.host_str().is_some_and(localhost_host))
}

fn lower_host_hash(host: &str) -> Option<[u8; 32]> {
    const MAX_RP_ID_LEN: usize = 253;

    if host.is_empty() || host.len() > MAX_RP_ID_LEN {
        return None;
    }
    let mut lower = [0_u8; MAX_RP_ID_LEN];
    for (dst, src) in lower.iter_mut().zip(host.bytes()) {
        *dst = src.to_ascii_lowercase();
    }
    Some(sha256_bytes(&lower[..host.len()]))
}

/// Returns the SHA-256 RP ID hash for a permitted `WebAuthn` origin.
#[must_use]
pub fn rp_id_hash_from_origin(origin: &str) -> Option<[u8; 32]> {
    let url = Url::parse(origin).ok()?;
    if WEBAUTHN_REQUIRE_HTTPS_ORIGIN && !origin_is_allowed(&url) {
        return None;
    }
    lower_host_hash(url.host_str()?)
}

// --- Stored objects (gated) ---

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// Chain coin object.
pub struct Coin {
    /// Coin owner.
    pub owner: SettlementKey,
    /// Coin value.
    pub value: u64,
}

impl From<KernelCoin> for Coin {
    fn from(coin: KernelCoin) -> Self {
        Self {
            owner: SettlementKey::from(coin.owner()),
            value: coin.value(),
        }
    }
}

impl From<Coin> for KernelCoin {
    fn from(coin: Coin) -> Self {
        Self::issue(coin.owner.into_kernel(), coin.value)
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
        KernelCoin::MAX_ENCODED_SIZE,
        larger(
            KernelEdge::MAX_ENCODED_SIZE,
            KernelRegistryChunk::MAX_ENCODED_SIZE,
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
                buf.put_slice(data);
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
            Self::OWNER_DATA_TAG => Ok(Self::OwnerData(payload)),
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
    bytes.extend_from_slice(&[1, 3]);
    bytes.extend_from_slice(&[2; KernelKey::LENGTH]);
    bytes.extend_from_slice(&[3; KernelKey::LENGTH]);
    bytes.extend_from_slice(&[4; 32]);
    // CloseKindSet: the basic-terms set (mutual, timeout).
    bytes.push(0b011);
    assert_eq!(bytes.len(), KernelEdge::MAX_ENCODED_SIZE);
    KernelEdge::decode_exact(&bytes).expect("test edge must use the kernel canonical layout")
}

// --- WebAuthnSignature (gated) ---

#[derive(Clone, Debug, PartialEq, Eq)]
/// `WebAuthn` signature payload committed by a transaction.
pub struct WebAuthnSignature {
    /// Raw secp256r1 ECDSA signature.
    pub signature: UserSignature,
    /// `WebAuthn` authenticator data.
    pub authenticator_data: AuthenticatorData,
    /// `WebAuthn` client data JSON.
    pub client_data_json: ClientDataJson,
}

fn byte_list_from_slice<const N: usize>(bytes: &[u8]) -> Option<Bounded<u8, N>> {
    if bytes.len() > N {
        return None;
    }
    let mut items = [0_u8; N];
    items[..bytes.len()].copy_from_slice(bytes);
    Bounded::new(items, bytes.len())
}

impl WebAuthnSignature {
    /// Builds a bounded `WebAuthn` signature payload.
    #[must_use]
    pub fn new(
        signature: UserSignature,
        authenticator_data: &[u8],
        client_data_json: &[u8],
    ) -> Option<Self> {
        if authenticator_data.len() < MIN_AUTHENTICATOR_DATA_LEN || client_data_json.is_empty() {
            return None;
        }
        Some(Self {
            signature,
            authenticator_data: byte_list_from_slice(authenticator_data)?,
            client_data_json: byte_list_from_slice(client_data_json)?,
        })
    }

    /// Builds a bounded signature payload from the DER encoding returned by
    /// `AuthenticatorAssertionResponse.signature`.
    #[must_use]
    pub fn from_der(
        signature_der: &[u8],
        authenticator_data: &[u8],
        client_data_json: &[u8],
    ) -> Option<Self> {
        let signature = p256::ecdsa::Signature::from_der(signature_der).ok()?;
        let signature = signature.normalize_s();
        let signature = UserSignature::decode(signature.to_bytes().as_ref()).ok()?;
        Self::new(signature, authenticator_data, client_data_json)
    }
}

impl EncodeSize for WebAuthnSignature {
    fn encode_size(&self) -> usize {
        self.signature.encode_size()
            + self.authenticator_data.encode_size()
            + self.client_data_json.encode_size()
    }
}

impl Write for WebAuthnSignature {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.signature.write(buf);
        self.authenticator_data.write(buf);
        self.client_data_json.write(buf);
    }
}

impl Read for WebAuthnSignature {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _cfg: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            signature: UserSignature::read(buf)?,
            authenticator_data: AuthenticatorData::read_cfg(
                buf,
                &(
                    RangeCfg::new(MIN_AUTHENTICATOR_DATA_LEN..=MAX_AUTHENTICATOR_DATA_LEN),
                    (),
                ),
            )?,
            client_data_json: ClientDataJson::read_cfg(
                buf,
                &(RangeCfg::new(1..=MAX_CLIENT_DATA_JSON_LEN), ()),
            )?,
        })
    }
}

// --- Transaction (gated) ---

// Keep transactions inline/stack-allocated to avoid per-transaction heap churn in hot paths.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug)]
/// Chain transaction.
pub enum Transaction {
    /// Transfer part or all of one input coin to a recipient.
    Transfer {
        /// Input coin object id.
        input: ObjectId,
        /// Recipient address.
        recipient: Address,
        /// Amount transferred to the recipient.
        amount: u64,
        /// Owner signature over the transfer challenge.
        signature: WebAuthnSignature,
    },
    /// Merge multiple input coins owned by the same address.
    MergeCoin {
        /// Sorted input coin object ids.
        inputs: MergeInputs,
        /// Owner signature over the merge challenge.
        signature: WebAuthnSignature,
    },
    /// Canonically encoded transaction for the settlement kernel.
    Kernel(KernelTx),
}

/// Why a merge transaction's input list is not admissible.
///
/// Merge validation runs twice — against QMDB in `execution::kernel`
/// and against the in-memory `owner_index` — and the two must agree
/// exactly, so the predicate lives here and each caller maps the fault
/// into its own error type. Callers keep their distinctions: a
/// duplicated input is a different fault from an out-of-order one.
#[cfg(any(feature = "indexer", feature = "validator"))]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum MergeInputFault {
    /// Fewer than two inputs — nothing to merge.
    TooFew,
    /// The same object appears twice.
    Duplicate(ObjectId),
    /// Inputs are not in ascending order.
    NonCanonical,
}

/// Validates a merge input list, or reports the first fault found.
#[cfg(any(feature = "indexer", feature = "validator"))]
pub(crate) fn merge_input_fault(inputs: &[ObjectId]) -> Option<MergeInputFault> {
    if inputs.len() < 2 {
        return Some(MergeInputFault::TooFew);
    }
    inputs.windows(2).find_map(|pair| {
        if pair[0] == pair[1] {
            Some(MergeInputFault::Duplicate(pair[0]))
        } else if pair[0] > pair[1] {
            Some(MergeInputFault::NonCanonical)
        } else {
            None
        }
    })
}

fn client_data_rp_hash(bytes: &[u8], expected_challenge: &[u8]) -> Option<[u8; 32]> {
    let json: JsonValue = serde_json::from_slice(bytes).ok()?;
    let obj = json.as_object()?;
    let ty = obj.get("type")?.as_str()?;
    let challenge = obj.get("challenge")?.as_str()?;
    let origin = obj.get("origin")?.as_str()?;
    let cross_origin = obj
        .get("crossOrigin")
        .and_then(JsonValue::as_bool)
        .unwrap_or(false);
    if ty != WEBAUTHN_TYPE_GET {
        return None;
    }
    if WEBAUTHN_REQUIRE_CROSS_ORIGIN_FALSE && cross_origin {
        return None;
    }
    let mut decoded_challenge = [0_u8; 32];
    let Ok(decoded_challenge) = Base64UrlUnpadded::decode(challenge, &mut decoded_challenge) else {
        return None;
    };
    if decoded_challenge != expected_challenge {
        return None;
    }
    rp_id_hash_from_origin(origin)
}

fn verify_webauthn_signature(
    expected_challenge: &[u8],
    signature: &WebAuthnSignature,
    owner: &UserPublicKey,
) -> bool {
    const FLAG_UP: u8 = 0x01;
    const FLAG_UV: u8 = 0x04;
    const FLAG_AT: u8 = 0x40;
    const FLAG_ED: u8 = 0x80;

    let authenticator_data = signature.authenticator_data.as_slice();
    let client_data_json = signature.client_data_json.as_slice();
    if authenticator_data.len() < MIN_AUTHENTICATOR_DATA_LEN || client_data_json.is_empty() {
        return false;
    }

    let Some(rp_hash) = client_data_rp_hash(client_data_json, expected_challenge) else {
        return false;
    };
    if authenticator_data[..32] != rp_hash {
        return false;
    }

    let flags = authenticator_data[32];
    if WEBAUTHN_REQUIRE_UP && (flags & FLAG_UP) == 0 {
        return false;
    }
    if WEBAUTHN_REQUIRE_UV && (flags & FLAG_UV) == 0 {
        return false;
    }
    if !WEBAUTHN_ALLOW_ATTESTED_CREDENTIAL_DATA && (flags & FLAG_AT) != 0 {
        return false;
    }
    if !WEBAUTHN_ALLOW_EXTENSIONS && (flags & FLAG_ED) != 0 {
        return false;
    }

    let client_hash = sha256_bytes(client_data_json);
    let mut msg = [0_u8; MAX_AUTHENTICATOR_DATA_LEN + 32];
    let msg_len = authenticator_data.len() + client_hash.len();
    msg[..authenticator_data.len()].copy_from_slice(authenticator_data);
    msg[authenticator_data.len()..msg_len].copy_from_slice(&client_hash);

    let Ok(verifying_key) = p256::ecdsa::VerifyingKey::from_sec1_bytes(owner.as_ref()) else {
        return false;
    };
    let Ok(sig) = p256::ecdsa::Signature::from_slice(signature.signature.as_ref()) else {
        return false;
    };
    verifying_key.verify(&msg[..msg_len], &sig).is_ok()
}

impl Transaction {
    /// Verifies a legacy transaction `WebAuthn` signature against
    /// `owner`, as authorized for `network`.
    ///
    /// A signature made for one network fails here under any other: the
    /// challenge it was produced over is not the challenge this
    /// recomputes.
    ///
    /// Kernel transactions deliberately return `false`: they authenticate
    /// inside kernel [`hellas_kernel::State::apply`] beginning in M4, never at
    /// this chain-domain signature layer.
    #[must_use]
    pub fn verify_signature(&self, network: NetworkId, owner: &Address) -> bool {
        match self {
            Self::Transfer {
                input,
                recipient,
                amount,
                signature,
            } => {
                let expected = transfer_challenge(network, input, recipient, *amount);
                verify_webauthn_signature(expected.as_ref(), signature, owner.public_key())
            }
            Self::MergeCoin { inputs, signature } => {
                let expected = merge_challenge(network, inputs.as_slice());
                verify_webauthn_signature(expected.as_ref(), signature, owner.public_key())
            }
            Self::Kernel(_) => false,
        }
    }
}

#[cfg(test)]
impl From<ed25519::PublicKey> for Address {
    fn from(pk: ed25519::PublicKey) -> Self {
        let key = secp256r1_key_from_material(pk.as_ref());
        addr_from_signing_key(&key)
    }
}

/// The network every in-crate test signs under.
///
/// One definition: a test that built its signature under a different
/// network than the one its verifier runs on would fail for the right
/// reason but the wrong cause, and the failure would read as a broken
/// signature rather than a mismatched fixture.
#[cfg(test)]
pub(crate) const TEST_NETWORK: NetworkId = match NetworkId::new("hellas-chain-test") {
    Some(network) => network,
    None => panic!("literal is a legal network id"),
};

#[cfg(test)]
impl Transaction {
    /// Builds a signed transfer transaction for tests, authorized for
    /// `network`.
    #[must_use]
    pub fn transfer(
        network: NetworkId,
        key: &PrivateKey,
        input: ObjectId,
        recipient: Address,
        amount: u64,
    ) -> Option<Self> {
        let secp_key = secp256r1_key_from_material(key.public_key().as_ref());
        let challenge = transfer_challenge(network, &input, &recipient, amount);
        Some(Self::Transfer {
            input,
            recipient,
            amount,
            signature: mock_webauthn_sign(&secp_key, &challenge)?,
        })
    }

    /// Builds a signed merge transaction for tests, authorized for
    /// `network`.
    #[must_use]
    pub fn merge(network: NetworkId, key: &PrivateKey, inputs: &[ObjectId]) -> Option<Self> {
        let mut items = [ObjectId::from([0; 32]); MAX_MERGE_INPUTS];
        if inputs.len() > items.len() {
            return None;
        }
        items[..inputs.len()].copy_from_slice(inputs);
        items[..inputs.len()].sort();
        let inputs = MergeInputs::new(items, inputs.len())?;
        let secp_key = secp256r1_key_from_material(key.public_key().as_ref());
        let challenge = merge_challenge(network, inputs.as_slice());
        Some(Self::MergeCoin {
            inputs,
            signature: mock_webauthn_sign(&secp_key, &challenge)?,
        })
    }
}

impl EncodeSize for Transaction {
    fn encode_size(&self) -> usize {
        match self {
            Self::Transfer {
                input,
                recipient,
                amount,
                signature,
            } => {
                u8::SIZE
                    + input.encode_size()
                    + recipient.encode_size()
                    + amount.encode_size()
                    + signature.encode_size()
            }
            Self::MergeCoin { inputs, signature } => {
                u8::SIZE + inputs.encode_size() + signature.encode_size()
            }
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
            Self::Transfer {
                input,
                recipient,
                amount,
                signature,
            } => {
                0u8.write(buf);
                input.write(buf);
                recipient.write(buf);
                amount.write(buf);
                signature.write(buf);
            }
            Self::MergeCoin { inputs, signature } => {
                1u8.write(buf);
                inputs.write(buf);
                signature.write(buf);
            }
            Self::Kernel(tx) => {
                2u8.write(buf);
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
            0 => Ok(Self::Transfer {
                input: ObjectId::read(buf)?,
                recipient: Address::read(buf)?,
                amount: u64::read(buf)?,
                signature: WebAuthnSignature::read(buf)?,
            }),
            1 => Ok(Self::MergeCoin {
                inputs: MergeInputs::read_cfg(buf, &(RangeCfg::new(2..=MAX_MERGE_INPUTS), ()))?,
                signature: WebAuthnSignature::read(buf)?,
            }),
            2 => {
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
/// Derives a deterministic secp256r1 signing key from `seed`.
#[must_use]
pub fn secp256r1_key_from_seed(seed: u64) -> p256::ecdsa::SigningKey {
    secp256r1_key_from_material(&seed.to_le_bytes())
}

#[cfg(test)]
/// Derives a chain address from a secp256r1 signing key.
#[must_use]
pub fn addr_from_signing_key(key: &p256::ecdsa::SigningKey) -> Address {
    Address::from(UserPublicKey::from(key.verifying_key().to_owned()))
}

#[cfg(test)]
const MOCK_WEBAUTHN_ORIGIN: &str = "https://wallet.hellas.ai";

#[cfg(test)]
fn push_bytes(dst: &mut [u8], len: &mut usize, bytes: &[u8]) -> Option<()> {
    let end = len.checked_add(bytes.len())?;
    if end > dst.len() {
        return None;
    }
    dst[*len..end].copy_from_slice(bytes);
    *len = end;
    Some(())
}

#[cfg(test)]
fn client_data_json_for_origin(challenge: &Digest, origin: &str) -> Option<ClientDataJson> {
    let mut challenge_buf = [0_u8; 43];
    let challenge_b64 = Base64UrlUnpadded::encode(challenge.as_ref(), &mut challenge_buf).ok()?;
    let mut json = [0_u8; MAX_CLIENT_DATA_JSON_LEN];
    let mut len = 0;
    push_bytes(&mut json, &mut len, br#"{"type":""#)?;
    push_bytes(&mut json, &mut len, WEBAUTHN_TYPE_GET.as_bytes())?;
    push_bytes(&mut json, &mut len, br#"","challenge":""#)?;
    push_bytes(&mut json, &mut len, challenge_b64.as_bytes())?;
    push_bytes(&mut json, &mut len, br#"","origin":""#)?;
    push_bytes(&mut json, &mut len, origin.as_bytes())?;
    push_bytes(&mut json, &mut len, br#"","crossOrigin":false}"#)?;
    byte_list_from_slice(&json[..len])
}

#[cfg(test)]
/// Creates a deterministic `WebAuthn` signature for tests using `origin`.
#[must_use]
pub fn mock_webauthn_sign_with_origin(
    key: &p256::ecdsa::SigningKey,
    challenge: &Digest,
    origin: &str,
) -> Option<WebAuthnSignature> {
    use p256::ecdsa::signature::Signer as _;

    let rp_id_hash = rp_id_hash_from_origin(origin)?;
    let client_data_json = client_data_json_for_origin(challenge, origin)?;

    let mut authenticator_data = [0_u8; MIN_AUTHENTICATOR_DATA_LEN];
    authenticator_data[..32].copy_from_slice(&rp_id_hash);
    authenticator_data[32] = 0x05; // UP | UV

    let client_hash = sha256_bytes(client_data_json.as_slice());
    let mut msg = [0_u8; MIN_AUTHENTICATOR_DATA_LEN + 32];
    msg[..authenticator_data.len()].copy_from_slice(&authenticator_data);
    msg[authenticator_data.len()..].copy_from_slice(&client_hash);

    let signed: p256::ecdsa::Signature = key.sign(&msg);
    let normalized = signed.normalize_s();
    let Ok(signature) = UserSignature::decode(normalized.to_bytes().as_ref()) else {
        return None;
    };

    Some(WebAuthnSignature {
        signature,
        authenticator_data: byte_list_from_slice(&authenticator_data)?,
        client_data_json,
    })
}

#[cfg(test)]
/// Creates a deterministic `WebAuthn` signature for tests.
#[must_use]
pub fn mock_webauthn_sign(
    key: &p256::ecdsa::SigningKey,
    challenge: &Digest,
) -> Option<WebAuthnSignature> {
    mock_webauthn_sign_with_origin(key, challenge, MOCK_WEBAUTHN_ORIGIN)
}

#[cfg(test)]
#[allow(clippy::disallowed_types, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use commonware_codec::{DecodeExt, Encode};
    use hellas_kernel::test_support::{valid_mutual_close_tx, valid_open_tx};

    fn test_merge_inputs(values: &[ObjectId]) -> MergeInputs {
        let mut items = [ObjectId::from([0; 32]); MAX_MERGE_INPUTS];
        items[..values.len()].copy_from_slice(values);
        MergeInputs::new(items, values.len()).expect("test merge inputs fit")
    }

    fn sample_transfer(key: &p256::ecdsa::SigningKey) -> (Address, Transaction) {
        let sender_addr = addr_from_signing_key(key);
        let recipient = addr_from_signing_key(&secp256r1_key_from_seed(2));
        let input = Digest::from([7; 32]);
        let challenge = transfer_challenge(TEST_NETWORK, &input, &recipient, 5);
        let signature = mock_webauthn_sign(key, &challenge).expect("mock signature");
        (
            sender_addr,
            Transaction::Transfer {
                input,
                recipient,
                amount: 5,
                signature,
            },
        )
    }

    #[test]
    fn webauthn_signature_accepts_browser_der() {
        let key = secp256r1_key_from_seed(17);
        let challenge = Digest::from([9; 32]);
        let original = mock_webauthn_sign(&key, &challenge).unwrap();
        let signature = p256::ecdsa::Signature::from_slice(original.signature.as_ref()).unwrap();
        let decoded = WebAuthnSignature::from_der(
            signature.to_der().as_bytes(),
            original.authenticator_data.as_slice(),
            original.client_data_json.as_slice(),
        )
        .unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn object_coin_codec_uses_kernel_canonical_payload_and_zero_padding() {
        let address = addr_from_signing_key(&secp256r1_key_from_seed(1));
        let owner = SettlementKey::from(&address);
        let object = Object::Coin(Coin { owner, value: 123 });
        let encoded = object.encode();

        let kernel_coin = KernelCoin::issue(owner.into_kernel(), 123);
        let mut canonical = [0_u8; KernelCoin::MAX_ENCODED_SIZE];
        let canonical_len = kernel_coin.write_to(&mut canonical);

        assert_eq!(encoded.len(), Object::SIZE);
        assert_eq!(encoded[0], Object::COIN_TAG);
        assert_eq!(&encoded[1..1 + canonical_len], &canonical);
        assert!(encoded[1 + canonical_len..].iter().all(|byte| *byte == 0));
        assert_eq!(Object::decode(encoded).expect("object decode"), object);
    }

    #[test]
    fn object_edge_codec_uses_kernel_canonical_payload() {
        let edge = test_edge();
        let object = Object::Edge(edge);
        let encoded = object.encode();
        let mut canonical = [0_u8; KernelEdge::MAX_ENCODED_SIZE];
        let canonical_len = edge.write_to(&mut canonical);

        assert_eq!(canonical_len, Object::PAYLOAD_SIZE);
        assert_eq!(encoded[0], Object::EDGE_TAG);
        assert_eq!(&encoded[1..], &canonical);
        assert_eq!(Object::decode(encoded).expect("object decode"), object);
    }

    #[test]
    fn stored_object_stays_164_bytes_across_every_arm() {
        // The stored object is a one-byte kind tag plus a payload area
        // padded to the widest kernel arm. A registry chunk is 130
        // canonical bytes, under the 163-byte edge, so adding it did not
        // widen a single stored coin, edge, or chunk. This number is
        // load-bearing for the fixed-size QMDB journal: changing it
        // rewrites every stored object.
        assert_eq!(KernelRegistryChunk::MAX_ENCODED_SIZE, 130);
        assert_eq!(KernelEdge::MAX_ENCODED_SIZE, 163);
        const { assert!(KernelCoin::MAX_ENCODED_SIZE <= KernelEdge::MAX_ENCODED_SIZE) };
        assert_eq!(Object::PAYLOAD_SIZE, 163);
        assert_eq!(Object::SIZE, 164);

        let chunk = test_registry_chunk();
        for object in [
            Object::Coin(Coin {
                owner: SettlementKey::from_bytes([0x42; SettlementKey::LENGTH]),
                value: 7,
            }),
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
        let object = Object::Coin(Coin {
            owner: SettlementKey::from_bytes([0x42; SettlementKey::LENGTH]),
            value: 7,
        });
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
        assert_eq!(Address::try_from(decoded), Err(AddressError::InvalidKey));
    }

    #[test]
    fn address_converts_to_and_from_settlement_key() {
        let address = addr_from_signing_key(&secp256r1_key_from_seed(42));
        let key = SettlementKey::from(&address);
        assert_eq!(Address::try_from(key), Ok(address));
    }

    #[test]
    fn transfer_codec_roundtrip() {
        let key = secp256r1_key_from_seed(1);
        let (_, tx) = sample_transfer(&key);
        let encoded = tx.encode();
        let decoded = Transaction::decode(encoded).expect("tx decode");
        assert_eq!(decoded.encode(), tx.encode());
    }

    #[test]
    fn every_transaction_arm_max_encoding_fits_advisory_block_budget() {
        let webauthn_max = UserSignature::SIZE
            + MAX_AUTHENTICATOR_DATA_LEN.encode_size()
            + MAX_AUTHENTICATOR_DATA_LEN
            + MAX_CLIENT_DATA_JSON_LEN.encode_size()
            + MAX_CLIENT_DATA_JSON_LEN;
        let transfer_max = u8::SIZE + ObjectId::SIZE + Address::SIZE + u64::SIZE + webauthn_max;
        let merge_max = u8::SIZE
            + MAX_MERGE_INPUTS.encode_size()
            + MAX_MERGE_INPUTS * ObjectId::SIZE
            + webauthn_max;
        let kernel_max =
            u8::SIZE + KernelTx::MAX_ENCODED_SIZE.encode_size() + KernelTx::MAX_ENCODED_SIZE;

        for (arm, maximum) in [
            ("transfer", transfer_max),
            ("merge", merge_max),
            ("kernel", kernel_max),
        ] {
            assert!(
                maximum < MAX_BLOCK_TX_BYTES / 8,
                "{arm} maximum {maximum} is not far below advisory block budget {MAX_BLOCK_TX_BYTES}"
            );
        }
    }

    /// A maximum-width close start: the widest revealed payment terms
    /// plus a present certificate.
    fn payment_close_start_tx() -> KernelTx {
        use hellas_kernel::{
            EarnedCertificate, Move, Party, PaymentCloseStart, Payout as KernelPayout, Sig,
            Terms as KernelTerms, WorkPaymentTerms, WorkStakeBondTerms,
        };

        let maker = hellas_kernel::Key::from_bytes([0x31; 33]);
        let taker = hellas_kernel::Key::from_bytes([0x32; 33]);
        let bond = WorkStakeBondTerms {
            parties: hellas_kernel::Parties::new(taker, maker),
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
            Some((certificate, Sig::from_bytes([0x66; 64]))),
            Sig::from_bytes([0x77; 64]),
        )))
    }

    fn payment_close_response_tx() -> KernelTx {
        use hellas_kernel::{
            EarnedCertificate, Move, Party, PaymentCloseResponse, Sig, StartId, TermsHash,
        };

        let edge = hellas_kernel::EdgeId::from_bytes([0x11; 32]);
        let terms = TermsHash::from_bytes([0x22; 32]);
        KernelTx::move_action(Move::RespondPaymentClose(PaymentCloseResponse::new(
            edge,
            StartId::from_bytes([0x33; 32]),
            Party::Taker,
            (
                EarnedCertificate::new(edge, terms, 4_242),
                Sig::from_bytes([0x66; 64]),
            ),
            Sig::from_bytes([0x77; 64]),
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
        let Transaction::Kernel(decoded) = decoded else {
            panic!("expected kernel transaction")
        };
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
            (payment_close_start_tx(), 619, 622),
            (payment_close_response_tx(), 274, 277),
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
    fn kernel_signature_verification_stays_inside_the_kernel() {
        let owner = addr_from_signing_key(&secp256r1_key_from_seed(1));
        let tx = Transaction::Kernel(valid_open_tx().expect("valid kernel open fixture"));
        assert!(!tx.verify_signature(TEST_NETWORK, &owner));
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

    /// Renders bytes for the golden-vector comparisons below.
    ///
    /// Local rather than `hex::encode`: `hex` arrives with the
    /// `indexer` feature, but this module compiles under `domain`
    /// alone, so reaching for it made `--features domain` fail to
    /// build its own tests.
    fn hex(bytes: &[u8]) -> String {
        bytes.iter().fold(String::new(), |mut out, byte| {
            use core::fmt::Write as _;
            let _ = write!(out, "{byte:02x}");
            out
        })
    }

    #[test]
    fn transaction_codec_rejects_unknown_tag() {
        assert!(Transaction::decode([0xff].as_slice()).is_err());
    }

    #[test]
    fn transfer_codec_matches_golden_bytes() {
        let key = secp256r1_key_from_seed(1);
        let (_, tx) = sample_transfer(&key);
        assert_eq!(
            hex(&tx.encode()),
            "00070707070707070707070707070707070707070707070707070707070707070703e57aa4ea4cd5ed2c6e5b23a5c9895b2ef185df9a63876b948e53179a9072787000000000000000055515839a903a3667bfd81cb8a112a4c33d392b489741d8caa5b0aca0a27678071efbd051540628bd0039b747a2e75c325f4dc01361241806d94112d327b8817125d6200140e870713dad50719cecb0abe5d8444155b8ab423f64c4358a412dcd52050000000089017b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a2276764f315f77344373763270344c4d4e68485964766275733465743748486d4a7a316e316f465f58544a63222c226f726967696e223a2268747470733a2f2f77616c6c65742e68656c6c61732e6169222c2263726f73734f726967696e223a66616c73657d"
        );
    }

    #[test]
    fn merge_codec_roundtrip() {
        let key = secp256r1_key_from_seed(1);
        let mut values = [
            Digest::from([3; 32]),
            Digest::from([1; 32]),
            Digest::from([2; 32]),
        ];
        values.sort();
        let inputs = test_merge_inputs(&values);
        let challenge = merge_challenge(TEST_NETWORK, inputs.as_slice());
        let tx = Transaction::MergeCoin {
            inputs,
            signature: mock_webauthn_sign(&key, &challenge).expect("mock signature"),
        };
        let encoded = tx.encode();
        let decoded = Transaction::decode(encoded).expect("tx decode");
        assert_eq!(decoded.encode(), tx.encode());
    }

    #[test]
    fn merge_codec_matches_golden_bytes() {
        let key = secp256r1_key_from_seed(1);
        let mut values = [
            Digest::from([3; 32]),
            Digest::from([1; 32]),
            Digest::from([2; 32]),
        ];
        values.sort();
        let inputs = test_merge_inputs(&values);
        let challenge = merge_challenge(TEST_NETWORK, inputs.as_slice());
        let tx = Transaction::MergeCoin {
            inputs,
            signature: mock_webauthn_sign(&key, &challenge).expect("mock signature"),
        };
        assert_eq!(
            hex(&tx.encode()),
            "010301010101010101010101010101010101010101010101010101010101010101010202020202020202020202020202020202020202020202020202020202020202030303030303030303030303030303030303030303030303030303030303030359c01cf0a9db59d8ed0dd411537f2386cca8faf41f3d577fe2432f2482f3cc517de9a527c492d08b5454b5680903b28530a6b9af0a882a00ef60dbf570593c7925d6200140e870713dad50719cecb0abe5d8444155b8ab423f64c4358a412dcd52050000000089017b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a227a3075326c4f53546c78305038334844387946734c37745f422d6a5f4b79326e62516a5f325558756d3149222c226f726967696e223a2268747470733a2f2f77616c6c65742e68656c6c61732e6169222c2263726f73734f726967696e223a66616c73657d"
        );
    }

    #[test]
    fn signature_verification_succeeds_with_correct_key() {
        let key = secp256r1_key_from_seed(1);
        let (sender, tx) = sample_transfer(&key);
        assert!(tx.verify_signature(TEST_NETWORK, &sender));
    }

    #[test]
    fn signature_verification_fails_with_wrong_key() {
        let key = secp256r1_key_from_seed(1);
        let wrong = addr_from_signing_key(&secp256r1_key_from_seed(2));
        let (_, tx) = sample_transfer(&key);
        assert!(!tx.verify_signature(TEST_NETWORK, &wrong));
    }

    #[test]
    fn signature_verification_fails_with_wrong_origin() {
        let key = secp256r1_key_from_seed(1);
        let (sender, mut tx) = sample_transfer(&key);
        let Transaction::Transfer {
            input,
            recipient,
            amount,
            signature,
        } = &mut tx
        else {
            panic!("expected transfer")
        };
        let challenge = transfer_challenge(TEST_NETWORK, input, recipient, *amount);
        signature.client_data_json =
            client_data_json_for_origin(&challenge, "https://evil.example").expect("client data");
        assert!(!tx.verify_signature(TEST_NETWORK, &sender));
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
            SettlementKey::from(addr_from_signing_key(&key)).to_string()
        }

        let (json, scalars) = (crate::genesis::HELLAS_DEVNET_1_JSON, [1_u8, 2]);
        let genesis: crate::genesis::Genesis =
            serde_json::from_str(json).expect("shipped document parses");
        let funded: Vec<&str> = genesis
            .allocations
            .iter()
            .map(|allocation| allocation.address.as_str())
            .collect();
        let mut expected: Vec<String> = scalars.iter().copied().map(address_for).collect();
        // The foundation allocation is documented in the network README; its
        // key is generated independently, not derived from a public scalar.
        expected.push("25uDmUCQcwYUHHyXthtEspGB2KVTmbys8vTSqAMXKNqRV".to_string());
        assert_eq!(funded, expected, "{}", genesis.network_id);
    }

    #[test]
    fn address_base58_roundtrip() {
        let addr = addr_from_signing_key(&secp256r1_key_from_seed(42));
        let encoded = addr.to_string();
        let decoded: Address = encoded.parse().expect("base58 decode");
        assert_eq!(addr, decoded);
    }

    #[test]
    fn challenge_prefix_declares_the_runtime_network_length() {
        let mut buf = BytesMut::new();
        challenge_prefix(&mut buf, TEST_NETWORK, TRANSFER_TAG);

        let after_domain = &buf[CHALLENGE_DOMAIN.len()..];
        assert_eq!(after_domain[0], WEBAUTHN_POLICY_VERSION);
        let declared_len = after_domain[1] as usize;
        assert_eq!(declared_len, TEST_NETWORK.as_bytes().len());
        assert_eq!(&after_domain[2..2 + declared_len], TEST_NETWORK.as_bytes());
        assert_eq!(after_domain[2 + declared_len], TRANSFER_TAG);
    }

    /// The whole point of making the network a runtime value: two
    /// networks must not produce the same challenge, and a passkey
    /// signature made for one must not verify under the other.
    #[test]
    fn a_challenge_is_bound_to_one_network() {
        let other = NetworkId::new("hellas-chain-other").expect("legal id");
        let key = PrivateKey::from_seed(3);
        let sender = Address::from(key.public_key());
        let input = ObjectId::from([9; 32]);
        let recipient = Address::from(PrivateKey::from_seed(4).public_key());

        assert_ne!(
            transfer_challenge(TEST_NETWORK, &input, &recipient, 5),
            transfer_challenge(other, &input, &recipient, 5),
        );
        assert_ne!(
            merge_challenge(TEST_NETWORK, &[input]),
            merge_challenge(other, &[input]),
        );

        let tx = Transaction::transfer(TEST_NETWORK, &key, input, recipient, 5)
            .expect("test transfer signs");
        assert!(tx.verify_signature(TEST_NETWORK, &sender));
        assert!(
            !tx.verify_signature(other, &sender),
            "a transfer authorized on one network must not settle on another",
        );

        let merge = Transaction::merge(TEST_NETWORK, &key, &[input]).expect("test merge signs");
        assert!(merge.verify_signature(TEST_NETWORK, &sender));
        assert!(
            !merge.verify_signature(other, &sender),
            "a merge authorized on one network must not settle on another",
        );
    }

    #[test]
    fn bounded_read_rejects_len_over_capacity_despite_loose_range() {
        // A caller passing a RangeCfg wider than the type's capacity must
        // still get a decode error, not a corrupt list.
        let oversized: Bounded<u8, 8> = byte_list_from_slice(&[7; 8]).expect("fits");
        let encoded = oversized.encode();
        let decoded =
            Bounded::<u8, 4>::read_cfg(&mut encoded.as_ref(), &(RangeCfg::new(0..=usize::MAX), ()));
        assert!(matches!(decoded, Err(CodecError::InvalidLength(8))));
    }

    #[cfg(any(feature = "indexer", feature = "validator"))]
    #[test]
    fn merge_input_faults_are_reported_in_order() {
        let id = |b: u8| ObjectId::from([b; 32]);
        assert_eq!(merge_input_fault(&[id(1)]), Some(MergeInputFault::TooFew));
        assert_eq!(
            merge_input_fault(&[id(1), id(1)]),
            Some(MergeInputFault::Duplicate(id(1))),
        );
        assert_eq!(
            merge_input_fault(&[id(3), id(1)]),
            Some(MergeInputFault::NonCanonical),
        );
        assert_eq!(merge_input_fault(&[id(1), id(2), id(3)]), None);
    }
}
