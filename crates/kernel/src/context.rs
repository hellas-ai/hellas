//! Block context and deterministic resource pricing.
//!
//! Abstract counterpart: the `height` state var in `models/l1.qnt` (read
//! by the `proofOk` Timeout guard in `models/verifier.qnt`).
//!
//! # Assumed of consensus
//!
//! **Block height advances monotonically across the chain.** The kernel
//! reads [`BlockHeight`] off the [`Context`] it is handed and trusts it
//! without re-checking any apply against the last one it saw. Consensus
//! guarantees the monotonicity; `models/l1.qnt` gets it by construction,
//! because `tick` is the only action that moves `height` and it only
//! ever increments. Violation: a timeout proof fires at the wrong block,
//! or a `Mutual` close is admitted after its edge expired.
//!
//! # Not modelled: the network
//!
//! [`NetworkId`] has no abstract counterpart. The models are
//! single-network and have no notion of a network at all: `openAuthOk`
//! and `proofOk` say only "the named party authorized this", never
//! "...here". That is deliberate. Cross-network replay is not a temporal
//! property — no reachable sequence of actions on one network exhibits
//! it — so a two-network model would multiply the state space without
//! making any new property expressible. It is a hash-domain property:
//! [`crate::Tx::open_hash`] and [`crate::Tx::payload_hash`] commit to
//! this field, and `tests/network.rs` pins it by replaying an identical
//! transaction under two networks and requiring the second to be
//! rejected. Consequence if the domains were *not* separated: every
//! proof in every model here would still hold, and would still be about
//! a chain whose witnesses another chain could spend.
//!
//! # Block time
//!
//! [`Context::block_time_ms`] is the timestamp the block itself carries,
//! which consensus has already bounded: never before its parent's, and
//! never more than [`crate::MAX_BLOCK_TIME_LEAD_MS`] past a verifier's
//! clock. One rule reads it — the close response deadline — because
//! that is the one settlement semantic racing a remote watcher's clock.
//!
//! # Deliberately absent
//!
//! - **Validator set.** The kernel never checks "is this signer in the
//!   active set?" — that knowledge lives in whichever
//!   [`crate::SigVerifier`] implementations
//!   the chain wires in. A future dispute mode that wants validator-
//!   quorum-signed seals expresses that policy inside the verifier
//!   impls; [`Context`] stays oblivious.

use crate::canonical::{
    Decode, DecodeError, ENVELOPE_SIZE, Encode, Writer, decode_envelope, decode_field,
    encode_envelope, tag,
};
use crate::consts::HASH_LENGTH;
use crate::network::NetworkId;

/// Hash of the previous finalized block.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub struct BlockHash([u8; Self::LENGTH]);

impl BlockHash {
    /// Encoded length of a block hash.
    pub const LENGTH: usize = HASH_LENGTH;

    /// Creates a block hash from canonical bytes.
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

/// Deterministic resource units consumed by one operation.
///
/// Three dimensions:
///
///   - `base`: fixed per-op overhead (always 1 for kernel ops; 0 for the
///     proof contribution alone).
///   - `slots`: each touched store slot. The kernel reads each slot for an
///     existence check and writes it for the insert/remove that follows, so
///     reads and writes always match — they are folded into one dimension.
///   - `proofs`: signature/seal verifications.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub struct Cost {
    base: u64,
    slots: u64,
    proofs: u64,
}

impl Cost {
    /// Zero resource cost.
    pub const ZERO: Self = Self {
        base: 0,
        slots: 0,
        proofs: 0,
    };

    /// Creates a resource cost.
    #[must_use]
    pub const fn new(base: u64, slots: u64, proofs: u64) -> Self {
        Self {
            base,
            slots,
            proofs,
        }
    }

    /// Returns the fixed operation unit count.
    #[must_use]
    pub const fn base(self) -> u64 {
        self.base
    }

    /// Returns the touched-slot unit count.
    #[must_use]
    pub const fn slots(self) -> u64 {
        self.slots
    }

    /// Returns the proof-verification unit count.
    #[must_use]
    pub const fn proofs(self) -> u64 {
        self.proofs
    }

    /// Adds two resource costs, returning `None` on overflow.
    #[must_use]
    pub fn checked_add(self, other: Self) -> Option<Self> {
        Some(Self {
            base: self.base.checked_add(other.base)?,
            slots: self.slots.checked_add(other.slots)?,
            proofs: self.proofs.checked_add(other.proofs)?,
        })
    }

    /// Returns true if every cost dimension is within `budget`.
    #[must_use]
    pub const fn fits(self, budget: Self) -> bool {
        self.base <= budget.base && self.slots <= budget.slots && self.proofs <= budget.proofs
    }
}

/// Deterministic fee schedule for kernel operation costs and live edge
/// lifetime.
///
/// `base`, `slot`, and `proof` price [`Cost`] dimensions. `lifetime` prices
/// each live edge slot per prepaid block and is charged explicitly on open;
/// it is not part of [`Cost`].
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub struct Fees {
    base: u64,
    slot: u64,
    proof: u64,
    lifetime: u64,
}

impl Fees {
    /// Zero-fee schedule for tests and local models.
    pub const ZERO: Self = Self {
        base: 0,
        slot: 0,
        proof: 0,
        lifetime: 0,
    };

    /// Creates a fee schedule.
    #[must_use]
    pub const fn new(base: u64, slot: u64, proof: u64, lifetime: u64) -> Self {
        Self {
            base,
            slot,
            proof,
            lifetime,
        }
    }

    /// Returns the price per fixed operation unit.
    #[must_use]
    pub const fn base(self) -> u64 {
        self.base
    }

    /// Returns the price per touched-slot unit.
    #[must_use]
    pub const fn slot(self) -> u64 {
        self.slot
    }

    /// Returns the price per proof-verification unit.
    #[must_use]
    pub const fn proof(self) -> u64 {
        self.proof
    }

    /// Returns the price per live edge slot per prepaid block.
    #[must_use]
    pub const fn lifetime(self) -> u64 {
        self.lifetime
    }

    /// Calculates the fee for `cost`.
    #[must_use]
    pub fn charge(self, cost: Cost) -> Option<u64> {
        let base = self.base.checked_mul(cost.base())?;
        let slots = self.slot.checked_mul(cost.slots())?;
        let proofs = self.proof.checked_mul(cost.proofs())?;
        base.checked_add(slots)?.checked_add(proofs)
    }
}

impl Encode for Fees {
    const MAX_ENCODED_SIZE: usize = ENVELOPE_SIZE + 4 * u64::MAX_ENCODED_SIZE;

    fn encoded_size(&self) -> usize {
        Self::MAX_ENCODED_SIZE
    }

    fn encode_to<W: Writer + ?Sized>(&self, writer: &mut W) {
        encode_envelope(writer, tag::FEES);
        self.base.encode_to(writer);
        self.slot.encode_to(writer);
        self.proof.encode_to(writer);
        self.lifetime.encode_to(writer);
    }
}

impl Decode for Fees {
    fn decode(buf: &[u8]) -> Result<(Self, usize), DecodeError> {
        let mut consumed = decode_envelope(buf, tag::FEES)?;
        let base = decode_field(buf, &mut consumed)?;
        let slot = decode_field(buf, &mut consumed)?;
        let proof = decode_field(buf, &mut consumed)?;
        let lifetime = decode_field(buf, &mut consumed)?;
        Ok((Self::new(base, slot, proof, lifetime), consumed))
    }
}

/// Monotonic finalized block height.
#[derive(Debug, Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BlockHeight(u64);

impl BlockHeight {
    /// Creates a block height.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the integer block height.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl Encode for BlockHeight {
    const MAX_ENCODED_SIZE: usize = ENVELOPE_SIZE + u64::MAX_ENCODED_SIZE;

    fn encoded_size(&self) -> usize {
        Self::MAX_ENCODED_SIZE
    }

    fn encode_to<W: Writer + ?Sized>(&self, writer: &mut W) {
        encode_envelope(writer, tag::BLOCK_HEIGHT);
        self.0.encode_to(writer);
    }
}

impl Decode for BlockHeight {
    fn decode(buf: &[u8]) -> Result<(Self, usize), DecodeError> {
        let mut consumed = decode_envelope(buf, tag::BLOCK_HEIGHT)?;
        let value = decode_field(buf, &mut consumed)?;
        Ok((Self::new(value), consumed))
    }
}

/// Explicit context for applying one ordered kernel operation.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub struct Context {
    network: NetworkId,
    block_height: BlockHeight,
    block_time_ms: u64,
    previous_hash: BlockHash,
    fees: Fees,
}

impl Context {
    /// Creates an operation context.
    ///
    /// `network` is not optional and has no default: every
    /// authorization the kernel checks under this context commits to
    /// it, and a context that could not name its network would let one
    /// network's signatures settle on another.
    #[must_use]
    pub const fn new(
        network: NetworkId,
        block_height: BlockHeight,
        block_time_ms: u64,
        previous_hash: BlockHash,
    ) -> Self {
        Self::with_fees(
            network,
            block_height,
            block_time_ms,
            previous_hash,
            Fees::ZERO,
        )
    }

    /// Creates an operation context with an explicit fee schedule.
    #[must_use]
    pub const fn with_fees(
        network: NetworkId,
        block_height: BlockHeight,
        block_time_ms: u64,
        previous_hash: BlockHash,
        fees: Fees,
    ) -> Self {
        Self {
            network,
            block_height,
            block_time_ms,
            previous_hash,
            fees,
        }
    }

    /// Returns the network every authorization under this context is
    /// bound to.
    #[must_use]
    pub const fn network(self) -> NetworkId {
        self.network
    }

    /// Returns the finalized block height for this operation.
    #[must_use]
    pub const fn block_height(self) -> BlockHeight {
        self.block_height
    }

    /// Returns the block's own timestamp, in milliseconds.
    #[must_use]
    pub const fn block_time_ms(self) -> u64 {
        self.block_time_ms
    }

    /// Returns the previous finalized block hash.
    #[must_use]
    pub const fn previous_hash(self) -> BlockHash {
        self.previous_hash
    }

    /// Returns the fee schedule active for this operation.
    #[must_use]
    pub const fn fees(self) -> Fees {
        self.fees
    }

    /// Calculates the fee for `cost` under the active schedule.
    #[must_use]
    pub fn fee(self, cost: Cost) -> Option<u64> {
        self.fees.charge(cost)
    }
}
