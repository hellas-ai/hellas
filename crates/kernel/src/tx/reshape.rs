//! The owner transaction: consume owned coins, issue coins.
//!
//! One shape covers everything an owner does to its own coins without an
//! edge: delegating them to a node key, clearing a delegation, sweeping
//! them back, splitting, merging, and paying a third party. Each is "the
//! owner consumes coins it owns and issues coins", so there is one
//! transition and no per-purpose variant.
//!
//! # Why a reshape consumes its inputs
//!
//! A delegation that edited a coin in place would be a message with no
//! consumed input, and a message with no consumed input verifies the
//! same way every time it is submitted: the bytes that delegated a coin
//! to a node could be replayed after the owner cleared that delegation,
//! re-arming the key the owner had just fired. Consuming the inputs and
//! issuing fresh coins makes every reshape one-use — a replay fails on
//! its first input, which no longer exists.
//!
//! Abstract counterpart: the `reshape` action in `models/delegation.qnt`.

use hellas_xet::SingleChunkHasher;

use crate::{
    canonical::{Decode, DecodeError, Encode, Writer, decode_field},
    consts::{MAX_EDGE_INPUTS, MAX_EDGE_OUTPUTS},
    context::{Context, Cost},
    error::{ApplyError, InvalidReshapeReason, KernelResult},
    event::Change,
    list::List,
    network::NetworkId,
    object::Coin,
    primitive::{CoinId, PayloadHash},
    store::Batch,
    tx::{Auth, Payout},
    verifier::SigVerifier,
};

type Inputs = List<CoinId, MAX_EDGE_INPUTS>;
type Outputs = List<Payout, MAX_EDGE_OUTPUTS>;

/// An owner's reshape of its own coins.
///
/// Every input must exist and share one owner, `auth` must be that
/// owner's over [`Reshape::payload_hash`], and the outputs must carry
/// exactly the value the inputs held. Outputs may name any owner and any
/// delegate: paying a third party, or delegating to a node key, is the
/// owner's decision and this is the one place it is made.
#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub struct Reshape {
    inputs: Inputs,
    outputs: Outputs,
    auth: Auth,
}

impl Reshape {
    /// Creates a reshape.
    #[must_use]
    pub const fn new(inputs: Inputs, outputs: Outputs, auth: Auth) -> Self {
        Self {
            inputs,
            outputs,
            auth,
        }
    }

    /// Returns the coins consumed.
    #[must_use]
    pub const fn inputs(&self) -> &Inputs {
        &self.inputs
    }

    /// Returns the coins issued.
    #[must_use]
    pub const fn outputs(&self) -> &Outputs {
        &self.outputs
    }

    /// Returns the owner's authorization.
    #[must_use]
    pub const fn auth(&self) -> &Auth {
        &self.auth
    }

    /// Returns the hash the owner signs to reshape `inputs` into
    /// `outputs` on `network`.
    ///
    /// Network-bound for the same reason as [`crate::Tx::open_hash`]: two
    /// deployments seeded alike derive the same coin ids, and an owner's
    /// reshape on one must not spend the same-named coins on the other.
    #[must_use]
    pub fn payload_hash(network: NetworkId, inputs: &Inputs, outputs: &Outputs) -> PayloadHash {
        let mut hasher = SingleChunkHasher::new();
        hasher.update(crate::consts::OWNER_RESHAPE);
        network.encode_to(&mut hasher);
        inputs.encode_to(&mut hasher);
        outputs.encode_to(&mut hasher);
        PayloadHash::from_bytes(hasher.finalize().into_bytes())
    }

    /// Returns the ids of the coins a reshape of `inputs` into `outputs`
    /// issues on `network`, in output order.
    #[must_use]
    pub fn output_ids(
        network: NetworkId,
        inputs: &Inputs,
        outputs: &Outputs,
    ) -> List<CoinId, MAX_EDGE_OUTPUTS> {
        let mut ids = [CoinId::ZERO; MAX_EDGE_OUTPUTS];
        for (index, (slot, payout)) in ids.iter_mut().zip(outputs).enumerate() {
            *slot = output_id(network, inputs, index, *payout);
        }
        List::take(ids, outputs.len())
    }

    /// Returns the deterministic resource cost of this reshape: every
    /// coin it consumes or issues, and its one signature.
    #[must_use]
    pub fn cost(&self) -> Cost {
        let slots = self.inputs.len().saturating_add(self.outputs.len());
        Cost::new(1, u64::try_from(slots).unwrap_or(u64::MAX), 1)
    }

    pub(super) fn apply<B, V>(
        &self,
        context: Context,
        verifier: &V,
        batch: &B,
    ) -> KernelResult<Change>
    where
        B: Batch,
        V: SigVerifier + ?Sized,
    {
        let reject = |reason| ApplyError::InvalidReshape { reason };
        if let Some(id) = super::duplicate(self.inputs.as_slice()) {
            return Err(ApplyError::DuplicateInput { id });
        }

        let mut coins = [(CoinId::ZERO, Coin::ZERO); MAX_EDGE_INPUTS];
        for (slot, id) in coins.iter_mut().zip(&self.inputs) {
            let coin = batch.coin(*id).ok_or(ApplyError::MissingCoin { id: *id })?;
            *slot = (*id, coin);
        }
        let coins = List::take(coins, self.inputs.len());

        // One owner signs one reshape. The delegate is not consulted: a
        // reshape is an owner's act, and a delegate's reach ends at the
        // opens it may fund.
        let Some((_, first)) = coins.as_slice().first() else {
            return Err(reject(InvalidReshapeReason::NoInputs));
        };
        let owner = first.owner();
        if coins.iter().any(|(_, coin)| coin.owner() != owner) {
            return Err(reject(InvalidReshapeReason::OwnerMismatch));
        }

        let held = coins
            .checked_sum(|(_, coin)| coin.value())
            .ok_or_else(|| reject(InvalidReshapeReason::ValueOverflow))?;
        let issued = self
            .outputs
            .checked_sum(|payout| payout.value())
            .ok_or_else(|| reject(InvalidReshapeReason::ValueOverflow))?;
        if held != issued {
            return Err(reject(InvalidReshapeReason::ValueMismatch));
        }

        let network = context.network();
        let mut issued_coins = [(CoinId::ZERO, Coin::ZERO); MAX_EDGE_OUTPUTS];
        for (index, (slot, payout)) in issued_coins.iter_mut().zip(&self.outputs).enumerate() {
            let id = output_id(network, &self.inputs, index, *payout);
            if batch.coin(id).is_some() {
                return Err(ApplyError::OutputExists { id });
            }
            *slot = (id, payout.coin());
        }
        let issued_coins = List::take(issued_coins, self.outputs.len());

        // Cryptography last, as on every other path.
        let hash = Self::payload_hash(network, &self.inputs, &self.outputs);
        if !verifier.verify_auth(&self.auth, owner, hash) {
            return Err(reject(InvalidReshapeReason::BadSignature));
        }
        Ok(Change::reshape(&coins, &issued_coins))
    }
}

fn output_id(network: NetworkId, inputs: &Inputs, index: usize, payout: Payout) -> CoinId {
    let mut hasher = SingleChunkHasher::new();
    hasher.update(crate::consts::COIN_RESHAPE);
    network.encode_to(&mut hasher);
    inputs.encode_to(&mut hasher);
    index.encode_to(&mut hasher);
    payout.owner().encode_to(&mut hasher);
    CoinId::from_bytes(hasher.finalize().into_bytes())
}

impl Encode for Reshape {
    const MAX_ENCODED_SIZE: usize =
        Inputs::MAX_ENCODED_SIZE + Outputs::MAX_ENCODED_SIZE + Auth::MAX_ENCODED_SIZE;

    fn encoded_size(&self) -> usize {
        self.inputs.encoded_size() + self.outputs.encoded_size() + self.auth.encoded_size()
    }

    fn encode_to<W: Writer + ?Sized>(&self, writer: &mut W) {
        self.inputs.encode_to(writer);
        self.outputs.encode_to(writer);
        self.auth.encode_to(writer);
    }
}

impl Decode for Reshape {
    fn decode(buf: &[u8]) -> Result<(Self, usize), DecodeError> {
        let mut consumed = 0;
        let inputs = decode_field(buf, &mut consumed)?;
        let outputs = decode_field(buf, &mut consumed)?;
        let auth = decode_field(buf, &mut consumed)?;
        Ok((Self::new(inputs, outputs, auth), consumed))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitive::Key;

    /// Every preimage this module hashes stays inside one Xet chunk at
    /// its widest: a node cannot unwind from the hasher's assert.
    #[test]
    fn reshape_preimages_fit_one_xet_chunk() {
        let payload = crate::consts::OWNER_RESHAPE.len()
            + NetworkId::MAX_ENCODED_SIZE
            + Inputs::MAX_ENCODED_SIZE
            + Outputs::MAX_ENCODED_SIZE;
        let id = crate::consts::COIN_RESHAPE.len()
            + NetworkId::MAX_ENCODED_SIZE
            + Inputs::MAX_ENCODED_SIZE
            + usize::MAX_ENCODED_SIZE
            + Key::MAX_ENCODED_SIZE;
        assert!(payload < hellas_xet::MIN_CHUNK_SIZE);
        assert!(id < hellas_xet::MIN_CHUNK_SIZE);
    }
}
