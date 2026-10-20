//! Owner-authorized delegation and reclamation of live coins.
//!
//! Preparation reads one finalized snapshot. The owner signs the resulting
//! kernel payload; submission consumes precisely those inputs, so racing spends
//! and replay are rejected by consensus instead of changing another coin.

use hellas_chain::{LightClient, QueryError};
use hellas_kernel::{
    Auth, CoinId, Key, List, MAX_EDGE_INPUTS, MAX_EDGE_OUTPUTS, NetworkId, PayloadHash, Payout,
    Reshape, Secp256k1Verifier, SigVerifier, Tx,
};

#[derive(Debug, thiserror::Error)]
pub enum CoinOwnerError {
    #[error(transparent)]
    Query(#[from] QueryError),
    #[error("the chain has no finalized snapshot")]
    NoSnapshot,
    #[error("coin selection must contain 1 to {MAX_EDGE_INPUTS} inputs")]
    Inputs,
    #[error("selected coin is absent: {0:?}")]
    Missing(CoinId),
    #[error("selected coin belongs to another owner: {0:?}")]
    Owner(CoinId),
    #[error("selected coin values overflow")]
    ValueOverflow,
    #[error("chain network does not match the requested signing network")]
    Network,
    #[error("authorization is not the selected owner's signature over this reshape")]
    Authorization,
}

/// The exact inputs and output an owner is asked to authorize.
/// The output stays with that owner; only its delegation changes.
#[derive(Debug, Clone)]
pub struct OwnerReshape {
    network: NetworkId,
    owner: Key,
    inputs: List<CoinId, MAX_EDGE_INPUTS>,
    outputs: List<Payout, MAX_EDGE_OUTPUTS>,
}

impl OwnerReshape {
    /// Read the selected live coins at one finalized block. `None` reclaims
    /// them without a delegate; `Some(node)` delegates the resulting coin.
    pub async fn prepare<C: LightClient>(
        chain: &C,
        network: NetworkId,
        owner: Key,
        selected: &[CoinId],
        delegate: Option<Key>,
    ) -> Result<Self, CoinOwnerError> {
        if selected.is_empty() || selected.len() > MAX_EDGE_INPUTS {
            return Err(CoinOwnerError::Inputs);
        }
        if chain.get_consensus_info().await?.network_id != network.as_str() {
            return Err(CoinOwnerError::Network);
        }
        let snapshot = chain
            .get_latest_block()
            .await?
            .ok_or(CoinOwnerError::NoSnapshot)?;
        let mut value = 0_u64;
        let mut inputs = [CoinId::from_bytes([0; CoinId::LENGTH]); MAX_EDGE_INPUTS];
        for (slot, id) in inputs.iter_mut().zip(selected) {
            let coin = chain
                .get_coin(snapshot.payload, id.to_bytes().into())
                .await?
                .ok_or(CoinOwnerError::Missing(*id))?;
            if coin.owner.into_kernel() != owner {
                return Err(CoinOwnerError::Owner(*id));
            }
            value = value
                .checked_add(coin.value)
                .ok_or(CoinOwnerError::ValueOverflow)?;
            *slot = *id;
        }
        Ok(Self {
            network,
            owner,
            inputs: List::take(inputs, selected.len()),
            outputs: List::take(
                [Payout::delegated(owner, delegate, value); MAX_EDGE_OUTPUTS],
                1,
            ),
        })
    }

    #[must_use]
    pub fn payload_hash(&self) -> PayloadHash {
        Reshape::payload_hash(self.network, &self.inputs, &self.outputs)
    }

    #[must_use]
    pub const fn inputs(&self) -> &List<CoinId, MAX_EDGE_INPUTS> {
        &self.inputs
    }

    #[must_use]
    pub const fn outputs(&self) -> &List<Payout, MAX_EDGE_OUTPUTS> {
        &self.outputs
    }

    #[must_use]
    pub fn output_ids(&self) -> List<CoinId, MAX_EDGE_OUTPUTS> {
        Reshape::output_ids(self.network, &self.inputs, &self.outputs)
    }

    /// Bind a native or passkey owner authorization to these exact bytes.
    pub fn authorize(self, auth: Auth) -> Result<Tx, CoinOwnerError> {
        if !Secp256k1Verifier::new().verify_auth(&auth, self.owner, self.payload_hash()) {
            return Err(CoinOwnerError::Authorization);
        }
        Ok(Tx::Owner(Reshape::new(self.inputs, self.outputs, auth)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hellas_kernel::Secp256k1Signer;

    #[test]
    fn delegate_cannot_authorize_owner_sweep_or_reuse_delegation_signature() {
        let owner = Secp256k1Signer::from_secret_scalar([11; 32]).unwrap();
        let node = Secp256k1Signer::from_secret_scalar([12; 32]).unwrap();
        let plan = OwnerReshape {
            network: NetworkId::new("owner-reshape-test").unwrap(),
            owner: owner.party_key(),
            inputs: List::take([CoinId::from_bytes([1; 32]); MAX_EDGE_INPUTS], 1),
            outputs: List::take(
                [Payout::delegated(owner.party_key(), Some(node.party_key()), 100);
                    MAX_EDGE_OUTPUTS],
                1,
            ),
        };
        let delegation_auth = Auth::native(owner.sign(plan.payload_hash()));
        let mut sweep = plan.clone();
        sweep.outputs = List::take([Payout::new(owner.party_key(), 100); MAX_EDGE_OUTPUTS], 1);
        assert!(matches!(
            sweep
                .clone()
                .authorize(Auth::native(node.sign(sweep.payload_hash()))),
            Err(CoinOwnerError::Authorization)
        ));
        assert!(matches!(
            sweep.clone().authorize(delegation_auth.clone()),
            Err(CoinOwnerError::Authorization)
        ));
        assert_ne!(plan.payload_hash(), sweep.payload_hash());
        let Tx::Owner(tx) = sweep
            .clone()
            .authorize(Auth::native(owner.sign(sweep.payload_hash())))
            .unwrap()
        else {
            panic!("owner reshape")
        };
        assert_eq!(
            tx.outputs().as_slice(),
            &[Payout::new(owner.party_key(), 100)]
        );
        assert!(plan.authorize(delegation_auth).is_ok());
    }
    #[test]
    fn standalone_sdk_accepts_a_passkey_owner() {
        let owner = hellas_kernel::SoftPasskey::from_secret_scalar([21; 32]).unwrap();
        let plan = OwnerReshape {
            network: NetworkId::new("owner-passkey-test").unwrap(),
            owner: owner.party_key(),
            inputs: List::take([CoinId::from_bytes([1; 32]); MAX_EDGE_INPUTS], 1),
            outputs: List::take([Payout::new(owner.party_key(), 100); MAX_EDGE_OUTPUTS], 1),
        };
        let auth = Auth::webauthn(owner.sign(plan.payload_hash()).unwrap());
        assert!(plan.authorize(auth).is_ok());
    }
}
