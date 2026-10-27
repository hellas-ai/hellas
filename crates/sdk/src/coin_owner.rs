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
    #[error("channel requires {required} but at most four eligible coins provide {available}")]
    Insufficient { required: u64, available: u64 },
    #[error(transparent)]
    Query(#[from] QueryError),
    #[error("the chain has no finalized snapshot")]
    NoSnapshot,
    #[error("coin selection must contain 1 to {MAX_EDGE_INPUTS} distinct inputs")]
    Inputs,
    #[error("selected coin is absent from this owner's live coins: {0:?}")]
    Missing(CoinId),
    #[error("split requires a positive delegated value within the selected balance")]
    Split,
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
    floor: Option<(u64, [u8; 32])>,
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
        split: Option<u64>,
    ) -> Result<Self, CoinOwnerError> {
        if selected.is_empty()
            || selected.len() > MAX_EDGE_INPUTS
            || selected
                .iter()
                .enumerate()
                .any(|(index, id)| selected[..index].contains(id))
        {
            return Err(CoinOwnerError::Inputs);
        }
        let snapshot = chain
            .get_objects(
                selected
                    .iter()
                    .copied()
                    .map(hellas_chain::domain::coin_object_id)
                    .collect(),
            )
            .await?
            .ok_or(CoinOwnerError::NoSnapshot)?;
        if snapshot.network != network {
            return Err(CoinOwnerError::Network);
        }
        let mut value = 0_u64;
        let mut inputs = [CoinId::from_bytes([0; CoinId::LENGTH]); MAX_EDGE_INPUTS];
        for (slot, id) in inputs.iter_mut().zip(selected) {
            let Some(hellas_chain::domain::Object::Coin(coin)) = snapshot
                .objects
                .get(&hellas_chain::domain::coin_object_id(*id))
            else {
                return Err(CoinOwnerError::Missing(*id));
            };
            if coin.owner != owner.into() {
                return Err(CoinOwnerError::Missing(*id));
            }
            value = value
                .checked_add(coin.value)
                .ok_or(CoinOwnerError::ValueOverflow)?;
            *slot = *id;
        }
        let mut outputs = Vec::new();
        if let Some(unit) = split {
            if delegate.is_none() || unit == 0 || unit > value {
                return Err(CoinOwnerError::Split);
            }
            let count = (value / unit).min((MAX_EDGE_OUTPUTS - 1) as u64);
            for _ in 0..count {
                outputs.push(Payout::delegated(owner, delegate, unit));
            }
            let change = value - count * unit;
            if change > 0 {
                outputs.push(Payout::new(owner, change));
            }
        } else {
            outputs.push(Payout::delegated(owner, delegate, value));
        }
        let count = outputs.len();
        let slots = std::array::from_fn(|index| {
            outputs.get(index).cloned().unwrap_or(Payout::new(owner, 0))
        });
        Ok(Self {
            floor: Some((snapshot.block.height, snapshot.block.payload.into())),
            network,
            owner,
            inputs: List::take(inputs, selected.len()),
            outputs: List::take(slots, count),
        })
    }

    /// Select at most four verified owner coins. Listing entries are discovery
    /// hints; only objects authenticated at one finalized root authorize value.
    pub async fn split<C: LightClient>(
        chain: &C,
        network: NetworkId,
        owner: Key,
        need: u64,
        delegate: Key,
    ) -> Result<Self, CoinOwnerError> {
        Self::split_avoiding(
            chain,
            network,
            owner,
            need,
            delegate,
            &std::collections::BTreeSet::new(),
        )
        .await
    }

    pub(crate) async fn split_avoiding<C: LightClient>(
        chain: &C,
        network: NetworkId,
        owner: Key,
        need: u64,
        delegate: Key,
        reserved: &std::collections::BTreeSet<CoinId>,
    ) -> Result<Self, CoinOwnerError> {
        if need == 0 {
            return Err(CoinOwnerError::Split);
        }
        let listing = chain
            .get_coins_by_owner(owner.into())
            .await?
            .ok_or(CoinOwnerError::NoSnapshot)?;
        let mut candidates = listing
            .coins
            .into_iter()
            .filter(|(id, _)| !reserved.contains(&CoinId::from_bytes((*id).into())))
            .collect::<Vec<_>>();
        candidates.sort_unstable_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        let mut seen = std::collections::BTreeSet::new();
        candidates.retain(|(id, _)| seen.insert(*id));
        let mut eligible = Vec::new();
        for batch in candidates.chunks(32) {
            let snapshot = chain
                .get_objects(batch.iter().map(|(id, _)| *id).collect())
                .await?
                .ok_or(CoinOwnerError::NoSnapshot)?;
            if snapshot.network != network {
                return Err(CoinOwnerError::Network);
            }
            eligible.extend(snapshot.objects.into_iter().filter_map(|(id, object)| {
                let hellas_chain::domain::Object::Coin(coin) = object else {
                    return None;
                };
                (coin.owner == owner.into()
                    && coin.value > 0
                    && (coin.delegate.is_none() || coin.delegate == Some(delegate.into())))
                .then_some((CoinId::from_bytes(id.into()), coin.value))
            }));
            eligible.sort_unstable_by(|a, b| {
                b.1.cmp(&a.1)
                    .then_with(|| a.0.to_bytes().cmp(&b.0.to_bytes()))
            });
            eligible.dedup_by_key(|coin| coin.0);
            eligible.truncate(hellas_kernel::MAX_PARTY_INPUTS);
            if eligible
                .iter()
                .fold(0_u64, |sum, coin| sum.saturating_add(coin.1))
                >= need
            {
                break;
            }
        }
        let mut selected = Vec::new();
        let mut covered = 0_u64;
        for (coin, value) in eligible {
            if covered >= need {
                break;
            }
            covered = covered
                .checked_add(value)
                .ok_or(CoinOwnerError::ValueOverflow)?;
            selected.push(coin);
        }
        if selected.is_empty() {
            return Err(CoinOwnerError::Insufficient {
                required: need,
                available: 0,
            });
        }
        // Discovery can span finalized roots. Re-read every selected input together
        // before asking the owner to authorize a value or a remainder.
        let snapshot = chain
            .get_objects(
                selected
                    .iter()
                    .copied()
                    .map(hellas_chain::domain::coin_object_id)
                    .collect(),
            )
            .await?
            .ok_or(CoinOwnerError::NoSnapshot)?;
        if snapshot.network != network {
            return Err(CoinOwnerError::Network);
        }
        let mut total = 0_u64;
        for id in &selected {
            let Some(hellas_chain::domain::Object::Coin(coin)) = snapshot
                .objects
                .get(&hellas_chain::domain::coin_object_id(*id))
            else {
                return Err(CoinOwnerError::Missing(*id));
            };
            if coin.owner != owner.into()
                || (coin.delegate.is_some() && coin.delegate != Some(delegate.into()))
            {
                return Err(CoinOwnerError::Missing(*id));
            }
            total = total
                .checked_add(coin.value)
                .ok_or(CoinOwnerError::ValueOverflow)?;
        }
        if total < need {
            return Err(CoinOwnerError::Insufficient {
                required: need,
                available: total,
            });
        }
        let inputs = List::take(
            std::array::from_fn(|index| {
                selected
                    .get(index)
                    .copied()
                    .unwrap_or(CoinId::from_bytes([0; CoinId::LENGTH]))
            }),
            selected.len(),
        );
        let mut payouts = vec![Payout::delegated(owner, Some(delegate), need)];
        if total > need {
            payouts.push(Payout::new(owner, total - need));
        }
        let outputs = List::take(
            std::array::from_fn(|index| {
                payouts.get(index).copied().unwrap_or(Payout::new(owner, 0))
            }),
            payouts.len(),
        );
        Ok(Self {
            network,
            owner,
            inputs,
            outputs,
            floor: Some((snapshot.block.height, snapshot.block.payload.into())),
        })
    }

    pub(crate) const fn floor(&self) -> Option<(u64, [u8; 32])> {
        self.floor
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
            floor: None,
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
    #[tokio::test]
    async fn standalone_sdk_accepts_an_async_passkey_authenticator() {
        use hellas_auth::{
            Digest,
            authority::{AuthorityError, PasskeyAssertion},
        };
        use hellas_work::authenticator::{Authenticator, PublicKey, kernel_auth};
        struct NativePrompt(hellas_kernel::SoftPasskey);
        #[async_trait::async_trait]
        impl Authenticator for NativePrompt {
            fn public_key(&self) -> Result<PublicKey, AuthorityError> {
                self.0.public_key()
            }
            async fn assert(&self, challenge: Digest) -> Result<PasskeyAssertion, AuthorityError> {
                tokio::task::yield_now().await;
                self.0.assert(challenge).await
            }
        }
        let owner = NativePrompt(hellas_kernel::SoftPasskey::from_secret_scalar([21; 32]).unwrap());
        let plan = OwnerReshape {
            floor: None,
            network: NetworkId::new("owner-passkey-test").unwrap(),
            owner: Key::from_bytes(owner.public_key().unwrap().to_compressed()),
            inputs: List::take([CoinId::from_bytes([1; 32]); MAX_EDGE_INPUTS], 1),
            outputs: List::take(
                [Payout::new(
                    Key::from_bytes(owner.public_key().unwrap().to_compressed()),
                    100,
                ); MAX_EDGE_OUTPUTS],
                1,
            ),
        };
        let auth = kernel_auth(
            &owner.public_key().unwrap(),
            &owner
                .assert(Digest::from(*plan.payload_hash().as_bytes()))
                .await
                .unwrap(),
        )
        .unwrap();
        assert!(plan.authorize(auth).is_ok());
    }
}
