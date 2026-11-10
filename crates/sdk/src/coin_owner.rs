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
    #[error("payment must be positive and no greater than the selected balance")]
    Payment,
    #[error("recipient must be a valid P-256 or secp256k1 public key")]
    Recipient,
    #[error("selected coin values overflow")]
    ValueOverflow,
    #[error("chain network does not match the requested signing network")]
    Network,
    #[error("authorization is not the selected owner's signature over this reshape")]
    Authorization,
}

/// The exact inputs and output an owner is asked to authorize.
/// Outputs either retain ownership or pay an explicitly selected recipient.
#[derive(Debug, Clone)]
pub struct OwnerReshape {
    network: NetworkId,
    owner: Key,
    inputs: List<CoinId, MAX_EDGE_INPUTS>,
    outputs: List<Payout, MAX_EDGE_OUTPUTS>,
    floor: Option<(u64, [u8; 32])>,
}

impl OwnerReshape {
    /// Reject destinations that cannot be controlled by either owner scheme.
    pub fn validate_recipient(recipient: Key) -> Result<(), CoinOwnerError> {
        if Secp256k1Verifier::is_valid_key(recipient)
            || hellas_auth::authority::PrincipalId::from_public_key(hellas_auth::PublicKey::P256(
                *recipient.as_bytes(),
            ))
            .is_ok()
        {
            Ok(())
        } else {
            Err(CoinOwnerError::Recipient)
        }
    }

    /// Pay a recipient from verified owner coins, returning undelegated change.
    pub async fn pay<C: LightClient>(
        chain: &C,
        network: NetworkId,
        owner: Key,
        selected: &[CoinId],
        recipient: Key,
        amount: u64,
    ) -> Result<Self, CoinOwnerError> {
        Self::validate_recipient(recipient)?;
        let mut plan = Self::prepare(chain, network, owner, selected, None, None).await?;
        let balance = plan.outputs.as_slice()[0].value();
        if amount == 0 || amount > balance {
            return Err(CoinOwnerError::Payment);
        }
        let mut outputs = [Payout::new(owner, 0); MAX_EDGE_OUTPUTS];
        outputs[0] = Payout::new(recipient, amount);
        let count = if amount < balance {
            outputs[1] = Payout::new(owner, balance - amount);
            2
        } else {
            1
        };
        plan.outputs = List::take(outputs, count);
        Ok(plan)
    }

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
                    .map(hellas_chain::domain::ObjectKey::Coin)
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
            let Some(coin) = snapshot.coin(*id)? else {
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
        let mut eligible = Vec::new();
        let mut after = None;
        loop {
            let page = chain
                .get_holdings(owner.into(), after)
                .await?
                .ok_or(CoinOwnerError::NoSnapshot)?;
            eligible.extend(
                page.owned_coins(owner.into())
                    .into_iter()
                    .filter_map(|(id, coin)| {
                        (!reserved.contains(&id)
                            && coin.value > 0
                            && (coin.delegate.is_none() || coin.delegate == Some(delegate.into())))
                        .then_some((id, coin.value))
                    }),
            );
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
            after = page.next_holdings();
            if after.is_none() {
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
                    .map(hellas_chain::domain::ObjectKey::Coin)
                    .collect(),
            )
            .await?
            .ok_or(CoinOwnerError::NoSnapshot)?;
        if snapshot.network != network {
            return Err(CoinOwnerError::Network);
        }
        let mut total = 0_u64;
        for id in &selected {
            let Some(coin) = snapshot.coin(*id)? else {
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

    #[derive(Clone)]
    struct PagedFunding {
        owner: hellas_chain::domain::SettlementKey,
        network: NetworkId,
        pages: std::sync::Arc<std::sync::atomic::AtomicU64>,
        reads: std::sync::Arc<std::sync::Mutex<Vec<Vec<hellas_chain::domain::ObjectKey>>>>,
    }

    impl PagedFunding {
        fn coin(&self, id: hellas_chain::domain::ObjectId) -> hellas_chain::domain::Object {
            let value = if id.0[0] == 129 { 200 } else { 1 };
            hellas_chain::domain::Object::Coin(hellas_chain::domain::Coin::owned(self.owner, value))
        }
    }

    impl hellas_chain::LightClient for PagedFunding {
        async fn get_holdings(
            &self,
            owner: hellas_chain::domain::SettlementKey,
            after: Option<hellas_chain::domain::ObjectKey>,
        ) -> Result<
            Option<hellas_chain::Verified<hellas_chain::ObjectSnapshot>>,
            hellas_chain::QueryError,
        > {
            assert_eq!(owner, self.owner);
            let start = after.map_or(1, |key| key.id().0[0] as usize + 1);
            let end = (start + 32).min(130);
            let page = self.pages.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
            let keys: Vec<_> = (start..end)
                .map(|index| hellas_chain::domain::ObjectId::from([index as u8; 32]))
                .collect();
            let snapshot = hellas_chain::ObjectSnapshot::new(
                self.network,
                hellas_chain::LatestBlock {
                    height: page + 1,
                    payload: hellas_chain::domain::Digest::from([page as u8; 32]),
                    state_root: hellas_chain::domain::Digest::from([page as u8; 32]),
                    finalization: Vec::new(),
                },
                0,
                keys.iter().map(|id| (*id, self.coin(*id))).collect(),
            )
            .with_holdings(keys, start as u64 - 1, 129)?;
            Ok(Some(hellas_chain::Verified::assume_for_tests(snapshot)))
        }

        async fn get_objects(
            &self,
            keys: Vec<hellas_chain::domain::ObjectKey>,
        ) -> Result<
            Option<hellas_chain::Verified<hellas_chain::ObjectSnapshot>>,
            hellas_chain::QueryError,
        > {
            self.reads.lock().unwrap().push(keys.clone());
            let page = self.pages.load(std::sync::atomic::Ordering::SeqCst);
            Ok(Some(hellas_chain::Verified::assume_for_tests(
                hellas_chain::ObjectSnapshot::new(
                    self.network,
                    hellas_chain::LatestBlock {
                        height: page + 2,
                        payload: hellas_chain::domain::Digest::from([(page + 1) as u8; 32]),
                        state_root: hellas_chain::domain::Digest::from([(page + 1) as u8; 32]),
                        finalization: Vec::new(),
                    },
                    0,
                    keys.into_iter()
                        .map(|key| (key.id(), self.coin(key.id())))
                        .collect(),
                ),
            )))
        }

        async fn get_state_root(
            &self,
        ) -> Result<Option<hellas_chain::domain::Digest>, hellas_chain::QueryError> {
            unreachable!()
        }
        async fn get_finalization(
            &self,
            _: hellas_chain::domain::Digest,
        ) -> Result<Option<Vec<u8>>, hellas_chain::QueryError> {
            unreachable!()
        }
        async fn get_latest_block(
            &self,
        ) -> Result<Option<hellas_chain::LatestBlock>, hellas_chain::QueryError> {
            unreachable!()
        }
        async fn get_finalized_block(
            &self,
            _: hellas_chain::FinalizedBlockQuery,
        ) -> Result<Option<hellas_chain::FinalizedBlock>, hellas_chain::QueryError> {
            unreachable!()
        }
        async fn submit_tx(
            &self,
            _: hellas_chain::domain::Transaction,
        ) -> Result<hellas_chain::SubmitTxOutcome, hellas_chain::QueryError> {
            unreachable!()
        }
        async fn get_validators(&self) -> Result<Vec<String>, hellas_chain::QueryError> {
            unreachable!()
        }
        async fn get_consensus_info(
            &self,
        ) -> Result<hellas_chain::ConsensusInfo, hellas_chain::QueryError> {
            unreachable!()
        }
    }

    #[tokio::test]
    async fn split_finds_later_page_funding_and_rechecks_selected_input_at_one_root() {
        let signer = Secp256k1Signer::from_secret_scalar([21; 32]).unwrap();
        let owner: hellas_chain::domain::SettlementKey = signer.party_key().into();
        let network = NetworkId::new("paged-funding-test").unwrap();
        let source = PagedFunding {
            owner,
            network,
            pages: Default::default(),
            reads: Default::default(),
        };
        let plan = OwnerReshape::split(
            &source,
            network,
            signer.party_key(),
            200,
            signer.party_key(),
        )
        .await
        .unwrap();
        assert_eq!(source.pages.load(std::sync::atomic::Ordering::SeqCst), 5);
        assert_eq!(plan.inputs().as_slice(), &[CoinId::from_bytes([129; 32])]);
        let reads = source.reads.lock().unwrap();
        assert_eq!(
            reads.last().unwrap(),
            &vec![hellas_chain::domain::ObjectKey::Coin(CoinId::from_bytes(
                [129; 32]
            ))]
        );
        assert!(reads.iter().all(|batch| batch.len() <= 32));
        assert_eq!(plan.floor(), Some((7, [6; 32])));
        assert_eq!(plan.outputs().as_slice()[0].value(), 200);
    }

    #[test]
    fn recipients_must_be_valid_points_on_a_supported_owner_curve() {
        let native = Secp256k1Signer::from_secret_scalar([12; 32]).unwrap();
        let passkey = hellas_kernel::SoftPasskey::from_secret_scalar([21; 32]).unwrap();
        for key in [native.party_key(), passkey.party_key()] {
            OwnerReshape::validate_recipient(key).unwrap();
        }
        let mut invalid_point = [0xff; 33];
        invalid_point[0] = 2;
        for bytes in [[0; 33], [0xff; 33], invalid_point] {
            assert!(matches!(
                OwnerReshape::validate_recipient(Key::from_bytes(bytes)),
                Err(CoinOwnerError::Recipient)
            ));
        }
    }

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
        use hellas_authority::authenticator::{Authenticator, PublicKey, kernel_auth};
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
