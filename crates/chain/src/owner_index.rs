use crate::HellasBlock;
use crate::domain::{
    Coin, ObjectId, ObjectKind, SettlementKey, Transaction, coin_object_id, edge_object_id,
    genesis_object_id,
};
use crate::owner_proof::{HOLDING_COIN, HOLDING_DELEGATED};
use commonware_consensus::{Block as _, Heightable};
use commonware_cryptography::{Digestible, sha256::Digest};
use hellas_kernel::{NetworkId, Parties};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, RwLock},
};

/// Coin holdings shared by the replay index and authenticated owner tree.
pub(crate) fn coin_holdings(coin: Coin) -> impl Iterator<Item = (SettlementKey, u8, u64)> {
    std::iter::once((coin.owner, HOLDING_COIN, coin.value)).chain(
        coin.delegate
            .filter(|delegate| *delegate != coin.owner)
            .map(|delegate| (delegate, HOLDING_DELEGATED, 0)),
    )
}

/// Every authority or destination key committed by an edge, once each.
pub(crate) fn edge_keys(parties: Parties) -> BTreeSet<SettlementKey> {
    [parties.maker(), parties.taker()]
        .into_iter()
        .flat_map(|party| {
            [
                Some(party.owner()),
                Some(party.signer()),
                party.payout_delegate(),
            ]
            .into_iter()
            .flatten()
            .map(SettlementKey::from)
        })
        .collect()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OwnerCursor {
    pub height: u64,
    pub payload: Digest,
    pub state_root: Digest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApplyOutcome {
    Applied,
    Duplicate,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OwnerIndexError {
    #[error("finalized block height gap: current={current} next={next}")]
    HeightGap { current: u64, next: u64 },
    #[error("conflicting block at height {height}")]
    ConflictingHeight { height: u64 },
    #[error("finalized block parent mismatch at height {height}")]
    ParentMismatch { height: u64 },
    #[error("object not found: {id:?}")]
    ObjectNotFound { id: ObjectId },
    #[error("output object collision: {id:?}")]
    OutputCollision { id: ObjectId },
    #[error("wrong object kind for {id:?}: expected {expected}, found {actual}")]
    WrongObjectKind {
        id: ObjectId,
        expected: ObjectKind,
        actual: ObjectKind,
    },
}

#[derive(Clone)]
pub struct OwnerIndex {
    inner: Arc<RwLock<State>>,
}

impl OwnerIndex {
    pub fn new(
        network: NetworkId,
        genesis: &HellasBlock,
        genesis_allocations: Vec<(SettlementKey, u64)>,
    ) -> Self {
        Self {
            inner: Arc::new(RwLock::new(State::new(
                network,
                genesis,
                genesis_allocations,
            ))),
        }
    }

    pub fn apply_finalized(&self, block: &HellasBlock) -> Result<ApplyOutcome, OwnerIndexError> {
        self.inner
            .write()
            .expect("owner index lock poisoned")
            .apply_finalized(block)
    }

    #[cfg(feature = "full-node")]
    pub(crate) fn publish_cursor(&self, block: &HellasBlock) {
        self.inner
            .write()
            .expect("owner index lock poisoned")
            .cursor = OwnerCursor {
            height: block.height().get(),
            payload: block.digest(),
            state_root: block.state_root(),
        };
    }

    pub fn cursor(&self) -> OwnerCursor {
        self.inner.read().expect("owner index lock poisoned").cursor
    }

    #[cfg(test)]
    pub(crate) fn get_coin(&self, object_id: &ObjectId) -> Result<Option<Coin>, OwnerIndexError> {
        self.get_coin_snapshot(object_id).1
    }

    pub fn get_coin_snapshot(
        &self,
        object_id: &ObjectId,
    ) -> (OwnerCursor, Result<Option<Coin>, OwnerIndexError>) {
        let state = self.inner.read().expect("owner index lock poisoned");
        (state.cursor, state.get_coin(object_id))
    }

    #[cfg(test)]
    pub(crate) fn get_edges_by_owner(&self, owner: &SettlementKey) -> Vec<(ObjectId, Parties)> {
        self.get_edges_by_owner_snapshot(owner).1
    }

    pub fn get_edges_by_owner_snapshot(
        &self,
        owner: &SettlementKey,
    ) -> (OwnerCursor, Vec<(ObjectId, Parties)>) {
        let state = self.inner.read().expect("owner index lock poisoned");
        let edges = state
            .edges_by_owner
            .get(owner)
            .into_iter()
            .flatten()
            .filter_map(|id| state.edges.get(id).map(|edge| (*id, *edge)))
            .collect();
        (state.cursor, edges)
    }

    #[cfg(test)]
    pub(crate) fn get_coins_by_owner(&self, owner: &SettlementKey) -> Vec<(ObjectId, u64)> {
        self.get_coins_by_owner_snapshot(owner).1
    }

    pub fn get_coins_by_owner_snapshot(
        &self,
        owner: &SettlementKey,
    ) -> (OwnerCursor, Vec<(ObjectId, u64)>) {
        let state = self.inner.read().expect("owner index lock poisoned");
        let coins = state
            .by_owner
            .get(owner)
            .map(|coins| {
                coins
                    .iter()
                    .filter_map(|((kind, id), value)| {
                        (*kind == HOLDING_COIN).then_some((*id, *value))
                    })
                    .collect()
            })
            .unwrap_or_default();
        (state.cursor, coins)
    }

    // Only the kernel tests read this, and they need `kernel`.
    #[cfg(all(test, any(feature = "validator", feature = "full-node")))]
    pub(crate) fn all_coins_for_test(&self) -> BTreeMap<ObjectId, Coin> {
        self.inner
            .read()
            .expect("owner index lock poisoned")
            .coins
            .clone()
    }

    #[cfg(test)]
    pub(crate) fn all_edges_for_test(&self) -> BTreeMap<ObjectId, Parties> {
        self.inner
            .read()
            .expect("owner index lock poisoned")
            .edges
            .clone()
    }
}

#[derive(Clone)]
struct State {
    /// The network this index replays. Held rather than passed per call:
    /// a reshape's output ids are derived under it, and the index replays
    /// finalized blocks from one chain, so the network is a property of
    /// the index, not of an individual transaction.
    network: NetworkId,
    cursor: OwnerCursor,
    genesis_allocations: Vec<(SettlementKey, u64)>,
    coins: BTreeMap<ObjectId, Coin>,
    by_owner: BTreeMap<SettlementKey, BTreeMap<(u8, ObjectId), u64>>,
    edges: BTreeMap<ObjectId, Parties>,
    edges_by_owner: BTreeMap<SettlementKey, BTreeSet<ObjectId>>,
}

impl State {
    fn new(
        network: NetworkId,
        genesis: &HellasBlock,
        genesis_allocations: Vec<(SettlementKey, u64)>,
    ) -> Self {
        Self {
            network,
            cursor: OwnerCursor {
                height: genesis.height().get(),
                payload: genesis.digest(),
                state_root: genesis.state_root(),
            },
            genesis_allocations,
            coins: BTreeMap::new(),
            by_owner: BTreeMap::new(),
            edges: BTreeMap::new(),
            edges_by_owner: BTreeMap::new(),
        }
    }

    /// The kind of object `id` names, if this index holds one.
    ///
    /// Derived rather than stored. `coins` and `edges` are disjoint by
    /// construction — every insert refuses an id either map already
    /// holds — so the pair of maps *is* the kind table. A third map
    /// maintained alongside them adds no information and one more way
    /// for the three to fall out of step.
    ///
    /// This index answers "what does this owner hold", and registry
    /// chunks have no owner, so it never stores one and this never
    /// returns [`ObjectKind::RegistryChunk`]. Callers still name that
    /// kind explicitly rather than folding it into a wildcard, so
    /// indexing a further kind later is a compile error here instead of
    /// a silent "no such object".
    fn kind_of(&self, id: &ObjectId) -> Option<ObjectKind> {
        if self.coins.contains_key(id) {
            Some(ObjectKind::Coin)
        } else if self.edges.contains_key(id) {
            Some(ObjectKind::Edge)
        } else {
            None
        }
    }

    fn get_coin(&self, id: &ObjectId) -> Result<Option<Coin>, OwnerIndexError> {
        if let Some(coin) = self.coins.get(id) {
            return Ok(Some(*coin));
        }
        match self.kind_of(id) {
            Some(
                actual @ (ObjectKind::Edge | ObjectKind::RegistryChunk | ObjectKind::OwnerData),
            ) => Err(OwnerIndexError::WrongObjectKind {
                id: *id,
                expected: ObjectKind::Coin,
                actual,
            }),
            Some(ObjectKind::Coin) | None => Ok(None),
        }
    }

    fn apply_finalized(&mut self, block: &HellasBlock) -> Result<ApplyOutcome, OwnerIndexError> {
        let height = block.height().get();
        let payload = block.digest();
        if height == self.cursor.height {
            if payload == self.cursor.payload {
                return Ok(ApplyOutcome::Duplicate);
            }
            return Err(OwnerIndexError::ConflictingHeight { height });
        }
        // Marshal can redeliver finalized blocks below an archive-replayed cursor.
        if height < self.cursor.height {
            return Ok(ApplyOutcome::Duplicate);
        }
        let next_height = self.cursor.height.saturating_add(1);
        if height != next_height {
            return Err(OwnerIndexError::HeightGap {
                current: self.cursor.height,
                next: height,
            });
        }
        if block.parent() != self.cursor.payload {
            return Err(OwnerIndexError::ParentMismatch { height });
        }

        let mut next = self.clone();
        if next.cursor.height == 0 {
            next.seed_genesis()?;
        }
        for tx in block.txs() {
            next.apply_transaction(tx)?;
        }
        next.cursor = OwnerCursor {
            height,
            payload,
            state_root: block.state_root(),
        };
        *self = next;
        Ok(ApplyOutcome::Applied)
    }

    fn seed_genesis(&mut self) -> Result<(), OwnerIndexError> {
        for (idx, (owner, value)) in self.genesis_allocations.clone().into_iter().enumerate() {
            let Ok(validator_index) = u16::try_from(idx) else {
                break;
            };
            self.insert_coin(
                genesis_object_id(validator_index),
                Coin::owned(owner, value),
            )?;
        }
        Ok(())
    }

    fn apply_transaction(&mut self, tx: &Transaction) -> Result<(), OwnerIndexError> {
        match tx {
            Transaction::Kernel(tx) => self.apply_kernel(tx),
        }
    }

    fn apply_kernel(&mut self, tx: &hellas_kernel::Tx) -> Result<(), OwnerIndexError> {
        match tx {
            hellas_kernel::Tx::Open { funding, terms, .. } => {
                let edge_id = edge_object_id(hellas_kernel::Tx::edge_id_of(funding, terms));
                if self.kind_of(&edge_id).is_some() {
                    return Err(OwnerIndexError::OutputCollision { id: edge_id });
                }
                for id in funding.maker().iter().chain(funding.taker()) {
                    self.remove_coin(&coin_object_id(*id))?;
                }
                self.insert_edge(edge_id, terms.parties())
            }
            hellas_kernel::Tx::Close { input, outputs, .. } => {
                let edge_id = edge_object_id(*input);
                self.remove_edge(&edge_id)?;
                for (id, payout) in hellas_kernel::Tx::close_output_ids(*input, outputs)
                    .iter()
                    .zip(outputs)
                {
                    self.insert_coin(coin_object_id(*id), Coin::from(payout.coin()))?;
                }
                Ok(())
            }
            // The reshape's outputs name the coins it issues exactly,
            // delegates included, so the index reads them off the
            // transaction the way it reads a close's payouts.
            hellas_kernel::Tx::Owner(reshape) => {
                for id in reshape.inputs() {
                    self.remove_coin(&coin_object_id(*id))?;
                }
                let ids = hellas_kernel::Reshape::output_ids(
                    self.network,
                    reshape.inputs(),
                    reshape.outputs(),
                );
                for (id, payout) in ids.iter().zip(reshape.outputs()) {
                    self.insert_coin(coin_object_id(*id), Coin::from(payout.coin()))?;
                }
                Ok(())
            }
            // A move owns nothing. It consumes no coin, produces no
            // coin, and leaves the edge it addresses exactly where it
            // was — the state it writes is registry state, which this
            // index does not project.
            hellas_kernel::Tx::Move { .. } => Ok(()),
        }
    }

    fn insert_coin(&mut self, id: ObjectId, coin: Coin) -> Result<(), OwnerIndexError> {
        if self.kind_of(&id).is_some() {
            return Err(OwnerIndexError::OutputCollision { id });
        }
        for (key, kind, balance) in coin_holdings(coin) {
            self.by_owner
                .entry(key)
                .or_default()
                .insert((kind, id), balance);
        }
        self.coins.insert(id, coin);
        Ok(())
    }

    fn remove_coin(&mut self, id: &ObjectId) -> Result<Coin, OwnerIndexError> {
        let coin = self
            .coins
            .remove(id)
            .ok_or(OwnerIndexError::ObjectNotFound { id: *id })?;
        for (key, kind, _) in coin_holdings(coin) {
            let held = self
                .by_owner
                .get_mut(&key)
                .ok_or(OwnerIndexError::ObjectNotFound { id: *id })?;
            if held.remove(&(kind, *id)).is_none() {
                return Err(OwnerIndexError::ObjectNotFound { id: *id });
            }
            if held.is_empty() {
                self.by_owner.remove(&key);
            }
        }
        Ok(coin)
    }

    fn insert_edge(&mut self, id: ObjectId, edge: Parties) -> Result<(), OwnerIndexError> {
        if self.kind_of(&id).is_some() {
            return Err(OwnerIndexError::OutputCollision { id });
        }
        for key in edge_keys(edge) {
            self.edges_by_owner.entry(key).or_default().insert(id);
        }
        self.edges.insert(id, edge);
        Ok(())
    }

    fn remove_edge(&mut self, id: &ObjectId) -> Result<Parties, OwnerIndexError> {
        let edge = match self.edges.remove(id) {
            Some(edge) => edge,
            None => {
                return match self.kind_of(id) {
                    Some(
                        actual @ (ObjectKind::Coin
                        | ObjectKind::RegistryChunk
                        | ObjectKind::OwnerData),
                    ) => Err(OwnerIndexError::WrongObjectKind {
                        id: *id,
                        expected: ObjectKind::Edge,
                        actual,
                    }),
                    Some(ObjectKind::Edge) | None => {
                        Err(OwnerIndexError::ObjectNotFound { id: *id })
                    }
                };
            }
        };
        for owner in edge_keys(edge) {
            let remove_owner = {
                let owned = self
                    .edges_by_owner
                    .get_mut(&owner)
                    .expect("owner index missing active edge owner");
                assert!(
                    owned.remove(id),
                    "owner index active edge missing from owner set"
                );
                owned.is_empty()
            };
            if remove_owner {
                self.edges_by_owner.remove(&owner);
            }
        }
        Ok(edge)
    }
}

#[cfg(test)]
mod tests;
