use crate::HellasBlock;
use crate::domain::{
    Address, Coin, MergeInputFault, ObjectId, ObjectKind, SettlementKey, Transaction,
    coin_object_id, edge_object_id, genesis_object_id, merge_input_fault, output_object_id,
};
use commonware_codec::Encode;
use commonware_consensus::{Block as _, Heightable};
use commonware_cryptography::{Digestible, Hasher, Sha256, sha256::Digest};
use hellas_kernel::NetworkId;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, RwLock},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IndexedEdge {
    pub maker: SettlementKey,
    pub taker: SettlementKey,
}

impl From<hellas_kernel::Parties> for IndexedEdge {
    fn from(parties: hellas_kernel::Parties) -> Self {
        Self {
            maker: SettlementKey::from(parties.maker()),
            taker: SettlementKey::from(parties.taker()),
        }
    }
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
    #[error("invalid signature")]
    InvalidSignature,
    #[error("insufficient balance: available={available} requested={requested}")]
    InsufficientBalance { available: u64, requested: u64 },
    #[error("transfer amount must be > 0")]
    ZeroAmount,
    #[error("duplicate merge input: {id:?}")]
    DuplicateInput { id: ObjectId },
    #[error("merge requires at least 2 inputs")]
    TooFewMergeInputs,
    #[error("merge inputs must be strictly increasing")]
    NonCanonicalMergeInputs,
    #[error("merge inputs must have the same owner")]
    MergeOwnerMismatch,
    #[error("merge overflowed u64 total")]
    MergeOverflow,
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
    pub(crate) fn get_edges_by_owner(&self, owner: &SettlementKey) -> Vec<(ObjectId, IndexedEdge)> {
        self.get_edges_by_owner_snapshot(owner).1
    }

    pub fn get_edges_by_owner_snapshot(
        &self,
        owner: &SettlementKey,
    ) -> (OwnerCursor, Vec<(ObjectId, IndexedEdge)>) {
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
            .map(|coins| coins.iter().map(|(id, value)| (*id, *value)).collect())
            .unwrap_or_default();
        (state.cursor, coins)
    }

    /// Deterministic owner holdings for rebuilding the authenticated native proof snapshot.
    #[cfg(feature = "explorer-origin")]
    pub(crate) fn holdings_snapshot(&self) -> Vec<(SettlementKey, ObjectId, u8, u64)> {
        let state = self.inner.read().expect("owner index lock poisoned");
        let mut holdings = Vec::new();
        for (id, coin) in &state.coins {
            holdings.push((coin.owner, *id, 0, coin.value));
        }
        for (id, edge) in &state.edges {
            holdings.push((edge.maker, *id, 1, 0));
            if edge.taker != edge.maker {
                holdings.push((edge.taker, *id, 1, 0));
            }
        }
        holdings.sort();
        holdings
    }

    #[cfg(test)]
    pub(crate) fn all_coins_for_test(&self) -> BTreeMap<ObjectId, Coin> {
        self.inner
            .read()
            .expect("owner index lock poisoned")
            .coins
            .clone()
    }

    #[cfg(test)]
    pub(crate) fn all_edges_for_test(&self) -> BTreeMap<ObjectId, IndexedEdge> {
        self.inner
            .read()
            .expect("owner index lock poisoned")
            .edges
            .clone()
    }
}

#[derive(Clone)]
struct State {
    /// The network whose signatures this index accepts. Held rather
    /// than passed per call: the index replays finalized blocks from
    /// one chain, so the network is a property of the index, not of an
    /// individual transaction.
    network: NetworkId,
    cursor: OwnerCursor,
    genesis_allocations: Vec<(SettlementKey, u64)>,
    coins: BTreeMap<ObjectId, Coin>,
    by_owner: BTreeMap<SettlementKey, BTreeMap<ObjectId, u64>>,
    edges: BTreeMap<ObjectId, IndexedEdge>,
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
            self.insert_coin(genesis_object_id(validator_index), Coin { owner, value })?;
        }
        Ok(())
    }

    fn apply_transaction(&mut self, tx: &Transaction) -> Result<(), OwnerIndexError> {
        match tx {
            Transaction::Transfer {
                input,
                recipient,
                amount,
                ..
            } => self.apply_transfer(tx, *input, recipient, *amount),
            Transaction::MergeCoin { inputs, .. } => self.apply_merge(tx, inputs.as_slice()),
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
                self.insert_edge(edge_id, terms.parties().into())
            }
            hellas_kernel::Tx::Close { input, outputs, .. } => {
                let edge_id = edge_object_id(*input);
                self.remove_edge(&edge_id)?;
                for (id, payout) in hellas_kernel::Tx::close_output_ids(*input, outputs)
                    .iter()
                    .zip(outputs)
                {
                    self.insert_coin(
                        coin_object_id(*id),
                        Coin {
                            owner: SettlementKey::from(payout.owner()),
                            value: payout.value(),
                        },
                    )?;
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

    fn apply_transfer(
        &mut self,
        tx: &Transaction,
        input: ObjectId,
        recipient: &Address,
        amount: u64,
    ) -> Result<(), OwnerIndexError> {
        let coin = self
            .coins
            .get(&input)
            .cloned()
            .ok_or(OwnerIndexError::ObjectNotFound { id: input })?;
        let owner = Address::try_from(coin.owner).map_err(|_| OwnerIndexError::InvalidSignature)?;
        if !tx.verify_signature(self.network, &owner) {
            return Err(OwnerIndexError::InvalidSignature);
        }
        if amount == 0 {
            return Err(OwnerIndexError::ZeroAmount);
        }
        if amount > coin.value {
            return Err(OwnerIndexError::InsufficientBalance {
                available: coin.value,
                requested: amount,
            });
        }

        let tx_digest = Sha256::hash(&tx.encode());
        let recipient_id = output_object_id(&tx_digest, 0);
        if self.kind_of(&recipient_id).is_some() {
            return Err(OwnerIndexError::OutputCollision { id: recipient_id });
        }

        let change_value = coin.value - amount;
        let change_id = if change_value > 0 {
            let id = output_object_id(&tx_digest, 1);
            if self.kind_of(&id).is_some() || id == recipient_id {
                return Err(OwnerIndexError::OutputCollision { id });
            }
            Some(id)
        } else {
            None
        };

        self.remove_coin(&input)?;
        self.insert_coin(
            recipient_id,
            Coin {
                owner: SettlementKey::from(recipient),
                value: amount,
            },
        )?;
        if let Some(change_id) = change_id {
            self.insert_coin(
                change_id,
                Coin {
                    owner: coin.owner,
                    value: change_value,
                },
            )?;
        }
        Ok(())
    }

    fn apply_merge(
        &mut self,
        tx: &Transaction,
        inputs: &[ObjectId],
    ) -> Result<(), OwnerIndexError> {
        if let Some(fault) = merge_input_fault(inputs) {
            return Err(match fault {
                MergeInputFault::TooFew => OwnerIndexError::TooFewMergeInputs,
                MergeInputFault::Duplicate(id) => OwnerIndexError::DuplicateInput { id },
                MergeInputFault::NonCanonical => OwnerIndexError::NonCanonicalMergeInputs,
            });
        }

        let mut owner = None;
        let mut total = 0u64;
        for input in inputs {
            let coin = self
                .coins
                .get(input)
                .ok_or(OwnerIndexError::ObjectNotFound { id: *input })?;
            if let Some(expected) = owner.as_ref() {
                if &coin.owner != expected {
                    return Err(OwnerIndexError::MergeOwnerMismatch);
                }
            } else {
                owner = Some(coin.owner);
            }
            total = total
                .checked_add(coin.value)
                .ok_or(OwnerIndexError::MergeOverflow)?;
        }
        let Some(owner) = owner else {
            return Err(OwnerIndexError::MergeOwnerMismatch);
        };
        let address = Address::try_from(owner).map_err(|_| OwnerIndexError::InvalidSignature)?;
        if !tx.verify_signature(self.network, &address) {
            return Err(OwnerIndexError::InvalidSignature);
        }

        let tx_digest = Sha256::hash(&tx.encode());
        let output_id = output_object_id(&tx_digest, 0);
        if self.kind_of(&output_id).is_some() {
            return Err(OwnerIndexError::OutputCollision { id: output_id });
        }

        for input in inputs {
            self.remove_coin(input)?;
        }
        self.insert_coin(
            output_id,
            Coin {
                owner,
                value: total,
            },
        )?;
        Ok(())
    }

    fn insert_coin(&mut self, id: ObjectId, coin: Coin) -> Result<(), OwnerIndexError> {
        if self.kind_of(&id).is_some() {
            return Err(OwnerIndexError::OutputCollision { id });
        }
        self.by_owner
            .entry(coin.owner)
            .or_default()
            .insert(id, coin.value);
        self.coins.insert(id, coin);
        Ok(())
    }

    fn remove_coin(&mut self, id: &ObjectId) -> Result<Coin, OwnerIndexError> {
        let coin = self
            .coins
            .remove(id)
            .ok_or(OwnerIndexError::ObjectNotFound { id: *id })?;
        let remove_owner = {
            let owned = self
                .by_owner
                .get_mut(&coin.owner)
                .expect("owner index missing active coin owner");
            owned.remove(id);
            owned.is_empty()
        };
        if remove_owner {
            self.by_owner.remove(&coin.owner);
        }
        Ok(coin)
    }

    fn insert_edge(&mut self, id: ObjectId, edge: IndexedEdge) -> Result<(), OwnerIndexError> {
        if self.kind_of(&id).is_some() {
            return Err(OwnerIndexError::OutputCollision { id });
        }
        self.edges_by_owner
            .entry(edge.maker)
            .or_default()
            .insert(id);
        self.edges_by_owner
            .entry(edge.taker)
            .or_default()
            .insert(id);
        self.edges.insert(id, edge);
        Ok(())
    }

    fn remove_edge(&mut self, id: &ObjectId) -> Result<IndexedEdge, OwnerIndexError> {
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
        for owner in [edge.maker, edge.taker]
            .into_iter()
            .take(if edge.maker == edge.taker { 1 } else { 2 })
        {
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
