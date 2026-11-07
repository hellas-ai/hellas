//! Consensus owner tree and rank-authenticated holdings pages.
//!
//! Nodes live in the same speculative storage transaction as object changes. The root is
//! committed in canonical blocks; these proofs never substitute a historical QMDB value proof
//! for proof of the current owner state.
use crate::domain::{Digest, Object, SettlementKey};
use commonware_cryptography::{Hasher as _, Sha256};
use serde::{Deserialize, Serialize};

// Current RPC merges each page's holdings into the object-key request. One full
// page must fit that request's key budget; the verifier derives it from here.
pub const OWNER_PAGE_LIMIT: u32 = 32;
pub const OWNER_NODE_BYTES: usize = 163;

/// A coin its owner holds. The only kind whose balance is spendable, and
/// so the only kind a page's balance counts.
pub const HOLDING_COIN: u8 = 0;
/// An edge one of the key's party roles is committed to, as owner,
/// signer or payout delegate. Balance zero.
pub const HOLDING_EDGE: u8 = 1;
/// A coin delegated to the key: it may fund a work open under the key's
/// own signature, but it is its owner's coin. Balance zero.
pub const HOLDING_DELEGATED: u8 = 2;
type Key = [u8; 32];

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnerCommitment {
    pub hash: Key,
    pub count: u64,
    pub balance: u128,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum OwnerLeaf {
    Summary(OwnerCommitment),
    Holding { kind: u8, balance: u64 },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnerPathProof {
    pub leaf: Option<OwnerLeaf>,
    pub siblings: Vec<OwnerSibling>,
}

/// Empty siblings are implied. Strictly increasing depths make the proof compact and canonical.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnerSibling {
    pub depth: u16,
    pub commitment: OwnerCommitment,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HoldingProof {
    pub object_id: Key,
    pub path: OwnerPathProof,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnerPageProof {
    pub owner: String,
    pub summary: OwnerPathProof,
    pub offset: u64,
    pub limit: u32,
    pub holdings: Vec<HoldingProof>,
    /// A proof of the requested cursor, including its absence after deletion.
    pub after_key: Option<Key>,
    pub after_path: Option<OwnerPathProof>,
}

#[cfg(feature = "proof-verify")]
impl OwnerPageProof {
    pub(crate) fn into_proto(self) -> hellas_rpc::pb::chain::OwnerPageProof {
        hellas_rpc::pb::chain::OwnerPageProof {
            owner: self.owner,
            summary: Some(self.summary.into_proto()),
            offset: self.offset,
            limit: self.limit,
            holdings: self
                .holdings
                .into_iter()
                .map(|holding| hellas_rpc::pb::chain::HoldingProof {
                    object_id: holding.object_id.to_vec(),
                    path: Some(holding.path.into_proto()),
                })
                .collect(),
            after_key: self.after_key.map(|key| key.to_vec()),
            after_path: self.after_path.map(OwnerPathProof::into_proto),
        }
    }

    pub(crate) fn from_proto(
        value: hellas_rpc::pb::chain::OwnerPageProof,
    ) -> Result<Self, OwnerProofError> {
        Ok(Self {
            owner: value.owner,
            summary: OwnerPathProof::from_proto(value.summary.ok_or(OwnerProofError::Invalid)?)?,
            offset: value.offset,
            limit: value.limit,
            holdings: value
                .holdings
                .into_iter()
                .map(|holding| {
                    Ok(HoldingProof {
                        object_id: holding
                            .object_id
                            .try_into()
                            .map_err(|_| OwnerProofError::Invalid)?,
                        path: OwnerPathProof::from_proto(
                            holding.path.ok_or(OwnerProofError::Invalid)?,
                        )?,
                    })
                })
                .collect::<Result<_, OwnerProofError>>()?,
            after_key: value
                .after_key
                .map(|key| key.try_into().map_err(|_| OwnerProofError::Invalid))
                .transpose()?,
            after_path: value
                .after_path
                .map(OwnerPathProof::from_proto)
                .transpose()?,
        })
    }
}

#[cfg(feature = "proof-verify")]
impl OwnerPathProof {
    fn into_proto(self) -> hellas_rpc::pb::chain::OwnerPathProof {
        use hellas_rpc::pb::chain::{OwnerHoldingLeaf, owner_leaf::Value};
        hellas_rpc::pb::chain::OwnerPathProof {
            leaf: self.leaf.map(|leaf| hellas_rpc::pb::chain::OwnerLeaf {
                value: Some(match leaf {
                    OwnerLeaf::Summary(commitment) => Value::Summary(commitment.into_proto()),
                    OwnerLeaf::Holding { kind, balance } => Value::Holding(OwnerHoldingLeaf {
                        kind: kind.into(),
                        balance,
                    }),
                }),
            }),
            siblings: self
                .siblings
                .into_iter()
                .map(|sibling| hellas_rpc::pb::chain::OwnerSibling {
                    depth: sibling.depth.into(),
                    commitment: Some(sibling.commitment.into_proto()),
                })
                .collect(),
        }
    }

    fn from_proto(value: hellas_rpc::pb::chain::OwnerPathProof) -> Result<Self, OwnerProofError> {
        use hellas_rpc::pb::chain::owner_leaf::Value;
        let leaf = value
            .leaf
            .map(|leaf| match leaf.value.ok_or(OwnerProofError::Invalid)? {
                Value::Summary(commitment) => {
                    Ok(OwnerLeaf::Summary(OwnerCommitment::from_proto(commitment)?))
                }
                Value::Holding(holding) => Ok(OwnerLeaf::Holding {
                    kind: holding
                        .kind
                        .try_into()
                        .map_err(|_| OwnerProofError::Invalid)?,
                    balance: holding.balance,
                }),
            })
            .transpose()?;
        let siblings = value
            .siblings
            .into_iter()
            .map(|sibling| {
                Ok(OwnerSibling {
                    depth: sibling
                        .depth
                        .try_into()
                        .map_err(|_| OwnerProofError::Invalid)?,
                    commitment: OwnerCommitment::from_proto(
                        sibling.commitment.ok_or(OwnerProofError::Invalid)?,
                    )?,
                })
            })
            .collect::<Result<_, OwnerProofError>>()?;
        Ok(Self { leaf, siblings })
    }
}

#[cfg(feature = "proof-verify")]
impl OwnerCommitment {
    fn into_proto(self) -> hellas_rpc::pb::chain::OwnerCommitment {
        hellas_rpc::pb::chain::OwnerCommitment {
            hash: self.hash.to_vec(),
            count: self.count,
            balance: self.balance.to_be_bytes().to_vec(),
        }
    }

    fn from_proto(value: hellas_rpc::pb::chain::OwnerCommitment) -> Result<Self, OwnerProofError> {
        Ok(Self {
            hash: value
                .hash
                .try_into()
                .map_err(|_| OwnerProofError::Invalid)?,
            count: value.count,
            balance: u128::from_be_bytes(
                value
                    .balance
                    .try_into()
                    .map_err(|_| OwnerProofError::Invalid)?,
            ),
        })
    }
}

/// The current object and authenticated owner leaf must describe the same holding.
#[derive(Debug, PartialEq, Eq)]
pub enum VerifiedHolding {
    OwnedCoin {
        value: u64,
        delegated_to_owner: bool,
    },
    DelegatedCoin(u64),
    Edge,
}

pub fn validate_holding(
    owner: SettlementKey,
    holding: &HoldingProof,
    object: &Object,
) -> Result<VerifiedHolding, OwnerProofError> {
    match (&holding.path.leaf, object) {
        (
            Some(OwnerLeaf::Holding {
                kind: HOLDING_COIN,
                balance,
            }),
            Object::Coin(coin),
        ) if coin.owner == owner && *balance == coin.value => Ok(VerifiedHolding::OwnedCoin {
            value: coin.value,
            delegated_to_owner: coin.delegate == Some(owner),
        }),
        (
            Some(OwnerLeaf::Holding {
                kind: HOLDING_DELEGATED,
                balance: 0,
            }),
            Object::Coin(coin),
        ) if coin.delegate == Some(owner) => Ok(VerifiedHolding::DelegatedCoin(coin.value)),
        (
            Some(OwnerLeaf::Holding {
                kind: HOLDING_EDGE,
                balance: 0,
            }),
            Object::Edge(_),
        ) => Ok(VerifiedHolding::Edge),
        _ => Err(OwnerProofError::Binding),
    }
}

#[derive(Debug, thiserror::Error)]
pub enum OwnerProofError {
    #[error("owner tree storage failed: {0}")]
    Storage(String),
    #[error("invalid owner tree node or proof")]
    Invalid,
    #[error("owner proof does not match the finalized root or requested owner/page")]
    Binding,
    #[error("owner page limit or offset is invalid")]
    Page,
}

#[allow(async_fn_in_trait)]
pub trait OwnerTreeStore {
    async fn get_node(
        &self,
        key: Digest,
    ) -> Result<Option<[u8; OWNER_NODE_BYTES]>, OwnerProofError>;
    async fn put_node(
        &mut self,
        key: Digest,
        value: Option<[u8; OWNER_NODE_BYTES]>,
    ) -> Result<(), OwnerProofError>;
}

fn hash(bytes: &[u8]) -> Key {
    Sha256::hash(bytes).into()
}
fn owner_key(owner: &SettlementKey) -> Key {
    hash(owner.as_ref())
}
fn holding_scope(owner: &SettlementKey) -> Key {
    let mut bytes = b"hellas-owner-holdings-v1".to_vec();
    bytes.extend_from_slice(owner.as_ref());
    hash(&bytes)
}
fn node_key(scope: Key, key: Key, depth: usize) -> Digest {
    let mut prefix = key;
    for bit in depth..256 {
        prefix[bit / 8] &= !(1 << (7 - bit % 8));
    }
    let mut bytes = b"hellas-owner-node-v1".to_vec();
    bytes.extend_from_slice(&scope);
    bytes.extend_from_slice(&(depth as u16).to_be_bytes());
    bytes.extend_from_slice(&prefix);
    Sha256::hash(&bytes)
}
fn bit(key: Key, depth: usize) -> bool {
    key[depth / 8] & (1 << (7 - depth % 8)) != 0
}
fn write_commit(out: &mut Vec<u8>, value: OwnerCommitment) {
    out.extend_from_slice(&value.hash);
    out.extend_from_slice(&value.count.to_be_bytes());
    out.extend_from_slice(&value.balance.to_be_bytes());
}
fn read_commit(bytes: &[u8]) -> Result<OwnerCommitment, OwnerProofError> {
    if bytes.len() != 56 {
        return Err(OwnerProofError::Invalid);
    }
    let value = OwnerCommitment {
        hash: bytes[..32].try_into().unwrap(),
        count: u64::from_be_bytes(bytes[32..40].try_into().unwrap()),
        balance: u128::from_be_bytes(bytes[40..56].try_into().unwrap()),
    };
    if (value.count == 0) != (value.hash == [0; 32]) || (value.count == 0 && value.balance != 0) {
        return Err(OwnerProofError::Invalid);
    }
    Ok(value)
}
fn combine(
    left: OwnerCommitment,
    right: OwnerCommitment,
) -> Result<OwnerCommitment, OwnerProofError> {
    let count = left
        .count
        .checked_add(right.count)
        .ok_or(OwnerProofError::Invalid)?;
    let balance = left
        .balance
        .checked_add(right.balance)
        .ok_or(OwnerProofError::Invalid)?;
    if count == 0 {
        return Ok(OwnerCommitment::default());
    }
    let mut bytes = b"hellas-owner-branch-v1".to_vec();
    write_commit(&mut bytes, left);
    write_commit(&mut bytes, right);
    Ok(OwnerCommitment {
        hash: hash(&bytes),
        count,
        balance,
    })
}
fn leaf_commit(
    scope: Key,
    key: Key,
    leaf: &Option<OwnerLeaf>,
) -> Result<OwnerCommitment, OwnerProofError> {
    let Some(leaf) = leaf else {
        return Ok(OwnerCommitment::default());
    };
    let mut bytes = b"hellas-owner-leaf-v1".to_vec();
    bytes.extend_from_slice(&scope);
    bytes.extend_from_slice(&key);
    let balance = match leaf {
        OwnerLeaf::Summary(root) => {
            if scope != [0; 32] || root.count == 0 {
                return Err(OwnerProofError::Invalid);
            }
            bytes.push(1);
            write_commit(&mut bytes, *root);
            root.balance
        }
        OwnerLeaf::Holding { kind, balance } => {
            // Only a held coin carries balance, so a page's total is the
            // key's spendable value and never counts a delegated coin or
            // an edge.
            let valid = match *kind {
                HOLDING_COIN => true,
                HOLDING_EDGE | HOLDING_DELEGATED => *balance == 0,
                _ => false,
            };
            if scope == [0; 32] || !valid {
                return Err(OwnerProofError::Invalid);
            }
            bytes.push(2);
            bytes.push(*kind);
            bytes.extend_from_slice(&balance.to_be_bytes());
            u128::from(*balance)
        }
    };
    Ok(OwnerCommitment {
        hash: hash(&bytes),
        count: 1,
        balance,
    })
}
fn encode_leaf(leaf: &OwnerLeaf) -> [u8; OWNER_NODE_BYTES] {
    let mut bytes = Vec::new();
    match leaf {
        OwnerLeaf::Summary(root) => {
            bytes.push(1);
            write_commit(&mut bytes, *root);
        }
        OwnerLeaf::Holding { kind, balance } => {
            bytes.push(2);
            bytes.push(*kind);
            bytes.extend_from_slice(&balance.to_be_bytes());
        }
    }
    let mut out = [0; OWNER_NODE_BYTES];
    out[..bytes.len()].copy_from_slice(&bytes);
    out
}
fn decode_leaf(raw: Option<[u8; OWNER_NODE_BYTES]>) -> Result<Option<OwnerLeaf>, OwnerProofError> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    match raw[0] {
        1 if raw[57..].iter().all(|b| *b == 0) => {
            Ok(Some(OwnerLeaf::Summary(read_commit(&raw[1..57])?)))
        }
        2 if raw[10..].iter().all(|b| *b == 0) => Ok(Some(OwnerLeaf::Holding {
            kind: raw[1],
            balance: u64::from_be_bytes(raw[2..10].try_into().unwrap()),
        })),
        _ => Err(OwnerProofError::Invalid),
    }
}
fn branch(
    raw: Option<[u8; OWNER_NODE_BYTES]>,
) -> Result<(OwnerCommitment, OwnerCommitment), OwnerProofError> {
    let Some(raw) = raw else {
        return Ok((OwnerCommitment::default(), OwnerCommitment::default()));
    };
    if raw[0] != 0 || raw[113..].iter().any(|b| *b != 0) {
        return Err(OwnerProofError::Invalid);
    }
    Ok((read_commit(&raw[1..57])?, read_commit(&raw[57..113])?))
}
fn encode_branch(left: OwnerCommitment, right: OwnerCommitment) -> Option<[u8; OWNER_NODE_BYTES]> {
    if left.count == 0 && right.count == 0 {
        return None;
    }
    let mut bytes = vec![0];
    write_commit(&mut bytes, left);
    write_commit(&mut bytes, right);
    let mut out = [0; OWNER_NODE_BYTES];
    out[..bytes.len()].copy_from_slice(&bytes);
    Some(out)
}

async fn update<S: OwnerTreeStore>(
    store: &mut S,
    scope: Key,
    key: Key,
    leaf: Option<OwnerLeaf>,
) -> Result<OwnerCommitment, OwnerProofError> {
    let proof = path(store, scope, key).await?;
    let siblings = expand_siblings(&proof)?;
    let mut current = leaf_commit(scope, key, &leaf)?;
    store
        .put_node(node_key(scope, key, 256), leaf.as_ref().map(encode_leaf))
        .await?;
    for depth in (0..256).rev() {
        let sibling = siblings[depth];
        let (left, right) = if bit(key, depth) {
            (sibling, current)
        } else {
            (current, sibling)
        };
        current = combine(left, right)?;
        store
            .put_node(node_key(scope, key, depth), encode_branch(left, right))
            .await?;
    }
    Ok(current)
}
async fn path<S: OwnerTreeStore>(
    store: &S,
    scope: Key,
    key: Key,
) -> Result<OwnerPathProof, OwnerProofError> {
    let mut siblings = Vec::new();
    for depth in 0..256 {
        let (left, right) = branch(store.get_node(node_key(scope, key, depth)).await?)?;
        let sibling = if bit(key, depth) { left } else { right };
        if sibling.count > 0 {
            siblings.push(OwnerSibling {
                depth: depth as u16,
                commitment: sibling,
            });
        }
    }
    let leaf = decode_leaf(store.get_node(node_key(scope, key, 256)).await?)?;
    Ok(OwnerPathProof { leaf, siblings })
}
fn expand_siblings(proof: &OwnerPathProof) -> Result<Vec<OwnerCommitment>, OwnerProofError> {
    if proof.siblings.len() > 256 {
        return Err(OwnerProofError::Invalid);
    }
    let mut siblings = vec![OwnerCommitment::default(); 256];
    let mut previous = None;
    for sibling in &proof.siblings {
        let depth = usize::from(sibling.depth);
        if depth >= 256
            || previous.is_some_and(|previous| depth <= previous)
            || sibling.commitment.count == 0
        {
            return Err(OwnerProofError::Invalid);
        }
        let mut bytes = Vec::new();
        write_commit(&mut bytes, sibling.commitment);
        read_commit(&bytes)?;
        siblings[depth] = sibling.commitment;
        previous = Some(depth);
    }
    Ok(siblings)
}
fn verify_path(
    scope: Key,
    key: Key,
    proof: &OwnerPathProof,
) -> Result<(OwnerCommitment, u64), OwnerProofError> {
    let siblings = expand_siblings(proof)?;
    let mut current = leaf_commit(scope, key, &proof.leaf)?;
    let mut rank = 0_u64;
    for depth in (0..256).rev() {
        let sibling = siblings[depth];
        let mut bytes = Vec::new();
        write_commit(&mut bytes, sibling);
        read_commit(&bytes)?;
        current = if bit(key, depth) {
            rank = rank
                .checked_add(sibling.count)
                .ok_or(OwnerProofError::Invalid)?;
            combine(sibling, current)?
        } else {
            combine(current, sibling)?
        };
    }
    Ok((current, rank))
}

pub async fn owner_root<S: OwnerTreeStore>(store: &S) -> Result<Key, OwnerProofError> {
    let (left, right) = branch(store.get_node(node_key([0; 32], [0; 32], 0)).await?)?;
    Ok(combine(left, right)?.hash)
}

/// Applies one object's owner membership to speculative storage. The kind is one of
/// [`HOLDING_COIN`], [`HOLDING_EDGE`] and [`HOLDING_DELEGATED`]; only a held coin contributes to
/// spendable balance. Removing the last holding removes its owner.
pub async fn update_holding<S: OwnerTreeStore>(
    store: &mut S,
    owner: SettlementKey,
    object_id: Digest,
    value: Option<(u8, u64)>,
) -> Result<(), OwnerProofError> {
    let holdings = update(
        store,
        holding_scope(&owner),
        object_id.into(),
        value.map(|(kind, balance)| OwnerLeaf::Holding { kind, balance }),
    )
    .await?;
    update(
        store,
        [0; 32],
        owner_key(&owner),
        if holdings.count == 0 {
            None
        } else {
            Some(OwnerLeaf::Summary(holdings))
        },
    )
    .await?;
    Ok(())
}

pub async fn prove_owner_page<S: OwnerTreeStore>(
    store: &S,
    owner: SettlementKey,
    offset: u64,
    limit: u32,
) -> Result<OwnerPageProof, OwnerProofError> {
    if limit == 0 || limit > OWNER_PAGE_LIMIT {
        return Err(OwnerProofError::Page);
    }
    let summary = path(store, [0; 32], owner_key(&owner)).await?;
    let holdings_root = match &summary.leaf {
        None => OwnerCommitment::default(),
        Some(OwnerLeaf::Summary(root)) => *root,
        _ => return Err(OwnerProofError::Invalid),
    };
    if offset > holdings_root.count {
        return Err(OwnerProofError::Page);
    }
    let end = offset
        .saturating_add(u64::from(limit))
        .min(holdings_root.count);
    let scope = holding_scope(&owner);
    let mut holdings = Vec::new();
    let mut stack = vec![([0; 32], 0_usize, 0_u64, holdings_root)];
    while let Some((key, depth, rank, commit)) = stack.pop() {
        if commit.count == 0 || rank >= end || rank.saturating_add(commit.count) <= offset {
            continue;
        }
        if depth == 256 {
            holdings.push(HoldingProof {
                object_id: key,
                path: path(store, scope, key).await?,
            });
            continue;
        }
        let (left, right) = branch(store.get_node(node_key(scope, key, depth)).await?)?;
        if combine(left, right)? != commit {
            return Err(OwnerProofError::Invalid);
        }
        let mut right_key = key;
        right_key[depth / 8] |= 1 << (7 - depth % 8);
        stack.push((
            right_key,
            depth + 1,
            rank.checked_add(left.count)
                .ok_or(OwnerProofError::Invalid)?,
            right,
        ));
        stack.push((key, depth + 1, rank, left));
    }
    Ok(OwnerPageProof {
        owner: owner.to_string(),
        summary,
        offset,
        limit,
        holdings,
        after_key: None,
        after_path: None,
    })
}

/// Prove the first holdings strictly after a key at this owner root. A deleted
/// cursor has an absence proof; its insertion rank is the next page's start.
pub async fn prove_owner_page_after<S: OwnerTreeStore>(
    store: &S,
    owner: SettlementKey,
    after: Option<Key>,
    limit: u32,
) -> Result<OwnerPageProof, OwnerProofError> {
    let Some(key) = after else {
        return prove_owner_page(store, owner, 0, limit).await;
    };
    let cursor = path(store, holding_scope(&owner), key).await?;
    let (_, rank) = verify_path(holding_scope(&owner), key, &cursor)?;
    let offset = rank
        .checked_add(u64::from(cursor.leaf.is_some()))
        .ok_or(OwnerProofError::Invalid)?;
    let mut page = prove_owner_page(store, owner, offset, limit).await?;
    page.after_key = Some(key);
    page.after_path = Some(cursor);
    Ok(page)
}

/// Verifies ownership, total spendable balance, absence, and page completeness at one finalized
/// owner root. Returns the authenticated summary (its count is the total number of holdings).
pub fn verify_owner_page(
    root: Key,
    owner: SettlementKey,
    offset: u64,
    limit: u32,
    proof: &OwnerPageProof,
) -> Result<OwnerCommitment, OwnerProofError> {
    if proof.after_key.is_some() || proof.after_path.is_some() {
        return Err(OwnerProofError::Binding);
    }
    verify_owner_page_at(root, owner, offset, limit, proof)
}

pub fn verify_owner_page_after(
    root: Key,
    owner: SettlementKey,
    after: Option<Key>,
    limit: u32,
    proof: &OwnerPageProof,
) -> Result<OwnerCommitment, OwnerProofError> {
    let offset = match (after, proof.after_key, proof.after_path.as_ref()) {
        (None, None, None) => 0,
        (Some(requested), Some(proved), Some(path)) if requested == proved => {
            let (commitment, rank) = verify_path(holding_scope(&owner), requested, path)?;
            let summary = match &proof.summary.leaf {
                Some(OwnerLeaf::Summary(summary)) => *summary,
                None => OwnerCommitment::default(),
                _ => return Err(OwnerProofError::Invalid),
            };
            if commitment != summary {
                return Err(OwnerProofError::Binding);
            }
            rank.checked_add(u64::from(path.leaf.is_some()))
                .ok_or(OwnerProofError::Invalid)?
        }
        _ => return Err(OwnerProofError::Binding),
    };
    verify_owner_page_at(root, owner, offset, limit, proof)
}

fn verify_owner_page_at(
    root: Key,
    owner: SettlementKey,
    offset: u64,
    limit: u32,
    proof: &OwnerPageProof,
) -> Result<OwnerCommitment, OwnerProofError> {
    if proof.owner != owner.to_string() || proof.offset != offset || proof.limit != limit {
        return Err(OwnerProofError::Binding);
    }
    if limit == 0 || limit > OWNER_PAGE_LIMIT {
        return Err(OwnerProofError::Page);
    }
    if verify_path([0; 32], owner_key(&owner), &proof.summary)?
        .0
        .hash
        != root
    {
        return Err(OwnerProofError::Binding);
    }
    let summary = match &proof.summary.leaf {
        None => OwnerCommitment::default(),
        Some(OwnerLeaf::Summary(root)) => *root,
        _ => return Err(OwnerProofError::Invalid),
    };
    if offset > summary.count
        || proof.holdings.len() as u64 != u64::from(limit).min(summary.count - offset)
    {
        return Err(OwnerProofError::Page);
    }
    for (position, holding) in proof.holdings.iter().enumerate() {
        if !matches!(holding.path.leaf, Some(OwnerLeaf::Holding { .. })) {
            return Err(OwnerProofError::Invalid);
        }
        let (actual, rank) = verify_path(holding_scope(&owner), holding.object_id, &holding.path)?;
        if actual != summary || rank != offset + position as u64 {
            return Err(OwnerProofError::Binding);
        }
    }
    Ok(summary)
}

/// Rebuildable native snapshot backend. Durable native history remains in the finalized archive.
#[derive(Clone, Default)]
pub struct MemoryOwnerTree {
    nodes: std::collections::BTreeMap<Digest, [u8; OWNER_NODE_BYTES]>,
}
impl OwnerTreeStore for MemoryOwnerTree {
    async fn get_node(
        &self,
        key: Digest,
    ) -> Result<Option<[u8; OWNER_NODE_BYTES]>, OwnerProofError> {
        Ok(self.nodes.get(&key).copied())
    }
    async fn put_node(
        &mut self,
        key: Digest,
        value: Option<[u8; OWNER_NODE_BYTES]>,
    ) -> Result<(), OwnerProofError> {
        match value {
            Some(value) => {
                self.nodes.insert(key, value);
            }
            None => {
                self.nodes.remove(&key);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod holding_tests {
    use super::*;

    #[test]
    fn holding_leaf_must_match_current_coin_owner_delegate_and_value() {
        let owner = SettlementKey::from_bytes([1; 33]);
        let delegate = SettlementKey::from_bytes([2; 33]);
        let holding = HoldingProof {
            object_id: [3; 32],
            path: OwnerPathProof {
                leaf: Some(OwnerLeaf::Holding {
                    kind: HOLDING_COIN,
                    balance: 7,
                }),
                siblings: Vec::new(),
            },
        };
        let coin = Object::Coin(crate::domain::Coin::owned(owner, 7));
        assert_eq!(
            validate_holding(owner, &holding, &coin).unwrap(),
            VerifiedHolding::OwnedCoin {
                value: 7,
                delegated_to_owner: false
            }
        );
        assert!(validate_holding(delegate, &holding, &coin).is_err());
        let wrong_value = Object::Coin(crate::domain::Coin::owned(owner, 8));
        assert!(validate_holding(owner, &holding, &wrong_value).is_err());

        let delegated = HoldingProof {
            path: OwnerPathProof {
                leaf: Some(OwnerLeaf::Holding {
                    kind: HOLDING_DELEGATED,
                    balance: 0,
                }),
                siblings: Vec::new(),
            },
            ..holding
        };
        let coin = Object::Coin(crate::domain::Coin {
            owner,
            delegate: Some(delegate),
            value: 7,
        });
        assert_eq!(
            validate_holding(delegate, &delegated, &coin).unwrap(),
            VerifiedHolding::DelegatedCoin(7)
        );
    }
}

#[cfg(all(test, feature = "indexer"))]
mod tests {
    use super::*;
    use commonware_runtime::{Runner as _, deterministic};
    #[test]
    fn cursor_proof_starts_at_insertion_rank_after_removal() {
        deterministic::Runner::default().start(|_| async {
            let owner = SettlementKey::from_bytes([3; 33]);
            let mut tree = MemoryOwnerTree::default();
            for key in [1_u8, 3, 5, 7] {
                update_holding(
                    &mut tree,
                    owner,
                    Digest::from([key; 32]),
                    Some((HOLDING_COIN, 1)),
                )
                .await
                .unwrap();
            }
            let first = prove_owner_page_after(&tree, owner, None, 2).await.unwrap();
            let root = owner_root(&tree).await.unwrap();
            verify_owner_page_after(root, owner, None, 2, &first).unwrap();
            assert_eq!(
                first
                    .holdings
                    .iter()
                    .map(|holding| holding.object_id[0])
                    .collect::<Vec<_>>(),
                vec![1, 3]
            );
            update_holding(&mut tree, owner, Digest::from([3; 32]), None)
                .await
                .unwrap();
            let root = owner_root(&tree).await.unwrap();
            let second = prove_owner_page_after(&tree, owner, Some([3; 32]), 2)
                .await
                .unwrap();
            verify_owner_page_after(root, owner, Some([3; 32]), 2, &second).unwrap();
            assert_eq!(
                second
                    .holdings
                    .iter()
                    .map(|holding| holding.object_id[0])
                    .collect::<Vec<_>>(),
                vec![5, 7]
            );
            assert!(verify_owner_page_after(root, owner, Some([1; 32]), 2, &second).is_err());
            let mut omitted = second.clone();
            omitted.holdings.remove(0);
            assert!(verify_owner_page_after(root, owner, Some([3; 32]), 2, &omitted).is_err());
        });
    }
    #[test]
    fn compact_pages_omit_empty_paths_and_reject_duplicate_depths() {
        deterministic::Runner::default().start(|_| async {
            let owner = SettlementKey::from_bytes([3; 33]);
            let mut tree = MemoryOwnerTree::default();
            for index in 0_u64..64 {
                let id = Sha256::hash(&index.to_be_bytes());
                update_holding(&mut tree, owner, id, Some((0, index)))
                    .await
                    .unwrap();
            }
            let root = owner_root(&tree).await.unwrap();
            let page = prove_owner_page(&tree, owner, 0, OWNER_PAGE_LIMIT)
                .await
                .unwrap();
            verify_owner_page(root, owner, 0, OWNER_PAGE_LIMIT, &page).unwrap();
            assert_eq!(page.holdings.len(), OWNER_PAGE_LIMIT as usize);
            let next =
                prove_owner_page(&tree, owner, u64::from(OWNER_PAGE_LIMIT), OWNER_PAGE_LIMIT)
                    .await
                    .unwrap();
            verify_owner_page(
                root,
                owner,
                u64::from(OWNER_PAGE_LIMIT),
                OWNER_PAGE_LIMIT,
                &next,
            )
            .unwrap();
            assert_eq!(next.holdings.len(), OWNER_PAGE_LIMIT as usize);
            let bytes = serde_json::to_vec(&page).unwrap();
            assert!(
                bytes.len() < 256 * 1024,
                "compact owner page used {} bytes",
                bytes.len()
            );
            let mut bad = page;
            let sibling = bad.holdings[0].path.siblings[0].clone();
            bad.holdings[0].path.siblings.insert(0, sibling);
            assert!(verify_owner_page(root, owner, 0, OWNER_PAGE_LIMIT, &bad).is_err());
        });
    }

    #[test]
    fn membership_absence_rank_completeness_and_tampering() {
        deterministic::Runner::default().start(|_| async {
            let mut tree = MemoryOwnerTree::default();
            let owner = SettlementKey::from_bytes([1; 33]);
            let absent = SettlementKey::from_bytes([2; 33]);
            for (id, balance) in [(1, 10), (3, 30), (2, 20)] {
                update_holding(&mut tree, owner, Digest::from([id; 32]), Some((0, balance)))
                    .await
                    .unwrap();
            }
            let root = owner_root(&tree).await.unwrap();
            let page = prove_owner_page(&tree, owner, 1, 1).await.unwrap();
            let summary = verify_owner_page(root, owner, 1, 1, &page).unwrap();
            assert_eq!(summary.count, 3);
            assert_eq!(summary.balance, 60);
            assert_eq!(page.holdings[0].object_id, [2; 32]);
            let empty = prove_owner_page(&tree, absent, 0, 5).await.unwrap();
            assert_eq!(
                verify_owner_page(root, absent, 0, 5, &empty).unwrap().count,
                0
            );
            let last = prove_owner_page(&tree, owner, 2, OWNER_PAGE_LIMIT)
                .await
                .unwrap();
            assert_eq!(last.holdings.len(), 1);
            verify_owner_page(root, owner, 2, OWNER_PAGE_LIMIT, &last).unwrap();
            let mut bad = page.clone();
            bad.holdings.clear();
            assert!(verify_owner_page(root, owner, 1, 1, &bad).is_err());
            let mut bad = page.clone();
            bad.holdings[0].object_id = [3; 32];
            assert!(verify_owner_page(root, owner, 1, 1, &bad).is_err());
            let mut bad = page.clone();
            if let Some(OwnerLeaf::Summary(summary)) = &mut bad.summary.leaf {
                summary.balance += 1;
            }
            assert!(verify_owner_page(root, owner, 1, 1, &bad).is_err());
            assert!(verify_owner_page(root, absent, 1, 1, &page).is_err());
            update_holding(&mut tree, owner, Digest::from([2; 32]), None)
                .await
                .unwrap();
            let changed = owner_root(&tree).await.unwrap();
            assert_ne!(root, changed);
            assert!(verify_owner_page(changed, owner, 1, 1, &page).is_err());
            for id in [1, 3] {
                update_holding(&mut tree, owner, Digest::from([id; 32]), None)
                    .await
                    .unwrap();
            }
            assert_eq!(owner_root(&tree).await.unwrap(), [0; 32]);
        });
    }
}
