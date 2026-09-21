use super::{store::UtxoDatabase, verifier::ChainVerifier, working_set::BlockWorkingSet};
use crate::domain::{
    Address, Coin, MAX_EDGE_LIFETIME_BLOCKS, MergeInputFault, Object, ObjectId, ObjectKind,
    SettlementKey, Transaction, coin_object_id, edge_object_id, genesis_object_id,
    merge_input_fault, output_object_id, registry_chunk_object_id,
};
use commonware_codec::Encode;
#[cfg(any(feature = "validator", test))]
use commonware_codec::EncodeSize;
use commonware_cryptography::{Hasher, Sha256};
use commonware_glue::stateful::db::DatabaseSet;
use commonware_runtime::Spawner;
use commonware_storage::Context as StorageContext;
#[cfg(any(feature = "validator", test))]
use hellas_kernel::InvalidProofReason;
use hellas_kernel::{
    ApplyError, CloseKind, Coin as KernelCoin, CoinId, Context as KernelContext, EdgeId, Event,
    EventKind, Move as KernelMove, Proof as KernelProof, RegistryChunkId, RegistryDiff, State,
    TermsProfile, Tx as KernelTx, bond_lease_slots, pending_payment_close_slot,
};
use thiserror::Error;
use tracing::warn;

type Batch<E> = <UtxoDatabase<E> as DatabaseSet<E>>::Unmerkleized;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ExecutionError {
    #[error("object not found: {id:?}")]
    ObjectNotFound { id: ObjectId },
    #[error("wrong object kind for {id:?}: expected {expected}, found {actual}")]
    WrongObjectKind {
        id: ObjectId,
        expected: ObjectKind,
        actual: ObjectKind,
    },
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
    #[error("storage error: {0}")]
    Storage(String),
    #[error("kernel host/store contract failure: {error:?}")]
    KernelHostContract { error: ApplyError },
    #[error("kernel transaction rejected: {error:?}")]
    KernelApply { error: ApplyError },
    #[error("staked open lifetime {blocks} blocks exceeds the consensus cap {max}")]
    EdgeLifetimeExceeded { blocks: u64, max: u64 },
}

#[cfg(any(feature = "validator", test))]
impl ExecutionError {
    pub fn is_transient_for_mempool(&self) -> bool {
        matches!(
            self,
            Self::ObjectNotFound { .. }
                | Self::KernelApply {
                    error: ApplyError::InvalidProof {
                        reason: InvalidProofReason::TimeoutNotReached,
                        ..
                    }
                }
        )
    }

    pub fn is_fatal_storage(&self) -> bool {
        matches!(self, Self::Storage(_) | Self::KernelHostContract { .. })
    }
}

fn storage_err<E: core::fmt::Debug>(err: E) -> ExecutionError {
    ExecutionError::Storage(format!("{err:?}"))
}

fn require_coin(id: ObjectId, object: Option<Object>) -> Result<Coin, ExecutionError> {
    match object {
        Some(Object::Coin(coin)) => Ok(coin),
        Some(object) => Err(ExecutionError::WrongObjectKind {
            id,
            expected: ObjectKind::Coin,
            actual: object.kind(),
        }),
        None => Err(ExecutionError::ObjectNotFound { id }),
    }
}

fn legacy_owner_address(owner: SettlementKey) -> Result<Address, ExecutionError> {
    Address::try_from(owner).map_err(|_| ExecutionError::InvalidSignature)
}

async fn object_exists<E>(batches: &Batch<E>, id: &ObjectId) -> Result<bool, ExecutionError>
where
    E: StorageContext + Spawner + Send + Sync + 'static,
{
    batches
        .get(id)
        .await
        .map(|value| value.is_some())
        .map_err(storage_err)
}

#[cfg(any(feature = "validator", test))]
pub async fn execute_all<E>(
    context: KernelContext,
    verifier: &ChainVerifier,
    txs: &[Transaction],
    genesis_allocations: &[(SettlementKey, u64)],
    batches: Batch<E>,
) -> Result<Batch<E>, ExecutionError>
where
    E: StorageContext + Spawner + Send + Sync + 'static,
{
    let mut batches = maybe_seed_genesis(context, genesis_allocations, batches, None).await?;
    for tx in txs {
        let next = apply_transaction(batches, context, verifier, tx)
            .await
            .map_err(|(_, err)| err)?;
        batches = next;
    }
    Ok(batches)
}

#[cfg(any(feature = "validator", test))]
pub async fn execute_proposal<E>(
    context: KernelContext,
    verifier: &ChainVerifier,
    candidates: Vec<Transaction>,
    genesis_allocations: &[(SettlementKey, u64)],
    max_txs: usize,
    max_tx_bytes: usize,
    batches: Batch<E>,
) -> Result<(Batch<E>, Vec<Transaction>, Vec<Transaction>), ExecutionError>
where
    E: StorageContext + Spawner + Send + Sync + 'static,
{
    let mut batches = maybe_seed_genesis(context, genesis_allocations, batches, None).await?;
    let mut included = Vec::new();
    let mut retained = Vec::new();
    let mut included_bytes = 0_usize;
    let mut candidates = candidates.into_iter();

    while let Some(tx) = candidates.next() {
        let next_bytes = included_bytes.saturating_add(tx.encode_size());
        if included.len() >= max_txs || next_bytes > max_tx_bytes {
            retained.push(tx);
            retained.extend(candidates);
            break;
        }

        match apply_transaction(batches, context, verifier, &tx).await {
            Ok(next) => {
                batches = next;
                included_bytes = next_bytes;
                included.push(tx);
            }
            Err((next, err))
                if err.is_transient_for_mempool() && !response_contest_was_removed(&tx, &err) =>
            {
                batches = next;
                retained.push(tx);
            }
            Err((next, err)) if err.is_fatal_storage() => {
                let _ = next;
                return Err(err);
            }
            Err((next, _err)) => {
                batches = next;
            }
        }
    }

    Ok((batches, included, retained))
}

#[cfg(any(feature = "validator", test))]
fn response_contest_was_removed(transaction: &Transaction, error: &ExecutionError) -> bool {
    let Transaction::Kernel(KernelTx::Move {
        action: KernelMove::RespondPaymentClose(response),
    }) = transaction
    else {
        return false;
    };
    matches!(
        error,
        ExecutionError::ObjectNotFound { id }
            if *id == edge_object_id(response.payment_edge())
    )
}

// Preserve the validator's allocation limit and identifier derivation for replay.
fn genesis_coins(
    allocations: &[(SettlementKey, u64)],
) -> impl Iterator<Item = (ObjectId, Coin)> + '_ {
    allocations
        .iter()
        .enumerate()
        .map_while(|(idx, (owner, balance))| {
            let Ok(index) = u16::try_from(idx) else {
                warn!(
                    index = idx,
                    "validator index overflow; truncating genesis allocation"
                );
                return None;
            };
            Some((
                genesis_object_id(index),
                Coin {
                    owner: *owner,
                    value: *balance,
                },
            ))
        })
}

async fn maybe_seed_genesis<E>(
    context: KernelContext,
    genesis_allocations: &[(SettlementKey, u64)],
    mut batches: Batch<E>,
    mut changes: Option<&mut Vec<(ObjectId, Option<Object>)>>,
) -> Result<Batch<E>, ExecutionError>
where
    E: StorageContext + Spawner + Send + Sync + 'static,
{
    if context.block_height().get() != 1 {
        return Ok(batches);
    }

    for (id, coin) in genesis_coins(genesis_allocations) {
        batches = super::owner_tree::write_owned(batches, id, Some(Object::Coin(coin)))
            .await
            .map_err(|(_, error)| error)?;
        if let Some(changes) = changes.as_deref_mut() {
            changes.push((id, Some(Object::Coin(coin))));
        }
    }
    Ok(batches)
}

async fn apply_transaction<E>(
    mut batches: Batch<E>,
    context: KernelContext,
    verifier: &ChainVerifier,
    tx: &Transaction,
) -> Result<Batch<E>, (Batch<E>, ExecutionError)>
where
    E: StorageContext + Spawner + Send + Sync + 'static,
{
    match tx {
        Transaction::Transfer {
            input,
            recipient,
            amount,
            ..
        } => {
            let object = match batches.get(input).await.map_err(storage_err) {
                Ok(object) => object,
                Err(err) => return Err((batches, err)),
            };
            let coin = match require_coin(*input, object) {
                Ok(coin) => coin,
                Err(err) => return Err((batches, err)),
            };
            let owner = match legacy_owner_address(coin.owner) {
                Ok(owner) => owner,
                Err(err) => return Err((batches, err)),
            };
            if !tx.verify_signature(context.network(), &owner) {
                return Err((batches, ExecutionError::InvalidSignature));
            }
            if *amount == 0 {
                return Err((batches, ExecutionError::ZeroAmount));
            }
            if *amount > coin.value {
                return Err((
                    batches,
                    ExecutionError::InsufficientBalance {
                        available: coin.value,
                        requested: *amount,
                    },
                ));
            }

            let tx_digest = Sha256::hash(&tx.encode());
            let recipient_id = output_object_id(&tx_digest, 0);
            match object_exists(&batches, &recipient_id).await {
                Ok(false) => {}
                Ok(true) => {
                    return Err((
                        batches,
                        ExecutionError::OutputCollision { id: recipient_id },
                    ));
                }
                Err(err) => return Err((batches, err)),
            }

            let change_value = coin.value - amount;
            let change_id = if change_value > 0 {
                let id = output_object_id(&tx_digest, 1);
                let exists = if id == recipient_id {
                    true
                } else {
                    match object_exists(&batches, &id).await {
                        Ok(exists) => exists,
                        Err(err) => return Err((batches, err)),
                    }
                };
                if exists {
                    return Err((batches, ExecutionError::OutputCollision { id }));
                }
                Some(id)
            } else {
                None
            };

            batches = super::owner_tree::write_owned(batches, *input, None).await?;
            batches = super::owner_tree::write_owned(
                batches,
                recipient_id,
                Some(Object::Coin(Coin {
                    owner: SettlementKey::from(recipient),
                    value: *amount,
                })),
            )
            .await?;

            if let Some(change_id) = change_id {
                batches = super::owner_tree::write_owned(
                    batches,
                    change_id,
                    Some(Object::Coin(Coin {
                        owner: coin.owner,
                        value: change_value,
                    })),
                )
                .await?;
            }
            Ok(batches)
        }
        Transaction::MergeCoin { inputs, .. } => {
            if let Some(fault) = merge_input_fault(inputs.as_slice()) {
                return Err((
                    batches,
                    match fault {
                        MergeInputFault::TooFew => ExecutionError::TooFewMergeInputs,
                        MergeInputFault::Duplicate(id) => ExecutionError::DuplicateInput { id },
                        MergeInputFault::NonCanonical => ExecutionError::NonCanonicalMergeInputs,
                    },
                ));
            }

            let mut owner: Option<SettlementKey> = None;
            let mut total = 0u64;
            for input in inputs {
                let object = match batches.get(input).await.map_err(storage_err) {
                    Ok(object) => object,
                    Err(err) => return Err((batches, err)),
                };
                let coin = match require_coin(*input, object) {
                    Ok(coin) => coin,
                    Err(err) => return Err((batches, err)),
                };
                if let Some(expected_owner) = owner.as_ref() {
                    if &coin.owner != expected_owner {
                        return Err((batches, ExecutionError::MergeOwnerMismatch));
                    }
                } else {
                    owner = Some(coin.owner);
                }
                total = match total.checked_add(coin.value) {
                    Some(total) => total,
                    None => return Err((batches, ExecutionError::MergeOverflow)),
                };
            }
            let Some(owner) = owner else {
                return Err((batches, ExecutionError::MergeOwnerMismatch));
            };
            let address = match legacy_owner_address(owner) {
                Ok(address) => address,
                Err(err) => return Err((batches, err)),
            };
            if !tx.verify_signature(context.network(), &address) {
                return Err((batches, ExecutionError::InvalidSignature));
            }

            let tx_digest = Sha256::hash(&tx.encode());
            let output_id = output_object_id(&tx_digest, 0);
            match object_exists(&batches, &output_id).await {
                Ok(false) => {}
                Ok(true) => {
                    return Err((batches, ExecutionError::OutputCollision { id: output_id }));
                }
                Err(err) => return Err((batches, err)),
            }

            for input in inputs {
                batches = super::owner_tree::write_owned(batches, *input, None).await?;
            }
            batches = super::owner_tree::write_owned(
                batches,
                output_id,
                Some(Object::Coin(Coin {
                    owner,
                    value: total,
                })),
            )
            .await?;
            Ok(batches)
        }
        Transaction::Kernel(tx) => apply_kernel_transaction(batches, context, verifier, tx).await,
    }
}

async fn load_coin_slot<E>(
    batches: &Batch<E>,
    working: &mut BlockWorkingSet,
    id: CoinId,
) -> Result<(), ExecutionError>
where
    E: StorageContext + Spawner + Send + Sync + 'static,
{
    let object_id = coin_object_id(id);
    let coin = match batches.get(&object_id).await.map_err(storage_err)? {
        Some(Object::Coin(coin)) => Some(KernelCoin::from(coin)),
        Some(object) => {
            return Err(ExecutionError::WrongObjectKind {
                id: object_id,
                expected: ObjectKind::Coin,
                actual: object.kind(),
            });
        }
        None => None,
    };
    working.insert_coin_slot(id, coin);
    Ok(())
}

async fn load_edge_slot<E>(
    batches: &Batch<E>,
    working: &mut BlockWorkingSet,
    id: EdgeId,
) -> Result<(), ExecutionError>
where
    E: StorageContext + Spawner + Send + Sync + 'static,
{
    let object_id = edge_object_id(id);
    let edge = match batches.get(&object_id).await.map_err(storage_err)? {
        Some(Object::Edge(edge)) => Some(edge),
        Some(object) => {
            return Err(ExecutionError::WrongObjectKind {
                id: object_id,
                expected: ObjectKind::Edge,
                actual: object.kind(),
            });
        }
        None => None,
    };
    working.insert_edge_slot(id, edge);
    Ok(())
}

/// Preloads the registry chunk slot `id` into `working`.
///
/// Kept beside the coin and edge loaders because the three obey one rule:
/// a slot the kernel may write has to be declared before apply, whether
/// it is currently occupied or not.
async fn load_registry_chunk_slot<E>(
    batches: &Batch<E>,
    working: &mut BlockWorkingSet,
    id: RegistryChunkId,
) -> Result<(), ExecutionError>
where
    E: StorageContext + Spawner + Send + Sync + 'static,
{
    let object_id = registry_chunk_object_id(id);
    let chunk = match batches.get(&object_id).await.map_err(storage_err)? {
        Some(Object::RegistryChunk(chunk)) => Some(chunk),
        Some(object) => {
            return Err(ExecutionError::WrongObjectKind {
                id: object_id,
                expected: ObjectKind::RegistryChunk,
                actual: object.kind(),
            });
        }
        None => None,
    };
    working.insert_registry_chunk_slot(id, chunk);
    Ok(())
}

async fn load_kernel_slots<E>(
    batches: &Batch<E>,
    context: KernelContext,
    tx: &KernelTx,
) -> Result<BlockWorkingSet, ExecutionError>
where
    E: StorageContext + Spawner + Send + Sync + 'static,
{
    let mut working = BlockWorkingSet::new();
    match tx {
        KernelTx::Open { funding, terms, .. } => {
            for id in funding.maker().iter().chain(funding.taker()) {
                load_coin_slot(batches, &mut working, *id).await?;
            }
            load_edge_slot(batches, &mut working, KernelTx::edge_id_of(funding, terms)).await?;
            // A work-payment open leases the bond it names, which means
            // it reads that edge and writes both chunks of the lease.
            // All three have to be declared: an undeclared read is
            // reported as absence, which would let a live bond look
            // missing, and an undeclared write cannot be replayed at
            // all.
            if let TermsProfile::WorkPayment(payment) = terms.profile() {
                load_edge_slot(batches, &mut working, payment.bond_edge).await?;
                for slot in bond_lease_slots(context.network(), payment.bond_edge) {
                    load_registry_chunk_slot(batches, &mut working, slot).await?;
                }
            }
        }
        KernelTx::Close {
            input,
            proof,
            outputs,
        } => {
            load_edge_slot(batches, &mut working, *input).await?;
            for id in KernelTx::close_output_ids(*input, outputs).iter() {
                load_coin_slot(batches, &mut working, *id).await?;
            }
            // The two work-payment exits read, and retire, the contest
            // record. Declaring it only when a record is expected would
            // be the wrong plan for the freeze route, whose *absence*
            // check is a read of the same slot.
            if matches!(proof.kind(), CloseKind::Freeze | CloseKind::Adjudicated) {
                load_registry_chunk_slot(
                    batches,
                    &mut working,
                    pending_payment_close_slot(context.network(), *input),
                )
                .await?;
            }
            // A tag-4 bond's timeout is decided by its lease: unleased
            // it may be taken at once, leased it waits for the horizon
            // and deletes the record. Both slots are declared whichever
            // way that goes, for the same reason the freeze route
            // declares a slot it may find empty — the absence is the
            // answer, so it has to be read rather than assumed.
            if let KernelProof::Timeout { terms } = proof
                && matches!(terms.profile(), TermsProfile::WorkStakeBond(_))
            {
                for slot in bond_lease_slots(context.network(), *input) {
                    load_registry_chunk_slot(batches, &mut working, slot).await?;
                }
            }
        }
        // A move consumes nothing. It reads the edge it addresses and
        // writes the one derived contest slot, and the host has to
        // declare both: `BlockWorkingSet` reports an undeclared read as
        // absence, which would let a live edge masquerade as missing.
        KernelTx::Move { action } => {
            let payment_edge = match action {
                KernelMove::StartPaymentClose(start) => start.payment_edge(),
                KernelMove::RespondPaymentClose(response) => response.payment_edge(),
            };
            load_edge_slot(batches, &mut working, payment_edge).await?;
            load_registry_chunk_slot(
                batches,
                &mut working,
                pending_payment_close_slot(context.network(), payment_edge),
            )
            .await?;
        }
    }
    Ok(working)
}

// `State::apply` uses the same MissingCoin/MissingEdge variants during its
// read-only validation and during its fold. The immutable parent working set
// distinguishes them: an absent preloaded value is user-controlled and
// transient, while a value that existed before apply but vanished during fold
// proves that the host violated the kernel Batch contract.
fn classify_kernel_error(working: &BlockWorkingSet, source: ApplyError) -> ExecutionError {
    match source {
        ApplyError::MissingCoin { id } if working.coin(id).is_none() => {
            ExecutionError::ObjectNotFound {
                id: coin_object_id(id),
            }
        }
        ApplyError::MissingEdge { id } if working.edge(id).is_none() => {
            ExecutionError::ObjectNotFound {
                id: edge_object_id(id),
            }
        }
        ApplyError::MissingRegistryChunk { id } if working.registry_chunk(id).is_none() => {
            ExecutionError::ObjectNotFound {
                id: registry_chunk_object_id(id),
            }
        }
        ApplyError::MissingCoin { .. }
        | ApplyError::CoinChanged { .. }
        | ApplyError::MissingEdge { .. }
        | ApplyError::EdgeChanged { .. }
        | ApplyError::MissingRegistryChunk { .. }
        | ApplyError::RegistryChunkChanged { .. }
        | ApplyError::CoinInsertRejected { .. }
        | ApplyError::EdgeInsertRejected { .. }
        | ApplyError::RegistryChunkInsertRejected { .. }
        // A transition that overran or duplicated its own registry diff
        // decided which slots it writes before writing any of them, so
        // this is the kernel disagreeing with itself rather than a
        // payload the host can blame.
        | ApplyError::RegistryDiffRejected { .. } => {
            ExecutionError::KernelHostContract { error: source }
        }
        ApplyError::OutputExists { .. }
        | ApplyError::EdgeExists { .. }
        | ApplyError::DuplicateInput { .. }
        | ApplyError::InvalidOpen { .. }
        | ApplyError::InvalidClose { .. }
        | ApplyError::InvalidProof { .. }
        | ApplyError::InvalidMove { .. } => ExecutionError::KernelApply { error: source },
    }
}

async fn replay_kernel_event<E>(
    mut batches: Batch<E>,
    working: &BlockWorkingSet,
    event: &Event,
) -> (Batch<E>, Option<ExecutionError>)
where
    E: StorageContext + Spawner + Send + Sync + 'static,
{
    // Event order is the consensus-authoritative diff. Never enumerate the
    // HashMaps in BlockWorkingSet: their iteration order is process-local.
    match event.kind() {
        EventKind::EdgeOpened { inputs, output } => {
            for id in inputs {
                if working.coin(*id).is_some() {
                    return (
                        batches,
                        Some(ExecutionError::KernelHostContract {
                            error: ApplyError::CoinChanged { id: *id },
                        }),
                    );
                }
                batches = match super::owner_tree::write_owned(batches, coin_object_id(*id), None)
                    .await
                {
                    Ok(next) => next,
                    Err((next, error)) => return (next, Some(error)),
                };
            }
            let Some(edge) = working.edge(*output) else {
                return (
                    batches,
                    Some(ExecutionError::KernelHostContract {
                        error: ApplyError::MissingEdge { id: *output },
                    }),
                );
            };
            batches = match super::owner_tree::write_owned(
                batches,
                edge_object_id(*output),
                Some(Object::Edge(edge)),
            )
            .await
            {
                Ok(next) => next,
                Err((next, error)) => return (next, Some(error)),
            };
        }
        EventKind::EdgeClosed { input, outputs } => {
            if working.edge(*input).is_some() {
                return (
                    batches,
                    Some(ExecutionError::KernelHostContract {
                        error: ApplyError::EdgeChanged { id: *input },
                    }),
                );
            }
            batches =
                match super::owner_tree::write_owned(batches, edge_object_id(*input), None).await {
                    Ok(next) => next,
                    Err((next, error)) => return (next, Some(error)),
                };
            for id in outputs {
                let Some(coin) = working.coin(*id) else {
                    return (
                        batches,
                        Some(ExecutionError::KernelHostContract {
                            error: ApplyError::MissingCoin { id: *id },
                        }),
                    );
                };
                batches = match super::owner_tree::write_owned(
                    batches,
                    coin_object_id(*id),
                    Some(Object::Coin(Coin::from(coin))),
                )
                .await
                {
                    Ok(next) => next,
                    Err((next, error)) => return (next, Some(error)),
                };
            }
        }
    }
    (batches, None)
}

/// Persists an operation's registry writes into the batch that already
/// carries its coin and edge effect.
///
/// The kernel's [`RegistryDiff`] is the authoritative slot list, in
/// replay order. Every mutation is first checked against the post-apply
/// working set: the kernel wrote these slots itself, so a working set
/// that reports anything else means the host's `Batch` is not the store
/// the kernel actually applied to — the same contract failure the event
/// replay below checks for coins and edges.
///
/// Nothing here is conditional on the operation having a public event.
/// A registry-only operation announces nothing, and replaying only
/// events would drop its state entirely.
fn replay_kernel_registry<E>(
    mut batches: Batch<E>,
    working: &BlockWorkingSet,
    registry: &RegistryDiff,
) -> (Batch<E>, Option<ExecutionError>)
where
    E: StorageContext + Spawner + Send + Sync + 'static,
{
    for mutation in registry {
        let id = mutation.id();
        if working.registry_chunk(id) != mutation.chunk() {
            return (
                batches,
                Some(ExecutionError::KernelHostContract {
                    error: ApplyError::RegistryChunkChanged { id },
                }),
            );
        }
        batches = batches.write(
            registry_chunk_object_id(id),
            mutation.chunk().map(Object::RegistryChunk),
        );
    }
    (batches, None)
}

/// Consensus admission checked before the kernel ever sees the
/// transaction: an admitted open must commit a bounded lifetime,
/// because lifetime fees are zero and a distant timeout would be
/// operationally permanent.
fn check_open(context: KernelContext, tx: &KernelTx) -> Result<(), ExecutionError> {
    let KernelTx::Open { terms, .. } = tx else {
        return Ok(());
    };
    // The kernel already prices lifetime: `open_lifetime_fee` charges
    // `fees.lifetime * blocks` against funding and rejects an open that
    // cannot pay for the span it commits. `KERNEL_FEES` is `Fees::ZERO`,
    // so that bound currently charges nothing and bounds nothing, and
    // consensus caps the span directly instead.
    //
    // The cap applies to EVERY open, not just bonds: a `u64::MAX`
    // timeout on a basic edge is exactly as permanent as one on a
    // stake bond, and locks its funding just as long.
    let blocks = terms
        .timeout()
        .get()
        .saturating_sub(context.block_height().get());
    if blocks > MAX_EDGE_LIFETIME_BLOCKS {
        return Err(ExecutionError::EdgeLifetimeExceeded {
            blocks,
            max: MAX_EDGE_LIFETIME_BLOCKS,
        });
    }
    // There is deliberately no profile gate beside the lifetime cap.
    // Every remaining close is settleable by the kernel itself —
    // `Mutual`, `Timeout`, `Freeze` and `Adjudicated` are checked
    // inline, against staged registry state — and a work payment
    // requires a live tag-4 bond to lease, so it cannot be opened
    // against stake that does not exist.
    Ok(())
}

async fn apply_kernel_transaction<E>(
    batches: Batch<E>,
    context: KernelContext,
    verifier: &ChainVerifier,
    tx: &KernelTx,
) -> Result<Batch<E>, (Batch<E>, ExecutionError)>
where
    E: StorageContext + Spawner + Send + Sync + 'static,
{
    apply_kernel_transaction_observed(batches, context, verifier, tx, None).await
}

async fn apply_kernel_transaction_observed<E>(
    batches: Batch<E>,
    context: KernelContext,
    verifier: &ChainVerifier,
    tx: &KernelTx,
    changes: Option<&mut Vec<(ObjectId, Option<Object>)>>,
) -> Result<Batch<E>, (Batch<E>, ExecutionError)>
where
    E: StorageContext + Spawner + Send + Sync + 'static,
{
    if let Err(err) = check_open(context, tx) {
        return Err((batches, err));
    }
    let working = match load_kernel_slots(&batches, context, tx).await {
        Ok(working) => working,
        Err(err) => return Err((batches, err)),
    };
    let mut state = State::new(working);
    let outcome = match state.apply(context, verifier, tx) {
        Ok(outcome) => outcome,
        Err(source) => {
            let err = classify_kernel_error(state.store(), source);
            return Err((batches, err));
        }
    };
    let working = state.into_store();
    // Both halves land in one batch, which the block commits or drops
    // as a unit: an event persisted without its registry writes would
    // be a partially applied operation.
    let (batches, replay_error) = match outcome.public_event() {
        Some(event) => replay_kernel_event(batches, &working, event).await,
        None => (batches, None),
    };
    if let Some(error) = replay_error {
        return Err((batches, error));
    }
    let (batches, replay_error) = replay_kernel_registry(batches, &working, outcome.registry());
    match replay_error {
        Some(error) => Err((batches, error)),
        None => {
            if let Some(changes) = changes {
                if let Some(event) = outcome.public_event() {
                    match event.kind() {
                        EventKind::EdgeOpened { inputs, output } => {
                            changes.extend(inputs.iter().map(|id| (coin_object_id(*id), None)));
                            changes.push((
                                edge_object_id(*output),
                                working.edge(*output).map(Object::Edge),
                            ));
                        }
                        EventKind::EdgeClosed { input, outputs } => {
                            changes.push((edge_object_id(*input), None));
                            changes.extend(outputs.iter().map(|id| {
                                (
                                    coin_object_id(*id),
                                    working.coin(*id).map(|coin| Object::Coin(Coin::from(coin))),
                                )
                            }));
                        }
                    }
                }
                changes.extend(outcome.registry().into_iter().map(|mutation| {
                    (
                        registry_chunk_object_id(mutation.id()),
                        mutation.chunk().map(Object::RegistryChunk),
                    )
                }));
            }
            Ok(batches)
        }
    }
}

/// Finalized replay with the authoritative kernel object and registry diffs.
/// Owner metadata remains in the QMDB batch and therefore participates in its root;
/// the public object projection stores only spendable/edge/registry objects.
#[cfg(feature = "indexer-api")]
pub(crate) async fn execute_all_observed<E>(
    context: KernelContext,
    verifier: &ChainVerifier,
    txs: &[Transaction],
    genesis_allocations: &[(SettlementKey, u64)],
    batches: Batch<E>,
) -> Result<(Batch<E>, Vec<(ObjectId, Option<Object>)>), ExecutionError>
where
    E: StorageContext + Spawner + Send + Sync + 'static,
{
    let mut changes = Vec::new();
    let mut batches =
        maybe_seed_genesis(context, genesis_allocations, batches, Some(&mut changes)).await?;
    for tx in txs {
        if let Transaction::Kernel(kernel) = tx {
            batches = apply_kernel_transaction_observed(
                batches,
                context,
                verifier,
                kernel,
                Some(&mut changes),
            )
            .await
            .map_err(|(_, error)| error)?;
        } else {
            batches = apply_transaction(batches, context, verifier, tx)
                .await
                .map_err(|(_, error)| error)?;
            let digest = Sha256::hash(&tx.encode());
            let mut ids = vec![output_object_id(&digest, 0)];
            match tx {
                Transaction::Transfer { input, .. } => {
                    ids.push(*input);
                    ids.push(output_object_id(&digest, 1));
                }
                Transaction::MergeCoin { inputs, .. } => ids.extend(inputs.iter().copied()),
                Transaction::Kernel(_) => unreachable!(),
            }
            for id in ids {
                changes.push((id, batches.get(&id).await.map_err(storage_err)?));
            }
        }
    }
    Ok((batches, changes))
}

#[cfg(test)]
mod tests;
