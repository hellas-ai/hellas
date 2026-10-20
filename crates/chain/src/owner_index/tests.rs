use super::*;
use crate::domain::genesis_object_id;
use crate::execution::test_support::{
    index_block, index_genesis as genesis, kernel_fixture, owner_key as settlement, owner_signer,
    validator_key as key,
};
use commonware_consensus::types::{Epoch, Height, Round, View};
use commonware_cryptography::{Digest as _, Signer as _};
use commonware_cryptography::{Hasher as _, Sha256};
use commonware_storage::{merkle::Location, mmr};
use commonware_utils::non_empty_range;
use hellas_kernel::SoftPasskey;
use hellas_kernel::{
    Auth, CloseKind, CoinId, List, MAX_EDGE_INPUTS, MAX_EDGE_OUTPUTS, Parties, PartyAuth,
    PartyKeys, Payout, Proof, ProtocolCode, Reshape, Terms, Tx,
};

fn block(parent: &HellasBlock, txs: Vec<Transaction>) -> HellasBlock {
    index_block(parent, commonware_cryptography::sha256::Digest::EMPTY, txs)
}

/// An owner's reshape of `inputs` into `outputs`, signed by
/// [`owner_signer`]`(owner)`, and the ids of the coins it issues.
fn reshape(
    owner: u8,
    inputs: &[ObjectId],
    outputs: &[(SettlementKey, Option<SettlementKey>, u64)],
) -> (Transaction, Vec<ObjectId>) {
    let mut input_ids = [CoinId::from_bytes([0; 32]); MAX_EDGE_INPUTS];
    for (slot, id) in input_ids.iter_mut().zip(inputs) {
        *slot = CoinId::from_bytes(id.0);
    }
    let inputs = List::take(input_ids, inputs.len());
    let mut payouts = [Payout::default(); MAX_EDGE_OUTPUTS];
    for (slot, (owner, delegate, value)) in payouts.iter_mut().zip(outputs) {
        *slot = Payout::delegated(
            owner.into_kernel(),
            delegate.map(SettlementKey::into_kernel),
            *value,
        );
    }
    let outputs = List::take(payouts, outputs.len());
    let hash = Reshape::payload_hash(crate::domain::TEST_NETWORK, &inputs, &outputs);
    let ids = Reshape::output_ids(crate::domain::TEST_NETWORK, &inputs, &outputs)
        .iter()
        .copied()
        .map(coin_object_id)
        .collect();
    let auth = Auth::native(owner_signer(owner).sign(hash));
    (
        Transaction::Kernel(Tx::Owner(Reshape::new(inputs, outputs, auth))),
        ids,
    )
}

/// Owner 1 pays 40 of its 100 to owner 2 and keeps 60.
fn payment() -> (Transaction, Vec<ObjectId>) {
    reshape(
        1,
        &[genesis_object_id(0)],
        &[(settlement(2), None, 40), (settlement(1), None, 60)],
    )
}

#[test]
fn indexes_finalized_owner_transitions() {
    let genesis = genesis();
    let indexer = OwnerIndex::new(
        crate::domain::TEST_NETWORK,
        &genesis,
        vec![(settlement(1), 100)],
    );
    let input = genesis_object_id(0);
    let (tx, ids) = payment();
    let (recipient_id, change_id) = (ids[0], ids[1]);
    let block = block(&genesis, vec![tx]);

    assert_eq!(indexer.apply_finalized(&block), Ok(ApplyOutcome::Applied));
    assert_eq!(
        indexer.get_coins_by_owner(&settlement(2)),
        vec![(recipient_id, 40)]
    );
    assert_eq!(
        indexer.get_coins_by_owner(&settlement(1)),
        vec![(change_id, 60)]
    );
    assert_eq!(indexer.get_coin(&input), Ok(None));
}

#[test]
fn duplicate_finalized_block_is_idempotent() {
    let genesis = genesis();
    let indexer = OwnerIndex::new(
        crate::domain::TEST_NETWORK,
        &genesis,
        vec![(settlement(1), 100)],
    );
    let (tx, _) = payment();
    let block = block(&genesis, vec![tx]);

    assert_eq!(indexer.apply_finalized(&block), Ok(ApplyOutcome::Applied));
    let before = indexer.get_coins_by_owner(&settlement(1));
    let cursor = indexer.cursor();

    assert_eq!(indexer.apply_finalized(&block), Ok(ApplyOutcome::Duplicate));
    assert_eq!(indexer.get_coins_by_owner(&settlement(1)), before);
    assert_eq!(indexer.cursor(), cursor);
}

#[test]
fn stale_finalized_block_is_acknowledged_without_reapplying() {
    let genesis = genesis();
    let indexer = OwnerIndex::new(
        crate::domain::TEST_NETWORK,
        &genesis,
        vec![(settlement(1), 100)],
    );
    let (tx, _) = payment();
    let first = block(&genesis, vec![tx]);
    let second = block(&first, Vec::new());

    assert_eq!(indexer.apply_finalized(&first), Ok(ApplyOutcome::Applied));
    assert_eq!(indexer.apply_finalized(&second), Ok(ApplyOutcome::Applied));
    let cursor = indexer.cursor();
    assert_eq!(cursor.height, 2);
    assert_eq!(cursor.payload, second.digest());
    let before = indexer.get_coins_by_owner(&settlement(2));

    assert_eq!(indexer.apply_finalized(&first), Ok(ApplyOutcome::Duplicate));
    assert_eq!(indexer.cursor(), cursor);
    assert_eq!(indexer.get_coins_by_owner(&settlement(2)), before);
}

#[test]
fn forward_height_gap_is_rejected() {
    let genesis = genesis();
    let indexer = OwnerIndex::new(
        crate::domain::TEST_NETWORK,
        &genesis,
        vec![(settlement(1), 100)],
    );
    let first = block(&genesis, Vec::new());
    let second = block(&first, Vec::new());
    let third = block(&second, Vec::new());

    assert_eq!(indexer.apply_finalized(&first), Ok(ApplyOutcome::Applied));
    assert_eq!(
        indexer.apply_finalized(&third),
        Err(OwnerIndexError::HeightGap {
            current: 1,
            next: 3
        })
    );
    assert_eq!(indexer.cursor().height, 1);
    assert_eq!(indexer.cursor().payload, first.digest());
}

#[test]
fn conflicting_payload_at_cursor_height_is_rejected() {
    let genesis = genesis();
    let indexer = OwnerIndex::new(
        crate::domain::TEST_NETWORK,
        &genesis,
        vec![(settlement(1), 100)],
    );
    let first = block(&genesis, Vec::new());
    let fork = index_block(&genesis, Sha256::hash(b"fork-1"), Vec::new());
    assert_ne!(first.digest(), fork.digest());

    assert_eq!(indexer.apply_finalized(&first), Ok(ApplyOutcome::Applied));
    assert_eq!(
        indexer.apply_finalized(&fork),
        Err(OwnerIndexError::ConflictingHeight { height: 1 })
    );
    assert_eq!(indexer.cursor().height, 1);
    assert_eq!(indexer.cursor().payload, first.digest());
}

/// A block is applied whole or not at all: a reshape that spends a coin
/// the index does not hold fails the block, and the good reshape before
/// it in the same block leaves no trace.
#[test]
fn rejected_block_does_not_mutate_index() {
    let genesis = genesis();
    let indexer = OwnerIndex::new(
        crate::domain::TEST_NETWORK,
        &genesis,
        vec![(settlement(1), 100)],
    );
    let (good_tx, ids) = payment();
    let missing = Sha256::hash(b"no such coin");
    let (bad_tx, _) = reshape(1, &[missing], &[(settlement(2), None, 1)]);
    let bad_block = block(&genesis, vec![good_tx.clone(), bad_tx]);

    assert_eq!(
        indexer.apply_finalized(&bad_block),
        Err(OwnerIndexError::ObjectNotFound { id: missing })
    );
    assert_eq!(indexer.cursor().height, 0);
    assert_eq!(indexer.get_coin(&genesis_object_id(0)), Ok(None));
    assert!(indexer.get_coins_by_owner(&settlement(2)).is_empty());

    let good_block = block(&genesis, vec![good_tx]);
    assert_eq!(
        indexer.apply_finalized(&good_block),
        Ok(ApplyOutcome::Applied)
    );
    assert_eq!(
        indexer.get_coins_by_owner(&settlement(2)),
        vec![(ids[0], 40)]
    );
}

/// A reshape's coins are indexed exactly as the kernel issues them,
/// delegate included: the outputs name them, so the index needs no kernel
/// to know them.
#[test]
fn indexes_a_delegating_reshape_with_its_delegate() {
    let genesis = genesis();
    let indexer = OwnerIndex::new(
        crate::domain::TEST_NETWORK,
        &genesis,
        vec![(settlement(1), 100)],
    );
    let node = settlement(9);
    let (tx, ids) = reshape(
        1,
        &[genesis_object_id(0)],
        &[(settlement(1), Some(node), 70), (settlement(1), None, 30)],
    );
    assert_eq!(
        indexer.apply_finalized(&block(&genesis, vec![tx])),
        Ok(ApplyOutcome::Applied)
    );
    assert_eq!(
        indexer.get_coin(&ids[0]),
        Ok(Some(Coin {
            owner: settlement(1),
            delegate: Some(node),
            value: 70,
        }))
    );
    assert_eq!(
        indexer.get_coin(&ids[1]),
        Ok(Some(Coin::owned(settlement(1), 30)))
    );
    assert_eq!(indexer.get_coin(&genesis_object_id(0)), Ok(None));
    // The node owns nothing: the coin is the owner's, and only its owner
    // lists it.
    assert!(indexer.get_coins_by_owner(&node).is_empty());
}

#[test]
fn indexes_kernel_edge_parties_and_coin_transitions() {
    let genesis = genesis();
    let fixture = kernel_fixture(10).expect("kernel fixture");
    let indexer = OwnerIndex::new(
        crate::domain::TEST_NETWORK,
        &genesis,
        fixture.allocations.clone(),
    );
    let open_block = block(&genesis, vec![Transaction::Kernel(fixture.open.clone())]);
    let edge_id = edge_object_id(fixture.edge);
    let indexed_edge = fixture.terms.parties();
    assert_eq!(
        indexer.apply_finalized(&open_block),
        Ok(ApplyOutcome::Applied)
    );
    assert_eq!(
        indexer.all_edges_for_test().get(&edge_id).copied(),
        Some(indexed_edge)
    );
    assert_eq!(
        indexer.get_edges_by_owner(&SettlementKey::from(indexed_edge.maker().owner())),
        vec![(edge_id, indexed_edge)]
    );
    assert_eq!(
        indexer.get_edges_by_owner(&SettlementKey::from(indexed_edge.taker().owner())),
        vec![(edge_id, indexed_edge)]
    );
    assert_eq!(indexer.get_coin(&genesis_object_id(0)), Ok(None));
    assert_eq!(indexer.get_coin(&genesis_object_id(1)), Ok(None));
    assert_eq!(
        indexer.get_coin(&edge_id),
        Err(OwnerIndexError::WrongObjectKind {
            id: edge_id,
            expected: ObjectKind::Coin,
            actual: ObjectKind::Edge,
        })
    );

    let close_block = block(
        &open_block,
        vec![Transaction::Kernel(fixture.mutual_close.clone())],
    );
    assert_eq!(
        indexer.apply_finalized(&close_block),
        Ok(ApplyOutcome::Applied)
    );
    assert_eq!(indexer.all_edges_for_test().get(&edge_id).copied(), None);
    assert!(
        indexer
            .get_edges_by_owner(&SettlementKey::from(indexed_edge.maker().owner()))
            .is_empty()
    );
    assert!(
        indexer
            .get_edges_by_owner(&SettlementKey::from(indexed_edge.taker().owner()))
            .is_empty()
    );
    for (id, payout) in fixture.payout_ids().iter().zip(&fixture.outputs) {
        let id = coin_object_id(*id);
        assert_eq!(
            indexer.get_coin(&id),
            Ok(Some(Coin::owned(
                SettlementKey::from(payout.owner()),
                payout.value(),
            )))
        );
    }
}

#[test]
fn same_party_edge_has_one_owner_membership_and_closes_cleanly() {
    let genesis = genesis();
    let template = kernel_fixture(10).expect("kernel fixture");
    let passkey = SoftPasskey::from_secret_scalar([11; 32]).expect("same-party passkey");
    let party = passkey.party_key();
    let owner = SettlementKey::from(party);
    let mut payout_values = [Payout::default(); MAX_EDGE_OUTPUTS];
    *payout_values.first_mut().expect("first payout slot") = Payout::new(party, 40);
    *payout_values.get_mut(1).expect("second payout slot") = Payout::new(party, 60);
    let outputs = List::take(payout_values, 2);
    let terms = Terms::basic(
        ProtocolCode::new(1),
        Parties::new(PartyKeys::sole(party), PartyKeys::sole(party)),
        template.terms.timeout(),
        outputs.clone(),
    );
    let funding = template.funding;
    let edge = Tx::edge_id_of(&funding, &terms);
    let open_hash = Tx::open_hash(crate::domain::TEST_NETWORK, &funding, &terms);
    let open = Tx::open(
        funding,
        terms.clone(),
        PartyAuth::owner(Auth::webauthn(
            passkey.sign(open_hash).expect("maker assertion"),
        )),
        PartyAuth::owner(Auth::webauthn(
            passkey.sign(open_hash).expect("taker assertion"),
        )),
    );
    let close_hash = Tx::payload_hash(
        crate::domain::TEST_NETWORK,
        edge,
        CloseKind::Mutual,
        terms.hash(),
        &outputs,
    );
    let close = Tx::close(
        edge,
        Proof::mutual(
            PartyAuth::owner(Auth::webauthn(
                passkey.sign(close_hash).expect("maker close assertion"),
            )),
            PartyAuth::owner(Auth::webauthn(
                passkey.sign(close_hash).expect("taker close assertion"),
            )),
        ),
        outputs,
    );
    let indexer = OwnerIndex::new(
        crate::domain::TEST_NETWORK,
        &genesis,
        vec![(owner, 40), (owner, 60)],
    );
    let open_block = block(&genesis, vec![Transaction::Kernel(open)]);
    let edge_id = edge_object_id(edge);
    let indexed = terms.parties();

    assert_eq!(
        indexer.apply_finalized(&open_block),
        Ok(ApplyOutcome::Applied)
    );
    assert_eq!(indexer.get_edges_by_owner(&owner), vec![(edge_id, indexed)]);

    let close_block = block(&open_block, vec![Transaction::Kernel(close)]);
    assert_eq!(
        indexer.apply_finalized(&close_block),
        Ok(ApplyOutcome::Applied)
    );
    assert!(indexer.get_edges_by_owner(&owner).is_empty());
    assert_eq!(indexer.all_edges_for_test().get(&edge_id).copied(), None);
}

#[test]
fn duplicate_kernel_open_is_atomic_output_collision() {
    let genesis = genesis();
    let fixture = kernel_fixture(10).expect("kernel fixture");
    let indexer = OwnerIndex::new(
        crate::domain::TEST_NETWORK,
        &genesis,
        fixture.allocations.clone(),
    );
    let open_block = block(&genesis, vec![Transaction::Kernel(fixture.open.clone())]);
    assert_eq!(
        indexer.apply_finalized(&open_block),
        Ok(ApplyOutcome::Applied)
    );
    let cursor = indexer.cursor();
    let edge_id = edge_object_id(fixture.edge);
    let edge = indexer.all_edges_for_test().get(&edge_id).copied();
    let maker_edges = indexer.get_edges_by_owner(&fixture.maker);

    let duplicate = block(&open_block, vec![Transaction::Kernel(fixture.open)]);
    assert_eq!(
        indexer.apply_finalized(&duplicate),
        Err(OwnerIndexError::OutputCollision { id: edge_id })
    );
    assert_eq!(indexer.cursor(), cursor);
    assert_eq!(indexer.all_edges_for_test().get(&edge_id).copied(), edge);
    assert_eq!(indexer.get_edges_by_owner(&fixture.maker), maker_edges);
}

#[test]
fn close_of_unknown_edge_is_typed_and_does_not_mutate() {
    let genesis = genesis();
    let fixture = kernel_fixture(10).expect("kernel fixture");
    let indexer = OwnerIndex::new(
        crate::domain::TEST_NETWORK,
        &genesis,
        fixture.allocations.clone(),
    );
    let edge_id = edge_object_id(fixture.edge);
    let close_block = block(&genesis, vec![Transaction::Kernel(fixture.mutual_close)]);

    assert_eq!(
        indexer.apply_finalized(&close_block),
        Err(OwnerIndexError::ObjectNotFound { id: edge_id })
    );
    assert_eq!(indexer.cursor().height, 0);
    assert_eq!(indexer.all_edges_for_test().get(&edge_id).copied(), None);
    assert!(indexer.get_edges_by_owner(&fixture.maker).is_empty());
}

#[test]
fn replay_matches_incremental_indexing() {
    let genesis = genesis();
    let (tx1, ids) = payment();
    let change_id = ids[1];
    let block1 = block(&genesis, vec![tx1]);
    let (tx2, _) = reshape(
        1,
        &[change_id],
        &[(settlement(3), None, 25), (settlement(1), None, 35)],
    );
    let block2 = block(&block1, vec![tx2]);

    let incremental = OwnerIndex::new(
        crate::domain::TEST_NETWORK,
        &genesis,
        vec![(settlement(1), 100)],
    );
    incremental.apply_finalized(&block1).unwrap();
    incremental.apply_finalized(&block2).unwrap();

    let replayed = OwnerIndex::new(
        crate::domain::TEST_NETWORK,
        &genesis,
        vec![(settlement(1), 100)],
    );
    for block in [&block1, &block2] {
        replayed.apply_finalized(block).unwrap();
    }

    assert_eq!(replayed.cursor(), incremental.cursor());
    assert_eq!(
        replayed.get_coins_by_owner(&settlement(1)),
        incremental.get_coins_by_owner(&settlement(1))
    );
    assert_eq!(
        replayed.get_coins_by_owner(&settlement(2)),
        incremental.get_coins_by_owner(&settlement(2))
    );
    assert_eq!(
        replayed.get_coins_by_owner(&settlement(3)),
        incremental.get_coins_by_owner(&settlement(3))
    );
}

#[test]
fn rejects_parent_mismatch() {
    let genesis = genesis();
    let indexer = OwnerIndex::new(
        crate::domain::TEST_NETWORK,
        &genesis,
        vec![(settlement(1), 100)],
    );
    let bad_parent = Sha256::hash(b"bad-parent");
    let sync_target = crate::execution::store::UtxoSyncTarget::new(
        Sha256::hash(b"root-1"),
        non_empty_range!(
            Location::<mmr::Family>::new(0),
            Location::<mmr::Family>::new(1)
        ),
    );
    let block = HellasBlock::new(
        commonware_consensus::simplex::types::Context {
            round: Round::new(Epoch::zero(), View::new(1)),
            leader: key(0).public_key(),
            parent: (View::zero(), bad_parent),
        },
        bad_parent,
        Height::new(1),
        1,
        Sha256::hash(b"state-1"),
        sync_target,
        Vec::new(),
    );

    assert_eq!(
        indexer.apply_finalized(&block),
        Err(OwnerIndexError::ParentMismatch { height: 1 })
    );
}
