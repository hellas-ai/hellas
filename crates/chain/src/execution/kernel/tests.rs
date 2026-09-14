use super::*;
use crate::domain::{KERNEL_FEES, MAX_TXS_PER_BLOCK};
use crate::execution::{
    ChainVerifier,
    store::{UtxoDatabase, utxo_db_config},
    test_support::{
        index_block, index_genesis, kernel_fixture, kernel_fixture_at, legacy_address, run_qmdb,
        validator_key,
    },
};
use crate::owner_index::{ApplyOutcome, OwnerIndex};
use commonware_glue::stateful::db::{DatabaseSet, Merkleized as _, Unmerkleized as _};
use commonware_runtime::{Supervisor as _, tokio};
use hellas_kernel::{BlockHash, BlockHeight, InsertError};
use std::collections::{BTreeMap, BTreeSet};

fn context(height: u64) -> KernelContext {
    KernelContext::with_fees(
        crate::domain::TEST_NETWORK,
        BlockHeight::new(height),
        BlockHash::from_bytes([height.saturating_sub(1) as u8; BlockHash::LENGTH]),
        KERNEL_FEES,
    )
}

async fn database(context: tokio::Context, partition: &str) -> UtxoDatabase<tokio::Context> {
    let config = utxo_db_config(&context, partition, 1024, 8);
    <UtxoDatabase<_> as DatabaseSet<_>>::init(context, config).await
}

async fn apply_and_finalize(
    database: &UtxoDatabase<tokio::Context>,
    context: KernelContext,
    txs: &[Transaction],
    genesis_allocations: &[(SettlementKey, u64)],
) -> commonware_cryptography::sha256::Digest {
    let batches = database.new_batches().await;
    let batches = execute_all(
        context,
        &ChainVerifier::new(),
        txs,
        genesis_allocations,
        batches,
    )
    .await
    .expect("block executes");
    let merkleized = batches.merkleize().await.expect("block merkleizes");
    let root = merkleized.root();
    database.finalize(merkleized).await;
    root
}

async fn read_objects(
    database: &UtxoDatabase<tokio::Context>,
    ids: &BTreeSet<ObjectId>,
) -> (
    BTreeMap<ObjectId, Coin>,
    BTreeMap<ObjectId, hellas_kernel::Edge>,
) {
    let reader = database.read().await;
    let mut coins = BTreeMap::new();
    let mut edges = BTreeMap::new();
    for id in ids {
        match reader.get(id).await.expect("QMDB object read") {
            Some(Object::Coin(coin)) => {
                coins.insert(*id, coin);
            }
            Some(Object::Edge(edge)) => {
                edges.insert(*id, edge);
            }
            Some(Object::RegistryChunk(chunk)) => {
                panic!("kernel open/close scenarios store no registry chunk, found {chunk:?}");
            }
            Some(Object::OwnerData(_)) => panic!("object id collided with owner metadata"),
            None => {}
        }
    }
    (coins, edges)
}

async fn assert_index_matches_qmdb(
    database: &UtxoDatabase<tokio::Context>,
    index: &OwnerIndex,
    known_ids: &[ObjectId],
    known_edge_owners: &[SettlementKey],
) {
    let indexed_coins = index.all_coins_for_test();
    let indexed_edges = index.all_edges_for_test();
    // QMDB does not expose a full object iterator. Probe every id derived
    // from the applied transaction graph plus every id known to the index,
    // so index-only extras cannot hide from this state-set comparison.
    let mut probe_ids: BTreeSet<_> = known_ids.iter().copied().collect();
    probe_ids.extend(indexed_coins.keys().copied());
    probe_ids.extend(indexed_edges.keys().copied());

    let (coins, edges) = read_objects(database, &probe_ids).await;
    assert_eq!(indexed_coins, coins);
    assert_eq!(
        indexed_edges.keys().copied().collect::<BTreeSet<_>>(),
        edges.keys().copied().collect::<BTreeSet<_>>()
    );

    let mut edge_owners: BTreeSet<_> = known_edge_owners.iter().copied().collect();
    for (id, edge) in &edges {
        let indexed = crate::owner_index::IndexedEdge::from(edge.parties());
        assert_eq!(indexed_edges.get(id), Some(&indexed));
        edge_owners.insert(indexed.maker);
        edge_owners.insert(indexed.taker);
    }
    for owner in edge_owners {
        let expected: Vec<_> = edges
            .iter()
            .filter_map(|(id, edge)| {
                let indexed = crate::owner_index::IndexedEdge::from(edge.parties());
                (owner == indexed.maker || owner == indexed.taker).then_some((*id, indexed))
            })
            .collect();
        assert_eq!(index.get_edges_by_owner(&owner), expected);
    }
}

#[test]
fn edge_in_coin_slot_is_typed_and_non_transient() {
    let id = ObjectId::from([0x44; 32]);
    let err = require_coin(id, Some(Object::Edge(crate::domain::test_edge())))
        .expect_err("edge is not a coin");
    assert_eq!(
        err,
        ExecutionError::WrongObjectKind {
            id,
            expected: ObjectKind::Coin,
            actual: ObjectKind::Edge,
        }
    );
    assert!(!err.is_transient_for_mempool());
}

#[test]
fn non_p256_owner_is_invalid_not_transient() {
    let owner = SettlementKey::from_bytes([0xa5; SettlementKey::LENGTH]);
    let err = legacy_owner_address(owner).expect_err("not a P-256 point");
    assert_eq!(err, ExecutionError::InvalidSignature);
    assert!(!err.is_transient_for_mempool());
}

#[test]
fn qmdb_genesis_open_mutual_close_lands_payouts_and_consumes_edge() {
    run_qmdb(|runtime| async move {
        let database = database(runtime, "mutual_close").await;
        let fixture = kernel_fixture(10).expect("kernel fixture");
        apply_and_finalize(
            &database,
            context(1),
            &[Transaction::Kernel(fixture.open.clone())],
            &fixture.allocations,
        )
        .await;

        let edge_id = edge_object_id(fixture.edge);
        assert!(matches!(
            database
                .read()
                .await
                .get(&edge_id)
                .await
                .expect("edge read"),
            Some(Object::Edge(_))
        ));

        apply_and_finalize(
            &database,
            context(2),
            &[Transaction::Kernel(fixture.mutual_close.clone())],
            &fixture.allocations,
        )
        .await;
        assert_eq!(
            database
                .read()
                .await
                .get(&edge_id)
                .await
                .expect("edge read"),
            None
        );
        for (id, payout) in fixture.payout_ids().iter().zip(&fixture.outputs) {
            assert_eq!(
                database
                    .read()
                    .await
                    .get(&coin_object_id(*id))
                    .await
                    .expect("payout read"),
                Some(Object::Coin(Coin {
                    owner: SettlementKey::from(payout.owner()),
                    value: payout.value(),
                }))
            );
        }
    });
}

#[test]
fn owner_index_matches_qmdb_across_legacy_and_kernel_blocks() {
    run_qmdb(|runtime| async move {
        let database = database(runtime, "index_qmdb_agreement").await;
        let mutual = kernel_fixture(10).expect("mutual-close fixture");
        let timeout = kernel_fixture_at(4, 2, 9, 10).expect("timeout-close fixture");
        let legacy_owner = legacy_address(21);
        let legacy_recipient = legacy_address(22);
        let mut allocations = mutual.allocations.clone();
        allocations.extend_from_slice(&timeout.allocations);
        allocations.push((SettlementKey::from(&legacy_owner), 90));

        let transfer = Transaction::transfer(
            crate::domain::TEST_NETWORK,
            &validator_key(21),
            genesis_object_id(4),
            legacy_recipient,
            35,
        )
        .expect("legacy transfer fixture");
        let transfer_digest = Sha256::hash(&transfer.encode());
        let transfer_recipient = output_object_id(&transfer_digest, 0);
        let transfer_change = output_object_id(&transfer_digest, 1);
        let mutual_edge_id = edge_object_id(mutual.edge);
        let timeout_edge_id = edge_object_id(timeout.edge);
        let mutual_payout_ids: Vec<_> = mutual
            .payout_ids()
            .iter()
            .copied()
            .map(coin_object_id)
            .collect();
        let timeout_payout_ids: Vec<_> = timeout
            .payout_ids()
            .iter()
            .copied()
            .map(coin_object_id)
            .collect();
        let mut known_ids: Vec<_> = (0..=4).map(genesis_object_id).collect();
        known_ids.extend([
            transfer_recipient,
            transfer_change,
            mutual_edge_id,
            timeout_edge_id,
        ]);
        known_ids.extend_from_slice(&mutual_payout_ids);
        known_ids.extend_from_slice(&timeout_payout_ids);
        known_ids.sort_unstable();
        known_ids.dedup();
        let mutual_parties = mutual.terms.parties();
        let timeout_parties = timeout.terms.parties();
        let known_edge_owners = [
            SettlementKey::from(mutual_parties.maker()),
            SettlementKey::from(mutual_parties.taker()),
            SettlementKey::from(timeout_parties.maker()),
            SettlementKey::from(timeout_parties.taker()),
        ];
        let genesis = index_genesis();
        let index = OwnerIndex::new(crate::domain::TEST_NETWORK, &genesis, allocations.clone());
        let first_txs = vec![
            transfer,
            Transaction::Kernel(mutual.open.clone()),
            Transaction::Kernel(timeout.open.clone()),
        ];
        let first_root = apply_and_finalize(&database, context(1), &first_txs, &allocations).await;
        let first_block = index_block(&genesis, first_root, first_txs);
        assert_eq!(
            index.apply_finalized(&first_block),
            Ok(ApplyOutcome::Applied)
        );
        assert_index_matches_qmdb(&database, &index, &known_ids, &known_edge_owners).await;

        let second_txs = vec![Transaction::Kernel(mutual.mutual_close.clone())];
        let second_root =
            apply_and_finalize(&database, context(2), &second_txs, &allocations).await;
        let second_block = index_block(&first_block, second_root, second_txs);
        assert_eq!(
            index.apply_finalized(&second_block),
            Ok(ApplyOutcome::Applied)
        );
        assert_index_matches_qmdb(&database, &index, &known_ids, &known_edge_owners).await;

        let third_txs = Vec::new();
        let third_root = apply_and_finalize(&database, context(3), &third_txs, &allocations).await;
        let third_block = index_block(&second_block, third_root, third_txs);
        assert_eq!(
            index.apply_finalized(&third_block),
            Ok(ApplyOutcome::Applied)
        );
        assert_index_matches_qmdb(&database, &index, &known_ids, &known_edge_owners).await;

        let fourth_txs = vec![Transaction::Kernel(timeout.timeout_close.clone())];
        let fourth_root =
            apply_and_finalize(&database, context(4), &fourth_txs, &allocations).await;
        let fourth_block = index_block(&third_block, fourth_root, fourth_txs);
        assert_eq!(
            index.apply_finalized(&fourth_block),
            Ok(ApplyOutcome::Applied)
        );
        assert_index_matches_qmdb(&database, &index, &known_ids, &known_edge_owners).await;
    });
}

#[test]
fn qmdb_timeout_close_succeeds_after_height_advance() {
    run_qmdb(|runtime| async move {
        let database = database(runtime, "timeout_close").await;
        let fixture = kernel_fixture(3).expect("kernel fixture");
        apply_and_finalize(
            &database,
            context(1),
            &[Transaction::Kernel(fixture.open.clone())],
            &fixture.allocations,
        )
        .await;
        apply_and_finalize(&database, context(2), &[], &fixture.allocations).await;
        apply_and_finalize(
            &database,
            context(3),
            &[Transaction::Kernel(fixture.timeout_close.clone())],
            &fixture.allocations,
        )
        .await;

        assert_eq!(
            database
                .read()
                .await
                .get(&edge_object_id(fixture.edge))
                .await
                .expect("edge read"),
            None
        );
        for id in fixture.payout_ids().iter() {
            assert!(matches!(
                database
                    .read()
                    .await
                    .get(&coin_object_id(*id))
                    .await
                    .expect("payout read"),
                Some(Object::Coin(_))
            ));
        }
    });
}

#[test]
fn identical_kernel_block_has_identical_qmdb_root() {
    run_qmdb(|runtime| async move {
        let first = database(runtime.child("determinism_a"), "determinism_a").await;
        let second = database(runtime.child("determinism_b"), "determinism_b").await;
        let fixture = kernel_fixture(10).expect("kernel fixture");
        let txs = [Transaction::Kernel(fixture.open.clone())];
        let first_root = apply_and_finalize(&first, context(1), &txs, &fixture.allocations).await;
        let second_root = apply_and_finalize(&second, context(1), &txs, &fixture.allocations).await;
        assert_eq!(first_root, second_root);
    });
}

#[test]
fn kernel_error_taxonomy_distinguishes_transient_drop_and_fatal() {
    run_qmdb(|runtime| async move {
        let fixture = kernel_fixture(10).expect("kernel fixture");

        let missing_database = database(runtime.child("missing"), "missing_taxonomy").await;
        let missing_batches = missing_database.new_batches().await;
        let (_, included, retained) = execute_proposal(
            context(1),
            &ChainVerifier::new(),
            vec![Transaction::Kernel(fixture.open.clone())],
            &[],
            MAX_TXS_PER_BLOCK,
            usize::MAX,
            missing_batches,
        )
        .await
        .expect("missing input is not fatal");
        assert!(included.is_empty());
        assert_eq!(retained.len(), 1);

        let bad_auth_database = database(runtime.child("bad_auth"), "bad_auth_taxonomy").await;
        let bad_auth_batches = bad_auth_database.new_batches().await;
        let (_, included, retained) = execute_proposal(
            context(1),
            &ChainVerifier::new(),
            vec![Transaction::Kernel(
                fixture.bad_auth_open().expect("bad-auth fixture"),
            )],
            &fixture.allocations,
            MAX_TXS_PER_BLOCK,
            usize::MAX,
            bad_auth_batches,
        )
        .await
        .expect("bad auth is a non-fatal drop");
        assert!(included.is_empty());
        assert!(retained.is_empty());

        let contract_database = database(runtime.child("contract"), "contract_taxonomy").await;
        let contract_batches = contract_database.new_batches().await;
        let contract_batches = execute_all(
            context(1),
            &ChainVerifier::new(),
            &[],
            &fixture.allocations,
            contract_batches,
        )
        .await
        .expect("genesis seed");
        let working = load_kernel_slots(&contract_batches, context(1), &fixture.open)
            .await
            .expect("preload funded slots");
        let input = fixture
            .funding
            .maker()
            .iter()
            .next()
            .copied()
            .expect("maker input");
        let fatal = classify_kernel_error(&working, ApplyError::MissingCoin { id: input });
        assert!(fatal.is_fatal_storage());
        assert_eq!(
            fatal,
            ExecutionError::KernelHostContract {
                error: ApplyError::MissingCoin { id: input },
            }
        );
        assert!(
            ExecutionError::KernelHostContract {
                error: ApplyError::CoinInsertRejected {
                    id: input,
                    reason: InsertError::Unavailable,
                },
            }
            .is_fatal_storage()
        );
    });
}

#[test]
fn response_with_removed_payment_edge_is_dropped_from_proposals() {
    use hellas_kernel::{EarnedCertificate, Party, PaymentCloseResponse, Sig, StartId, TermsHash};

    run_qmdb(|runtime| async move {
        let database = database(runtime, "removed_response_edge").await;
        let edge = EdgeId::from_bytes([0x41; EdgeId::LENGTH]);
        let response = PaymentCloseResponse::new(
            edge,
            StartId::from_bytes([0x42; StartId::LENGTH]),
            Party::Taker,
            (
                EarnedCertificate::new(edge, TermsHash::from_bytes([0x43; 32]), 7),
                Sig::from_bytes([0x44; Sig::LENGTH]),
            ),
            Sig::from_bytes([0x45; Sig::LENGTH]),
        );
        let (_, included, retained) = execute_proposal(
            context(1),
            &ChainVerifier::new(),
            vec![Transaction::Kernel(KernelTx::move_action(
                KernelMove::RespondPaymentClose(response),
            ))],
            &[],
            MAX_TXS_PER_BLOCK,
            usize::MAX,
            database.new_batches().await,
        )
        .await
        .expect("a removed response edge is a non-fatal drop");
        assert!(included.is_empty());
        assert!(retained.is_empty());
    });
}

/// The lifetime cap covers every open, not just stake bonds.
///
/// It once sat behind the stake-bond early return, so a
/// basic edge could commit a `u64::MAX` timeout — permanent under
/// exactly the justification the cap exists for, since zero
/// lifetime fees price the span at nothing either way.
#[test]
fn basic_opens_are_bounded_by_the_lifetime_cap() {
    use hellas_kernel::{
        Auth, BlockHeight as KernelHeight, Funding, Key as KernelKey, List,
        MAX_EDGE_OUTPUTS as OUTPUTS, MAX_PARTY_INPUTS as INPUTS, Parties, Payout as KernelPayout,
        ProtocolCode, Sig, Terms as KernelTerms,
    };
    run_qmdb(|runtime| async move {
        let database = database(runtime, "basic_lifetime_cap").await;
        let batches = database.new_batches().await;
        let basic_open = |timeout: u64| {
            let terms = KernelTerms::basic(
                ProtocolCode::new(1),
                Parties::new(
                    KernelKey::from_bytes([2; KernelKey::LENGTH]),
                    KernelKey::from_bytes([3; KernelKey::LENGTH]),
                ),
                KernelHeight::new(timeout),
                List::take([KernelPayout::default(); OUTPUTS], 0),
            );
            let zero = CoinId::from_bytes([0; CoinId::LENGTH]);
            let empty = List::take([zero; INPUTS], 0);
            let garbage = Auth::native(Sig::from_bytes([0; 64]));
            Transaction::Kernel(KernelTx::open(
                Funding::new(empty.clone(), empty),
                terms,
                garbage.clone(),
                garbage,
            ))
        };
        let over = 1 + crate::domain::MAX_EDGE_LIFETIME_BLOCKS + 1;
        let (batches, error) = apply_transaction(
            batches,
            context(1),
            &ChainVerifier::new(),
            &basic_open(over),
        )
        .await
        .err()
        .expect("an unbounded basic open is refused");
        assert_eq!(
            error,
            ExecutionError::EdgeLifetimeExceeded {
                blocks: crate::domain::MAX_EDGE_LIFETIME_BLOCKS + 1,
                max: crate::domain::MAX_EDGE_LIFETIME_BLOCKS,
            }
        );

        // In-cap, the gate falls through to ordinary kernel
        // validation — proof the cap is what refused the first one.
        let (_batches, error) =
            apply_transaction(batches, context(1), &ChainVerifier::new(), &basic_open(50))
                .await
                .err()
                .expect("kernel still validates admitted opens");
        assert!(matches!(error, ExecutionError::KernelApply { .. }));
    });
}

/// Consensus admission has nothing to say about a work profile:
/// both the tag-4 bond and the payment edge reach the kernel and
/// are decided there. Asserting kernel rejections here means a
/// gate that came back would fail as an admission error where a
/// kernel error is expected.
#[test]
fn the_native_work_profiles_reach_the_kernel_ungated() {
    use hellas_kernel::{
        Auth, BlockHeight as KernelHeight, Funding, Key as KernelKey, List,
        MAX_EDGE_OUTPUTS as OUTPUTS, MAX_PARTY_INPUTS as INPUTS, Parties, Payout as KernelPayout,
        Sig, Terms as KernelTerms, WorkPaymentTerms, WorkStakeBondTerms,
    };

    let provider = KernelKey::from_bytes([2; KernelKey::LENGTH]);
    let client = KernelKey::from_bytes([3; KernelKey::LENGTH]);
    let mut stake_outputs = [KernelPayout::default(); OUTPUTS];
    stake_outputs[0] = KernelPayout::new(provider, 1);
    let bond = WorkStakeBondTerms {
        parties: Parties::new(provider, client),
        timeout: KernelHeight::new(50),
        timeout_outputs: List::take(stake_outputs, 1),
        max_job_price: 1,
    };
    let payment = KernelTerms::work_payment(WorkPaymentTerms {
        bond_edge: EdgeId::from_bytes([6; EdgeId::LENGTH]),
        bond_terms: bond.clone(),
        private_policy_commitment: [7; 32],
        omit_response_blocks: hellas_kernel::MIN_OMIT_RESPONSE_BLOCKS,
        start_validity_blocks: 8,
        omission_bond: 1,
    });
    let work_open = |terms: KernelTerms| {
        let zero = CoinId::from_bytes([0; CoinId::LENGTH]);
        let empty = List::take([zero; INPUTS], 0);
        let garbage = Auth::native(Sig::from_bytes([0; 64]));
        Transaction::Kernel(KernelTx::open(
            Funding::new(empty.clone(), empty),
            terms,
            garbage.clone(),
            garbage,
        ))
    };
    let work_bond = work_open(KernelTerms::work_stake_bond(bond));
    let payment_terms = payment.clone();
    let work_payment = work_open(payment);

    run_qmdb(|runtime| async move {
        let database = database(runtime, "work_profile_gate").await;
        let batches = database.new_batches().await;

        // A tag-4 bond reaches the kernel. Here the
        // kernel refuses it because a zero-funded open cannot lock
        // the stake it commits — which is proof the gate is no
        // longer what stops it.
        let (batches, error) =
            apply_transaction(batches, context(1), &ChainVerifier::new(), &work_bond)
                .await
                .err()
                .expect("work bond open refused");
        assert!(
            matches!(error, ExecutionError::KernelApply { .. }),
            "a native work bond is admitted to the kernel: {error:?}",
        );
        assert!(!error.is_transient_for_mempool());

        // The payment edge locks no stake and consensus settles it
        // inline, so admission has nothing left to say about it. It
        // is refused here by the kernel, for an unfunded channel:
        // this open locks no value at all, so its omission bond is
        // larger than everything a close could distribute. That
        // check runs before the bond is loaded, which is why this
        // names a capacity failure and not a missing bond.
        let (_batches, error) =
            apply_transaction(batches, context(1), &ChainVerifier::new(), &work_payment)
                .await
                .err()
                .expect("unfunded work payment open refused");
        assert_eq!(
            error,
            ExecutionError::KernelApply {
                error: ApplyError::InvalidOpen {
                    output: hellas_kernel::Tx::edge_id_of(
                        &Funding::new(
                            List::take([CoinId::from_bytes([0; CoinId::LENGTH]); INPUTS], 0),
                            List::take([CoinId::from_bytes([0; CoinId::LENGTH]); INPUTS], 0),
                        ),
                        &payment_terms,
                    ),
                    reason: hellas_kernel::InvalidOpenReason::WorkPaymentCapacityUnfunded,
                },
            },
        );
        assert!(!error.is_transient_for_mempool());
    });
}

/// A funded payment open naming a bond that is not there is refused,
/// and refused as a *missing object* rather than as bad terms: the
/// bond may simply not have landed yet, and the mempool's job is to
/// hold that transaction rather than drop it.
///
/// This is the reviewer's attack at the chain boundary. `C` signs a
/// bond open and a payment open for the same block; `P` withholds
/// the bond and submits the payment alone. Before the lease existed,
/// consensus consumed the client's funding and created a payment
/// edge whose named bond did not exist.
#[test]
fn a_payment_open_naming_an_absent_bond_is_retained_not_settled() {
    use hellas_kernel::{
        Auth, BlockHeight as KernelHeight, Funding, List, MAX_EDGE_OUTPUTS,
        MAX_PARTY_INPUTS as INPUTS, Parties, Payout as KernelPayout, Secp256k1Signer,
        Terms as KernelTerms, WorkPaymentTerms, WorkStakeBondTerms,
    };

    const FUNDING: u64 = 100;

    let Ok(client) = Secp256k1Signer::from_secret_scalar([0x41; 32]) else {
        panic!("client key");
    };
    let Ok(provider) = Secp256k1Signer::from_secret_scalar([0x42; 32]) else {
        panic!("provider key");
    };
    let client_key = client.party_key();
    let provider_key = provider.party_key();
    let network = crate::domain::TEST_NETWORK;

    let bond = WorkStakeBondTerms {
        parties: Parties::new(provider_key, client_key),
        timeout: KernelHeight::new(500),
        timeout_outputs: List::take([KernelPayout::new(provider_key, 12); MAX_EDGE_OUTPUTS], 1),
        max_job_price: 4,
    };
    // The bond edge id of a bond nobody posted.
    let bond_funding = Funding::new(
        List::take([CoinId::from_bytes(genesis_object_id(1).into()); INPUTS], 1),
        List::take([CoinId::from_bytes([0; CoinId::LENGTH]); INPUTS], 0),
    );
    let bond_edge =
        KernelTx::edge_id_of(&bond_funding, &KernelTerms::work_stake_bond(bond.clone()));

    let terms = KernelTerms::work_payment(WorkPaymentTerms {
        bond_edge,
        bond_terms: bond,
        private_policy_commitment: [0x45; 32],
        omit_response_blocks: hellas_kernel::MIN_OMIT_RESPONSE_BLOCKS,
        start_validity_blocks: 8,
        omission_bond: 2,
    });
    let funding = Funding::new(
        List::take([CoinId::from_bytes(genesis_object_id(0).into()); INPUTS], 1),
        List::take([CoinId::from_bytes([0; CoinId::LENGTH]); INPUTS], 0),
    );
    let edge = KernelTx::edge_id_of(&funding, &terms);
    let open_hash = KernelTx::open_hash(network, &funding, &terms);
    let open = Transaction::Kernel(KernelTx::open(
        funding,
        terms,
        Auth::native(client.sign(open_hash)),
        Auth::native(provider.sign(open_hash)),
    ));

    run_qmdb(|runtime| async move {
        let database = database(runtime, "payment_without_bond").await;
        let batches = database.new_batches().await;
        let allocations = vec![(SettlementKey::from(client_key), FUNDING)];

        // Applied alone, it is refused as the missing bond edge —
        // and that error is transient, so the mempool holds the
        // transaction until the bond lands rather than dropping a
        // signature the client can never reissue.
        let batches = execute_all(
            context(1),
            &ChainVerifier::new(),
            &[],
            &allocations,
            batches,
        )
        .await
        .expect("genesis seed");
        let (batches, error) = apply_transaction(batches, context(1), &ChainVerifier::new(), &open)
            .await
            .err()
            .expect("a payment open without its bond is refused");
        assert_eq!(
            error,
            ExecutionError::ObjectNotFound {
                id: edge_object_id(bond_edge),
            },
        );
        assert!(error.is_transient_for_mempool());
        assert!(!error.is_fatal_storage());

        // In a proposal it is retained, not included: no unbonded
        // channel is settled and no client funding is consumed.
        let (batches, included, retained) = execute_proposal(
            context(1),
            &ChainVerifier::new(),
            vec![open],
            &allocations,
            MAX_TXS_PER_BLOCK,
            usize::MAX,
            batches,
        )
        .await
        .expect("a payment open without its bond is not fatal");
        assert!(included.is_empty());
        assert_eq!(retained.len(), 1);

        // And the block that block would commit holds no such edge.
        let merkleized = batches.merkleize().await.expect("block merkleizes");
        database.finalize(merkleized).await;
        let read = database.read().await;
        assert_eq!(
            read.get(&edge_object_id(edge)).await.expect("edge read"),
            None,
        );
        assert!(
            matches!(
                read.get(&genesis_object_id(0)).await,
                Ok(Some(Object::Coin(_))),
            ),
            "the client's funding is untouched",
        );
    });
}

/// A complete work-payment channel, end to end through consensus
/// execution: open, a client start that understates, the provider's
/// one response, and the adjudicated close that pays the contested
/// amount plus the forfeited omission bond.
///
/// This is the whole slice at the chain boundary — the lifted
/// admission gate, the declared registry slot, the atomic registry
/// replay, and the payout — rather than a kernel unit test with a
/// database attached. The start and its response share a block, so
/// the same-block visibility §4.6 requires is exercised here at the
/// storage layer and not only in the kernel.
///
/// Four transitions that must *not* be admitted ride alongside it,
/// on staged batches that are never finalized: a close inside the
/// response window, a close under the superseded seal, a client
/// answering its own start, and an answer at its deadline. A happy
/// path drives only legal transitions, so without these a kernel
/// rule that had stopped firing would leave this test green.
#[test]
fn a_work_payment_channel_settles_end_to_end_through_consensus() {
    use hellas_kernel::{
        Auth, BlockHeight as KernelHeight, Decode as _, EarnedCertificate, Funding,
        InvalidMoveReason, List, MAX_EDGE_OUTPUTS, MAX_PARTY_INPUTS as INPUTS, Move, Parties,
        Party, PaymentCloseResponse, PaymentCloseStart, Payout as KernelPayout,
        PendingPaymentClose, Proof, Secp256k1Signer, Terms as KernelTerms, WorkPaymentTerms,
        WorkStakeBondTerms, bond_lease_slots, pending_payment_close_slot,
    };

    const FUNDING: u64 = 100;
    /// The provider's whole allocation, and so the bond's stake:
    /// the open checks the two are equal.
    const STAKE: u64 = 12;
    const OMISSION_BOND: u64 = 2;
    const WINDOW: u64 = hellas_kernel::MIN_OMIT_RESPONSE_BLOCKS;
    /// The bond's timeout, and so the channel's admission horizon.
    const HORIZON: u64 = 500;
    // The client opens at 30; the provider answers with the client's
    // own signature for 60.
    const UNDERSTATED: u64 = 30;
    const EARNED: u64 = 60;

    let Ok(client) = Secp256k1Signer::from_secret_scalar([0x21; 32]) else {
        panic!("client key");
    };
    let Ok(provider) = Secp256k1Signer::from_secret_scalar([0x22; 32]) else {
        panic!("provider key");
    };
    let client_key = client.party_key();
    let provider_key = provider.party_key();
    let network = crate::domain::TEST_NETWORK;

    let bond = WorkStakeBondTerms {
        parties: Parties::new(provider_key, client_key),
        timeout: KernelHeight::new(HORIZON),
        timeout_outputs: List::take(
            [KernelPayout::new(provider_key, STAKE); MAX_EDGE_OUTPUTS],
            1,
        ),
        max_job_price: 4,
    };
    // The bond the channel leases: the provider's whole allocation,
    // staked under mirrored roles.
    let bond_for_timeout = bond.clone();
    let bond_terms = KernelTerms::work_stake_bond(bond.clone());
    let bond_funding = Funding::new(
        List::take([CoinId::from_bytes(genesis_object_id(1).into()); INPUTS], 1),
        List::take([CoinId::from_bytes([0; CoinId::LENGTH]); INPUTS], 0),
    );
    let bond_edge = KernelTx::edge_id_of(&bond_funding, &bond_terms);
    let bond_open_hash = KernelTx::open_hash(network, &bond_funding, &bond_terms);
    let bond_open = KernelTx::open(
        bond_funding,
        bond_terms,
        Auth::native(provider.sign(bond_open_hash)),
        Auth::native(client.sign(bond_open_hash)),
    );

    let terms = KernelTerms::work_payment(WorkPaymentTerms {
        bond_edge,
        bond_terms: bond,
        private_policy_commitment: [0x25; 32],
        omit_response_blocks: WINDOW,
        start_validity_blocks: 8,
        omission_bond: OMISSION_BOND,
    });

    let funding = Funding::new(
        List::take([CoinId::from_bytes(genesis_object_id(0).into()); INPUTS], 1),
        List::take([CoinId::from_bytes([0; CoinId::LENGTH]); INPUTS], 0),
    );
    let edge = KernelTx::edge_id_of(&funding, &terms);
    let open_hash = KernelTx::open_hash(network, &funding, &terms);
    let open = KernelTx::open(
        funding,
        terms.clone(),
        Auth::native(client.sign(open_hash)),
        Auth::native(provider.sign(open_hash)),
    );

    // The client understates, having closed its own issuance gate
    // first: this signature is the write-ahead commitment.
    let understated = EarnedCertificate::new(edge, terms.hash(), UNDERSTATED);
    let start_earned = understated.digest(network);
    let start_body_digest = hellas_kernel::start_digest(
        network,
        edge,
        terms.hash(),
        Party::Maker,
        (2, 2),
        start_earned,
    );
    let start = KernelTx::move_action(Move::StartPaymentClose(PaymentCloseStart::new(
        edge,
        terms.clone(),
        Party::Maker,
        (2, 2),
        Some((understated, client.sign(start_earned))),
        client.sign(start_body_digest),
    )));
    let start_id = hellas_kernel::start_id(start_body_digest, 2);

    // The provider answers with the greater certificate it holds —
    // the client's own signature, contradicting the client's start.
    let earned = EarnedCertificate::new(edge, terms.hash(), EARNED);
    let earned_digest = earned.digest(network);
    let response_body_digest = hellas_kernel::response_digest(
        network,
        edge,
        terms.hash(),
        start_id,
        Party::Taker,
        earned_digest,
    );
    let response = KernelTx::move_action(Move::RespondPaymentClose(PaymentCloseResponse::new(
        edge,
        start_id,
        Party::Taker,
        (earned, client.sign(earned_digest)),
        provider.sign(response_body_digest),
    )));
    // The same answer, kept to resubmit once its window has shut.
    let late_response = response.clone();
    // And the answer the client is not allowed to give: the same
    // certificate and the same contest, signed by the maker in the
    // maker's role. Every signature on it verifies.
    let client_response_digest = hellas_kernel::response_digest(
        network,
        edge,
        terms.hash(),
        start_id,
        Party::Maker,
        earned_digest,
    );
    let client_response =
        KernelTx::move_action(Move::RespondPaymentClose(PaymentCloseResponse::new(
            edge,
            start_id,
            Party::Maker,
            (earned, client.sign(earned_digest)),
            client.sign(client_response_digest),
        )));

    // The bond's own exit, at the horizon it committed to. It is
    // leased for the whole of this test, so this is the close that
    // has to read the lease and delete it.
    let stake_return = List::take(
        [KernelPayout::new(provider_key, STAKE); MAX_EDGE_OUTPUTS],
        1,
    );
    let stake_out = KernelTx::close_output_ids(bond_edge, &stake_return)
        .iter()
        .next()
        .copied()
        .expect("one stake payout");
    let bond_timeout = KernelTx::close(
        bond_edge,
        Proof::timeout(KernelTerms::work_stake_bond(bond_for_timeout)),
        stake_return,
    );

    let provider_total = EARNED + OMISSION_BOND;
    let mut split = [KernelPayout::default(); MAX_EDGE_OUTPUTS];
    split[0] = KernelPayout::new(provider_key, provider_total);
    split[1] = KernelPayout::new(client_key, FUNDING - provider_total);
    let split = List::take(split, 2);
    let payout_ids = KernelTx::close_output_ids(edge, &split);

    run_qmdb(|runtime| async move {
        let database = database(runtime, "work_payment_end_to_end").await;
        let allocations = vec![
            (SettlementKey::from(client_key), FUNDING),
            (SettlementKey::from(provider_key), STAKE),
        ];
        let slot = registry_chunk_object_id(pending_payment_close_slot(network, edge));
        let lease = bond_lease_slots(network, bond_edge).map(registry_chunk_object_id);

        // Both in one block, in the order the design describes: `P`
        // posts the bond it holds a client-signed payment open
        // against, then submits that open. The payment reads an edge
        // created a transaction earlier in the same block, so this
        // passes only if the execution layer's staged batch reads
        // its own writes.
        apply_and_finalize(
            &database,
            context(1),
            &[Transaction::Kernel(bond_open), Transaction::Kernel(open)],
            &allocations,
        )
        .await;
        assert!(
            matches!(
                database.read().await.get(&edge_object_id(edge)).await,
                Ok(Some(Object::Edge(_))),
            ),
            "the lifted gate admits a work-payment open",
        );
        // The channel is bonded, durably: the open's edge and the
        // two lease chunks are one committed block.
        assert!(
            matches!(
                database.read().await.get(&edge_object_id(bond_edge)).await,
                Ok(Some(Object::Edge(_))),
            ),
            "the native work bond is admitted without the seal gate",
        );
        for (index, slot) in lease.into_iter().enumerate() {
            let Ok(Some(Object::RegistryChunk(chunk))) = database.read().await.get(&slot).await
            else {
                panic!("lease chunk {index} persisted");
            };
            assert_eq!(chunk.value_len(), 139, "the lease is its fixed width");
        }

        // Before the block that settles anything: the same start on
        // a staged batch that is never finalized, which is the only
        // state in which the contest's two window rules are
        // separable. The kernel owns these rules and unit-tests
        // them; what is asserted here is that they still bite a
        // transaction arriving through consensus execution. The
        // happy path below would not notice their loss — it drives
        // only legal transitions.
        let verifier = ChainVerifier::new();
        let Ok(probe) = apply_transaction(
            database.new_batches().await,
            context(2),
            &verifier,
            &Transaction::Kernel(start.clone()),
        )
        .await
        else {
            panic!("the start applies to a staged batch");
        };
        let Ok(Some(Object::RegistryChunk(chunk))) = probe.get(&slot).await else {
            panic!("the staged start wrote its contest record");
        };
        let Ok(opened) = PendingPaymentClose::decode_exact(chunk.data()) else {
            panic!("the staged record decodes");
        };
        assert!(!opened.responded(), "no answer has landed yet");
        // The contest as it stands before any answer, and the seal
        // that names exactly that state.
        let stale_commitment = opened.contest_commitment(network, edge, terms.hash());
        let mut understated_split = [KernelPayout::default(); MAX_EDGE_OUTPUTS];
        understated_split[0] = KernelPayout::new(provider_key, UNDERSTATED);
        understated_split[1] = KernelPayout::new(client_key, FUNDING - UNDERSTATED);
        let early_close = Transaction::Kernel(KernelTx::close(
            edge,
            Proof::adjudicated(stale_commitment),
            List::take(understated_split, 2),
        ));
        // The close a submitter racing the response would carry: the
        // settled split, under the seal of the contest it was built
        // against.
        let stale_close = Transaction::Kernel(KernelTx::close(
            edge,
            Proof::adjudicated(stale_commitment),
            split.clone(),
        ));

        // Everything about the early close is right for the state it
        // names — seal, split, both owners — and it is still refused,
        // because the provider's window has not run out. That guard
        // is the exact complement of the response's, so admitting
        // this would admit a close and an answer at one height.
        let (probe, error) = apply_transaction(probe, context(2), &verifier, &early_close)
            .await
            .err()
            .expect("an adjudicated close inside the response window is refused");
        assert_eq!(
            error,
            ExecutionError::KernelApply {
                error: ApplyError::InvalidProof {
                    input: edge,
                    reason: InvalidProofReason::ResponseWindowOpen,
                },
            },
        );

        // Only the certificate's beneficiary may answer. A client
        // "response" is the client raising its own claim, which its
        // start already let it do.
        let (probe, error) = apply_transaction(
            probe,
            context(2),
            &verifier,
            &Transaction::Kernel(client_response),
        )
        .await
        .err()
        .expect("a client response is refused");
        assert_eq!(
            error,
            ExecutionError::KernelApply {
                error: ApplyError::InvalidMove {
                    input: edge,
                    reason: InvalidMoveReason::ResponderNotBeneficiary,
                },
            },
        );

        // And the genuine answer, at the deadline its start opened.
        // The deadline is exclusive, so this is the first height at
        // which the answer is late — and, by the complement above,
        // the first height at which the close is not early.
        let (probe, error) = apply_transaction(
            probe,
            context(2 + WINDOW),
            &verifier,
            &Transaction::Kernel(late_response),
        )
        .await
        .err()
        .expect("a response at its deadline is refused");
        assert_eq!(
            error,
            ExecutionError::KernelApply {
                error: ApplyError::InvalidMove {
                    input: edge,
                    reason: InvalidMoveReason::ResponseWindowClosed,
                },
            },
        );
        // Nothing above is committed: the block below is what makes
        // the start real.
        drop(probe);

        // The start and the answer that depends on it ride in one
        // block, which is the case §4.6 fixes: "the charged lookup
        // observes earlier same-block mutations". The response reads
        // the contest slot the start wrote a transaction earlier, so
        // this passes only if the execution layer's staged batch
        // reads its own writes — separate blocks would prove only
        // that committed state is visible, which is a weaker claim
        // and the one every other test here makes.
        apply_and_finalize(
            &database,
            context(2),
            &[Transaction::Kernel(start), Transaction::Kernel(response)],
            &allocations,
        )
        .await;
        let Ok(Some(Object::RegistryChunk(chunk))) = database.read().await.get(&slot).await else {
            panic!("the block persisted its contest record");
        };
        let Ok(record) = PendingPaymentClose::decode_exact(chunk.data()) else {
            panic!("the stored record decodes");
        };
        assert_eq!(record.start_id(), start_id);
        assert_eq!(record.start_cumulative(), UNDERSTATED);
        assert_eq!(record.final_cumulative(), EARNED);
        assert!(
            record.responded(),
            "the response found the start from the same block",
        );
        assert!(
            record.penalty_due(),
            "the client contradicted its own start"
        );

        // The seal is what binds a close to one contest state. This
        // one pays the settled split — every payout below is
        // identical — but names the contest as it stood before the
        // answer landed, and the close it would have settled is
        // gone. Refusing it is the whole reason an adjudicated close
        // carries a seal the chain could have recomputed itself.
        let (probe, error) = apply_transaction(
            database.new_batches().await,
            context(3),
            &verifier,
            &stale_close,
        )
        .await
        .err()
        .expect("a close naming the pre-response contest is refused");
        assert_eq!(
            error,
            ExecutionError::KernelApply {
                error: ApplyError::InvalidProof {
                    input: edge,
                    reason: InvalidProofReason::ContestMismatch,
                },
            },
        );
        drop(probe);

        let close = KernelTx::close(
            edge,
            Proof::adjudicated(record.contest_commitment(network, edge, terms.hash())),
            split,
        );
        apply_and_finalize(
            &database,
            context(3),
            &[Transaction::Kernel(close)],
            &allocations,
        )
        .await;

        let read = database.read().await;
        assert_eq!(
            read.get(&edge_object_id(edge)).await.expect("edge read"),
            None,
        );
        assert_eq!(
            read.get(&slot).await.expect("contest slot read"),
            None,
            "the close retired the contest in the same batch as the payout",
        );
        for (id, expected) in payout_ids.iter().zip([
            (SettlementKey::from(provider_key), provider_total),
            (SettlementKey::from(client_key), FUNDING - provider_total),
        ]) {
            let Ok(Some(Object::Coin(coin))) = read.get(&coin_object_id(*id)).await else {
                panic!("payout coin exists");
            };
            assert_eq!((coin.owner, coin.value), expected);
        }
        drop(read);

        // Closing the payment does not release the bond: the client
        // keeps its unexpired challenge rights, so the lease outlives
        // the channel's edge and the stake waits for the horizon both
        // parties committed to.
        let Ok(Some(Object::RegistryChunk(_))) = database.read().await.get(&lease[0]).await else {
            panic!("the lease survives the payment close");
        };
        apply_and_finalize(
            &database,
            context(HORIZON),
            &[Transaction::Kernel(bond_timeout)],
            &allocations,
        )
        .await;
        let read = database.read().await;
        assert_eq!(
            read.get(&edge_object_id(bond_edge))
                .await
                .expect("bond read"),
            None,
        );
        for (index, slot) in lease.into_iter().enumerate() {
            assert_eq!(
                read.get(&slot).await.expect("lease read"),
                None,
                "the horizon close retired lease chunk {index}",
            );
        }
        let Ok(Some(Object::Coin(coin))) = read.get(&coin_object_id(stake_out)).await else {
            panic!("the stake returns to the provider");
        };
        assert_eq!(
            (coin.owner, coin.value),
            (SettlementKey::from(provider_key), STAKE)
        );
    });
}

/// The bytes a provider endpoint builds are the bytes consensus
/// accepts, and the coins they pay are the coins the certificate
/// named.
///
/// The test above hand-builds its start and its close. This one
/// calls the endpoint's own two builders — `close_start` and
/// `adjudicated_close` from `hellas_work::work_close` — and submits
/// what they return, so an endpoint that derived a window, a
/// contest identifier, a seal, or a split differently from the
/// kernel would fail here rather than at a demonstration.
///
/// Nothing about the certificate's *provenance* is proved here: it
/// is signed by the fixture's client key. That it comes from a job
/// the client checked and invoiced is `hellas-rpc`'s
/// `a_paid_job_closes_at_exactly_what_it_earned`.
#[test]
fn an_endpoint_built_close_settles_on_a_real_chain() {
    use hellas_kernel::{
        Auth, BlockHeight as KernelHeight, EarnedCertificate, Funding, List, MAX_EDGE_OUTPUTS,
        MAX_PARTY_INPUTS as INPUTS, Move, Parties, Party, Payout as KernelPayout, PendingSlot,
        Secp256k1Signer, Terms as KernelTerms, WorkPaymentTerms, WorkStakeBondTerms,
        adjudicated_payouts, parse_pending_close, pending_payment_close_slot,
        work_payment_settlement,
    };
    use hellas_rpc::protocol::work::{PaidChannel, PaidChannelPolicyV1, private_policy_commitment};
    use hellas_work::work_close::{adjudicated_close, close_start, start_body_digest};

    const FUNDING: u64 = 100;
    const STAKE: u64 = 12;
    const OMISSION_BOND: u64 = 2;
    const WINDOW: u64 = hellas_kernel::MIN_OMIT_RESPONSE_BLOCKS;
    const START_VALIDITY: u64 = 8;
    const HORIZON: u64 = 500;
    /// What the client signed for its one job.
    const EARNED: u64 = 60;
    const SALT: [u8; 32] = [0x5a; 32];
    /// The finalized height the endpoint has processed through when
    /// it decides to close.
    const CURSOR: u64 = 1;

    let Ok(client) = Secp256k1Signer::from_secret_scalar([0x21; 32]) else {
        panic!("client key");
    };
    let Ok(provider) = Secp256k1Signer::from_secret_scalar([0x22; 32]) else {
        panic!("provider key");
    };
    let client_key = client.party_key();
    let provider_key = provider.party_key();
    let network = crate::domain::TEST_NETWORK;
    let policy = PaidChannelPolicyV1 {
        compute_credit_limit: 40,
        delivery_credit_limit: 40,
    };

    let bond = WorkStakeBondTerms {
        parties: Parties::new(provider_key, client_key),
        timeout: KernelHeight::new(HORIZON),
        timeout_outputs: List::take(
            [KernelPayout::new(provider_key, STAKE); MAX_EDGE_OUTPUTS],
            1,
        ),
        max_job_price: 4,
    };
    let bond_terms = KernelTerms::work_stake_bond(bond.clone());
    let bond_funding = Funding::new(
        List::take([CoinId::from_bytes(genesis_object_id(1).into()); INPUTS], 1),
        List::take([CoinId::from_bytes([0; CoinId::LENGTH]); INPUTS], 0),
    );
    let bond_edge = KernelTx::edge_id_of(&bond_funding, &bond_terms);
    let bond_open_hash = KernelTx::open_hash(network, &bond_funding, &bond_terms);
    let bond_open = KernelTx::open(
        bond_funding,
        bond_terms,
        Auth::native(provider.sign(bond_open_hash)),
        Auth::native(client.sign(bond_open_hash)),
    );

    let payment = WorkPaymentTerms {
        bond_edge,
        bond_terms: bond,
        private_policy_commitment: private_policy_commitment(network, &SALT, &policy),
        omit_response_blocks: WINDOW,
        start_validity_blocks: START_VALIDITY,
        omission_bond: OMISSION_BOND,
    };
    let terms = KernelTerms::work_payment(payment.clone());
    let funding = Funding::new(
        List::take([CoinId::from_bytes(genesis_object_id(0).into()); INPUTS], 1),
        List::take([CoinId::from_bytes([0; CoinId::LENGTH]); INPUTS], 0),
    );
    let edge = KernelTx::edge_id_of(&funding, &terms);
    let open_hash = KernelTx::open_hash(network, &funding, &terms);
    let open = KernelTx::open(
        funding,
        terms.clone(),
        Auth::native(client.sign(open_hash)),
        Auth::native(provider.sign(open_hash)),
    );

    // The endpoint's view of the same channel, derived from the same
    // terms body the open commits to.
    let Ok(channel) = PaidChannel::new(network, edge, payment.clone(), &SALT, policy) else {
        panic!("the fixture channel opens");
    };
    assert_eq!(channel.payment_terms_hash(), terms.hash());

    run_qmdb(|runtime| async move {
        let database = database(runtime, "endpoint_built_close").await;
        let allocations = vec![
            (SettlementKey::from(client_key), FUNDING),
            (SettlementKey::from(provider_key), STAKE),
        ];
        let slot = registry_chunk_object_id(pending_payment_close_slot(network, edge));

        apply_and_finalize(
            &database,
            context(CURSOR),
            &[Transaction::Kernel(bond_open), Transaction::Kernel(open)],
            &allocations,
        )
        .await;

        // What the funded edge can settle, read off the edge rather
        // than off an expectation. Every amount below comes from it.
        let Ok(Some(Object::Edge(live))) = database.read().await.get(&edge_object_id(edge)).await
        else {
            panic!("the payment edge is live");
        };
        let Some(settlement) = work_payment_settlement(live.values(), OMISSION_BOND) else {
            panic!("a funded edge prices both exits");
        };
        assert!(EARNED <= settlement.capacity());

        // One client-signed certificate, and the start the endpoint
        // builds from it at the height it has processed through.
        let certificate = EarnedCertificate::new(edge, terms.hash(), EARNED);
        let signature = client.sign(certificate.digest(network));
        let Ok(start) = close_start(
            &channel,
            Party::Taker,
            CURSOR,
            Some((certificate, signature)),
            &provider,
        ) else {
            panic!("a channel with a certificate builds a close start");
        };
        assert_eq!(
            (start.valid_from_height(), start.valid_through_height()),
            (CURSOR + 1, CURSOR + START_VALIDITY),
            "the next block is the first one that can carry it",
        );
        let expected_id = hellas_kernel::start_id(start_body_digest(&channel, &start), CURSOR + 1);

        apply_and_finalize(
            &database,
            context(CURSOR + 1),
            &[Transaction::Kernel(KernelTx::move_action(
                Move::StartPaymentClose(start),
            ))],
            &allocations,
        )
        .await;
        let Ok(Some(Object::RegistryChunk(chunk))) = database.read().await.get(&slot).await else {
            panic!("the accepted start wrote its contest record");
        };
        let PendingSlot::Present(record) = parse_pending_close(Some(chunk), edge) else {
            panic!("the stored record is this edge's");
        };
        assert_eq!(
            record.start_id(),
            expected_id,
            "the endpoint derives the contest identifier the kernel did",
        );
        assert_eq!(record.start_cumulative(), EARNED);
        assert!(!record.responded());
        assert!(!record.penalty_due());
        assert_eq!(record.response_deadline(), CURSOR + 1 + WINDOW);

        // The client never answers. At the deadline the endpoint
        // builds its close out of the record the chain holds.
        let Ok(close) = adjudicated_close(&channel, settlement, &record) else {
            panic!("a spent window closes");
        };
        let KernelTx::Close { outputs, .. } = &close else {
            panic!("an adjudicated close is a close");
        };
        let Ok(expected_payouts) =
            adjudicated_payouts(settlement, payment.parties(), EARNED, false)
        else {
            panic!("the settled amount fits the route");
        };
        assert_eq!(outputs.as_slice(), expected_payouts);
        let payout_ids = KernelTx::close_output_ids(edge, outputs);

        apply_and_finalize(
            &database,
            context(record.response_deadline()),
            &[Transaction::Kernel(close.clone())],
            &allocations,
        )
        .await;

        let read = database.read().await;
        assert_eq!(
            read.get(&edge_object_id(edge)).await.expect("edge read"),
            None,
            "the close consumed the payment edge",
        );
        assert_eq!(
            read.get(&slot).await.expect("contest slot read"),
            None,
            "and retired the contest in the same batch",
        );
        for (id, expected) in payout_ids.iter().zip([
            (SettlementKey::from(provider_key), EARNED),
            (
                SettlementKey::from(client_key),
                settlement.adjudicated_total() - EARNED,
            ),
        ]) {
            let Ok(Some(Object::Coin(coin))) = read.get(&coin_object_id(*id)).await else {
                panic!("payout coin exists");
            };
            assert_eq!((coin.owner, coin.value), expected);
        }
    });
}

/// A client that opens below what it signed for pays the bond, and
/// the answer that proves it is one the endpoint built.
///
/// The other half of the contest, and the half the funded omission
/// bond exists for. The start here is a client's, built by the same
/// `close_start`; the answer is the provider's, built by
/// `close_response`; and the close pays the settled amount plus the
/// bond the client forfeited. An endpoint whose response digest
/// were not the kernel's would be refused at the block below rather
/// than at a demonstration.
#[test]
fn an_endpoint_built_response_forfeits_the_understaters_bond() {
    use hellas_kernel::{
        Auth, BlockHeight as KernelHeight, EarnedCertificate, Funding, List, MAX_EDGE_OUTPUTS,
        MAX_PARTY_INPUTS as INPUTS, Move, Parties, Party, Payout as KernelPayout, PendingSlot,
        Secp256k1Signer, Terms as KernelTerms, WorkPaymentTerms, WorkStakeBondTerms,
        adjudicated_payouts, parse_pending_close, pending_payment_close_slot,
        work_payment_settlement,
    };
    use hellas_rpc::protocol::work::{PaidChannel, PaidChannelPolicyV1, private_policy_commitment};
    use hellas_work::work_close::{adjudicated_close, close_response, close_start};

    const FUNDING: u64 = 100;
    const STAKE: u64 = 12;
    const OMISSION_BOND: u64 = 2;
    const WINDOW: u64 = hellas_kernel::MIN_OMIT_RESPONSE_BLOCKS;
    const HORIZON: u64 = 500;
    /// What the client signed for, and left out of its own start.
    const EARNED: u64 = 60;
    const SALT: [u8; 32] = [0x5a; 32];
    const CURSOR: u64 = 1;

    let Ok(client) = Secp256k1Signer::from_secret_scalar([0x21; 32]) else {
        panic!("client key");
    };
    let Ok(provider) = Secp256k1Signer::from_secret_scalar([0x22; 32]) else {
        panic!("provider key");
    };
    let client_key = client.party_key();
    let provider_key = provider.party_key();
    let network = crate::domain::TEST_NETWORK;
    let policy = PaidChannelPolicyV1 {
        compute_credit_limit: 40,
        delivery_credit_limit: 40,
    };

    let bond = WorkStakeBondTerms {
        parties: Parties::new(provider_key, client_key),
        timeout: KernelHeight::new(HORIZON),
        timeout_outputs: List::take(
            [KernelPayout::new(provider_key, STAKE); MAX_EDGE_OUTPUTS],
            1,
        ),
        max_job_price: 4,
    };
    let bond_terms = KernelTerms::work_stake_bond(bond.clone());
    let bond_funding = Funding::new(
        List::take([CoinId::from_bytes(genesis_object_id(1).into()); INPUTS], 1),
        List::take([CoinId::from_bytes([0; CoinId::LENGTH]); INPUTS], 0),
    );
    let bond_edge = KernelTx::edge_id_of(&bond_funding, &bond_terms);
    let bond_open_hash = KernelTx::open_hash(network, &bond_funding, &bond_terms);
    let bond_open = KernelTx::open(
        bond_funding,
        bond_terms,
        Auth::native(provider.sign(bond_open_hash)),
        Auth::native(client.sign(bond_open_hash)),
    );

    let payment = WorkPaymentTerms {
        bond_edge,
        bond_terms: bond,
        private_policy_commitment: private_policy_commitment(network, &SALT, &policy),
        omit_response_blocks: WINDOW,
        start_validity_blocks: 8,
        omission_bond: OMISSION_BOND,
    };
    let terms = KernelTerms::work_payment(payment.clone());
    let funding = Funding::new(
        List::take([CoinId::from_bytes(genesis_object_id(0).into()); INPUTS], 1),
        List::take([CoinId::from_bytes([0; CoinId::LENGTH]); INPUTS], 0),
    );
    let edge = KernelTx::edge_id_of(&funding, &terms);
    let open_hash = KernelTx::open_hash(network, &funding, &terms);
    let open = KernelTx::open(
        funding,
        terms.clone(),
        Auth::native(client.sign(open_hash)),
        Auth::native(provider.sign(open_hash)),
    );
    let Ok(channel) = PaidChannel::new(network, edge, payment.clone(), &SALT, policy) else {
        panic!("the fixture channel opens");
    };

    run_qmdb(|runtime| async move {
        let database = database(runtime, "endpoint_built_response").await;
        let allocations = vec![
            (SettlementKey::from(client_key), FUNDING),
            (SettlementKey::from(provider_key), STAKE),
        ];
        let slot = registry_chunk_object_id(pending_payment_close_slot(network, edge));

        apply_and_finalize(
            &database,
            context(CURSOR),
            &[Transaction::Kernel(bond_open), Transaction::Kernel(open)],
            &allocations,
        )
        .await;
        let Ok(Some(Object::Edge(live))) = database.read().await.get(&edge_object_id(edge)).await
        else {
            panic!("the payment edge is live");
        };
        let Some(settlement) = work_payment_settlement(live.values(), OMISSION_BOND) else {
            panic!("a funded edge prices both exits");
        };

        // The client opens claiming nothing, holding a certificate
        // for EARNED that it signed itself.
        let Ok(understated) = close_start(&channel, Party::Maker, CURSOR, None, &client) else {
            panic!("a client opens a close");
        };
        apply_and_finalize(
            &database,
            context(CURSOR + 1),
            &[Transaction::Kernel(KernelTx::move_action(
                Move::StartPaymentClose(understated),
            ))],
            &allocations,
        )
        .await;
        let Ok(Some(Object::RegistryChunk(chunk))) = database.read().await.get(&slot).await else {
            panic!("the accepted start wrote its contest record");
        };
        let PendingSlot::Present(opened) = parse_pending_close(Some(chunk), edge) else {
            panic!("the stored record is this edge's");
        };
        assert_eq!(opened.start_cumulative(), 0);

        // The provider answers with the client's own signature.
        let certificate = EarnedCertificate::new(edge, terms.hash(), EARNED);
        let signature = client.sign(certificate.digest(network));
        let response = close_response(
            &channel,
            opened.start_id(),
            (certificate, signature),
            &provider,
        );
        apply_and_finalize(
            &database,
            context(CURSOR + 2),
            &[Transaction::Kernel(KernelTx::move_action(
                Move::RespondPaymentClose(response),
            ))],
            &allocations,
        )
        .await;
        let Ok(Some(Object::RegistryChunk(chunk))) = database.read().await.get(&slot).await else {
            panic!("the answered contest is still recorded");
        };
        let PendingSlot::Present(answered) = parse_pending_close(Some(chunk), edge) else {
            panic!("the stored record is this edge's");
        };
        assert!(answered.responded(), "the endpoint's answer was accepted");
        assert_eq!(answered.final_cumulative(), EARNED);
        assert!(
            answered.penalty_due(),
            "the client contradicted its own start",
        );

        let Ok(close) = adjudicated_close(&channel, settlement, &answered) else {
            panic!("a spent window closes");
        };
        let KernelTx::Close { outputs, .. } = &close else {
            panic!("an adjudicated close is a close");
        };
        let Ok(expected_payouts) = adjudicated_payouts(settlement, payment.parties(), EARNED, true)
        else {
            panic!("the settled amount fits the route");
        };
        assert_eq!(outputs.as_slice(), expected_payouts);
        let payout_ids = KernelTx::close_output_ids(edge, outputs);

        apply_and_finalize(
            &database,
            context(answered.response_deadline()),
            &[Transaction::Kernel(close)],
            &allocations,
        )
        .await;

        let read = database.read().await;
        assert_eq!(
            read.get(&edge_object_id(edge)).await.expect("edge read"),
            None,
        );
        for (id, expected) in payout_ids.iter().zip([
            (SettlementKey::from(provider_key), EARNED + OMISSION_BOND),
            (
                SettlementKey::from(client_key),
                settlement.adjudicated_total() - EARNED - OMISSION_BOND,
            ),
        ]) {
            let Ok(Some(Object::Coin(coin))) = read.get(&coin_object_id(*id)).await else {
                panic!("payout coin exists");
            };
            assert_eq!((coin.owner, coin.value), expected);
        }
    });
}

#[test]
fn timeout_not_reached_is_retained_but_proof_expired_is_dropped() {
    let input = EdgeId::from_bytes([0x55; EdgeId::LENGTH]);
    let working = BlockWorkingSet::new();
    let timeout_not_reached = classify_kernel_error(
        &working,
        ApplyError::InvalidProof {
            input,
            reason: InvalidProofReason::TimeoutNotReached,
        },
    );
    assert_eq!(
        timeout_not_reached,
        ExecutionError::KernelApply {
            error: ApplyError::InvalidProof {
                input,
                reason: InvalidProofReason::TimeoutNotReached,
            },
        }
    );
    assert!(timeout_not_reached.is_transient_for_mempool());

    let proof_expired = classify_kernel_error(
        &working,
        ApplyError::InvalidProof {
            input,
            reason: InvalidProofReason::ProofExpired,
        },
    );
    assert_eq!(
        proof_expired,
        ExecutionError::KernelApply {
            error: ApplyError::InvalidProof {
                input,
                reason: InvalidProofReason::ProofExpired,
            },
        }
    );
    assert!(!proof_expired.is_transient_for_mempool());
}

#[test]
fn open_edge_id_collision_with_coin_is_wrong_kind_drop_and_preserves_state() {
    run_qmdb(|runtime| async move {
        let database = database(runtime, "open_coin_collision").await;
        let fixture = kernel_fixture(10).expect("kernel fixture");
        let batches = database.new_batches().await;
        let batches = execute_all(
            context(1),
            &ChainVerifier::new(),
            &[],
            &fixture.allocations,
            batches,
        )
        .await
        .expect("genesis seed");
        let collision_id = edge_object_id(fixture.edge);
        let collision = Object::Coin(Coin {
            owner: fixture.maker,
            value: 7,
        });
        let batches = batches.write(collision_id, Some(collision));
        let verifier = ChainVerifier::new();
        let (batches, error) = apply_transaction(
            batches,
            context(1),
            &verifier,
            &Transaction::Kernel(fixture.open.clone()),
        )
        .await
        .err()
        .expect("coin collision rejects open");
        assert_eq!(
            error,
            ExecutionError::WrongObjectKind {
                id: collision_id,
                expected: ObjectKind::Edge,
                actual: ObjectKind::Coin,
            }
        );
        assert!(!error.is_transient_for_mempool());

        let (batches, included, retained) = execute_proposal(
            context(1),
            &ChainVerifier::new(),
            vec![Transaction::Kernel(fixture.open.clone())],
            &[],
            MAX_TXS_PER_BLOCK,
            usize::MAX,
            batches,
        )
        .await
        .expect("wrong-kind candidate is a non-fatal proposal drop");
        assert!(included.is_empty());
        assert!(retained.is_empty());
        let batches = execute_all(context(1), &ChainVerifier::new(), &included, &[], batches)
            .await
            .expect("block without dropped open replays");
        assert_eq!(
            batches.get(&collision_id).await.expect("collision read"),
            Some(collision)
        );
        for (index, (owner, value)) in fixture.allocations.iter().enumerate() {
            let id = genesis_object_id(u16::try_from(index).expect("fixture index"));
            assert_eq!(
                batches.get(&id).await.expect("funding read"),
                Some(Object::Coin(Coin {
                    owner: *owner,
                    value: *value,
                }))
            );
        }
    });
}

#[test]
fn open_edge_id_collision_with_edge_is_edge_exists_drop_and_preserves_state() {
    run_qmdb(|runtime| async move {
        let database = database(runtime, "open_edge_collision").await;
        let fixture = kernel_fixture(10).expect("kernel fixture");
        let batches = database.new_batches().await;
        let batches = execute_all(
            context(1),
            &ChainVerifier::new(),
            &[],
            &fixture.allocations,
            batches,
        )
        .await
        .expect("genesis seed");
        let collision_id = edge_object_id(fixture.edge);
        let collision = Object::Edge(crate::domain::test_edge());
        let batches = batches.write(collision_id, Some(collision));
        let verifier = ChainVerifier::new();
        let (batches, error) = apply_transaction(
            batches,
            context(1),
            &verifier,
            &Transaction::Kernel(fixture.open.clone()),
        )
        .await
        .err()
        .expect("edge collision rejects open");
        assert_eq!(
            error,
            ExecutionError::KernelApply {
                error: ApplyError::EdgeExists { id: fixture.edge },
            }
        );
        assert!(!error.is_transient_for_mempool());

        let (batches, included, retained) = execute_proposal(
            context(1),
            &ChainVerifier::new(),
            vec![Transaction::Kernel(fixture.open.clone())],
            &[],
            MAX_TXS_PER_BLOCK,
            usize::MAX,
            batches,
        )
        .await
        .expect("edge-exists candidate is a non-fatal proposal drop");
        assert!(included.is_empty());
        assert!(retained.is_empty());
        let batches = execute_all(context(1), &ChainVerifier::new(), &included, &[], batches)
            .await
            .expect("block without dropped open replays");
        assert_eq!(
            batches.get(&collision_id).await.expect("collision read"),
            Some(collision)
        );
        for (index, (owner, value)) in fixture.allocations.iter().enumerate() {
            let id = genesis_object_id(u16::try_from(index).expect("fixture index"));
            assert_eq!(
                batches.get(&id).await.expect("funding read"),
                Some(Object::Coin(Coin {
                    owner: *owner,
                    value: *value,
                }))
            );
        }
    });
}

#[test]
fn registry_chunk_slots_load_from_the_authenticated_database() {
    run_qmdb(|runtime| async move {
        let database = database(runtime, "registry_slots").await;
        let chunk = crate::domain::test_registry_chunk();
        let stored = hellas_kernel::RegistryChunkId::derive(
            crate::domain::TEST_NETWORK,
            hellas_kernel::RegistryNamespace::BondLease,
            [0x33; 32],
            0,
        );
        let absent = hellas_kernel::RegistryChunkId::derive(
            crate::domain::TEST_NETWORK,
            hellas_kernel::RegistryNamespace::BondLease,
            [0x33; 32],
            1,
        );
        // A chunk id whose slot is occupied by another object kind.
        let occupied = hellas_kernel::RegistryChunkId::derive(
            crate::domain::TEST_NETWORK,
            hellas_kernel::RegistryNamespace::BondLease,
            [0x44; 32],
            0,
        );

        let batches = database.new_batches().await;
        let batches = batches.write(
            registry_chunk_object_id(stored),
            Some(Object::RegistryChunk(chunk)),
        );
        let batches = batches.write(
            registry_chunk_object_id(occupied),
            Some(Object::Coin(Coin {
                owner: SettlementKey::from_bytes([0x42; SettlementKey::LENGTH]),
                value: 5,
            })),
        );

        // The chunk survives the object codec's fixed-size padding
        // and comes back byte-identical.
        let mut working = BlockWorkingSet::new();
        load_registry_chunk_slot(&batches, &mut working, stored)
            .await
            .expect("stored chunk loads");
        assert_eq!(working.registry_chunk(stored), Some(chunk));

        // An empty slot is declared, not skipped: the kernel may
        // still write it, and a write to an undeclared slot fails.
        load_registry_chunk_slot(&batches, &mut working, absent)
            .await
            .expect("absent chunk loads as an empty slot");
        assert_eq!(working.registry_chunk(absent), None);

        assert_eq!(
            load_registry_chunk_slot(&batches, &mut working, occupied).await,
            Err(ExecutionError::WrongObjectKind {
                id: registry_chunk_object_id(occupied),
                expected: ObjectKind::RegistryChunk,
                actual: ObjectKind::Coin,
            }),
        );

        let undeclared = hellas_kernel::RegistryChunkId::derive(
            crate::domain::TEST_NETWORK,
            hellas_kernel::RegistryNamespace::PaymentClose,
            [0x55; 32],
            0,
        );
        let mut batch = hellas_kernel::Store::begin(&mut working);
        assert_eq!(
            hellas_kernel::Batch::insert_registry_chunk(&mut batch, undeclared, chunk),
            Err(InsertError::Unavailable),
        );
        assert_eq!(
            hellas_kernel::Batch::insert_registry_chunk(&mut batch, absent, chunk),
            Ok(())
        );
        hellas_kernel::Batch::commit(batch);
        assert_eq!(working.registry_chunk(absent), Some(chunk));
    });
}

/// The registry half of an outcome has to reach durable storage in
/// the same batch as its edge half. No landed transition writes a
/// chunk yet, so the replay is driven with a diff built by hand —
/// the exact shape `State::apply` hands back once a v2 transition
/// produces one.
#[test]
fn registry_writes_and_deletes_replay_into_the_block_batch() {
    run_qmdb(|runtime| async move {
        let database = database(runtime, "registry_replay").await;
        let chunk = crate::domain::test_registry_chunk();
        let created = hellas_kernel::RegistryChunkId::derive(
            crate::domain::TEST_NETWORK,
            hellas_kernel::RegistryNamespace::BondLease,
            [0x61; 32],
            0,
        );
        let removed = hellas_kernel::RegistryChunkId::derive(
            crate::domain::TEST_NETWORK,
            hellas_kernel::RegistryNamespace::BondLease,
            [0x61; 32],
            1,
        );

        // `removed` is durable before the block; `created` is not.
        let batches = database.new_batches().await;
        let batches = batches.write(
            registry_chunk_object_id(removed),
            Some(Object::RegistryChunk(chunk)),
        );

        // The post-apply working set: the kernel filled one slot
        // and emptied the other.
        let mut working = BlockWorkingSet::new();
        working.insert_registry_chunk_slot(created, Some(chunk));
        working.insert_registry_chunk_slot(removed, None);

        let mut diff = hellas_kernel::RegistryDiff::empty();
        diff.push(hellas_kernel::RegistryMutation::write(created, chunk))
            .expect("first slot");
        diff.push(hellas_kernel::RegistryMutation::delete(removed))
            .expect("second slot");

        let (batches, error) = replay_kernel_registry(batches, &working, &diff);
        assert_eq!(error, None);
        let merkleized = batches.merkleize().await.expect("block merkleizes");
        database.finalize(merkleized).await;

        let reader = database.read().await;
        assert_eq!(
            reader
                .get(&registry_chunk_object_id(created))
                .await
                .expect("QMDB read"),
            Some(Object::RegistryChunk(chunk)),
            "a written slot is durable",
        );
        assert_eq!(
            reader
                .get(&registry_chunk_object_id(removed))
                .await
                .expect("QMDB read"),
            None,
            "a deleted slot is gone",
        );
    });
}

/// The working set is the store the kernel just wrote through, so a
/// slot that does not hold what the diff says it holds means the
/// host's `Batch` is not that store. Replaying it anyway would
/// commit a state no kernel produced.
#[test]
fn registry_replay_refuses_a_working_set_that_disagrees_with_the_diff() {
    run_qmdb(|runtime| async move {
        let database = database(runtime, "registry_replay_disagrees").await;
        let chunk = crate::domain::test_registry_chunk();
        let id = hellas_kernel::RegistryChunkId::derive(
            crate::domain::TEST_NETWORK,
            hellas_kernel::RegistryNamespace::BondLease,
            [0x62; 32],
            0,
        );
        let expected = Some(ExecutionError::KernelHostContract {
            error: ApplyError::RegistryChunkChanged { id },
        });

        // A write the working set does not reflect.
        let mut absent = BlockWorkingSet::new();
        absent.insert_registry_chunk_slot(id, None);
        let mut write = hellas_kernel::RegistryDiff::empty();
        write
            .push(hellas_kernel::RegistryMutation::write(id, chunk))
            .expect("one slot");
        let (batches, error) =
            replay_kernel_registry(database.new_batches().await, &absent, &write);
        assert_eq!(error, expected);

        // A delete the working set did not perform.
        let mut present = BlockWorkingSet::new();
        present.insert_registry_chunk_slot(id, Some(chunk));
        let mut delete = hellas_kernel::RegistryDiff::empty();
        delete
            .push(hellas_kernel::RegistryMutation::delete(id))
            .expect("one slot");
        let (batches, error) = replay_kernel_registry(batches, &present, &delete);
        assert_eq!(error, expected);

        // Neither refusal wrote the slot.
        let merkleized = batches.merkleize().await.expect("block merkleizes");
        database.finalize(merkleized).await;
        let reader = database.read().await;
        assert_eq!(
            reader
                .get(&registry_chunk_object_id(id))
                .await
                .expect("QMDB read"),
            None,
        );
    });
}

#[test]
fn registry_host_contract_failures_classify_like_coin_and_edge_ones() {
    let working = BlockWorkingSet::new();
    let id = hellas_kernel::RegistryChunkId::derive(
        crate::domain::TEST_NETWORK,
        hellas_kernel::RegistryNamespace::BondLease,
        [0x11; 32],
        0,
    );

    // Undeclared slot: the value the transaction named is not live,
    // which is user error and transient for the mempool.
    let missing = classify_kernel_error(&working, ApplyError::MissingRegistryChunk { id });
    assert_eq!(
        missing,
        ExecutionError::ObjectNotFound {
            id: registry_chunk_object_id(id),
        }
    );
    assert!(missing.is_transient_for_mempool());

    // A chunk that moved under the kernel, or an insert the store
    // refused, is the host breaking the Batch contract.
    for error in [
        ApplyError::RegistryChunkChanged { id },
        ApplyError::RegistryChunkInsertRejected {
            id,
            reason: InsertError::Exists,
        },
    ] {
        let classified = classify_kernel_error(&working, error);
        assert_eq!(classified, ExecutionError::KernelHostContract { error });
        assert!(classified.is_fatal_storage());
    }
}

#[test]
fn proposal_byte_budget_stops_admission_and_retains_the_tail() {
    run_qmdb(|runtime| async move {
        let database = database(runtime, "byte_budget").await;
        let fixture = kernel_fixture(10).expect("kernel fixture");
        let open = Transaction::Kernel(fixture.open.clone());
        let close = Transaction::Kernel(fixture.mutual_close.clone());
        let budget = open.encode_size();
        let batches = database.new_batches().await;
        let (batches, included, retained) = execute_proposal(
            context(1),
            &ChainVerifier::new(),
            vec![open, close.clone(), close],
            &fixture.allocations,
            MAX_TXS_PER_BLOCK,
            budget,
            batches,
        )
        .await
        .expect("proposal execution");

        assert_eq!(included.len(), 1);
        assert_eq!(retained.len(), 2);
        assert!(matches!(included.first(), Some(Transaction::Kernel(tx)) if tx == &fixture.open));
        assert!(
            retained
                .iter()
                .all(|tx| matches!(tx, Transaction::Kernel(tx) if tx == &fixture.mutual_close))
        );
        assert!(matches!(
            batches
                .get(&edge_object_id(fixture.edge))
                .await
                .expect("edge read"),
            Some(Object::Edge(_))
        ));
    });
}

#[test]
fn owner_commitments_are_speculative_replayable_and_match_native_reconstruction() {
    run_qmdb(|runtime| async move {
        let first = database(runtime.child("owner_first"), "owner-first").await;
        let replay = database(runtime.child("owner_replay"), "owner-replay").await;
        let fixture = kernel_fixture(10).unwrap();
        let genesis = index_genesis();
        let owners = OwnerIndex::new(
            crate::domain::TEST_NETWORK,
            &genesis,
            fixture.allocations.clone(),
        );
        let mut parent = genesis;
        for (height, tx) in [(1, fixture.open.clone()), (2, fixture.mutual_close.clone())] {
            let before = super::super::owner_tree::root(&first.new_batches().await)
                .await
                .unwrap();
            let batches = execute_all(
                context(height),
                &ChainVerifier::new(),
                &[Transaction::Kernel(tx.clone())],
                &fixture.allocations,
                first.new_batches().await,
            )
            .await
            .unwrap();
            let expected = super::super::owner_tree::root(&batches).await.unwrap();
            // A competing/discarded speculative branch must not mutate the committed root.
            assert_eq!(
                super::super::owner_tree::root(&first.new_batches().await)
                    .await
                    .unwrap(),
                before
            );
            let merkleized = batches.merkleize().await.unwrap();
            let state_root = merkleized.root();
            first.finalize(merkleized).await;
            let replay_batches = execute_all(
                context(height),
                &ChainVerifier::new(),
                &[Transaction::Kernel(tx.clone())],
                &fixture.allocations,
                replay.new_batches().await,
            )
            .await
            .unwrap();
            assert_eq!(
                super::super::owner_tree::root(&replay_batches)
                    .await
                    .unwrap(),
                expected
            );
            let replay_merkleized = replay_batches.merkleize().await.unwrap();
            assert_eq!(replay_merkleized.root(), state_root);
            replay.finalize(replay_merkleized).await;
            let block = index_block(&parent, state_root, vec![Transaction::Kernel(tx)])
                .with_owner_root(expected);
            owners.apply_finalized(&block).unwrap();
            let mut rebuilt = crate::owner_proof::MemoryOwnerTree::default();
            for (id, coin) in owners.all_coins_for_test() {
                crate::owner_proof::update_holding(
                    &mut rebuilt,
                    coin.owner,
                    id,
                    Some((0, coin.value)),
                )
                .await
                .unwrap();
            }
            for (id, edge) in owners.all_edges_for_test() {
                crate::owner_proof::update_holding(&mut rebuilt, edge.maker, id, Some((1, 0)))
                    .await
                    .unwrap();
                if edge.taker != edge.maker {
                    crate::owner_proof::update_holding(&mut rebuilt, edge.taker, id, Some((1, 0)))
                        .await
                        .unwrap();
                }
            }
            assert_eq!(
                crate::owner_proof::owner_root(&rebuilt).await.unwrap(),
                expected
            );
            let page = crate::owner_proof::prove_owner_page(&rebuilt, fixture.maker, 0, 64)
                .await
                .unwrap();
            crate::owner_proof::verify_owner_page(expected, fixture.maker, 0, 64, &page).unwrap();
            parent = block;
        }
    });
}
