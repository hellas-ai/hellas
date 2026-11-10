use super::*;
use crate::{
    config::Config,
    domain::{KERNEL_FEES, ObjectKey, ObjectKind, Transaction, genesis_object_id},
    execution::{
        ChainVerifier, execute_all,
        store::utxo_db_config,
        test_support::{
            consensus_fixture, finality_envelope, index_block, index_genesis, owner_key, run_qmdb,
        },
    },
    indexer::fixtures::spawn_archive,
    owner_index::ApplyOutcome,
};
use commonware_codec::Encode as _;
use commonware_cryptography::Digestible as _;
use commonware_glue::stateful::db::{DatabaseSet, Merkleized as _, Unmerkleized as _};
use commonware_runtime::{Handle, Supervisor as _};
use hellas_kernel::{BlockHash, BlockHeight, Context as KernelContext, PartyAuth, PartyKeys};
use std::collections::BTreeSet;

#[cfg(feature = "client")]
mod witness;

struct ResponseFixture {
    client: LocalLightClient,
    database: UtxoDatabase<commonware_runtime::tokio::Context>,
    owner_index: OwnerIndex,
    chain_indexer: crate::indexer::fixtures::ArchiveSource,
    allocations: Vec<(SettlementKey, u64)>,
    contest: crate::HellasBlock,
    valid: PaymentCloseResponse,
    second: PaymentCloseResponse,
    bad_action: PaymentCloseResponse,
    absent: PaymentCloseResponse,
    valid_responses: Vec<PaymentCloseResponse>,
    _indexer: Handle<()>,
}

async fn response_fixture(
    runtime: commonware_runtime::tokio::Context,
    partition: &'static str,
) -> Box<ResponseFixture> {
    response_fixture_with_contests(runtime, partition, 1).await
}

async fn response_fixture_with_contests(
    runtime: commonware_runtime::tokio::Context,
    partition: &'static str,
    contest_count: usize,
) -> Box<ResponseFixture> {
    response_fixture_at(runtime, partition, contest_count, None).await
}

/// The fixture, optionally with one more empty block after the contests,
/// stamped at `cursor_stamp`: the block the response pre-admission reads
/// its clock from.
async fn response_fixture_at(
    runtime: commonware_runtime::tokio::Context,
    partition: &'static str,
    contest_count: usize,
    cursor_stamp: Option<u64>,
) -> Box<ResponseFixture> {
    use hellas_kernel::{
        Auth, EarnedCertificate, Funding, List, MAX_EDGE_OUTPUTS, MAX_PARTY_INPUTS, Move, Parties,
        Party, PaymentCloseStart, Payout, Secp256k1Signer, Terms, WorkPaymentTerms,
        WorkStakeBondTerms,
    };

    const FUNDING: u64 = 100;
    const STAKE: u64 = 12;
    const HORIZON: u64 = 500;
    const START_AMOUNT: u64 = 30;
    let network = crate::domain::TEST_NETWORK;
    let client_signer = Secp256k1Signer::from_secret_scalar([0x21; 32]).expect("client key");
    let provider_signer = Secp256k1Signer::from_secret_scalar([0x22; 32]).expect("provider key");
    let client_key = client_signer.party_key();
    let provider_key = provider_signer.party_key();

    let mut allocations = Vec::with_capacity(contest_count * 2);
    let mut transactions = Vec::with_capacity(contest_count * 3);
    let mut valid_responses = Vec::with_capacity(contest_count);
    let mut first_responses = None;
    for contest_index in 0..contest_count {
        let payment_coin = u16::try_from(contest_index * 2).expect("fixture coin index");
        let bond_coin = payment_coin
            .checked_add(1)
            .expect("fixture bond coin index");
        allocations.push((SettlementKey::from(client_key), FUNDING));
        allocations.push((SettlementKey::from(provider_key), STAKE));

        let bond = WorkStakeBondTerms {
            parties: Parties::new(PartyKeys::sole(provider_key), PartyKeys::sole(client_key)),
            timeout: BlockHeight::new(HORIZON),
            timeout_outputs: List::take([Payout::new(provider_key, STAKE); MAX_EDGE_OUTPUTS], 1),
            max_job_price: 4,
        };
        let bond_terms = Terms::work_stake_bond(bond.clone());
        let bond_funding = Funding::new(
            List::take(
                [CoinId::from_bytes(genesis_object_id(bond_coin).into()); MAX_PARTY_INPUTS],
                1,
            ),
            List::take(
                [CoinId::from_bytes([0; CoinId::LENGTH]); MAX_PARTY_INPUTS],
                0,
            ),
        );
        let bond_edge = hellas_kernel::Tx::edge_id_of(&bond_funding, &bond_terms);
        let bond_hash = hellas_kernel::Tx::open_hash(network, &bond_funding, &bond_terms);
        let bond_open = hellas_kernel::Tx::open(
            bond_funding,
            bond_terms,
            PartyAuth::owner(Auth::native(provider_signer.sign(bond_hash))),
            PartyAuth::owner(Auth::native(client_signer.sign(bond_hash))),
        );

        let terms = Terms::work_payment(WorkPaymentTerms {
            bond_edge,
            bond_terms: bond,
            private_policy_commitment: [0x25; 32],
            start_validity_blocks: 64,
            omission_bond: 2,
        });
        let funding = Funding::new(
            List::take(
                [CoinId::from_bytes(genesis_object_id(payment_coin).into()); MAX_PARTY_INPUTS],
                1,
            ),
            List::take(
                [CoinId::from_bytes([0; CoinId::LENGTH]); MAX_PARTY_INPUTS],
                0,
            ),
        );
        let edge = hellas_kernel::Tx::edge_id_of(&funding, &terms);
        let open_hash = hellas_kernel::Tx::open_hash(network, &funding, &terms);
        let payment_open = hellas_kernel::Tx::open(
            funding,
            terms.clone(),
            PartyAuth::owner(Auth::native(client_signer.sign(open_hash))),
            PartyAuth::owner(Auth::native(provider_signer.sign(open_hash))),
        );

        let understated = EarnedCertificate::new(edge, terms.hash(), START_AMOUNT);
        let understated_digest = understated.digest(network);
        let start_digest = hellas_kernel::start_digest(
            network,
            edge,
            terms.hash(),
            Party::Maker,
            (2, 65),
            understated_digest,
        );
        let start =
            hellas_kernel::Tx::move_action(Move::StartPaymentClose(PaymentCloseStart::new(
                edge,
                terms.clone(),
                Party::Maker,
                (2, 65),
                Some((
                    understated,
                    PartyAuth::owner(client_signer.sign(understated_digest)),
                )),
                PartyAuth::owner(client_signer.sign(start_digest)),
            )));
        let start_id = hellas_kernel::start_id(start_digest, 2);
        let make_response = |amount: u64, action_by_provider: bool| {
            let certificate = EarnedCertificate::new(edge, terms.hash(), amount);
            let earned_digest = certificate.digest(network);
            let action_digest = hellas_kernel::response_digest(
                network,
                edge,
                terms.hash(),
                start_id,
                Party::Taker,
                earned_digest,
            );
            PaymentCloseResponse::new(
                edge,
                start_id,
                Party::Taker,
                (
                    certificate,
                    PartyAuth::owner(client_signer.sign(earned_digest)),
                ),
                PartyAuth::owner(if action_by_provider {
                    provider_signer.sign(action_digest)
                } else {
                    client_signer.sign(action_digest)
                }),
            )
        };
        let valid = make_response(60, true);
        if contest_index == 0 {
            first_responses = Some((
                valid.clone(),
                make_response(61, true),
                make_response(62, false),
                start_id,
                terms.hash(),
                understated_digest,
                start_digest,
            ));
        }
        valid_responses.push(valid);
        transactions.push(Transaction::Kernel(bond_open));
        transactions.push(Transaction::Kernel(payment_open));
        transactions.push(Transaction::Kernel(start));
    }
    let (valid, second, bad_action, start_id, terms_hash, understated_digest, start_digest) =
        first_responses.expect("response fixture has at least one contest");
    let absent = PaymentCloseResponse::new(
        EdgeId::from_bytes([0xa8; EdgeId::LENGTH]),
        start_id,
        Party::Taker,
        (
            EarnedCertificate::new(EdgeId::from_bytes([0xa8; EdgeId::LENGTH]), terms_hash, 63),
            PartyAuth::owner(client_signer.sign(understated_digest)),
        ),
        PartyAuth::owner(provider_signer.sign(start_digest)),
    );

    let config = utxo_db_config(&runtime, partition, 1024, 8);
    let database =
        <UtxoDatabase<_> as DatabaseSet<_>>::init(runtime.child("response_database"), config).await;
    let genesis = index_genesis();
    let floor_root = apply(&database, &allocations, 1, &[]).await;
    let floor = index_block(&genesis, floor_root, Vec::new());
    let contest_root = apply(&database, &allocations, 2, &transactions).await;
    let contest = index_block(&floor, contest_root, transactions);
    let mut finalized = vec![floor, contest.clone()];
    if let Some(stamp) = cursor_stamp {
        let root = apply(&database, &allocations, 3, &[]).await;
        finalized.push(crate::execution::test_support::index_block_at(
            &contest,
            root,
            Vec::new(),
            stamp,
        ));
    }

    let consensus = consensus_fixture(95);
    let (chain_indexer, handle) = spawn_archive(
        runtime,
        partition,
        Config {
            mailbox_size: 32,
            replay_buffer: 32,
            write_buffer: 32,
            page_cache_size: 1024,
            page_cache_count: 8,
            ..Config::default()
        },
        consensus.verifier.clone(),
        genesis.clone(),
    )
    .await
    .expect("chain indexer");
    for block in &finalized {
        chain_indexer
            .publish_proof(block.clone(), &finality_envelope(&consensus, block))
            .await
            .expect("finalized ingest");
    }
    let owner_index = OwnerIndex::new(network, &genesis, allocations.clone());
    for block in &finalized {
        assert_eq!(
            owner_index.apply_finalized(block),
            Ok(ApplyOutcome::Applied)
        );
    }
    let client = LocalLightClient::new(
        database.clone(),
        owner_index.clone(),
        Mempool::default(),
        chain_indexer.archive.clone(),
        ConsensusInfo {
            validators: Vec::new(),
            threshold_identity: Vec::new(),
            network_id: network.as_str().to_string(),
        },
    );
    Box::new(ResponseFixture {
        client,
        database,
        owner_index,
        chain_indexer,
        allocations,
        contest,
        valid,
        second,
        bad_action,
        absent,
        valid_responses,
        _indexer: handle,
    })
}

/// The pre-admission clock is the cursor block's own stamp: a response
/// already at its deadline there is refused before it reaches a mempool,
/// and one stamp earlier is admitted. The contest is accepted at block
/// time 2 000 ms, so its window shuts at 2 000 + `RESPONSE_WINDOW_MS`.
#[test]
fn a_response_at_its_deadline_by_block_time_is_refused_before_the_mempool() {
    use hellas_kernel::Encode as _;
    use hellas_rpc::pb::{
        chain::{SubmitTxOutcome as ProtoOutcome, SubmitWorkResponseRequest},
        services::light_client::LightClientHandler,
    };
    let deadline = 2_000 + hellas_kernel::RESPONSE_WINDOW_MS;
    for (stamp, admitted) in [(deadline - 1, true), (deadline, false)] {
        run_qmdb(move |runtime| async move {
            let fixture = response_fixture_at(runtime, "response_block_time", 1, Some(stamp)).await;
            let (activity_tx, _activity_rx) = tokio::sync::broadcast::channel(1);
            let rpc = crate::server::LightClientRpc::new(fixture.client.clone(), activity_tx);
            let mut bytes = vec![0; hellas_kernel::PaymentCloseResponse::MAX_ENCODED_SIZE];
            let written = fixture.valid.write_to(&mut bytes);
            bytes.truncate(written);
            let outcome = LightClientHandler::submit_work_response(
                &rpc,
                SubmitWorkResponseRequest { response: bytes },
                hellas_wire::TransportContext::default(),
            )
            .await
            .map(|response| response.outcome);
            if admitted {
                assert_eq!(outcome.ok(), Some(ProtoOutcome::Enqueued as i32));
            } else {
                assert_ne!(
                    outcome.ok(),
                    Some(ProtoOutcome::Enqueued as i32),
                    "a response stamped at its deadline is late",
                );
                assert!(
                    fixture
                        .client
                        .mempool()
                        .inner
                        .lock()
                        .await
                        .responses
                        .is_empty()
                );
            }
        });
    }
}

fn response_transaction(response: &PaymentCloseResponse) -> Transaction {
    Transaction::Kernel(hellas_kernel::Tx::move_action(
        hellas_kernel::Move::RespondPaymentClose(response.clone()),
    ))
}

#[test]
fn round7_general_ids_cannot_block_response() {
    use hellas_kernel::Encode as _;
    use hellas_rpc::pb::{
        chain::{
            SubmitTxOutcome as ProtoOutcome, SubmitTxRequest, SubmitWorkResponseRequest,
            submit_tx_request,
        },
        services::light_client::LightClientHandler,
    };
    use hellas_wire::{PeerIdentity, TransportContext};

    run_qmdb(|runtime| async move {
        let fixture = response_fixture(runtime, "round7_response_source_isolation").await;
        let (activity_tx, _activity_rx) = tokio::sync::broadcast::channel(1);
        let rpc = crate::server::LightClientRpc::new(fixture.client.clone(), activity_tx);
        let general = hellas_kernel::test_support::valid_open_tx().expect("general tx fixture");
        let mut general_bytes = vec![0; hellas_kernel::Tx::MAX_ENCODED_SIZE];
        let written = general.write_to(&mut general_bytes);
        general_bytes.truncate(written);
        let request = SubmitTxRequest {
            tx: Some(submit_tx_request::Tx::KernelTx(general_bytes)),
        };

        for identity in 0_u16..256 {
            let mut bytes = [0_u8; 32];
            bytes[..2].copy_from_slice(&identity.to_be_bytes());
            let response = LightClientHandler::submit_tx(
                &rpc,
                request.clone(),
                TransportContext {
                    peer: Some(PeerIdentity(bytes)),
                    auth_level: hellas_wire::AuthLevel::Vouched,
                    ..TransportContext::default()
                },
            )
            .await
            .expect("general submission has an honest outcome");
            assert!(matches!(
                ProtoOutcome::try_from(response.outcome),
                Ok(ProtoOutcome::Enqueued | ProtoOutcome::Duplicate)
            ));
        }
        let response = LightClientHandler::submit_tx(
            &rpc,
            request,
            TransportContext {
                peer: Some(PeerIdentity([0xff; 32])),
                auth_level: hellas_wire::AuthLevel::Vouched,
                ..TransportContext::default()
            },
        )
        .await
        .expect("a saturated source table returns an outcome");
        assert_eq!(response.outcome, ProtoOutcome::Full as i32);

        let mut response_bytes = vec![0; hellas_kernel::PaymentCloseResponse::MAX_ENCODED_SIZE];
        let written = fixture.valid.write_to(&mut response_bytes);
        response_bytes.truncate(written);
        let response = LightClientHandler::submit_work_response(
            &rpc,
            SubmitWorkResponseRequest {
                response: response_bytes,
            },
            TransportContext::default(),
        )
        .await
        .expect("response route is independent of general identities");
        assert_eq!(response.outcome, ProtoOutcome::Enqueued as i32);
        let mempool = fixture.client.mempool().inner.lock().await;
        assert_eq!(mempool.general.len(), 1);
        assert_eq!(mempool.responses.len(), 1);
    });
}

#[test]
fn round3_certificate_only_response_is_rejected_and_one_slot_per_finalized_contest() {
    use hellas_kernel::Encode as _;
    use hellas_rpc::pb::{
        chain::{SubmitTxRequest, submit_tx_request},
        services::light_client::LightClientHandler,
    };
    use hellas_wire::TransportContext;

    run_qmdb(|runtime| async move {
        let fixture = response_fixture(runtime, "response_finalized_slot").await;
        assert_eq!(
            fixture
                .client
                .submit_tx(response_transaction(&fixture.absent))
                .await
                .expect("absent contest is an admission outcome"),
            SubmitTxOutcome::ValidationRejected,
        );
        assert!(
            fixture
                .client
                .mempool()
                .inner
                .lock()
                .await
                .responses
                .is_empty()
        );

        assert_eq!(
            fixture
                .client
                .submit_tx(response_transaction(&fixture.bad_action))
                .await
                .expect("bad action is an admission outcome"),
            SubmitTxOutcome::ValidationRejected,
        );
        assert!(
            fixture
                .client
                .mempool()
                .inner
                .lock()
                .await
                .responses
                .is_empty()
        );

        assert_eq!(
            fixture
                .client
                .submit_tx(response_transaction(&fixture.valid))
                .await
                .expect("valid response admission"),
            SubmitTxOutcome::Enqueued,
        );
        assert_eq!(
            fixture
                .client
                .submit_tx(response_transaction(&fixture.valid))
                .await
                .expect("exact resident admission"),
            SubmitTxOutcome::Duplicate,
        );
        assert_eq!(
            fixture
                .client
                .submit_tx(response_transaction(&fixture.second))
                .await
                .expect("occupied contest admission"),
            SubmitTxOutcome::Full,
        );
        let mempool = fixture.client.mempool().inner.lock().await;
        assert_eq!(mempool.responses.len(), 1);
        assert_eq!(
            payment_close_response(&mempool.responses.values().next().unwrap().transaction),
            Some(&fixture.valid),
        );
        drop(mempool);

        // The general wire method cannot smuggle the response into the
        // general queue; the dedicated method is the only wire spelling.
        let tx =
            hellas_kernel::Tx::move_action(hellas_kernel::Move::RespondPaymentClose(fixture.valid));
        let mut bytes = vec![0; hellas_kernel::Tx::MAX_ENCODED_SIZE];
        let written = tx.write_to(&mut bytes);
        bytes.truncate(written);
        let (activity_tx, _activity_rx) = tokio::sync::broadcast::channel(1);
        let rpc = crate::server::LightClientRpc::new(fixture.client, activity_tx);
        let error = LightClientHandler::submit_tx(
            &rpc,
            SubmitTxRequest {
                tx: Some(submit_tx_request::Tx::KernelTx(bytes)),
            },
            TransportContext::default(),
        )
        .await
        .expect_err("SubmitTx rejects PaymentCloseResponse");
        assert_eq!(error.code(), hellas_wire::WireCode::InvalidArgument);
    });
}

#[test]
fn resident_invalidated_by_finality_is_dropped_before_full() {
    run_qmdb(|runtime| async move {
        let fixture = response_fixture_with_contests(runtime, "response_finality_sweep", 2).await;
        assert_eq!(
            fixture
                .client
                .submit_tx(response_transaction(&fixture.valid))
                .await
                .expect("valid response admission"),
            SubmitTxOutcome::Enqueued,
        );

        // Consensus executes the same response authoritatively. Once that
        // block finalizes, the old resident is no longer valid because
        // the contest record is answered.
        let transactions = vec![response_transaction(&fixture.valid)];
        let root = apply(&fixture.database, &fixture.allocations, 3, &transactions).await;
        let answered = index_block(&fixture.contest, root, transactions);
        let consensus = consensus_fixture(95);
        fixture
            .chain_indexer
            .publish_proof(answered.clone(), &finality_envelope(&consensus, &answered))
            .await
            .expect("answered block finalizes");
        assert_eq!(
            fixture.owner_index.apply_finalized(&answered),
            Ok(ApplyOutcome::Applied)
        );

        let fresh = fixture.valid_responses[1].clone();
        assert_eq!(
            fixture
                .client
                .submit_tx(response_transaction(&fresh))
                .await
                .expect("fresh finalized contest is admitted"),
            SubmitTxOutcome::Enqueued,
        );
        let mempool = fixture.client.mempool().inner.lock().await;
        assert_eq!(
            mempool.responses.len(),
            1,
            "the finalized-invalid resident is removed before insertion",
        );
        assert!(
            mempool
                .responses
                .contains_key(&(fresh.payment_edge(), fresh.start_id())),
            "the freed response slot is reusable",
        );
    });
}

#[test]
fn invalid_incoming_response_does_not_sweep_residents() {
    run_qmdb(|runtime| async move {
        let fixture = response_fixture(runtime, "response_auth_before_sweep").await;
        let resident = MempoolEntry::new(response_transaction(&fixture.bad_action));
        let resident_digest = resident.digest;
        fixture
            .client
            .mempool()
            .inner
            .lock()
            .await
            .responses
            .insert(
                (
                    fixture.bad_action.payment_edge(),
                    fixture.bad_action.start_id(),
                ),
                resident,
            );

        assert_eq!(
            fixture
                .client
                .submit_tx(response_transaction(&fixture.bad_action))
                .await
                .expect("bad action is an admission outcome"),
            SubmitTxOutcome::ValidationRejected,
        );
        let mempool = fixture.client.mempool().inner.lock().await;
        assert_eq!(mempool.responses.len(), 1);
        assert_eq!(
            mempool.responses.values().next().map(|entry| entry.digest),
            Some(resident_digest),
            "an unauthenticated newcomer never reaches the resident sweep",
        );
    });
}

#[test]
fn full_response_mempool_reuses_slot_invalidated_by_finality() {
    run_qmdb(|runtime| async move {
        let fixture = response_fixture_with_contests(
            runtime,
            "response_full_finality_sweep",
            RESPONSE_MEMPOOL_CAPACITY + 1,
        )
        .await;
        for response in fixture
            .valid_responses
            .iter()
            .take(RESPONSE_MEMPOOL_CAPACITY)
        {
            assert_eq!(
                fixture
                    .client
                    .submit_tx(response_transaction(response))
                    .await
                    .expect("live response admission"),
                SubmitTxOutcome::Enqueued,
            );
        }
        assert_eq!(
            fixture.client.mempool().inner.lock().await.responses.len(),
            RESPONSE_MEMPOOL_CAPACITY,
        );

        let invalidated = fixture.valid_responses[0].clone();
        let transactions = vec![response_transaction(&invalidated)];
        let root = apply(&fixture.database, &fixture.allocations, 3, &transactions).await;
        let answered = index_block(&fixture.contest, root, transactions);
        let consensus = consensus_fixture(95);
        fixture
            .chain_indexer
            .publish_proof(answered.clone(), &finality_envelope(&consensus, &answered))
            .await
            .expect("answered block finalizes");
        assert_eq!(
            fixture.owner_index.apply_finalized(&answered),
            Ok(ApplyOutcome::Applied)
        );

        let fresh = fixture.valid_responses[RESPONSE_MEMPOOL_CAPACITY].clone();
        assert_eq!(
            fixture
                .client
                .submit_tx(response_transaction(&fresh))
                .await
                .expect("fresh contest admission"),
            SubmitTxOutcome::Enqueued,
            "the finalized-invalid resident is swept before the capacity decision",
        );
        let mempool = fixture.client.mempool().inner.lock().await;
        assert_eq!(mempool.responses.len(), RESPONSE_MEMPOOL_CAPACITY);
        assert!(
            mempool
                .responses
                .contains_key(&(fresh.payment_edge(), fresh.start_id()))
        );
    });
}

async fn finalized_payload_indexer(
    context: commonware_runtime::tokio::Context,
    genesis: crate::HellasBlock,
    finalized: crate::HellasBlock,
) -> (crate::indexer::fixtures::ArchiveSource, Handle<()>) {
    let fixture = consensus_fixture(91);
    let config = Config {
        mailbox_size: 32,
        replay_buffer: 32,
        write_buffer: 32,
        page_cache_size: 1024,
        page_cache_count: 8,
        ..Config::default()
    };
    let (indexer, handle) = spawn_archive(
        context,
        "rpc_finalized_floor",
        config,
        fixture.verifier.clone(),
        genesis,
    )
    .await
    .expect("chain indexer");
    indexer
        .publish_proof(finalized.clone(), &finality_envelope(&fixture, &finalized))
        .await
        .expect("finalized floor ingest");
    (indexer, handle)
}

#[test]
fn work_channel_snapshot_reads_every_object_at_one_finalized_block() {
    use hellas_kernel::{
        Auth, BlockHeight, CoinId, Funding, LeaseSlots, List, MAX_EDGE_OUTPUTS, MAX_PARTY_INPUTS,
        Parties, Payout, PendingSlot, Secp256k1Signer, Terms as KernelTerms, Tx as KernelTx,
        WorkPaymentTerms, WorkStakeBondTerms,
    };

    const FUNDING: u64 = 100;
    const STAKE: u64 = 12;
    const HORIZON: u64 = 500;

    let network = crate::domain::TEST_NETWORK;
    let Ok(client) = Secp256k1Signer::from_secret_scalar([0x21; 32]) else {
        panic!("client key");
    };
    let Ok(provider) = Secp256k1Signer::from_secret_scalar([0x22; 32]) else {
        panic!("provider key");
    };
    let client_key = client.party_key();
    let provider_key = provider.party_key();

    let bond = WorkStakeBondTerms {
        parties: Parties::new(PartyKeys::sole(provider_key), PartyKeys::sole(client_key)),
        timeout: BlockHeight::new(HORIZON),
        timeout_outputs: List::take([Payout::new(provider_key, STAKE); MAX_EDGE_OUTPUTS], 1),
        max_job_price: 4,
    };
    let bond_terms = KernelTerms::work_stake_bond(bond.clone());
    let bond_funding = Funding::new(
        List::take(
            [CoinId::from_bytes(genesis_object_id(1).into()); MAX_PARTY_INPUTS],
            1,
        ),
        List::take(
            [CoinId::from_bytes([0; CoinId::LENGTH]); MAX_PARTY_INPUTS],
            0,
        ),
    );
    let bond_edge = KernelTx::edge_id_of(&bond_funding, &bond_terms);
    let bond_open_hash = KernelTx::open_hash(network, &bond_funding, &bond_terms);
    let bond_open = KernelTx::open(
        bond_funding,
        bond_terms,
        PartyAuth::owner(Auth::native(provider.sign(bond_open_hash))),
        PartyAuth::owner(Auth::native(client.sign(bond_open_hash))),
    );

    let payment_terms = KernelTerms::work_payment(WorkPaymentTerms {
        bond_edge,
        bond_terms: bond,
        private_policy_commitment: [0x25; 32],
        start_validity_blocks: 8,
        omission_bond: 2,
    });
    let payment_funding = Funding::new(
        List::take(
            [CoinId::from_bytes(genesis_object_id(0).into()); MAX_PARTY_INPUTS],
            1,
        ),
        List::take(
            [CoinId::from_bytes([0; CoinId::LENGTH]); MAX_PARTY_INPUTS],
            0,
        ),
    );
    let payment_edge = KernelTx::edge_id_of(&payment_funding, &payment_terms);
    let payment_open_hash = KernelTx::open_hash(network, &payment_funding, &payment_terms);
    let payment_open = KernelTx::open(
        payment_funding,
        payment_terms,
        PartyAuth::owner(Auth::native(client.sign(payment_open_hash))),
        PartyAuth::owner(Auth::native(provider.sign(payment_open_hash))),
    );

    // The two coins the opens spend, and one the fixture leaves
    // alone. After both opens are applied the first two are gone and
    // the third is not, which is the whole of what a setup preflight
    // asks.
    let spent_by_bond = CoinId::from_bytes(genesis_object_id(1).into());
    let spent_by_payment = CoinId::from_bytes(genesis_object_id(0).into());
    let untouched = CoinId::from_bytes(genesis_object_id(2).into());
    let funding: BTreeSet<CoinId> = [spent_by_bond, spent_by_payment, untouched]
        .into_iter()
        .collect();
    let query = WorkChannelQuery {
        bond_edge,
        payment_edge: Some(payment_edge),
        funding: funding.clone(),
    };

    run_qmdb(|runtime| async move {
        let indexer_context = runtime.child("chain_indexer");
        let config = utxo_db_config(&runtime, "rpc_work_snapshot", 1024, 8);
        let database = <UtxoDatabase<_> as DatabaseSet<_>>::init(runtime, config).await;
        let allocations = vec![
            (SettlementKey::from(client_key), FUNDING),
            (SettlementKey::from(provider_key), STAKE),
            // A third allocation, left unspent: the wrong-kind case
            // below needs a coin that still exists after both opens
            // have consumed the first two.
            (owner_key(41), 7),
        ];
        let genesis = index_genesis();

        // Block one: the genesis allocations alone.
        let floor_root = apply(&database, &allocations, 1, &[]).await;
        let floor_block = index_block(&genesis, floor_root, Vec::new());

        // Block two: the two opens, in the order setup requires.
        let transactions = vec![
            Transaction::Kernel(bond_open),
            Transaction::Kernel(payment_open),
        ];
        let open_root = apply(&database, &allocations, 2, &transactions).await;
        let open_block = index_block(&floor_block, open_root, transactions);

        let fixture = consensus_fixture(93);
        let (chain_indexer, _handle) = spawn_archive(
            indexer_context,
            "rpc_work_snapshot",
            Config {
                mailbox_size: 32,
                replay_buffer: 32,
                write_buffer: 32,
                page_cache_size: 1024,
                page_cache_count: 8,
                ..Config::default()
            },
            fixture.verifier.clone(),
            genesis.clone(),
        )
        .await
        .expect("chain indexer");
        for block in [&floor_block, &open_block] {
            chain_indexer
                .publish_proof(block.clone(), &finality_envelope(&fixture, block))
                .await
                .expect("finalized ingest");
        }

        let behind_allocations = allocations.clone();
        let index = OwnerIndex::new(network, &genesis, allocations);

        // Before either block is applied there is no finalized state
        // to answer from, which is not the same fact as "this is not
        // a channel".
        assert!(matches!(
            work_channel_snapshot_at(&database, &index, &chain_indexer, network, query.clone())
                .await,
            Ok(None),
        ));

        assert_eq!(
            index.apply_finalized(&floor_block),
            Ok(ApplyOutcome::Applied)
        );
        assert_eq!(
            index.apply_finalized(&open_block),
            Ok(ApplyOutcome::Applied)
        );

        let snapshot =
            work_channel_snapshot_at(&database, &index, &chain_indexer, network, query.clone())
                .await
                .expect("work channel snapshot")
                .expect("finalized state is available");

        assert_eq!(snapshot.query(), &query);
        assert_eq!(
            snapshot.block().height,
            commonware_consensus::Heightable::height(&open_block).get()
        );
        assert_eq!(snapshot.block().state_root, open_root);
        assert_eq!(snapshot.block().payload, open_block.digest());
        assert_eq!(snapshot.block().state_root, database.read().await.root());

        let bond_state = snapshot.bond().expect("the bond edge is live");
        assert_eq!(bond_state.value(), STAKE);
        let payment_state = snapshot.payment().expect("the payment edge is live");
        assert_eq!(payment_state.value(), FUNDING);

        // The lease the payment open wrote, read out of the slots
        // the kernel derives.
        let LeaseSlots::Present(lease) = snapshot.lease() else {
            panic!("an open payment channel holds its bond's lease");
        };
        assert_eq!(lease.bond_edge(), bond_edge);
        assert_eq!(lease.payment_edge(), payment_edge);
        assert_eq!(lease.admission_horizon(), HORIZON);
        assert_eq!(snapshot.pending(), PendingSlot::Absent);

        // The coin answer, at the same block and out of the same
        // reader. Both opens have executed, so the two coins they
        // funded are gone and the third is not — and the reply is
        // the survivors, not the question.
        let live: BTreeSet<CoinId> = [untouched].into_iter().collect();
        assert_eq!(snapshot.live_funding(), &live);
        assert_eq!(snapshot.live_funding_of(&funding), Some(&live));
        // A snapshot is an answer about the coins its own query
        // named. Asked about any other set it says so rather than
        // reporting a subset of a different question.
        assert_eq!(
            snapshot.live_funding_of(&[spent_by_bond].into_iter().collect()),
            None,
        );

        // An index one block behind the database it is reporting for:
        // finalization committed the next block before publishing its
        // cursor. The snapshot is reported at the committed block the
        // objects were read from, never at the cursor the index still names.
        let behind = OwnerIndex::new(network, &genesis, behind_allocations);
        assert_eq!(
            behind.apply_finalized(&floor_block),
            Ok(ApplyOutcome::Applied)
        );
        assert_ne!(behind.cursor().state_root, database.read().await.root());
        assert!(
            chain_indexer
                .get_finalization(behind.cursor().payload)
                .await
                .expect("finalization query")
                .is_some(),
            "the behind cursor's own block is finalized, so only the root disagrees",
        );
        let behind_snapshot =
            work_channel_snapshot_at(&database, &behind, &chain_indexer, network, query.clone())
                .await
                .expect("the committed block is finalized")
                .expect("both edges are open at the committed block");
        assert_eq!(behind_snapshot.block().payload, open_block.digest());
        assert_eq!(behind_snapshot.block().state_root, open_root);
        assert_eq!(behind_snapshot.live_funding(), &live);

        // A channel naming a bond nobody opened is absent, not
        // faulty, and its edges are absent too.
        let absent = work_channel_snapshot_at(
            &database,
            &index,
            &chain_indexer,
            network,
            WorkChannelQuery {
                bond_edge: hellas_kernel::EdgeId::from_bytes([0xa7; 32]),
                payment_edge: Some(hellas_kernel::EdgeId::from_bytes([0xa8; 32])),
                funding: [CoinId::from_bytes([0xa9; CoinId::LENGTH])]
                    .into_iter()
                    .collect(),
            },
        )
        .await
        .expect("absent channel snapshot")
        .expect("finalized state is available");
        assert!(absent.bond().is_none());
        assert!(absent.payment().is_none());
        assert_eq!(absent.lease(), LeaseSlots::Absent);
        assert_eq!(absent.pending(), PendingSlot::Absent);
        assert!(
            absent.live_funding().is_empty(),
            "a coin nobody minted is not live",
        );

        // A live edge named as a funding coin is a typed refusal
        // too. Coin, edge, and chunk ids share one address space, so
        // the kind of the object found is the only thing that says
        // the question was answered.
        assert!(matches!(
            work_channel_snapshot_at(
                &database,
                &index,
                &chain_indexer,
                network,
                WorkChannelQuery {
                    bond_edge,
                    payment_edge: Some(payment_edge),
                    funding: [CoinId::from_bytes(payment_edge.to_bytes())]
                        .into_iter()
                        .collect(),
                },
            )
            .await,
            Err(QueryError::WrongObjectKind {
                expected: ObjectKind::Coin,
                actual: ObjectKind::Edge,
            }),
        ));

        // A coin where an edge was asked for is a typed refusal, not
        // an absent edge.
        assert!(matches!(
            work_channel_snapshot_at(
                &database,
                &index,
                &chain_indexer,
                network,
                WorkChannelQuery {
                    bond_edge: hellas_kernel::EdgeId::from_bytes(genesis_object_id(2).into()),
                    payment_edge: Some(payment_edge),
                    funding: BTreeSet::new(),
                },
            )
            .await,
            Err(QueryError::WrongObjectKind {
                expected: ObjectKind::Edge,
                actual: ObjectKind::Coin,
            }),
        ));
    });
}

/// Executes one block's transactions and finalizes the result,
/// returning the state root they produce.
async fn apply(
    database: &UtxoDatabase<commonware_runtime::tokio::Context>,
    allocations: &[(SettlementKey, u64)],
    height: u64,
    transactions: &[Transaction],
) -> Digest {
    let batches = database.new_batches().await;
    let batches = execute_all(
        KernelContext::with_fees(
            crate::domain::TEST_NETWORK,
            BlockHeight::new(height),
            height * 1_000,
            BlockHash::from_bytes([0; BlockHash::LENGTH]),
            KERNEL_FEES,
        ),
        &ChainVerifier::new(),
        transactions,
        allocations,
        batches,
    )
    .await
    .expect("block executes");
    let merkleized = batches.merkleize().await.expect("state merkleizes");
    let root = merkleized.root();
    database.finalize(merkleized).await;
    root
}

/// The extracted validator is sampled for every response it judged,
/// and for nothing it did not judge.
///
/// `validation_ms` is §4's third per-validator addend. An admitted
/// response and a rejected one both paid for it — a rejection is
/// validation that ran — so both are samples, and the `admissible`
/// field is what lets a reader separate them without a second seam.
/// General traffic reaches no validator here and emits nothing.
#[test]
fn every_judged_response_is_one_validation_sample() {
    use hellas_rpc::observe::Samples;
    use tracing::instrument::WithSubscriber as _;

    run_qmdb(|runtime| async move {
        let fixture = response_fixture(runtime, "validation_seam").await;
        let samples = std::sync::Arc::new(Samples::new());

        assert_eq!(
            fixture
                .client
                .submit_tx(response_transaction(&fixture.valid))
                .with_subscriber(samples.clone())
                .await
                .expect("a live response is an admission outcome"),
            SubmitTxOutcome::Enqueued,
        );
        assert_eq!(
            fixture
                .client
                .submit_tx(response_transaction(&fixture.bad_action))
                .with_subscriber(samples.clone())
                .await
                .expect("a bad action signature is an admission outcome"),
            SubmitTxOutcome::ValidationRejected,
        );
        let general = Transaction::Kernel(
            hellas_kernel::test_support::valid_open_tx().expect("general tx fixture"),
        );
        assert_eq!(
            fixture
                .client
                .submit_tx(general)
                .with_subscriber(samples.clone())
                .await
                .expect("general submission has an outcome"),
            SubmitTxOutcome::Enqueued,
        );

        let judged = samples.of("validation_ms");
        assert_eq!(
            judged.len(),
            2,
            "two responses were judged; general traffic is judged by nothing here",
        );
        assert_eq!(judged[0].field("admissible"), Some("true"));
        assert_eq!(judged[1].field("admissible"), Some("false"));
        assert_ne!(
            judged[0].field("start_id"),
            None,
            "each sample names the contest it judged",
        );
        assert!(
            judged.iter().all(|sample| sample.ms >= 0.0),
            "every sample carries the duration it is a sample of",
        );
    });
}

#[test]
fn finalized_reads_inside_the_commit_before_publish_window_use_the_committed_block() {
    run_qmdb(|runtime| async move {
        let indexer_context = runtime.child("publication_indexer");
        let config = utxo_db_config(&runtime, "publication_rpc", 1024, 8);
        let database = <UtxoDatabase<_> as DatabaseSet<_>>::init(runtime, config).await;
        let owner = owner_key(41);
        let allocations = vec![(owner, 100)];
        let genesis = index_genesis();
        let root = apply(&database, &allocations, 1, &[]).await;
        let floor = index_block(&genesis, root, vec![]);
        let (chain_indexer, _handle) =
            finalized_payload_indexer(indexer_context, genesis.clone(), floor.clone()).await;
        let index = OwnerIndex::new(crate::domain::TEST_NETWORK, &genesis, allocations.clone());
        index.apply_finalized(&floor).unwrap();
        let local = LocalLightClient::new(
            database.clone(),
            index.clone(),
            Mempool::default(),
            chain_indexer.archive.clone(),
            ConsensusInfo {
                validators: vec![],
                threshold_identity: vec![],
                network_id: crate::domain::TEST_NETWORK.as_str().into(),
            },
        );
        let (reshape, ids) = crate::execution::test_support::reshape(
            41,
            &[genesis_object_id(0)],
            &[(owner, None, 100)],
        );
        // Commit the real database but deliberately stop before App::finalized's
        // cursor publication. All reads below run inside that exact window.
        let root = apply(&database, &allocations, 2, std::slice::from_ref(&reshape)).await;
        let next = index_block(&floor, root, vec![reshape]);
        chain_indexer
            .publish_proof(
                next.clone(),
                &finality_envelope(&consensus_fixture(91), &next),
            )
            .await
            .unwrap();
        assert_ne!(index.cursor().state_root, root);
        let query = WorkChannelQuery {
            bond_edge: EdgeId::from_bytes([71; 32]),
            payment_edge: Some(EdgeId::from_bytes([72; 32])),
            funding: BTreeSet::new(),
        };
        // Every read resolves at once against the committed block; none waits
        // for the cursor, and nothing is published below.
        let coin = hellas_kernel::CoinId::from_bytes(ids[0].0);
        let (objects, held, snapshot) =
            tokio::time::timeout(hellas_channel::test_support::HANG_GUARD, async {
                tokio::join!(
                    local.get_objects(vec![
                        ObjectKey::Coin(coin),
                        ObjectKey::Edge(query.bond_edge)
                    ]),
                    local.get_holdings(owner, None),
                    local.work_channel_snapshot(query.clone()),
                )
            })
            .await
            .expect("reads inside the window do not wait for publication");
        assert_eq!(index.cursor().payload, floor.digest());
        let objects = objects.unwrap().unwrap();
        assert_eq!(objects.block.state_root, root);
        assert_eq!(objects.coin(coin).unwrap().unwrap().value, 100);
        assert_eq!(objects.edge(query.bond_edge).unwrap(), None);
        let held = held.unwrap().unwrap();
        assert_eq!(held.block.payload, next.digest());
        assert_eq!(held.block.state_root, root);
        let coins: Vec<_> = held
            .owned_coins(owner)
            .into_iter()
            .map(|(id, coin)| (id, coin.value))
            .collect();
        assert_eq!(coins, vec![(CoinId::from_bytes(ids[0].0), 100)]);
        assert_eq!(snapshot.unwrap().unwrap().block().payload, next.digest());

        // State that is not the next finalized block is refused at once, rather
        // than served at a block it was not read at.
        let (spend, _) =
            crate::execution::test_support::reshape(41, &[ids[0]], &[(owner, None, 100)]);
        apply(&database, &allocations, 3, &[spend]).await;
        for result in [
            local.get_holdings(owner, None).await.map(|_| ()),
            local.work_channel_snapshot(query).await.map(|_| ()),
        ] {
            assert!(matches!(result, Err(QueryError::StateUnavailable(message))
                if message == "database state is not a finalized block"));
        }
    });
}
